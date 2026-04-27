#!/usr/bin/env python3
"""
Sort exported CloudWatch JSONL files after collection.

This is intended for large files produced by extract_aws_web_traffic_evidence.py.
It sorts records by their CloudWatch event timestamp without loading the whole
file into memory. It can optionally remove duplicate CloudWatch event IDs.
"""

from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import multiprocessing as mp
import os
import tempfile
from concurrent.futures import ALL_COMPLETED, FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

try:
    import orjson
except ImportError:
    orjson = None


DEFAULT_EXPORT_PREFIX = "aws_web_traffic_export_"


@dataclass
class ChunkInfo:
    path: Path
    records: int


@dataclass
class RawChunkInfo:
    path: Path
    chunk_index: int
    records: int
    start_sequence: int


def progress(message: str) -> None:
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}", flush=True)


def find_latest_export_dir(cwd: Path) -> Path | None:
    candidates = [path for path in cwd.glob(f"{DEFAULT_EXPORT_PREFIX}*") if path.is_dir()]
    if not candidates:
        return None
    return sorted(candidates, key=lambda path: (path.stat().st_mtime, path.name))[-1]


def default_input_path(export_dir: Path) -> Path:
    jsonl_files = sorted((export_dir / "cloudwatch").glob("*.jsonl"))
    if not jsonl_files:
        raise FileNotFoundError(f"No CloudWatch JSONL files found in {export_dir / 'cloudwatch'}")
    if len(jsonl_files) > 1:
        progress(f"Found {len(jsonl_files)} JSONL files; using {jsonl_files[0]}")
    return jsonl_files[0]


def event_key(line: str, sequence: int) -> tuple[int, str, int]:
    try:
        event = orjson.loads(line) if orjson else json.loads(line)
    except Exception:
        return (10**30, f"parse-error-{sequence}", sequence)

    timestamp = event.get("timestamp")
    try:
        timestamp = int(timestamp)
    except (TypeError, ValueError):
        timestamp = 10**30

    event_id = event.get("eventId")
    if not event_id:
        event_id = hashlib.sha256(line.encode("utf-8", errors="replace")).hexdigest()

    return (timestamp, str(event_id), sequence)


def write_chunk(
    rows: list[tuple[tuple[int, str, int], str]],
    temp_dir: Path,
    chunk_index: int,
) -> ChunkInfo:
    rows.sort(key=lambda row: row[0])
    chunk_path = temp_dir / f"chunk_{chunk_index:06d}.jsonl"
    with chunk_path.open("w", encoding="utf-8") as handle:
        for key, line in rows:
            timestamp, event_id, sequence = key
            handle.write(f"{timestamp}\t{event_id}\t{sequence}\t{line}")
    return ChunkInfo(path=chunk_path, records=len(rows))


def write_raw_chunk(
    lines: list[str],
    temp_dir: Path,
    chunk_index: int,
    start_sequence: int,
) -> RawChunkInfo:
    chunk_path = temp_dir / f"raw_{chunk_index:06d}.jsonl"
    with chunk_path.open("w", encoding="utf-8") as handle:
        handle.writelines(lines)
    return RawChunkInfo(
        path=chunk_path,
        chunk_index=chunk_index,
        records=len(lines),
        start_sequence=start_sequence,
    )


def sort_raw_chunk(raw_chunk: RawChunkInfo) -> ChunkInfo:
    rows: list[tuple[tuple[int, str, int], str]] = []

    with raw_chunk.path.open("r", encoding="utf-8", errors="replace") as handle:
        for offset, line in enumerate(handle):
            if not line.endswith("\n"):
                line += "\n"
            sequence = raw_chunk.start_sequence + offset
            rows.append((event_key(line, sequence), line))

    sorted_chunk = write_chunk(rows, raw_chunk.path.parent, raw_chunk.chunk_index)
    raw_chunk.path.unlink(missing_ok=True)
    return sorted_chunk


def worker_count() -> int:
    return max(1, min(4, os.cpu_count() or 1))


def collect_finished(futures, chunks: list[ChunkInfo], block: bool = False):
    if not futures:
        return futures

    done, pending = wait(futures, return_when=ALL_COMPLETED if block else FIRST_COMPLETED)
    for future in done:
        chunk = future.result()
        chunks.append(chunk)
        progress(f"  sorted chunk {len(chunks)}: {chunk.records:,} records")
    return pending


def make_chunks(input_path: Path, temp_dir: Path, chunk_bytes: int) -> tuple[list[ChunkInfo], int]:
    chunks: list[ChunkInfo] = []
    lines: list[str] = []
    current_bytes = 0
    total_records = 0
    chunk_index = 0
    chunk_start_sequence = 0
    workers = worker_count()

    progress(f"Reading source: {input_path}")
    progress(f"Sorting chunks with {workers} worker process(es)")

    with ProcessPoolExecutor(max_workers=workers, mp_context=mp.get_context("fork")) as executor:
        futures = set()

        with input_path.open("r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                if not line.endswith("\n"):
                    line += "\n"

                lines.append(line)
                current_bytes += len(line.encode("utf-8", errors="replace"))
                total_records += 1

                if current_bytes >= chunk_bytes:
                    raw_chunk = write_raw_chunk(lines, temp_dir, chunk_index, chunk_start_sequence)
                    progress(f"  queued chunk {chunk_index + 1}: {raw_chunk.records:,} records")
                    futures.add(executor.submit(sort_raw_chunk, raw_chunk))

                    while len(futures) >= workers * 2:
                        futures = collect_finished(futures, chunks)

                    lines = []
                    current_bytes = 0
                    chunk_index += 1
                    chunk_start_sequence = total_records

        if lines:
            raw_chunk = write_raw_chunk(lines, temp_dir, chunk_index, chunk_start_sequence)
            progress(f"  queued chunk {chunk_index + 1}: {raw_chunk.records:,} records")
            futures.add(executor.submit(sort_raw_chunk, raw_chunk))

        while futures:
            futures = collect_finished(futures, chunks)

    chunks.sort(key=lambda chunk: chunk.path.name)
    return chunks, total_records


def parse_chunk_line(line: str) -> tuple[tuple[int, str, int], str]:
    timestamp, event_id, sequence, payload = line.split("\t", 3)
    return (int(timestamp), event_id, int(sequence)), payload


def merge_chunks(chunks: list[ChunkInfo], output_path: Path, dedupe: bool) -> tuple[int, int]:
    output_path.parent.mkdir(parents=True, exist_ok=True)

    handles = [chunk.path.open("r", encoding="utf-8") for chunk in chunks]
    heap = []
    written = 0
    duplicates = 0
    seen_ids: set[str] = set()

    try:
        for index, handle in enumerate(handles):
            line = handle.readline()
            if line:
                key, payload = parse_chunk_line(line)
                heapq.heappush(heap, (key, index, payload))

        progress(f"Merging {len(chunks):,} sorted chunk(s) into {output_path}")
        with output_path.open("w", encoding="utf-8") as output:
            while heap:
                key, index, payload = heapq.heappop(heap)
                _, event_id, _ = key

                if dedupe and event_id in seen_ids:
                    duplicates += 1
                else:
                    if dedupe:
                        seen_ids.add(event_id)
                    output.write(payload)
                    written += 1

                next_line = handles[index].readline()
                if next_line:
                    next_key, next_payload = parse_chunk_line(next_line)
                    heapq.heappush(heap, (next_key, index, next_payload))

                if written and written % 250000 == 0:
                    progress(f"  merged records={written:,}, duplicates_skipped={duplicates:,}")
    finally:
        for handle in handles:
            handle.close()

    return written, duplicates


def parse_size(value: str) -> int:
    text = value.strip().lower()
    multiplier = 1
    for suffix, factor in [("gb", 1024**3), ("g", 1024**3), ("mb", 1024**2), ("m", 1024**2)]:
        if text.endswith(suffix):
            multiplier = factor
            text = text[: -len(suffix)]
            break
    return int(float(text) * multiplier)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Externally sort a CloudWatch JSONL export by timestamp.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="JSONL file or export directory. Defaults to latest aws_web_traffic_export_* directory.",
    )
    parser.add_argument("--out", help="Output path. Defaults to <input>_sorted.jsonl.")
    parser.add_argument(
        "--replace",
        action="store_true",
        help="Atomically replace the source JSONL after sorting.",
    )
    parser.add_argument(
        "--dedupe",
        action="store_true",
        help="Drop duplicate CloudWatch event IDs while merging.",
    )
    parser.add_argument(
        "--chunk-size",
        default="512mb",
        help="Approximate in-memory chunk size before writing a sorted temp chunk.",
    )
    parser.add_argument(
        "--tmpdir",
        default=None,
        help="Temporary directory for sorted chunks. Use a disk with enough free space.",
    )
    return parser.parse_args()


def resolve_input(path_arg: str | None) -> Path:
    if path_arg:
        path = Path(path_arg).expanduser().resolve()
    else:
        export_dir = find_latest_export_dir(Path.cwd())
        if not export_dir:
            raise FileNotFoundError("No aws_web_traffic_export_* directory found.")
        path = export_dir.resolve()

    if path.is_dir():
        return default_input_path(path)
    return path


def main() -> int:
    args = parse_args()
    input_path = resolve_input(args.path)
    if not input_path.exists():
        raise FileNotFoundError(input_path)

    if args.replace and args.out:
        raise SystemExit("--replace and --out cannot be used together")

    output_path = (
        Path(args.out).expanduser().resolve()
        if args.out
        else input_path.with_name(f"{input_path.stem}_sorted{input_path.suffix}")
    )

    chunk_bytes = parse_size(args.chunk_size)
    temp_parent = Path(args.tmpdir).expanduser().resolve() if args.tmpdir else input_path.parent
    temp_parent.mkdir(parents=True, exist_ok=True)

    progress(f"Sorting by CloudWatch timestamp")
    progress(f"Input: {input_path}")
    progress(f"Output: {output_path}")
    progress(f"Chunk size: {chunk_bytes:,} bytes")
    progress(f"Dedupe: {'yes' if args.dedupe else 'no'}")

    with tempfile.TemporaryDirectory(prefix="sort_cloudwatch_", dir=temp_parent) as temp_name:
        temp_dir = Path(temp_name)
        chunks, total_records = make_chunks(input_path, temp_dir, chunk_bytes)
        written, duplicates = merge_chunks(chunks, output_path, args.dedupe)

    if args.replace:
        backup_path = input_path.with_name(f"{input_path.name}.unsorted.bak")
        progress(f"Replacing source. Backup: {backup_path}")
        os.replace(input_path, backup_path)
        os.replace(output_path, input_path)
        output_path = input_path

    progress(
        f"Done. input_records={total_records:,}, "
        f"output_records={written:,}, duplicates_skipped={duplicates:,}"
    )
    progress(f"Sorted file: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
