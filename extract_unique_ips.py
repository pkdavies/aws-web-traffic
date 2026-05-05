#!/usr/bin/env python3
from __future__ import annotations

import argparse
import calendar
import csv
import json
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
    import orjson
except ImportError:  # pragma: no cover - useful when the venv is not active
    orjson = None


CSV_HEADERS = [
    "Date",
    "Client IP",
    "@http.uri",
    "@http.status_code",
    "@http.method",
    "@UserAgent",
    "Content",
]


@dataclass
class ExtractedRow:
    timestamp_ms: int
    date: str
    client_ip: str
    uri: str
    status_code: str
    method: str
    user_agent: str
    content: str


def json_loads(value: bytes | str):
    if orjson is not None:
        return orjson.loads(value)
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return json.loads(value)


def parse_iso_datetime(value: str) -> datetime:
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def iso_z_from_ms(value: int) -> str:
    dt = datetime.fromtimestamp(value / 1000, tz=timezone.utc)
    return dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def apache_date_from_ms(value: int) -> str:
    return datetime.fromtimestamp(value / 1000, tz=timezone.utc).strftime(
        "%d/%b/%Y:%H:%M:%S +0000"
    )


def subtract_months(dt: datetime, months: int) -> datetime:
    month_index = dt.month - months - 1
    year = dt.year + month_index // 12
    month = month_index % 12 + 1
    day = min(dt.day, calendar.monthrange(year, month)[1])
    return dt.replace(year=year, month=month, day=day)


def ms_from_dt(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


def load_summary(export_dir: Path) -> dict:
    try:
        return json.loads((export_dir / "cloudwatch" / "aws-waf-logs-dluhc-ld_prod_waf_summary.json").read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def find_waf_jsonl(export_dir: Path) -> Path:
    cloudwatch_dir = export_dir / "cloudwatch"
    candidates = [
        path
        for path in sorted(cloudwatch_dir.glob("*.jsonl"))
        if "waf" in path.name.lower()
    ]
    if not candidates:
        candidates = sorted(cloudwatch_dir.glob("*.jsonl"))
    if not candidates:
        raise FileNotFoundError(f"No CloudWatch JSONL files found in {cloudwatch_dir}")
    if len(candidates) > 1:
        names = ", ".join(path.name for path in candidates)
        raise RuntimeError(f"Multiple JSONL candidates found; use --input. Candidates: {names}")
    return candidates[0]


def outer_timestamp_ms(line: bytes) -> int | None:
    try:
        outer = json_loads(line)
    except Exception:
        return None
    if not isinstance(outer, dict):
        return None
    value = outer.get("timestamp")
    if value is None:
        message = outer.get("message")
        if isinstance(message, str) and message.strip().startswith("{"):
            try:
                payload = json_loads(message)
            except Exception:
                return None
            if isinstance(payload, dict):
                value = payload.get("timestamp")
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def next_full_line(handle, offset: int) -> tuple[int, bytes]:
    handle.seek(offset)
    if offset:
        handle.readline()
    line_start = handle.tell()
    return line_start, handle.readline()


def seek_timestamp(handle, target_ms: int, size: int) -> int:
    lo = 0
    hi = size
    best = size

    while lo < hi:
        mid = (lo + hi) // 2
        line_start, line = next_full_line(handle, mid)
        if not line:
            hi = mid
            continue

        timestamp_ms = outer_timestamp_ms(line)
        if timestamp_ms is None:
            lo = handle.tell()
            continue

        if timestamp_ms < target_ms:
            lo = handle.tell()
        else:
            best = line_start
            hi = mid

    return best


def header_lookup(headers: list[dict]) -> dict[str, str]:
    lookup: dict[str, str] = {}
    for header in headers or []:
        if not isinstance(header, dict):
            continue
        name = str(header.get("name", "")).lower()
        if name:
            lookup[name] = str(header.get("value", "")).strip()
    return lookup


def first_forwarded_ip(value: str) -> str:
    if not value:
        return ""
    return value.split(",", 1)[0].strip()


def selected_client_ip(request: dict, headers: dict[str, str]) -> str:
    candidates = [
        headers.get("cf-connecting-ip", ""),
        headers.get("true-client-ip", ""),
        headers.get("x-real-ip", ""),
        first_forwarded_ip(headers.get("x-forwarded-for", "")),
        request.get("clientIp", ""),
    ]
    for candidate in candidates:
        candidate = str(candidate or "").strip()
        if candidate and candidate != "-":
            return candidate
    return ""


def request_uri(request: dict) -> str:
    uri = str(request.get("uri") or "/")
    args = str(request.get("args") or "")
    if args:
        return f"{uri}?{args}"
    return uri


def content_line(
    timestamp_ms: int,
    client_ip: str,
    method: str,
    uri: str,
    status_code: str,
    user_agent: str,
    headers: dict[str, str],
    request: dict,
) -> str:
    protocol = str(request.get("httpVersion") or "HTTP/?")
    referrer = headers.get("referer") or headers.get("referrer") or "-"
    status = status_code or "-"
    return (
        f'{client_ip} - - [{apache_date_from_ms(timestamp_ms)}] '
        f'"{method} {uri} {protocol}" {status} - "{referrer}" "{user_agent}"'
    )


def row_from_line(line: bytes) -> ExtractedRow | None:
    try:
        outer = json_loads(line)
    except Exception:
        return None
    if not isinstance(outer, dict):
        return None

    payload = outer
    message = outer.get("message")
    if isinstance(message, str) and message.strip().startswith("{"):
        try:
            payload = json_loads(message)
        except Exception:
            return None
    if not isinstance(payload, dict):
        return None

    request = payload.get("httpRequest")
    if not isinstance(request, dict):
        return None

    try:
        timestamp_ms = int(payload.get("timestamp", outer.get("timestamp")))
    except (TypeError, ValueError):
        return None

    headers = header_lookup(request.get("headers") or [])
    client_ip = selected_client_ip(request, headers)
    if not client_ip:
        return None

    method = str(request.get("httpMethod") or "").upper() or "UNKNOWN"
    uri = request_uri(request)
    status_code = str(payload.get("responseCodeSent") or "")
    user_agent = headers.get("user-agent") or "Unknown"

    return ExtractedRow(
        timestamp_ms=timestamp_ms,
        date=iso_z_from_ms(timestamp_ms),
        client_ip=client_ip,
        uri=uri,
        status_code=status_code,
        method=method,
        user_agent=user_agent,
        content=content_line(
            timestamp_ms,
            client_ip,
            method,
            uri,
            status_code,
            user_agent,
            headers,
            request,
        ),
    )


def write_rows(path: Path, rows: list[ExtractedRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(CSV_HEADERS)
        for row in rows:
            writer.writerow(
                [
                    row.date,
                    row.client_ip,
                    row.uri,
                    row.status_code,
                    row.method,
                    row.user_agent,
                    row.content,
                ]
            )


def progress(message: str) -> None:
    print(f"[*] {datetime.now().strftime('%H:%M:%S')} {message}", file=sys.stderr, flush=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extract one CSV row per unique client IP from an AWS WAF CloudWatch JSONL export."
    )
    parser.add_argument(
        "export_dir",
        nargs="?",
        default="aws_web_traffic_export_20260427",
        help="AWS export directory to read.",
    )
    parser.add_argument("--input", type=Path, help="CloudWatch JSONL file to read.")
    parser.add_argument("--out", type=Path, help="CSV output path.")
    parser.add_argument(
        "--months",
        type=int,
        default=2,
        help="Calendar months to include when --start is not supplied.",
    )
    parser.add_argument("--start", help="Inclusive UTC start timestamp, for example 2026-02-27T21:12:27Z.")
    parser.add_argument("--end", help="Exclusive UTC end timestamp. Defaults to the export's last event.")
    parser.add_argument(
        "--sample",
        choices=["latest", "first"],
        default="latest",
        help="Which event to retain for each unique IP.",
    )
    parser.add_argument(
        "--progress-interval",
        type=float,
        default=10.0,
        help="Seconds between progress messages.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    export_dir = Path(args.export_dir)
    input_path = args.input or find_waf_jsonl(export_dir)
    summary = load_summary(export_dir)

    if args.end:
        end_dt = parse_iso_datetime(args.end)
    elif summary.get("last_event_timestamp_ms") is not None:
        end_dt = datetime.fromtimestamp(
            int(summary["last_event_timestamp_ms"]) / 1000,
            tz=timezone.utc,
        )
    else:
        raise RuntimeError("Could not determine export end; pass --end.")

    if args.start:
        start_dt = parse_iso_datetime(args.start)
    else:
        start_dt = subtract_months(end_dt, args.months)

    start_ms = ms_from_dt(start_dt)
    end_ms = ms_from_dt(end_dt)
    if end_ms <= start_ms:
        raise ValueError("--end must be after --start")

    output_path = args.out or (
        Path("data")
        / f"{export_dir.name}_unique_client_ips_{start_dt.date()}_to_{end_dt.date()}.csv"
    )

    rows_by_ip: dict[str, ExtractedRow] = {}
    scanned = 0
    parsed = 0
    errors = 0
    started_at = time.monotonic()
    last_progress = started_at

    size = input_path.stat().st_size
    with input_path.open("rb") as handle:
        start_offset = seek_timestamp(handle, start_ms, size)
        handle.seek(start_offset)
        progress(
            f"Reading {input_path.name} from {iso_z_from_ms(start_ms)} to {iso_z_from_ms(end_ms)}"
        )
        progress(f"Seeked to byte {start_offset:,} of {size:,}")

        for line in handle:
            scanned += 1
            timestamp_ms = outer_timestamp_ms(line)
            if timestamp_ms is None:
                errors += 1
                continue
            if timestamp_ms >= end_ms:
                break
            if timestamp_ms < start_ms:
                continue

            row = row_from_line(line)
            if row is None:
                errors += 1
                continue

            parsed += 1
            existing = rows_by_ip.get(row.client_ip)
            if existing is None:
                rows_by_ip[row.client_ip] = row
            elif args.sample == "latest" and row.timestamp_ms >= existing.timestamp_ms:
                rows_by_ip[row.client_ip] = row

            now = time.monotonic()
            if now - last_progress >= args.progress_interval:
                elapsed = max(0.001, now - started_at)
                progress(
                    f"scanned={scanned:,}, parsed={parsed:,}, unique_ips={len(rows_by_ip):,}, "
                    f"rate={parsed / elapsed:,.0f}/s"
                )
                last_progress = now

    rows = sorted(rows_by_ip.values(), key=lambda row: row.timestamp_ms, reverse=True)
    write_rows(output_path, rows)

    elapsed = max(0.001, time.monotonic() - started_at)
    progress(
        f"Wrote {len(rows):,} unique IP rows to {output_path} "
        f"from {parsed:,} matching events in {elapsed:,.1f}s; errors={errors:,}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
