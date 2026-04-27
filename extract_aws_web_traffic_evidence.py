#!/usr/bin/env python3
import argparse
import gzip
import json
import os
import re
from collections import deque
from datetime import datetime, timedelta, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


KEYWORDS = re.compile(
    r"(ecs|nginx|php|fpm|wordpress|wp|waf|alb|elb|load|access|application|container)",
    re.I,
)


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value)[:180]


def write_json(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str))


def read_json(path: Path, default=None):
    try:
        return json.loads(path.read_text())
    except Exception:
        return default


def client(service, region):
    return boto3.client(service, region_name=region)


def progress(msg):
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def paginate(c, method, result_key, **kwargs):
    paginator = c.get_paginator(method)
    items = []
    for page in paginator.paginate(**kwargs):
        items.extend(page.get(result_key, []))
    return items


def try_call(label, func, default=None):
    try:
        print(f"[*] {label}")
        return func()
    except ClientError as e:
        print(f"[!] {label} failed: {e.response.get('Error', {}).get('Message', e)}")
        return default
    except Exception as e:
        print(f"[!] {label} failed: {e}")
        return default


def ms_to_dt(value):
    if value is None:
        return None
    return datetime.fromtimestamp(value / 1000, tz=timezone.utc)


def dt_to_ms(value):
    return int(value.timestamp() * 1000)


def iso_from_ms(value):
    dt = ms_to_dt(value)
    return dt.isoformat() if dt else None


def iso_to_ms(value):
    if not value:
        return None
    try:
        return dt_to_ms(datetime.fromisoformat(value))
    except Exception:
        return None


def cloudwatch_event_id(event):
    event_id = event.get("eventId")
    if event_id:
        return event_id
    return "|".join(
        str(event.get(key, ""))
        for key in ("timestamp", "logStreamName", "ingestionTime", "message")
    )


def inspect_existing_cloudwatch_file(path: Path, overlap_ms: int):
    """
    Scan an existing JSONL export once so a resumed run can avoid re-fetching
    the large middle section. The early/late ID windows let us overlap a small
    boundary safely without writing duplicate events.
    """
    state = {
        "records": 0,
        "errors": 0,
        "first_timestamp_ms": None,
        "last_timestamp_ms": None,
        "covered_start_ms": None,
        "covered_end_ms": None,
        "coverage_reliable": False,
        "early_event_ids": set(),
        "late_event_ids": set(),
    }

    if not path.exists() or path.stat().st_size == 0:
        return state

    progress(f"    Inspecting existing export for resume: {path}")
    late_events = deque()

    with open(path) as f:
        for line in f:
            if not line.strip():
                continue

            try:
                event = json.loads(line)
                timestamp = int(event["timestamp"])
            except Exception:
                state["errors"] += 1
                continue

            event_id = cloudwatch_event_id(event)
            state["records"] += 1

            first_ts = state["first_timestamp_ms"]
            if first_ts is None or timestamp < first_ts:
                state["first_timestamp_ms"] = timestamp
                state["early_event_ids"] = {event_id}
            elif timestamp <= first_ts + overlap_ms:
                state["early_event_ids"].add(event_id)

            last_ts = state["last_timestamp_ms"]
            if last_ts is None or timestamp > last_ts:
                state["last_timestamp_ms"] = timestamp
            late_events.append((timestamp, event_id))

            cutoff = state["last_timestamp_ms"] - overlap_ms
            while late_events and late_events[0][0] < cutoff:
                late_events.popleft()

            if state["records"] == 1 or state["records"] % 250000 == 0:
                progress(
                    f"        inspected={state['records']:,}, "
                    f"first={iso_from_ms(state['first_timestamp_ms'])}, "
                    f"last={iso_from_ms(state['last_timestamp_ms'])}"
                )

    state["late_event_ids"] = {event_id for _, event_id in late_events}
    state["covered_start_ms"] = state["first_timestamp_ms"]
    state["covered_end_ms"] = state["last_timestamp_ms"]
    progress(
        f"    Existing export has {state['records']:,} records "
        f"from {iso_from_ms(state['first_timestamp_ms'])} "
        f"to {iso_from_ms(state['last_timestamp_ms'])}"
    )
    return state


def existing_cloudwatch_state(summary_path: Path, outfile: Path, overlap_ms: int):
    summary = read_json(summary_path, {}) or {}
    current_size = outfile.stat().st_size if outfile.exists() else 0

    if (
        summary.get("resume_version") == 1
        and summary.get("output_file_size") == current_size
        and (
            summary.get("last_event_timestamp_ms") is not None
            or summary.get("covered_end_timestamp_ms") is not None
            or summary.get("requested_end") is not None
        )
    ):
        completed = summary.get("completed") is True
        covered_start_ms = summary.get("covered_start_timestamp_ms")
        covered_end_ms = summary.get("covered_end_timestamp_ms")
        if covered_start_ms is None:
            covered_start_ms = iso_to_ms(summary.get("requested_start"))
        if covered_end_ms is None:
            covered_end_ms = iso_to_ms(summary.get("requested_end"))

        if not completed:
            covered_end_ms = summary.get("last_event_timestamp_ms") or covered_end_ms

        progress(
            "    Using existing CloudWatch summary checkpoint: "
            f"records={int(summary.get('events_exported_total', 0)):,}, "
            f"completed={completed}, "
            f"resume_from={iso_from_ms(covered_end_ms or summary.get('last_event_timestamp_ms'))}"
        )

        return {
            "records": int(summary.get("events_exported_total", 0)),
            "errors": int(summary.get("existing_scan_errors", 0)),
            "first_timestamp_ms": summary.get("first_event_timestamp_ms"),
            "last_timestamp_ms": summary.get("last_event_timestamp_ms"),
            "covered_start_ms": covered_start_ms or summary.get("first_event_timestamp_ms"),
            "covered_end_ms": covered_end_ms or summary.get("last_event_timestamp_ms"),
            "coverage_reliable": completed,
            "early_event_ids": set(),
            "late_event_ids": set(),
            "from_summary": True,
        }

    return inspect_existing_cloudwatch_file(outfile, overlap_ms)


def export_identity(out, region):
    sts = client("sts", region)
    write_json(out / "inventory" / "aws_identity.json", sts.get_caller_identity())


def export_elb(out, region):
    elbv2 = client("elbv2", region)
    lbs = try_call(
        "Discovering load balancers",
        lambda: paginate(elbv2, "describe_load_balancers", "LoadBalancers"),
        [],
    )
    write_json(out / "alb" / "load_balancers.json", lbs)

    log_locations = []

    for lb in lbs:
        arn = lb["LoadBalancerArn"]
        name = safe_name(lb["LoadBalancerName"])
        attrs = try_call(
            f"Reading attributes for {lb['LoadBalancerName']}",
            lambda arn=arn: elbv2.describe_load_balancer_attributes(
                LoadBalancerArn=arn
            ).get("Attributes", []),
            [],
        )
        write_json(out / "alb" / f"attributes_{name}.json", attrs)

        attr_map = {a["Key"]: a.get("Value", "") for a in attrs}
        if attr_map.get("access_logs.s3.enabled") == "true":
            log_locations.append(
                {
                    "load_balancer": lb,
                    "bucket": attr_map.get("access_logs.s3.bucket"),
                    "prefix": attr_map.get("access_logs.s3.prefix", ""),
                }
            )

    write_json(out / "alb" / "alb_log_locations.json", log_locations)
    return log_locations


def download_s3_prefix(out, region, bucket, prefix, label):
    s3 = boto3.resource("s3", region_name=region)
    dest = out / "s3" / safe_name(label)
    dest.mkdir(parents=True, exist_ok=True)

    progress("=" * 80)
    progress(f"[*] Downloading S3 prefix")
    progress(f"    Source: s3://{bucket}/{prefix}")
    progress(f"    Destination: {dest}")

    count = 0
    skipped = 0
    total_bytes = 0

    for obj in s3.Bucket(bucket).objects.filter(Prefix=prefix or ""):
        if obj.key.endswith("/"):
            continue

        local = dest / obj.key.replace("/", "__")
        local.parent.mkdir(parents=True, exist_ok=True)

        if local.exists() and local.stat().st_size == (obj.size or 0):
            skipped += 1
            if skipped == 1 or skipped % 100 == 0:
                progress(f"    Skipped existing files={skipped:,}, latest={obj.key}")
            continue

        try:
            s3.Bucket(bucket).download_file(obj.key, str(local))
            count += 1
            total_bytes += obj.size or 0

            if count == 1 or count % 100 == 0:
                progress(
                    f"    Downloaded files={count:,}, "
                    f"bytes={total_bytes:,}, "
                    f"latest={obj.key}"
                )

        except Exception as e:
            progress(f"[!] Failed downloading {obj.key}: {e}")

    progress(
        f"[*] Finished S3 download: downloaded={count:,}, "
        f"skipped_existing={skipped:,}, bytes={total_bytes:,}"
    )
    return {"downloaded": count, "skipped_existing": skipped, "bytes": total_bytes}


def export_waf(out, region):
    all_configs = []

    for scope, waf_region in [("REGIONAL", region), ("CLOUDFRONT", "us-east-1")]:
        waf = client("wafv2", waf_region)

        print(f"[*] Discovering WAFv2 Web ACLs {scope}")
        acls = []
        next_marker = None

        while True:
            kwargs = {"Scope": scope, "Limit": 100}
            if next_marker:
                kwargs["NextMarker"] = next_marker

            try:
                resp = waf.list_web_acls(**kwargs)
            except Exception as e:
                print(f"[!] WAF list failed for {scope}: {e}")
                break

            acls.extend(resp.get("WebACLs", []))
            next_marker = resp.get("NextMarker")
            if not next_marker:
                break

        write_json(out / "waf" / f"web_acls_{scope}.json", acls)

        for acl in acls:
            name = acl["Name"]
            acl_id = acl["Id"]
            arn = acl["ARN"]
            safe = safe_name(f"{scope}_{name}_{acl_id}")

            detail = try_call(
                f"Reading WAF ACL {name}",
                lambda: waf.get_web_acl(Name=name, Scope=scope, Id=acl_id),
                {},
            )
            write_json(out / "waf" / f"web_acl_{safe}.json", detail)

            logging = try_call(
                f"Reading WAF logging config {name}",
                lambda: waf.get_logging_configuration(ResourceArn=arn),
                {},
            )
            write_json(out / "waf" / f"logging_{safe}.json", logging)

            if logging and "LoggingConfiguration" in logging:
                all_configs.append(
                    {
                        "scope": scope,
                        "region": waf_region,
                        "name": name,
                        "arn": arn,
                        "logging": logging["LoggingConfiguration"],
                    }
                )

    write_json(out / "waf" / "waf_logging_destinations.json", all_configs)
    return all_configs


def export_cloudwatch_interval(
    logs,
    log_group_name,
    outfile,
    interval_start,
    interval_end,
    skip_event_ids,
    max_new_events=0,
):
    written = 0
    skipped_duplicates = 0
    total_pages = 0
    errors = 0
    first_written_ms = None
    last_written_ms = None
    chunk_start = interval_start
    limit_hit = False

    with open(outfile, "a") as f:
        while chunk_start < interval_end:
            chunk_end = min(chunk_start + timedelta(days=1), interval_end)

            start_ms = dt_to_ms(chunk_start)
            end_ms = dt_to_ms(chunk_end)

            day_count = 0
            day_skipped = 0
            day_pages = 0
            day_started = datetime.now(timezone.utc)

            progress(f"    [DAY START] {chunk_start.date()} -> {chunk_end.date()}")

            try:
                paginator = logs.get_paginator("filter_log_events")

                for page in paginator.paginate(
                    logGroupName=log_group_name,
                    startTime=start_ms,
                    endTime=end_ms,
                    interleaved=True,
                    PaginationConfig={"PageSize": 10000},
                ):
                    day_pages += 1
                    total_pages += 1

                    for ev in page.get("events", []):
                        event_id = cloudwatch_event_id(ev)
                        if event_id in skip_event_ids:
                            skipped_duplicates += 1
                            day_skipped += 1
                            continue

                        f.write(json.dumps(ev, default=str) + "\n")
                        skip_event_ids.add(event_id)
                        written += 1
                        day_count += 1

                        timestamp = ev.get("timestamp")
                        if timestamp is not None:
                            timestamp = int(timestamp)
                            if first_written_ms is None or timestamp < first_written_ms:
                                first_written_ms = timestamp
                            if last_written_ms is None or timestamp > last_written_ms:
                                last_written_ms = timestamp

                        if max_new_events and written >= max_new_events:
                            progress(
                                f"    [LIMIT HIT] CW_MAX_EVENTS_PER_GROUP={max_new_events:,} new events"
                            )
                            limit_hit = True
                            raise StopIteration

                    if day_pages == 1 or day_pages % 10 == 0:
                        progress(
                            f"        pages={day_pages:,}, "
                            f"day_new_events={day_count:,}, "
                            f"day_duplicates={day_skipped:,}, "
                            f"run_new_events={written:,}"
                        )

            except StopIteration:
                break
            except KeyboardInterrupt:
                progress("[!] Interrupted by user, keeping partial export.")
                raise
            except Exception as e:
                errors += 1
                progress(f"[!] Could not export {log_group_name} for {chunk_start.date()}: {e}")

            elapsed = (datetime.now(timezone.utc) - day_started).total_seconds()
            progress(
                f"    [DAY DONE] {chunk_start.date()} "
                f"new_events={day_count:,}, duplicates={day_skipped:,}, "
                f"pages={day_pages:,}, seconds={elapsed:.1f}"
            )

            if limit_hit:
                break

            chunk_start = chunk_end

    return {
        "written": written,
        "skipped_duplicates": skipped_duplicates,
        "pages": total_pages,
        "first_written_ms": first_written_ms,
        "last_written_ms": last_written_ms,
        "errors": errors,
        "limit_hit": limit_hit,
    }


def export_cloudwatch(out, region, days_back, resume=True, resume_overlap_minutes=10):
    logs = client("logs", region)

    progress("[*] Discovering CloudWatch log groups")
    groups = try_call(
        "Discovering CloudWatch log groups",
        lambda: paginate(logs, "describe_log_groups", "logGroups"),
        [],
    )
    write_json(out / "cloudwatch" / "log_groups.json", groups)

    relevant = [g for g in groups if KEYWORDS.search(g.get("logGroupName", ""))]
    write_json(out / "cloudwatch" / "relevant_log_groups.json", relevant)

    progress(f"[*] Found {len(groups)} total CloudWatch log groups")
    progress(f"[*] Found {len(relevant)} relevant CloudWatch log groups")

    max_cloudwatch_days = int(os.environ.get("CW_DAYS_BACK", days_back))
    max_events_per_group = int(os.environ.get("CW_MAX_EVENTS_PER_GROUP", "0"))  # 0 = unlimited
    overlap_ms = max(0, int(resume_overlap_minutes * 60 * 1000))
    overlap_delta = timedelta(milliseconds=overlap_ms)

    start_dt = datetime.now(timezone.utc) - timedelta(days=max_cloudwatch_days)
    end_dt = datetime.now(timezone.utc)

    for group in relevant:
        name = group["logGroupName"]
        safe = safe_name(name)

        stored_bytes = group.get("storedBytes", 0)
        retention = group.get("retentionInDays", "Never expire")
        creation = group.get("creationTime")

        if creation:
            creation_dt = datetime.fromtimestamp(creation / 1000, tz=timezone.utc).isoformat()
        else:
            creation_dt = "unknown"

        progress("=" * 80)
        progress(f"[*] Exporting CloudWatch events: {name}")
        progress(f"    Stored bytes: {stored_bytes:,}")
        progress(f"    Retention: {retention}")
        progress(f"    Created: {creation_dt}")
        progress(f"    Export range: {start_dt.isoformat()} to {end_dt.isoformat()}")
        progress(f"    Output file: {out / 'cloudwatch' / (safe + '.jsonl')}")

        outfile = out / "cloudwatch" / f"{safe}.jsonl"
        outfile.parent.mkdir(parents=True, exist_ok=True)
        summary_path = out / "cloudwatch" / f"{safe}_summary.json"

        if resume:
            existing = existing_cloudwatch_state(summary_path, outfile, overlap_ms)
        else:
            existing = {
                "records": 0,
                "errors": 0,
                "first_timestamp_ms": None,
                "last_timestamp_ms": None,
                "covered_start_ms": None,
                "covered_end_ms": None,
                "coverage_reliable": False,
                "early_event_ids": set(),
                "late_event_ids": set(),
            }
            if outfile.exists():
                progress("    Resume disabled; replacing existing CloudWatch JSONL export")
                outfile.unlink()

        intervals = []
        if existing["records"] or existing.get("coverage_reliable"):
            covered_start = ms_to_dt(existing.get("covered_start_ms"))
            covered_end = ms_to_dt(existing.get("covered_end_ms"))
            first_existing = ms_to_dt(existing.get("first_timestamp_ms"))
            last_existing = ms_to_dt(existing.get("last_timestamp_ms"))
            coverage_reliable = existing.get("coverage_reliable", False)

            if covered_start and start_dt < covered_start:
                if coverage_reliable:
                    interval_end = min(end_dt, covered_start)
                    skip_ids = set()
                    label = "older requested range"
                elif first_existing and existing.get("early_event_ids"):
                    interval_end = min(end_dt, first_existing + overlap_delta)
                    skip_ids = set(existing["early_event_ids"])
                    label = "older requested range with boundary overlap"
                elif first_existing:
                    interval_end = min(end_dt, first_existing - timedelta(milliseconds=1))
                    skip_ids = set()
                    label = "older requested range"
                else:
                    interval_end = min(end_dt, covered_start)
                    skip_ids = set()
                    label = "older requested range"

                if start_dt < interval_end:
                    intervals.append((label, start_dt, interval_end, skip_ids))

            if covered_end and covered_end < end_dt:
                if coverage_reliable:
                    interval_start = max(start_dt, covered_end)
                    skip_ids = set()
                    label = "newer requested range"
                elif last_existing and existing.get("late_event_ids"):
                    interval_start = max(start_dt, last_existing - overlap_delta)
                    skip_ids = set(existing["late_event_ids"])
                    label = "newer requested range with boundary overlap"
                elif last_existing:
                    interval_start = max(start_dt, last_existing + timedelta(milliseconds=1))
                    skip_ids = set()
                    label = "newer requested range"
                else:
                    interval_start = max(start_dt, covered_end)
                    skip_ids = set()
                    label = "newer requested range"

                if interval_start < end_dt:
                    intervals.append((label, interval_start, end_dt, skip_ids))
        else:
            intervals.append(("full requested range", start_dt, end_dt, set()))

        if not intervals:
            progress("    Existing CloudWatch export already covers the requested range")

        total_written = 0
        total_skipped_duplicates = 0
        total_pages = 0
        total_errors = 0
        first_written_ms = None
        last_written_ms = None
        limit_hit = False

        for label, interval_start, interval_end, skip_ids in intervals:
            progress(
                f"    [RESUME RANGE] {label}: "
                f"{interval_start.isoformat()} to {interval_end.isoformat()}"
            )

            remaining = 0
            if max_events_per_group:
                remaining = max(0, max_events_per_group - total_written)
                if remaining == 0:
                    limit_hit = True
                    break

            result = export_cloudwatch_interval(
                logs,
                name,
                outfile,
                interval_start,
                interval_end,
                skip_ids,
                max_new_events=remaining,
            )

            total_written += result["written"]
            total_skipped_duplicates += result["skipped_duplicates"]
            total_pages += result["pages"]
            total_errors += result["errors"]

            if result["first_written_ms"] is not None:
                if first_written_ms is None or result["first_written_ms"] < first_written_ms:
                    first_written_ms = result["first_written_ms"]
            if result["last_written_ms"] is not None:
                if last_written_ms is None or result["last_written_ms"] > last_written_ms:
                    last_written_ms = result["last_written_ms"]

            if result["limit_hit"]:
                limit_hit = True
                break

        first_event_ms = existing.get("first_timestamp_ms")
        last_event_ms = existing.get("last_timestamp_ms")
        if first_written_ms is not None:
            first_event_ms = min(first_event_ms, first_written_ms) if first_event_ms is not None else first_written_ms
        if last_written_ms is not None:
            last_event_ms = max(last_event_ms, last_written_ms) if last_event_ms is not None else last_written_ms

        completed = not limit_hit and total_errors == 0
        if completed:
            requested_start_ms = dt_to_ms(start_dt)
            requested_end_ms = dt_to_ms(end_dt)
            existing_covered_start_ms = existing.get("covered_start_ms")
            existing_covered_end_ms = existing.get("covered_end_ms")
            covered_start_ms = (
                min(existing_covered_start_ms, requested_start_ms)
                if existing_covered_start_ms is not None
                else requested_start_ms
            )
            covered_end_ms = (
                max(existing_covered_end_ms, requested_end_ms)
                if existing_covered_end_ms is not None
                else requested_end_ms
            )
        else:
            covered_start_ms = existing.get("covered_start_ms")
            covered_end_ms = existing.get("covered_end_ms")

        total_records = existing.get("records", 0) + total_written
        output_size = outfile.stat().st_size if outfile.exists() else 0

        write_json(
            summary_path,
            {
                "resume_version": 1,
                "log_group": name,
                "completed": completed,
                "events_existing_before": existing.get("records", 0),
                "events_written_this_run": total_written,
                "events_exported_total": total_records,
                "events_exported": total_records,
                "duplicates_skipped_this_run": total_skipped_duplicates,
                "pages_exported_this_run": total_pages,
                "errors_this_run": total_errors,
                "file": str(outfile),
                "output_file_size": output_size,
                "requested_start": start_dt.isoformat(),
                "requested_end": end_dt.isoformat(),
                "covered_start_timestamp_ms": covered_start_ms,
                "covered_start_timestamp": iso_from_ms(covered_start_ms),
                "covered_end_timestamp_ms": covered_end_ms,
                "covered_end_timestamp": iso_from_ms(covered_end_ms),
                "days_exported": max_cloudwatch_days,
                "resume_enabled": resume,
                "resume_overlap_minutes": resume_overlap_minutes,
                "first_event_timestamp_ms": first_event_ms,
                "first_event_timestamp": iso_from_ms(first_event_ms),
                "last_event_timestamp_ms": last_event_ms,
                "last_event_timestamp": iso_from_ms(last_event_ms),
                "existing_scan_errors": existing.get("errors", 0),
                "stored_bytes": stored_bytes,
                "retention": retention,
                "created": creation_dt,
            },
        )

        progress(
            f"[*] Finished {name}: existing={existing.get('records', 0):,}, "
            f"new={total_written:,}, total={total_records:,}, "
            f"duplicates_skipped={total_skipped_duplicates:,}, "
            f"errors={total_errors:,}, pages={total_pages:,}"
        )


def export_ecs(out, region):
    ecs = client("ecs", region)

    clusters = try_call(
        "Discovering ECS clusters",
        lambda: paginate(ecs, "list_clusters", "clusterArns"),
        [],
    )
    write_json(out / "ecs" / "clusters.json", clusters)

    for cluster in clusters:
        safe_cluster = safe_name(cluster)

        services = try_call(
            f"Listing ECS services {cluster}",
            lambda: paginate(ecs, "list_services", "serviceArns", cluster=cluster),
            [],
        )
        write_json(out / "ecs" / f"services_{safe_cluster}.json", services)

        for i in range(0, len(services), 10):
            batch = services[i : i + 10]
            details = try_call(
                f"Describing ECS services batch {i}",
                lambda batch=batch: ecs.describe_services(
                    cluster=cluster,
                    services=batch,
                ).get("services", []),
                [],
            )
            write_json(out / "ecs" / f"service_details_{safe_cluster}_{i}.json", details)

            for svc in details:
                td = svc.get("taskDefinition")
                if not td:
                    continue
                td_detail = try_call(
                    f"Describing task definition {td}",
                    lambda td=td: ecs.describe_task_definition(taskDefinition=td),
                    {},
                )
                write_json(out / "ecs" / f"task_definition_{safe_name(td)}.json", td_detail)


def export_cloudtrail(out, region, days_back):
    ct = client("cloudtrail", region)
    start = datetime.now(timezone.utc) - timedelta(days=days_back)
    end = datetime.now(timezone.utc)

    sources = [
        "elasticloadbalancing.amazonaws.com",
        "wafv2.amazonaws.com",
        "ecs.amazonaws.com",
        "logs.amazonaws.com",
        "s3.amazonaws.com",
        "cloudfront.amazonaws.com",
    ]

    for source in sources:
        events = try_call(
            f"CloudTrail lookup {source}",
            lambda source=source: paginate(
                ct,
                "lookup_events",
                "Events",
                StartTime=start,
                EndTime=end,
                LookupAttributes=[
                    {"AttributeKey": "EventSource", "AttributeValue": source}
                ],
            ),
            [],
        )
        write_json(out / "cloudtrail" / f"{safe_name(source)}.json", events)


def export_s3_inventory(out, region):
    s3c = client("s3", region)

    buckets = try_call("Listing S3 buckets", lambda: s3c.list_buckets().get("Buckets", []), [])
    write_json(out / "s3" / "buckets.json", buckets)

    interesting = []

    for bucket in buckets:
        name = bucket["Name"]
        if re.search(r"(log|logs|alb|elb|waf|cloudtrail|access|nginx|wordpress|wp)", name, re.I):
            interesting.append(name)

        for api_name, filename in [
            ("get_bucket_logging", "logging"),
            ("get_bucket_location", "location"),
            ("get_bucket_versioning", "versioning"),
        ]:
            data = try_call(
                f"S3 {api_name} {name}",
                lambda api_name=api_name, name=name: getattr(s3c, api_name)(Bucket=name),
                {},
            )
            write_json(out / "s3" / "bucket_metadata" / f"{safe_name(name)}_{filename}.json", data)

    write_json(out / "s3" / "interesting_buckets.json", interesting)


def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--region", default=os.environ.get("AWS_REGION", "eu-west-2"))
    parser.add_argument("--days-back", type=int, default=365)
    parser.add_argument("--out", default=None)
    parser.add_argument("--download-alb-logs", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--resume", action=argparse.BooleanOptionalAction, default=True)
    parser.add_argument("--resume-overlap-minutes", type=int, default=10)
    args = parser.parse_args()

    out = Path(args.out or f"aws_web_traffic_export_{datetime.now().strftime('%Y%m%d')}")
    out.mkdir(parents=True, exist_ok=True)

    export_identity(out, args.region)
    alb_locations = export_elb(out, args.region)
    waf_configs = export_waf(out, args.region)
    export_cloudwatch(
        out,
        args.region,
        args.days_back,
        resume=args.resume,
        resume_overlap_minutes=args.resume_overlap_minutes,
    )
    export_ecs(out, args.region)
    export_cloudtrail(out, args.region, args.days_back)
    export_s3_inventory(out, args.region)

    if args.download_alb_logs:
        for loc in alb_locations:
            bucket = loc.get("bucket")
            prefix = loc.get("prefix") or ""
            if bucket:
                download_s3_prefix(out, args.region, bucket, prefix, f"alb_{bucket}_{prefix}")

    write_json(
        out / "SUMMARY.json",
        {
            "output_dir": str(out),
            "region": args.region,
            "days_back": args.days_back,
            "resume_enabled": args.resume,
            "resume_overlap_minutes": args.resume_overlap_minutes,
            "alb_log_locations_found": alb_locations,
            "waf_logging_configs_found": waf_configs,
            "notes": [
                "CloudWatch export is limited to log groups matching web-related names.",
                "CloudWatch JSONL exports resume from existing files and append older/newer gaps only.",
                "If ALB access logging was disabled historically, old traffic logs may not exist.",
                "WAF full logs only exist if WAF logging was previously configured.",
                "CloudTrail lookup-events normally has limited retention unless trail logs were delivered to S3/CloudWatch.",
            ],
        },
    )

    print()
    print("[+] Complete")
    print(f"[+] Output directory: {out}")
    print(f"[+] Review: {out / 'SUMMARY.json'}")


if __name__ == "__main__":
    main()
