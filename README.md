# AWS Web Traffic Extract

This project exports AWS web traffic evidence, sorts and deduplicates large CloudWatch JSONL exports, and generates static HTML usage reports from the collected evidence.

The normal workflow is:

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

.venv/bin/python extract.py --region eu-west-2 --days-back 365
.venv/bin/python report_full.py
```

`extract.py` writes an `aws_web_traffic_export_YYYYMMDD/` directory. The report scripts default to the newest directory matching that pattern.

## Requirements

- Python 3.10 or newer.
- AWS credentials configured for `boto3`, for example via environment variables, AWS SSO, or an AWS profile.
- Permissions to inspect the relevant AWS services: STS, ELBv2, WAFv2, CloudWatch Logs, ECS, CloudTrail, and S3.
- Python dependencies in `requirements.txt`.

Install dependencies with:

```bash
.venv/bin/pip install -r requirements.txt
```

`orjson` is required for the large JSONL processing paths. `tqdm` is used for report progress bars when available.

## Files

### `extract.py`

Main AWS evidence exporter. It discovers and exports:

- AWS account identity.
- ALB metadata and access log locations.
- WAFv2 Web ACLs and logging configuration.
- CloudWatch log groups matching web-related names.
- CloudWatch log events as JSONL.
- ECS cluster, service, and task-definition metadata.
- CloudTrail lookup events for relevant AWS services.
- S3 bucket inventory and selected metadata.
- ALB access logs from S3 when configured.

CloudWatch exports support resume by default. The script writes per-log-group `*_summary.json` files and uses them to append only older/newer missing ranges on later runs. Boundary overlap is controlled by `--resume-overlap-minutes` and duplicate CloudWatch event IDs are skipped within overlap windows.

At the end of a run, `extract.py` sorts and deduplicates CloudWatch JSONL exports by default by invoking `sort.py --replace`. It writes a `*_sort.json` marker beside each sorted JSONL. If the file size and mtime still match the marker on a later run, sorting is skipped.

Common commands:

```bash
.venv/bin/python extract.py
.venv/bin/python extract.py --region eu-west-2 --days-back 365
.venv/bin/python extract.py --out aws_web_traffic_export_manual
.venv/bin/python extract.py --no-download-alb-logs
.venv/bin/python extract.py --no-cloudtrail
.venv/bin/python extract.py --no-sort-cloudwatch
```

Useful environment variables:

- `AWS_REGION`: default region when `--region` is not supplied.
- `CW_DAYS_BACK`: override CloudWatch export lookback.
- `CW_MAX_EVENTS_PER_GROUP`: cap new CloudWatch events per log group, useful for testing.
- `CT_DAYS_BACK`: override CloudTrail lookup lookback, capped by CloudTrail retention.
- `SORT_CHUNK_SIZE`: default chunk size for `sort.py` when called by `extract.py`.
- `SORT_TMPDIR`: temporary directory for sort chunks.

### `sort.py`

External sorter for large CloudWatch JSONL files. It sorts records by CloudWatch event timestamp without loading the whole source file into memory. It creates temporary chunks, sorts chunks in worker processes, merges them, and deduplicates CloudWatch event IDs by default.

Direct usage:

```bash
.venv/bin/python sort.py aws_web_traffic_export_20260427/cloudwatch/example.jsonl
.venv/bin/python sort.py aws_web_traffic_export_20260427/cloudwatch/example.jsonl --replace
.venv/bin/python sort.py aws_web_traffic_export_20260427 --replace
.venv/bin/python sort.py example.jsonl --chunk-size 2048mb --tmpdir /large/tmp
```

Defaults:

- Output is `<input>_sorted.jsonl` unless `--replace` is used.
- `--dedupe` is enabled by default. Use `--no-dedupe` to keep duplicate event IDs.
- `--replace` keeps a `.unsorted.bak` backup beside the source file.

### `report_full.py`

Full yearly HTML report generator for large exports. It reads WAF CloudWatch JSONL and ALB access logs, aggregates yearly and monthly usage statistics, and writes a static HTML file.

It includes:

- Yearly summary and month-by-month breakdown.
- Daily and hourly traffic charts.
- Audience, country, device, browser, and OS breakdowns.
- Top paths, hosts, referrers, query keys, WAF rules, labels, and blocked events.
- Data quality table listing parsed files.

Common commands:

```bash
.venv/bin/python report_full.py
.venv/bin/python report_full.py aws_web_traffic_export_20260427
.venv/bin/python report_full.py --out aws_web_traffic_export_20260427/web_stats.html
.venv/bin/python report_full.py --anonymize-ips
.venv/bin/python report_full.py --max-records 100000
.venv/bin/python report_full.py --no-progress
```

The default output path is `<export_dir>/web_stats.html`.

Useful environment variable:

- `REPORT_TIMEZONE`: defaults to `Europe/London`.

### `report_quick.py`

Smaller static HTML report generator. It reads the same evidence export layout as `report_full.py`, but produces a simpler report without the yearly/monthly report structure and without the newer fast-progress path.

Common commands:

```bash
.venv/bin/python report_quick.py
.venv/bin/python report_quick.py aws_web_traffic_export_20260427
.venv/bin/python report_quick.py --out aws_web_traffic_export_20260427/web_usage_report.html
.venv/bin/python report_quick.py --anonymize-ips
.venv/bin/python report_quick.py --max-records 100000
```

The default output path is `<export_dir>/web_usage_report.html`.

### `.gitignore`

Ignores generated AWS export directories and Python bytecode:

- `aws_web*`
- `__pycache__/*`

## Generated Export Layout

A typical export directory contains:

```text
aws_web_traffic_export_YYYYMMDD/
  SUMMARY.json
  inventory/
  alb/
  waf/
  cloudwatch/
    log_groups.json
    relevant_log_groups.json
    <safe-log-group>.jsonl
    <safe-log-group>_summary.json
    <safe-log-group>_sort.json
    <safe-log-group>.jsonl.unsorted.bak
  ecs/
  cloudtrail/
  s3/
```

The `.jsonl.unsorted.bak` file is created only when `sort.py --replace` sorts an existing JSONL file.

## Notes

- Exported logs can contain IP addresses, user agents, request paths, and other sensitive operational data. Treat export directories as evidence files.
- Use report `--anonymize-ips` when sharing reports outside the operational team.
- CloudWatch full logs and ALB logs only exist for periods where logging was enabled and retained.
- CloudTrail lookup data is limited by CloudTrail retention unless trail logs were delivered elsewhere.
- Sorting and deduplication require enough free disk space for temporary chunks and the replacement backup.
