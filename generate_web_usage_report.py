#!/usr/bin/env python3
"""
Generate a static web usage monitoring report from AWS traffic evidence.

The script is designed to work with output from extract_aws_web_traffic_evidence.py.
It reads AWS WAF CloudWatch JSONL exports, and also understands ALB access logs if
they have been downloaded into the export directory.
"""

from __future__ import annotations

import argparse
import gzip
import json
import math
import os
import re
import shlex
import sys
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape
from ipaddress import ip_address
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qs, urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


DEFAULT_TITLE = "Web Usage Monitoring Report"
EXPORT_PREFIX = "aws_web_traffic_export_"
STATIC_EXTENSIONS = {
    ".avif",
    ".bmp",
    ".css",
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".json",
    ".map",
    ".png",
    ".svg",
    ".webp",
    ".woff",
    ".woff2",
}

CHART_COLORS = [
    "#0f766e",
    "#2563eb",
    "#d97706",
    "#dc2626",
    "#16a34a",
    "#7c3aed",
    "#0891b2",
    "#be123c",
]


@dataclass
class ParsedFile:
    path: Path
    kind: str
    records: int = 0
    errors: int = 0


@dataclass
class UsageStats:
    name: str
    total: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    unique_ips: set[str] = field(default_factory=set)
    sources: Counter = field(default_factory=Counter)
    actions: Counter = field(default_factory=Counter)
    statuses: Counter = field(default_factory=Counter)
    status_classes: Counter = field(default_factory=Counter)
    methods: Counter = field(default_factory=Counter)
    hosts: Counter = field(default_factory=Counter)
    paths: Counter = field(default_factory=Counter)
    normalized_paths: Counter = field(default_factory=Counter)
    countries: Counter = field(default_factory=Counter)
    devices: Counter = field(default_factory=Counter)
    browsers: Counter = field(default_factory=Counter)
    operating_systems: Counter = field(default_factory=Counter)
    user_agents: Counter = field(default_factory=Counter)
    referrers: Counter = field(default_factory=Counter)
    referrer_hosts: Counter = field(default_factory=Counter)
    daily: Counter = field(default_factory=Counter)
    hourly: Counter = field(default_factory=Counter)
    hour_of_day: Counter = field(default_factory=Counter)
    weekdays: Counter = field(default_factory=Counter)
    content_types: Counter = field(default_factory=Counter)
    query_keys: Counter = field(default_factory=Counter)
    waf_rules: Counter = field(default_factory=Counter)
    waf_labels: Counter = field(default_factory=Counter)
    client_ips: Counter = field(default_factory=Counter)
    blocked_paths: Counter = field(default_factory=Counter)
    blocked_countries: Counter = field(default_factory=Counter)
    blocked_ips: Counter = field(default_factory=Counter)
    bytes_sent: int = 0
    bytes_received: int = 0
    recent_events: deque[dict] = field(default_factory=lambda: deque(maxlen=20))
    recent_blocked_events: deque[dict] = field(default_factory=lambda: deque(maxlen=20))

    def add(self, event: dict) -> None:
        self.total += 1

        dt = event.get("timestamp")
        if dt:
            self.first_seen = dt if self.first_seen is None else min(self.first_seen, dt)
            self.last_seen = dt if self.last_seen is None else max(self.last_seen, dt)
            self.daily[dt.date().isoformat()] += 1
            self.hourly[dt.strftime("%Y-%m-%d %H:00")] += 1
            self.hour_of_day[f"{dt.hour:02d}:00"] += 1
            self.weekdays[dt.strftime("%a")] += 1

        source = clean_value(event.get("source"), "Unknown")
        self.sources[source] += 1

        action = clean_value(event.get("action"), "Observed")
        if action:
            self.actions[action] += 1

        status = clean_value(event.get("status_code"), "")
        if status and status != "-":
            self.statuses[status] += 1
            self.status_classes[status_class(status)] += 1

        method = clean_value(event.get("method"), "UNKNOWN")
        self.methods[method] += 1

        host = clean_value(event.get("host"), "Unknown")
        self.hosts[host] += 1

        path = clean_path(event.get("path"))
        normalized_path = normalize_path_for_grouping(path)
        self.paths[path] += 1
        self.normalized_paths[normalized_path] += 1
        self.content_types[classify_content_type(path)] += 1

        country = clean_value(event.get("country"), "Unknown")
        self.countries[country] += 1

        ip = clean_value(event.get("client_ip"), "")
        if ip:
            self.unique_ips.add(ip)
            self.client_ips[ip] += 1

        user_agent = clean_value(event.get("user_agent"), "Unknown")
        device, browser, os_name = classify_user_agent(user_agent)
        self.user_agents[user_agent] += 1
        self.devices[device] += 1
        self.browsers[browser] += 1
        self.operating_systems[os_name] += 1

        referrer = clean_value(event.get("referrer"), "")
        referrer_host = referrer_bucket(referrer, host)
        self.referrers[referrer or "Direct / none"] += 1
        self.referrer_hosts[referrer_host] += 1

        for key in event.get("query_keys") or []:
            self.query_keys[key] += 1

        rule = clean_value(event.get("waf_rule"), "")
        if rule:
            self.waf_rules[rule] += 1

        for label in event.get("waf_labels") or []:
            self.waf_labels[label] += 1

        self.bytes_sent += safe_int(event.get("bytes_sent"))
        self.bytes_received += safe_int(event.get("bytes_received"))

        sample = {
            "time": format_datetime(dt) if dt else "",
            "source": source,
            "action": action,
            "status": status,
            "method": method,
            "host": host,
            "path": path,
            "country": country,
            "client_ip": ip,
            "rule": rule,
        }
        self.recent_events.append(sample)

        if is_blocked_event(event):
            self.blocked_paths[path] += 1
            self.blocked_countries[country] += 1
            if ip:
                self.blocked_ips[ip] += 1
            self.recent_blocked_events.append(sample)


def clean_value(value, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    if not text or text == "-":
        return default
    return text


def safe_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def html_escape(value) -> str:
    return escape(str(value), quote=True)


def pct(part: int, total: int) -> str:
    if not total:
        return "0.0%"
    return f"{(part / total) * 100:.1f}%"


def fmt_int(value: int | float) -> str:
    return f"{int(value):,}"


def fmt_float(value: float) -> str:
    return f"{value:,.1f}"


def fmt_bytes(value: int) -> str:
    size = float(value)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if abs(size) < 1024 or unit == "TB":
            if unit == "B":
                return f"{int(size):,} {unit}"
            return f"{size:,.1f} {unit}"
        size /= 1024
    return f"{value:,} B"


def format_datetime(dt: datetime | None) -> str:
    if not dt:
        return ""
    return dt.strftime("%Y-%m-%d %H:%M:%S %Z").strip()


def status_class(status: str) -> str:
    if not status or not status[0].isdigit():
        return "Unknown"
    return f"{status[0]}xx"


def clean_path(value) -> str:
    path = clean_value(value, "/")
    if path.startswith("http://") or path.startswith("https://"):
        parsed = urlparse(path)
        path = parsed.path or "/"
    path = path.split("?", 1)[0] or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path


def normalize_path_for_grouping(path: str) -> str:
    path = clean_path(path)
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    uuid_re = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.I,
    )
    long_hex_re = re.compile(r"^[0-9a-f]{16,}$", re.I)
    parts = []
    for part in path.strip("/").split("/"):
        if not part:
            continue
        if part.isdigit() or uuid_re.match(part) or long_hex_re.match(part):
            parts.append(":id")
        elif len(part) > 80:
            parts.append(":value")
        else:
            parts.append(part)
    return "/" + "/".join(parts) if parts else "/"


def classify_content_type(path: str) -> str:
    lower = clean_path(path).lower()
    suffix = Path(lower).suffix
    if lower.startswith("/api/") or lower == "/api":
        return "API"
    if suffix in {".html", ".htm", ".php", ".aspx"} or not suffix:
        return "Page"
    if suffix in {".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".avif", ".ico"}:
        return "Image"
    if suffix in {".css", ".js", ".map"}:
        return "Frontend asset"
    if suffix in {".woff", ".woff2", ".ttf", ".otf", ".eot"}:
        return "Font"
    if suffix in {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv"}:
        return "Document"
    return "Other"


def classify_user_agent(user_agent: str) -> tuple[str, str, str]:
    ua = (user_agent or "").strip()
    low = ua.lower()
    if not ua or ua == "Unknown":
        return "Unknown", "Unknown", "Unknown"

    bot_markers = [
        "bot",
        "crawl",
        "spider",
        "slurp",
        "nmap",
        "curl",
        "wget",
        "python-requests",
        "go-http-client",
        "java/",
        "httpclient",
        "scrapy",
        "scanner",
    ]
    is_bot = any(marker in low for marker in bot_markers)

    if is_bot:
        device = "Bot / automation"
    elif "ipad" in low or "tablet" in low:
        device = "Tablet"
    elif "mobile" in low or "iphone" in low or ("android" in low and "mobile" in low):
        device = "Mobile"
    else:
        device = "Desktop"

    if "edg/" in low or "edge/" in low:
        browser = "Edge"
    elif "opr/" in low or "opera" in low:
        browser = "Opera"
    elif "chrome/" in low or "crios/" in low:
        browser = "Chrome"
    elif "firefox/" in low or "fxios/" in low:
        browser = "Firefox"
    elif "safari/" in low and "chrome/" not in low:
        browser = "Safari"
    elif "curl/" in low:
        browser = "curl"
    elif "wget/" in low:
        browser = "wget"
    elif "nmap" in low:
        browser = "Nmap"
    elif is_bot:
        browser = "Bot / automation"
    else:
        browser = "Other"

    if "windows nt" in low:
        os_name = "Windows"
    elif "iphone" in low or "ipad" in low or "cpu os" in low:
        os_name = "iOS / iPadOS"
    elif "android" in low:
        os_name = "Android"
    elif "mac os x" in low or "macintosh" in low:
        os_name = "macOS"
    elif "linux" in low:
        os_name = "Linux"
    elif is_bot:
        os_name = "Bot / unknown"
    else:
        os_name = "Other"

    return device, browser, os_name


def referrer_bucket(referrer: str, request_host: str) -> str:
    if not referrer:
        return "Direct / none"
    try:
        parsed = urlparse(referrer)
    except ValueError:
        return "Unknown / malformed"
    if not parsed.netloc:
        return "Unknown / malformed"
    if request_host and parsed.netloc.lower() == request_host.lower():
        return "Internal"
    return parsed.netloc.lower()


def truncate(value: str, limit: int = 64) -> str:
    value = str(value)
    if len(value) <= limit:
        return value
    return value[: max(0, limit - 3)] + "..."


def load_timezone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except ZoneInfoNotFoundError:
        print(f"[!] Unknown timezone {name!r}; falling back to UTC", file=sys.stderr)
        return ZoneInfo("UTC")


def timestamp_to_datetime(value, tz: ZoneInfo) -> datetime | None:
    if value is None:
        return None
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        text = str(value).replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(text).astimezone(tz)
        except ValueError:
            return None

    if numeric > 10_000_000_000:
        numeric = numeric / 1000
    return datetime.fromtimestamp(numeric, timezone.utc).astimezone(tz)


def get_header(headers: list[dict], *names: str) -> str:
    wanted = {name.lower() for name in names}
    for header in headers or []:
        name = str(header.get("name", "")).lower()
        if name in wanted:
            return str(header.get("value", "")).strip()
    return ""


def first_forwarded_ip(value: str) -> str:
    if not value:
        return ""
    return value.split(",", 1)[0].strip()


def anonymize_ip(value: str) -> str:
    if not value:
        return ""
    try:
        parsed = ip_address(value)
    except ValueError:
        return value
    if parsed.version == 4:
        parts = value.split(".")
        return ".".join(parts[:3] + ["0"])
    expanded = parsed.exploded.split(":")
    return ":".join(expanded[:4] + ["0000", "0000", "0000", "0000"])


def selected_client_ip(request: dict, headers: list[dict], anonymize: bool) -> str:
    candidates = [
        get_header(headers, "cf-connecting-ip"),
        get_header(headers, "true-client-ip"),
        get_header(headers, "x-real-ip"),
        first_forwarded_ip(get_header(headers, "x-forwarded-for")),
        request.get("clientIp", ""),
    ]
    for candidate in candidates:
        candidate = clean_value(candidate, "")
        if candidate:
            return anonymize_ip(candidate) if anonymize else candidate
    return ""


def waf_terminating_rule(payload: dict) -> str:
    base = clean_value(payload.get("terminatingRuleId"), "")
    for group in payload.get("ruleGroupList") or []:
        terminating = group.get("terminatingRule")
        if terminating and terminating.get("ruleId"):
            group_id = clean_value(group.get("ruleGroupId"), "")
            rule_id = clean_value(terminating.get("ruleId"), "")
            if group_id:
                return f"{group_id} / {rule_id}"
            return rule_id
    return base


def waf_event_from_payload(
    payload: dict,
    outer_timestamp,
    tz: ZoneInfo,
    anonymize: bool,
) -> dict | None:
    request = payload.get("httpRequest")
    if not isinstance(request, dict):
        return None

    headers = request.get("headers") or []
    timestamp = timestamp_to_datetime(payload.get("timestamp", outer_timestamp), tz)
    host = clean_value(request.get("host"), get_header(headers, "host") or "Unknown")
    referrer = get_header(headers, "referer", "referrer")
    args = clean_value(request.get("args"), "")
    query_keys = sorted(parse_qs(args, keep_blank_values=True).keys()) if args else []

    country = clean_value(get_header(headers, "cf-ipcountry"), "")
    if not country or country == "XX":
        country = clean_value(request.get("country"), "Unknown")

    labels = [
        clean_value(item.get("name"), "")
        for item in payload.get("labels") or []
        if isinstance(item, dict) and clean_value(item.get("name"), "")
    ]

    return {
        "source": "AWS WAF",
        "timestamp": timestamp,
        "action": clean_value(payload.get("action"), "Observed").upper(),
        "method": clean_value(request.get("httpMethod"), "UNKNOWN").upper(),
        "host": host,
        "path": clean_path(request.get("uri")),
        "country": country,
        "client_ip": selected_client_ip(request, headers, anonymize),
        "user_agent": get_header(headers, "user-agent") or "Unknown",
        "referrer": referrer,
        "query_keys": query_keys,
        "waf_rule": waf_terminating_rule(payload),
        "waf_labels": labels,
        "bytes_received": safe_int(payload.get("requestBodySize")),
    }


def parse_cloudwatch_waf_line(
    line: str,
    tz: ZoneInfo,
    anonymize: bool,
) -> dict | None:
    try:
        outer = json.loads(line)
    except json.JSONDecodeError:
        return None

    if not isinstance(outer, dict):
        return None

    if "httpRequest" in outer:
        return waf_event_from_payload(outer, outer.get("timestamp"), tz, anonymize)

    message = outer.get("message")
    if not isinstance(message, str) or not message.strip().startswith("{"):
        return None

    try:
        payload = json.loads(message)
    except json.JSONDecodeError:
        return None

    if not isinstance(payload, dict):
        return None

    return waf_event_from_payload(payload, outer.get("timestamp"), tz, anonymize)


def split_host_port(value: str) -> str:
    if not value:
        return ""
    if value.startswith("[") and "]" in value:
        return value[1 : value.index("]")]
    if ":" in value:
        return value.rsplit(":", 1)[0]
    return value


def parse_alb_line(line: str, tz: ZoneInfo, anonymize: bool) -> dict | None:
    try:
        fields = shlex.split(line)
    except ValueError:
        return None

    if len(fields) < 14:
        return None

    timestamp = timestamp_to_datetime(fields[1], tz)
    client_ip = split_host_port(fields[3])
    request_line = fields[12]
    user_agent = fields[13] if len(fields) > 13 else "Unknown"

    request_parts = request_line.split()
    if len(request_parts) >= 2:
        method = request_parts[0].upper()
        raw_url = request_parts[1]
    else:
        method = "UNKNOWN"
        raw_url = "/"

    parsed_url = urlparse(raw_url)
    host = parsed_url.netloc or clean_value(fields[2], "Unknown")
    path = parsed_url.path or "/"
    query_keys = sorted(parse_qs(parsed_url.query, keep_blank_values=True).keys())

    elb_status = clean_value(fields[8], "")
    target_status = clean_value(fields[9], "")
    status = target_status if target_status and target_status != "-" else elb_status

    return {
        "source": "ALB access log",
        "timestamp": timestamp,
        "action": status_class(status) if status else "Observed",
        "status_code": status,
        "method": method,
        "host": host,
        "path": path,
        "country": "Unknown",
        "client_ip": anonymize_ip(client_ip) if anonymize else client_ip,
        "user_agent": user_agent or "Unknown",
        "query_keys": query_keys,
        "bytes_received": safe_int(fields[10]),
        "bytes_sent": safe_int(fields[11]),
    }


def is_blocked_event(event: dict) -> bool:
    action = clean_value(event.get("action"), "").upper()
    if action in {"BLOCK", "CAPTCHA", "CHALLENGE"}:
        return True
    status = clean_value(event.get("status_code"), "")
    return status.startswith("4") or status.startswith("5")


def open_text(path: Path):
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return path.open("r", encoding="utf-8", errors="replace")


def find_latest_export_dir(cwd: Path) -> Path | None:
    candidates = [path for path in cwd.glob(f"{EXPORT_PREFIX}*") if path.is_dir()]
    if not candidates:
        return None
    return sorted(candidates, key=lambda path: (path.stat().st_mtime, path.name))[-1]


def load_waf_stats(
    export_dir: Path,
    tz: ZoneInfo,
    anonymize: bool,
    max_records: int,
) -> tuple[UsageStats, list[ParsedFile]]:
    stats = UsageStats("AWS WAF")
    parsed_files: list[ParsedFile] = []
    cloudwatch_dir = export_dir / "cloudwatch"

    for path in sorted(cloudwatch_dir.glob("*.jsonl")):
        parsed = ParsedFile(path=path, kind="AWS WAF CloudWatch JSONL")
        parsed_files.append(parsed)
        with open_text(path) as handle:
            for line in handle:
                if max_records and stats.total >= max_records:
                    return stats, parsed_files
                line = line.strip()
                if not line:
                    continue
                event = parse_cloudwatch_waf_line(line, tz, anonymize)
                if event is None:
                    parsed.errors += 1
                    continue
                parsed.records += 1
                stats.add(event)

    return stats, parsed_files


def looks_like_alb_log(path: Path, export_dir: Path) -> bool:
    rel = str(path.relative_to(export_dir)).lower()
    name = path.name.lower()
    if "/cloudwatch/" in f"/{rel}":
        return False
    if path.suffix.lower() == ".json" or path.suffix.lower() == ".jsonl":
        return False
    return (
        "elasticloadbalancing" in rel
        or "alb" in rel
        or name.endswith(".log")
        or name.endswith(".log.gz")
        or ("/s3/" in f"/{rel}" and path.suffix.lower() in {".gz", ".log", ".txt"})
    )


def load_alb_stats(
    export_dir: Path,
    tz: ZoneInfo,
    anonymize: bool,
    max_records: int,
) -> tuple[UsageStats, list[ParsedFile]]:
    stats = UsageStats("ALB access logs")
    parsed_files: list[ParsedFile] = []

    for path in sorted(export_dir.rglob("*")):
        if not path.is_file() or not looks_like_alb_log(path, export_dir):
            continue
        parsed = ParsedFile(path=path, kind="ALB access log")
        parsed_files.append(parsed)
        with open_text(path) as handle:
            for line in handle:
                if max_records and stats.total >= max_records:
                    return stats, parsed_files
                line = line.strip()
                if not line:
                    continue
                event = parse_alb_line(line, tz, anonymize)
                if event is None:
                    parsed.errors += 1
                    continue
                parsed.records += 1
                stats.add(event)

    return stats, parsed_files


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def load_export_context(export_dir: Path) -> dict:
    identity = load_json(export_dir / "inventory" / "aws_identity.json") or {}
    load_balancers = load_json(export_dir / "alb" / "load_balancers.json") or []
    waf_destinations = load_json(export_dir / "waf" / "waf_logging_destinations.json") or []
    log_groups = load_json(export_dir / "cloudwatch" / "relevant_log_groups.json") or []

    return {
        "account": identity.get("Account", "Unknown"),
        "load_balancers": [
            item.get("LoadBalancerName", "Unknown")
            for item in load_balancers
            if isinstance(item, dict)
        ],
        "waf_acls": [
            item.get("name", "Unknown")
            for item in waf_destinations
            if isinstance(item, dict)
        ],
        "log_groups": [
            item.get("logGroupName", "Unknown")
            for item in log_groups
            if isinstance(item, dict)
        ],
    }


def counter_rows(counter: Counter, limit: int = 10) -> list[tuple[str, int]]:
    return [(str(label), count) for label, count in counter.most_common(limit)]


def ordered_counter_rows(counter: Counter, keys: Iterable[str]) -> list[tuple[str, int]]:
    return [(key, counter.get(key, 0)) for key in keys]


def empty_panel(message: str) -> str:
    return f'<p class="empty">{html_escape(message)}</p>'


def bar_chart(
    rows: list[tuple[str, int]],
    aria_label: str,
    color: str = CHART_COLORS[0],
    width: int = 860,
    label_width: int = 280,
) -> str:
    rows = [(label, count) for label, count in rows if count]
    if not rows:
        return empty_panel("No data available for this chart.")

    bar_area = width - label_width - 110
    row_height = 34
    top = 18
    height = top + len(rows) * row_height + 20
    max_count = max(count for _, count in rows) or 1
    parts = [
        f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{html_escape(aria_label)}">',
        f'<line x1="{label_width}" y1="4" x2="{label_width}" y2="{height - 12}" class="axis" />',
    ]
    for index, (label, count) in enumerate(rows):
        y = top + index * row_height
        bar_width = max(2, int((count / max_count) * bar_area))
        parts.append(
            f'<text x="0" y="{y + 18}" class="chart-label">'
            f'<title>{html_escape(label)}</title>{html_escape(truncate(label, 38))}</text>'
        )
        parts.append(
            f'<rect x="{label_width}" y="{y + 3}" width="{bar_width}" height="19" '
            f'rx="3" fill="{color}" />'
        )
        parts.append(
            f'<text x="{label_width + bar_width + 8}" y="{y + 18}" class="chart-value">'
            f'{fmt_int(count)}</text>'
        )
    parts.append("</svg>")
    return "\n".join(parts)


def vertical_bar_chart(
    rows: list[tuple[str, int]],
    aria_label: str,
    color: str = CHART_COLORS[1],
    width: int = 860,
    height: int = 260,
) -> str:
    if not rows:
        return empty_panel("No data available for this chart.")

    left = 42
    right = 18
    top = 16
    bottom = 42
    chart_width = width - left - right
    chart_height = height - top - bottom
    max_count = max(count for _, count in rows) or 1
    slot = chart_width / len(rows)
    bar_width = max(4, min(22, slot * 0.66))

    parts = [
        f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{html_escape(aria_label)}">',
    ]
    for tick in range(5):
        value = max_count * tick / 4
        y = top + chart_height - (chart_height * tick / 4)
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}" class="chart-grid" />')
        parts.append(f'<text x="0" y="{y + 4:.1f}" class="axis-label">{fmt_int(value)}</text>')

    for index, (label, count) in enumerate(rows):
        bar_height = (count / max_count) * chart_height if max_count else 0
        x = left + index * slot + (slot - bar_width) / 2
        y = top + chart_height - bar_height
        parts.append(
            f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_width:.1f}" height="{bar_height:.1f}" '
            f'rx="3" fill="{color}"><title>{html_escape(label)}: {fmt_int(count)}</title></rect>'
        )
        if len(rows) <= 24 or index % max(1, math.ceil(len(rows) / 24)) == 0:
            parts.append(
                f'<text x="{x + bar_width / 2:.1f}" y="{height - 14}" '
                f'class="axis-label centered">{html_escape(label)}</text>'
            )

    parts.append("</svg>")
    return "\n".join(parts)


def line_chart(
    rows: list[tuple[str, int]],
    aria_label: str,
    color: str = CHART_COLORS[1],
    width: int = 860,
    height: int = 260,
) -> str:
    rows = [(label, count) for label, count in rows if count]
    if len(rows) == 1:
        return bar_chart(rows, aria_label, color=color, width=width)
    if not rows:
        return empty_panel("No data available for this chart.")

    left = 46
    right = 18
    top = 16
    bottom = 44
    chart_width = width - left - right
    chart_height = height - top - bottom
    max_count = max(count for _, count in rows) or 1
    x_step = chart_width / (len(rows) - 1)

    points = []
    for index, (_, count) in enumerate(rows):
        x = left + index * x_step
        y = top + chart_height - (count / max_count) * chart_height
        points.append((x, y))

    point_text = " ".join(f"{x:.1f},{y:.1f}" for x, y in points)
    parts = [
        f'<svg class="chart" viewBox="0 0 {width} {height}" role="img" aria-label="{html_escape(aria_label)}">',
    ]
    for tick in range(5):
        value = max_count * tick / 4
        y = top + chart_height - (chart_height * tick / 4)
        parts.append(f'<line x1="{left}" y1="{y:.1f}" x2="{width - right}" y2="{y:.1f}" class="chart-grid" />')
        parts.append(f'<text x="0" y="{y + 4:.1f}" class="axis-label">{fmt_int(value)}</text>')

    parts.append(
        f'<polyline points="{point_text}" fill="none" stroke="{color}" stroke-width="3" '
        'stroke-linecap="round" stroke-linejoin="round" />'
    )

    if len(rows) <= 35:
        for (x, y), (label, count) in zip(points, rows):
            parts.append(
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="3.5" fill="{color}">'
                f'<title>{html_escape(label)}: {fmt_int(count)}</title></circle>'
            )

    parts.append(f'<text x="{left}" y="{height - 14}" class="axis-label">{html_escape(rows[0][0])}</text>')
    parts.append(
        f'<text x="{width - right}" y="{height - 14}" class="axis-label end">{html_escape(rows[-1][0])}</text>'
    )
    parts.append("</svg>")
    return "\n".join(parts)


def counter_table(
    counter: Counter,
    total: int,
    label_heading: str,
    limit: int = 10,
    empty_message: str = "No data available.",
) -> str:
    rows = counter_rows(counter, limit)
    if not rows:
        return empty_panel(empty_message)

    table_rows = []
    for rank, (label, count) in enumerate(rows, start=1):
        table_rows.append(
            "<tr>"
            f"<td>{rank}</td>"
            f"<td title=\"{html_escape(label)}\">{html_escape(truncate(label, 90))}</td>"
            f"<td class=\"num\">{fmt_int(count)}</td>"
            f"<td class=\"num\">{pct(count, total)}</td>"
            "</tr>"
        )
    return (
        '<table><thead><tr>'
        '<th class="rank">#</th>'
        f'<th>{html_escape(label_heading)}</th>'
        '<th class="num">Count</th>'
        '<th class="num">Share</th>'
        '</tr></thead><tbody>'
        + "\n".join(table_rows)
        + "</tbody></table>"
    )


def event_table(events: Iterable[dict], empty_message: str) -> str:
    rows = list(events)
    if not rows:
        return empty_panel(empty_message)
    body = []
    for event in reversed(rows):
        outcome = event.get("status") or event.get("action") or ""
        body.append(
            "<tr>"
            f"<td>{html_escape(event.get('time', ''))}</td>"
            f"<td>{html_escape(outcome)}</td>"
            f"<td>{html_escape(event.get('method', ''))}</td>"
            f"<td title=\"{html_escape(event.get('path', ''))}\">{html_escape(truncate(event.get('path', ''), 80))}</td>"
            f"<td>{html_escape(event.get('country', ''))}</td>"
            f"<td>{html_escape(event.get('client_ip', ''))}</td>"
            f"<td title=\"{html_escape(event.get('rule', ''))}\">{html_escape(truncate(event.get('rule', ''), 60))}</td>"
            "</tr>"
        )
    return (
        '<table><thead><tr>'
        '<th>Time</th><th>Outcome</th><th>Method</th><th>Path</th>'
        '<th>Country</th><th>Client IP</th><th>Rule</th>'
        '</tr></thead><tbody>'
        + "\n".join(body)
        + "</tbody></table>"
    )


def files_table(files: list[ParsedFile], export_dir: Path) -> str:
    if not files:
        return empty_panel("No input files were found.")
    body = []
    for item in files:
        try:
            display_path = item.path.relative_to(export_dir)
        except ValueError:
            display_path = item.path
        body.append(
            "<tr>"
            f"<td>{html_escape(display_path)}</td>"
            f"<td>{html_escape(item.kind)}</td>"
            f"<td class=\"num\">{fmt_int(item.records)}</td>"
            f"<td class=\"num\">{fmt_int(item.errors)}</td>"
            "</tr>"
        )
    return (
        '<table><thead><tr>'
        '<th>File</th><th>Type</th><th class="num">Parsed records</th><th class="num">Skipped lines</th>'
        '</tr></thead><tbody>'
        + "\n".join(body)
        + "</tbody></table>"
    )


def metric_card(label: str, value: str, detail: str = "") -> str:
    return (
        '<div class="metric">'
        f'<div class="metric-label">{html_escape(label)}</div>'
        f'<div class="metric-value">{html_escape(value)}</div>'
        f'<div class="metric-detail">{html_escape(detail)}</div>'
        '</div>'
    )


def list_text(values: list[str], empty: str = "None found") -> str:
    clean = [value for value in values if value]
    return ", ".join(clean) if clean else empty


def report_period(stats: UsageStats) -> str:
    if not stats.first_seen or not stats.last_seen:
        return "No dated records"
    return f"{format_datetime(stats.first_seen)} to {format_datetime(stats.last_seen)}"


def period_days(stats: UsageStats) -> int:
    if not stats.first_seen or not stats.last_seen:
        return 0
    return max(1, (stats.last_seen.date() - stats.first_seen.date()).days + 1)


def peak_label(counter: Counter) -> tuple[str, int]:
    return counter.most_common(1)[0] if counter else ("None", 0)


def render_report(
    export_dir: Path,
    title: str,
    timezone_name: str,
    primary: UsageStats,
    waf_stats: UsageStats,
    alb_stats: UsageStats,
    parsed_files: list[ParsedFile],
    context: dict,
    anonymized: bool,
) -> str:
    generated_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    days = period_days(primary)
    avg_per_day = primary.total / days if days else 0
    blocked = sum(primary.actions[action] for action in ["BLOCK", "CAPTCHA", "CHALLENGE"])
    http_errors = sum(
        count for status, count in primary.statuses.items() if status.startswith("4") or status.startswith("5")
    )
    peak_day, peak_day_count = peak_label(primary.daily)
    peak_hour, peak_hour_count = peak_label(primary.hourly)

    if waf_stats.total:
        outcome_label = "Blocked / challenged"
        outcome_value = pct(blocked, primary.total)
        outcome_detail = f"{fmt_int(blocked)} of {fmt_int(primary.total)} WAF records"
    else:
        outcome_label = "HTTP error rate"
        outcome_value = pct(http_errors, primary.total)
        outcome_detail = f"{fmt_int(http_errors)} 4xx/5xx responses"

    metrics = [
        metric_card("Requests observed", fmt_int(primary.total), primary.name),
        metric_card("Unique client IPs", fmt_int(len(primary.unique_ips)), "Best effort from request headers"),
        metric_card("Countries", fmt_int(len(primary.countries)), "Based on WAF or proxy country data"),
        metric_card("Paths requested", fmt_int(len(primary.normalized_paths)), "Normalised by common IDs"),
        metric_card(outcome_label, outcome_value, outcome_detail),
        metric_card("Average per day", fmt_float(avg_per_day), f"Across {fmt_int(days)} day(s)"),
        metric_card("Peak day", peak_day, f"{fmt_int(peak_day_count)} requests"),
        metric_card("Peak hour", peak_hour, f"{fmt_int(peak_hour_count)} requests"),
    ]
    if alb_stats.total:
        metrics.append(metric_card("ALB records", fmt_int(alb_stats.total), "Used for HTTP status and bytes where present"))
        metrics.append(metric_card("Data sent", fmt_bytes(alb_stats.bytes_sent), "From ALB access logs"))

    daily_rows = sorted(primary.daily.items())
    hour_rows = ordered_counter_rows(primary.hour_of_day, [f"{hour:02d}:00" for hour in range(24)])
    weekday_order = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    weekday_rows = ordered_counter_rows(primary.weekdays, weekday_order)

    status_stats = alb_stats if alb_stats.total else primary
    action_rows = counter_rows(primary.actions, 10)
    source_rows = counter_rows(primary.sources, 10)

    status_section = ""
    if status_stats.statuses:
        status_section = f"""
        <section>
          <h2>HTTP Response Monitoring</h2>
          <div class="grid two">
            <div class="panel">
              <h3>Status Classes</h3>
              {bar_chart(counter_rows(status_stats.status_classes, 8), "HTTP status classes", CHART_COLORS[2])}
            </div>
            <div class="panel">
              <h3>Status Codes</h3>
              {counter_table(status_stats.statuses, status_stats.total, "Status code", 12)}
            </div>
          </div>
        </section>
        """

    no_data_message = ""
    if not primary.total:
        no_data_message = """
        <section>
          <div class="panel">
            <h2>No Traffic Records Found</h2>
            <p>The script found the export directory but did not find parseable WAF JSONL or ALB access log records.</p>
          </div>
        </section>
        """

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html_escape(title)}</title>
  <style>
    :root {{
      --page: #f5f7fa;
      --panel: #ffffff;
      --ink: #182230;
      --muted: #5f6b7a;
      --line: #d8dee8;
      --line-soft: #ebeff5;
      --teal: #0f766e;
      --blue: #2563eb;
      --amber: #d97706;
      --red: #dc2626;
      --green: #16a34a;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      background: var(--page);
      color: var(--ink);
      font-family: Arial, Helvetica, sans-serif;
      line-height: 1.45;
    }}
    header {{
      background: #ffffff;
      border-bottom: 1px solid var(--line);
    }}
    .wrap {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 28px 22px;
    }}
    h1, h2, h3 {{
      margin: 0;
      line-height: 1.2;
      letter-spacing: 0;
    }}
    h1 {{
      font-size: 30px;
      margin-bottom: 10px;
    }}
    h2 {{
      font-size: 22px;
      margin: 30px 0 14px;
    }}
    h3 {{
      font-size: 16px;
      margin-bottom: 14px;
    }}
    p {{
      margin: 0 0 12px;
      color: var(--muted);
    }}
    .meta {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px 22px;
      color: var(--muted);
      font-size: 14px;
    }}
    .meta strong {{ color: var(--ink); font-weight: 700; }}
    .metrics {{
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 14px;
      margin-top: 22px;
    }}
    .metric, .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 8px;
      box-shadow: 0 1px 2px rgba(16, 24, 40, 0.04);
    }}
    .metric {{
      padding: 16px;
      min-height: 116px;
    }}
    .metric-label {{
      color: var(--muted);
      font-size: 13px;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .metric-value {{
      margin-top: 8px;
      font-size: 28px;
      font-weight: 700;
      overflow-wrap: anywhere;
    }}
    .metric-detail {{
      margin-top: 6px;
      color: var(--muted);
      font-size: 13px;
    }}
    .grid {{
      display: grid;
      grid-template-columns: 1fr;
      gap: 16px;
    }}
    .grid.two {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
    .grid.three {{ grid-template-columns: repeat(3, minmax(0, 1fr)); }}
    .panel {{
      padding: 18px;
      overflow: hidden;
    }}
    .chart {{
      width: 100%;
      height: auto;
      display: block;
    }}
    .axis, .chart-grid {{
      stroke: var(--line);
      stroke-width: 1;
    }}
    .chart-grid {{
      stroke: var(--line-soft);
    }}
    .chart-label, .chart-value, .axis-label {{
      fill: var(--ink);
      font-size: 13px;
    }}
    .axis-label {{
      fill: var(--muted);
      font-size: 11px;
    }}
    .centered {{ text-anchor: middle; }}
    .end {{ text-anchor: end; }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 14px;
    }}
    th, td {{
      padding: 10px 8px;
      border-bottom: 1px solid var(--line-soft);
      text-align: left;
      vertical-align: top;
    }}
    th {{
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0;
      background: #fafbfc;
    }}
    td {{
      overflow-wrap: anywhere;
    }}
    .rank {{ width: 44px; }}
    .num {{ text-align: right; white-space: nowrap; }}
    .empty {{
      padding: 22px;
      border: 1px dashed var(--line);
      border-radius: 8px;
      background: #fbfcfe;
      color: var(--muted);
    }}
    .note {{
      color: var(--muted);
      font-size: 13px;
      margin-top: 10px;
    }}
    footer {{
      color: var(--muted);
      font-size: 13px;
      padding-bottom: 28px;
    }}
    @media (max-width: 920px) {{
      .metrics {{ grid-template-columns: repeat(2, minmax(0, 1fr)); }}
      .grid.two, .grid.three, .meta {{ grid-template-columns: 1fr; }}
    }}
    @media (max-width: 560px) {{
      .wrap {{ padding: 20px 14px; }}
      .metrics {{ grid-template-columns: 1fr; }}
      h1 {{ font-size: 24px; }}
      .metric-value {{ font-size: 24px; }}
      table {{ font-size: 13px; }}
      th, td {{ padding: 8px 6px; }}
    }}
    @media print {{
      body {{ background: #ffffff; }}
      .metric, .panel {{ box-shadow: none; break-inside: avoid; }}
      .wrap {{ max-width: none; }}
    }}
  </style>
</head>
<body>
  <header>
    <div class="wrap">
      <h1>{html_escape(title)}</h1>
      <p>Static usage summary generated from AWS traffic evidence. Figures are log observations, not cookie-based analytics.</p>
      <div class="meta">
        <div><strong>Source directory:</strong> {html_escape(str(export_dir))}</div>
        <div><strong>Generated:</strong> {html_escape(generated_at)}</div>
        <div><strong>Reporting period:</strong> {html_escape(report_period(primary))}</div>
        <div><strong>Report timezone:</strong> {html_escape(timezone_name)}</div>
        <div><strong>AWS account:</strong> {html_escape(context.get("account", "Unknown"))}</div>
        <div><strong>Load balancers:</strong> {html_escape(list_text(context.get("load_balancers", [])))}</div>
        <div><strong>WAF ACLs:</strong> {html_escape(list_text(context.get("waf_acls", [])))}</div>
        <div><strong>Client IPs:</strong> {"Anonymised to network level" if anonymized else "Shown as observed in logs"}</div>
      </div>
      <div class="metrics">
        {"".join(metrics)}
      </div>
    </div>
  </header>

  <main class="wrap">
    {no_data_message}

    <section>
      <h2>Traffic Volume</h2>
      <div class="grid two">
        <div class="panel">
          <h3>Requests By Day</h3>
          {line_chart(daily_rows, "Requests by day", CHART_COLORS[1])}
        </div>
        <div class="panel">
          <h3>Requests By Hour Of Day</h3>
          {vertical_bar_chart(hour_rows, "Requests by hour of day", CHART_COLORS[0])}
        </div>
        <div class="panel">
          <h3>Requests By Weekday</h3>
          {vertical_bar_chart(weekday_rows, "Requests by weekday", CHART_COLORS[4])}
        </div>
        <div class="panel">
          <h3>Observed Sources And Outcomes</h3>
          {bar_chart(source_rows + action_rows, "Sources and outcomes", CHART_COLORS[2])}
        </div>
      </div>
    </section>

    <section>
      <h2>Audience And Technology</h2>
      <div class="grid three">
        <div class="panel">
          <h3>Countries</h3>
          {bar_chart(counter_rows(primary.countries, 12), "Top countries", CHART_COLORS[0])}
        </div>
        <div class="panel">
          <h3>Device Types</h3>
          {bar_chart(counter_rows(primary.devices, 8), "Device types", CHART_COLORS[1])}
        </div>
        <div class="panel">
          <h3>Browsers</h3>
          {bar_chart(counter_rows(primary.browsers, 8), "Browsers", CHART_COLORS[2])}
        </div>
        <div class="panel">
          <h3>Operating Systems</h3>
          {counter_table(primary.operating_systems, primary.total, "Operating system", 10)}
        </div>
        <div class="panel">
          <h3>Client IPs</h3>
          {counter_table(primary.client_ips, primary.total, "Client IP", 12)}
        </div>
        <div class="panel">
          <h3>User Agents</h3>
          {counter_table(primary.user_agents, primary.total, "User agent", 8)}
        </div>
      </div>
    </section>

    <section>
      <h2>Content And Referrals</h2>
      <div class="grid two">
        <div class="panel">
          <h3>Top Requested Paths</h3>
          {counter_table(primary.normalized_paths, primary.total, "Path", 15)}
        </div>
        <div class="panel">
          <h3>Content Types</h3>
          {bar_chart(counter_rows(primary.content_types, 8), "Content types", CHART_COLORS[4])}
        </div>
        <div class="panel">
          <h3>Hosts</h3>
          {counter_table(primary.hosts, primary.total, "Host", 10)}
        </div>
        <div class="panel">
          <h3>Referrer Hosts</h3>
          {counter_table(primary.referrer_hosts, primary.total, "Referrer host", 12)}
        </div>
        <div class="panel">
          <h3>HTTP Methods</h3>
          {bar_chart(counter_rows(primary.methods, 8), "HTTP methods", CHART_COLORS[1])}
        </div>
        <div class="panel">
          <h3>Query String Keys</h3>
          {counter_table(primary.query_keys, primary.total, "Query key", 12)}
        </div>
      </div>
    </section>

    <section>
      <h2>Security Signals</h2>
      <div class="grid two">
        <div class="panel">
          <h3>WAF Actions</h3>
          {bar_chart(counter_rows(waf_stats.actions if waf_stats.total else primary.actions, 10), "WAF actions", CHART_COLORS[3])}
        </div>
        <div class="panel">
          <h3>WAF Rules</h3>
          {counter_table(waf_stats.waf_rules if waf_stats.total else primary.waf_rules, waf_stats.total or primary.total, "Rule", 12)}
        </div>
        <div class="panel">
          <h3>Blocked Paths</h3>
          {counter_table(waf_stats.blocked_paths if waf_stats.total else primary.blocked_paths, max(1, blocked or primary.total), "Path", 12)}
        </div>
        <div class="panel">
          <h3>Blocked Countries</h3>
          {counter_table(waf_stats.blocked_countries if waf_stats.total else primary.blocked_countries, max(1, blocked or primary.total), "Country", 12)}
        </div>
        <div class="panel">
          <h3>WAF Labels</h3>
          {counter_table(waf_stats.waf_labels if waf_stats.total else primary.waf_labels, waf_stats.total or primary.total, "Label", 12)}
        </div>
        <div class="panel">
          <h3>Recent Blocked Events</h3>
          {event_table(waf_stats.recent_blocked_events if waf_stats.total else primary.recent_blocked_events, "No blocked or error events found.")}
        </div>
      </div>
    </section>

    {status_section}

    <section>
      <h2>Recent Observations</h2>
      <div class="panel">
        <h3>Latest Parsed Requests</h3>
        {event_table(primary.recent_events, "No recent events available.")}
      </div>
    </section>

    <section>
      <h2>Data Quality</h2>
      <div class="panel">
        <h3>Parsed Files</h3>
        {files_table(parsed_files, export_dir)}
        <p class="note">If WAF and ALB logs both exist, WAF records are used as the primary traffic count to avoid double counting. ALB records are still used for HTTP status and transfer-size summaries.</p>
      </div>
    </section>
  </main>

  <footer class="wrap">
    Generated by generate_web_usage_report.py. Store this HTML alongside the evidence export for an audit trail.
  </footer>
</body>
</html>
"""


def write_report(path: Path, html: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a static HTML web usage report from AWS WAF and ALB evidence exports."
    )
    parser.add_argument(
        "export_dir",
        nargs="?",
        help="Evidence export directory. Defaults to the latest aws_web_traffic_export_* directory.",
    )
    parser.add_argument(
        "--out",
        help="Output HTML path. Defaults to <export_dir>/web_usage_report.html.",
    )
    parser.add_argument("--title", default=DEFAULT_TITLE)
    parser.add_argument(
        "--timezone",
        default=os.environ.get("REPORT_TIMEZONE", "Europe/London"),
        help="Timezone for chart and table timestamps. Default: Europe/London.",
    )
    parser.add_argument(
        "--anonymize-ips",
        action="store_true",
        help="Mask client IP addresses in counters and tables.",
    )
    parser.add_argument(
        "--max-records",
        type=int,
        default=0,
        help="Optional maximum records per source to parse. 0 means no limit.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    cwd = Path.cwd()
    export_dir = Path(args.export_dir) if args.export_dir else find_latest_export_dir(cwd)
    if export_dir is None:
        print("[!] No aws_web_traffic_export_* directory found. Pass an export directory explicitly.", file=sys.stderr)
        return 1
    export_dir = export_dir.expanduser().resolve()
    if not export_dir.is_dir():
        print(f"[!] Export directory does not exist: {export_dir}", file=sys.stderr)
        return 1

    tz = load_timezone(args.timezone)
    out = Path(args.out).expanduser().resolve() if args.out else export_dir / "web_usage_report.html"

    print(f"[*] Reading evidence from {export_dir}")
    waf_stats, waf_files = load_waf_stats(export_dir, tz, args.anonymize_ips, args.max_records)
    print(f"[*] Parsed WAF records: {fmt_int(waf_stats.total)}")
    alb_stats, alb_files = load_alb_stats(export_dir, tz, args.anonymize_ips, args.max_records)
    print(f"[*] Parsed ALB records: {fmt_int(alb_stats.total)}")

    primary = waf_stats if waf_stats.total else alb_stats
    parsed_files = waf_files + alb_files
    context = load_export_context(export_dir)
    html = render_report(
        export_dir=export_dir,
        title=args.title,
        timezone_name=args.timezone,
        primary=primary,
        waf_stats=waf_stats,
        alb_stats=alb_stats,
        parsed_files=parsed_files,
        context=context,
        anonymized=args.anonymize_ips,
    )
    write_report(out, html)
    print(f"[+] Wrote report: {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
