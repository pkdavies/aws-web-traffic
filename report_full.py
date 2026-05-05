#!/usr/bin/env python3
"""
Generate a static yearly web usage monitoring report from AWS traffic evidence.

The script is designed to work with output from extract.py
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
import time
from calendar import monthrange
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache
from html import escape
from ipaddress import ip_address
from pathlib import Path
from typing import Iterable
from urllib.parse import unquote_plus, urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

try:
    from tqdm import tqdm
except ImportError:
    tqdm = None

try:
    import orjson
except ImportError:
    print("[!] Missing required dependency: orjson. Install it with: .venv/bin/pip install orjson", file=sys.stderr)
    raise SystemExit(1)


DEFAULT_TITLE = "Yearly Web Usage Statistics"
EXPORT_PREFIX = "aws_web_traffic_export_"
JSON_PARSER = "orjson"
JSON_DECODE_ERRORS = (orjson.JSONDecodeError,)
UUID_PATH_PART_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.I,
)
LONG_HEX_PATH_PART_RE = re.compile(r"^[0-9a-f]{16,}$", re.I)
BOT_MARKERS = (
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
)
MONITORING_USER_AGENT_MARKERS = (
    "pingdom",
    "elb-healthchecker",
    "healthchecker",
    "health check",
    "healthcheck",
)
MONITORING_PATHS = {
    "/health",
    "/health/",
    "/healthcheck",
    "/health-check",
    "/ping",
    "/ping/",
    "/status",
    "/status/",
}
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
    filtered: int = 0
    errors: int = 0


@dataclass(slots=True)
class PreparedEvent:
    timestamp: datetime | None
    day: str
    hour: str
    hour_of_day: str
    weekday: str
    source: str
    action: str
    status: str
    status_class: str
    method: str
    host: str
    path: str
    normalized_path: str
    content_type: str
    country: str
    client_ip: str
    client_ip_source: str
    edge_client_ip: str
    user_agent: str
    device: str
    browser: str
    os_name: str
    referrer: str
    referrer_host: str
    query_keys: tuple[str, ...]
    waf_rule: str
    waf_labels: tuple[str, ...]
    ja3_fingerprint: str
    ja4_fingerprint: str
    bytes_sent: int
    bytes_received: int
    sample: dict
    blocked: bool


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
    client_ip_sources: Counter = field(default_factory=Counter)
    client_ip_categories: Counter = field(default_factory=Counter)
    edge_client_ips: Counter = field(default_factory=Counter)
    ip_user_agent_pairs: Counter = field(default_factory=Counter)
    ip_user_agents: dict[str, set[str]] = field(default_factory=dict)
    ja3_fingerprints: Counter = field(default_factory=Counter)
    ja4_fingerprints: Counter = field(default_factory=Counter)
    blocked_paths: Counter = field(default_factory=Counter)
    blocked_countries: Counter = field(default_factory=Counter)
    blocked_ips: Counter = field(default_factory=Counter)
    bytes_sent: int = 0
    bytes_received: int = 0
    recent_events: deque[dict] = field(default_factory=lambda: deque(maxlen=20))
    recent_blocked_events: deque[dict] = field(default_factory=lambda: deque(maxlen=20))

    def add(self, event: dict) -> None:
        self.add_prepared(prepare_usage_event(event))

    def add_prepared(self, event: PreparedEvent, detailed: bool = True) -> None:
        self.total += 1

        dt = event.timestamp
        if dt:
            self.first_seen = dt if self.first_seen is None else min(self.first_seen, dt)
            self.last_seen = dt if self.last_seen is None else max(self.last_seen, dt)
            self.daily[event.day] += 1
            self.hour_of_day[event.hour_of_day] += 1
            self.weekdays[event.weekday] += 1
            if detailed:
                self.hourly[event.hour] += 1

        if detailed:
            self.sources[event.source] += 1

        if event.action:
            self.actions[event.action] += 1

        if event.status:
            self.statuses[event.status] += 1
            if detailed:
                self.status_classes[event.status_class] += 1

        if detailed:
            self.methods[event.method] += 1
            self.hosts[event.host] += 1
            self.paths[event.path] += 1
            self.content_types[event.content_type] += 1

        self.normalized_paths[event.normalized_path] += 1
        self.countries[event.country] += 1

        if event.client_ip:
            self.unique_ips.add(event.client_ip)
            if detailed:
                self.client_ips[event.client_ip] += 1
                self.client_ip_categories[ip_address_category(event.client_ip)] += 1
                if event.client_ip_source:
                    self.client_ip_sources[event.client_ip_source] += 1
                if event.user_agent:
                    pair_key = f"{event.client_ip} | {event.user_agent}"
                    self.ip_user_agent_pairs[pair_key] += 1
                    self.ip_user_agents.setdefault(event.client_ip, set()).add(event.user_agent)
        elif detailed and event.client_ip_source:
            self.client_ip_sources[event.client_ip_source] += 1

        if detailed and event.edge_client_ip:
            self.edge_client_ips[event.edge_client_ip] += 1

        if detailed and event.ja3_fingerprint:
            self.ja3_fingerprints[event.ja3_fingerprint] += 1

        if detailed and event.ja4_fingerprint:
            self.ja4_fingerprints[event.ja4_fingerprint] += 1

        if detailed:
            self.user_agents[event.user_agent] += 1
            self.devices[event.device] += 1
            self.browsers[event.browser] += 1
            self.operating_systems[event.os_name] += 1
            self.referrers[event.referrer or "Direct / none"] += 1
        self.referrer_hosts[event.referrer_host] += 1

        if detailed:
            for key in event.query_keys:
                self.query_keys[key] += 1

            if event.waf_rule:
                self.waf_rules[event.waf_rule] += 1

            for label in event.waf_labels:
                self.waf_labels[label] += 1

            self.bytes_sent += event.bytes_sent
            self.bytes_received += event.bytes_received
            self.recent_events.append(event.sample)

            if event.blocked:
                self.blocked_paths[event.path] += 1
                self.blocked_countries[event.country] += 1
                if event.client_ip:
                    self.blocked_ips[event.client_ip] += 1
                self.recent_blocked_events.append(event.sample)


def month_key(dt: datetime | None) -> str:
    if not dt:
        return "undated"
    return dt.strftime("%Y-%m")


def month_label(key: str) -> str:
    if key == "undated":
        return "Undated"
    try:
        return datetime.strptime(key, "%Y-%m").strftime("%b %Y")
    except ValueError:
        return key


def month_days(key: str) -> int:
    if key == "undated":
        return 0
    try:
        year, month = [int(part) for part in key.split("-", 1)]
    except ValueError:
        return 0
    return monthrange(year, month)[1]


def month_keys_between(first_seen: datetime | None, last_seen: datetime | None) -> list[str]:
    if not first_seen or not last_seen:
        return []

    keys = []
    year = first_seen.year
    month = first_seen.month
    while (year, month) <= (last_seen.year, last_seen.month):
        keys.append(f"{year:04d}-{month:02d}")
        month += 1
        if month == 13:
            month = 1
            year += 1
    return keys


def prepare_usage_event(event: dict) -> PreparedEvent:
    dt = event.get("timestamp")
    source = clean_value(event.get("source"), "Unknown")
    action = clean_value(event.get("action"), "Observed")
    status = clean_value(event.get("status_code"), "")
    method = clean_value(event.get("method"), "UNKNOWN")
    host = clean_value(event.get("host"), "Unknown")
    path = clean_path(event.get("path"))
    normalized_path = normalize_path_for_grouping(path)
    country = clean_value(event.get("country"), "Unknown")
    client_ip = clean_value(event.get("client_ip"), "")
    client_ip_source = clean_value(event.get("client_ip_source"), "")
    edge_client_ip = clean_value(event.get("edge_client_ip"), "")
    user_agent = clean_value(event.get("user_agent"), "Unknown")
    device, browser, os_name = classify_user_agent(user_agent)
    referrer = clean_value(event.get("referrer"), "")
    referrer_host = referrer_bucket(referrer, host)
    waf_rule = clean_value(event.get("waf_rule"), "")
    waf_labels = tuple(event.get("waf_labels") or ())
    ja3_fingerprint = clean_value(event.get("ja3_fingerprint"), "")
    ja4_fingerprint = clean_value(event.get("ja4_fingerprint"), "")
    status_bucket = status_class(status) if status else ""

    sample = {
        "time": dt,
        "source": source,
        "action": action,
        "status": status,
        "method": method,
        "host": host,
        "path": path,
        "country": country,
        "client_ip": client_ip,
        "client_ip_source": client_ip_source,
        "rule": waf_rule,
    }

    if dt:
        day = dt.date().isoformat()
        hour = dt.strftime("%Y-%m-%d %H:00")
        hour_of_day = f"{dt.hour:02d}:00"
        weekday = dt.strftime("%a")
    else:
        day = ""
        hour = ""
        hour_of_day = ""
        weekday = ""

    return PreparedEvent(
        timestamp=dt,
        day=day,
        hour=hour,
        hour_of_day=hour_of_day,
        weekday=weekday,
        source=source,
        action=action,
        status=status,
        status_class=status_bucket,
        method=method,
        host=host,
        path=path,
        normalized_path=normalized_path,
        content_type=classify_content_type(path),
        country=country,
        client_ip=client_ip,
        client_ip_source=client_ip_source,
        edge_client_ip=edge_client_ip,
        user_agent=user_agent,
        device=device,
        browser=browser,
        os_name=os_name,
        referrer=referrer,
        referrer_host=referrer_host,
        query_keys=tuple(event.get("query_keys") or ()),
        waf_rule=waf_rule,
        waf_labels=waf_labels,
        ja3_fingerprint=ja3_fingerprint,
        ja4_fingerprint=ja4_fingerprint,
        bytes_sent=safe_int(event.get("bytes_sent")),
        bytes_received=safe_int(event.get("bytes_received")),
        sample=sample,
        blocked=is_blocked_event(event),
    )


def add_event(stats: UsageStats, monthly: dict[str, UsageStats], event: dict) -> None:
    prepared = prepare_usage_event(event)
    stats.add_prepared(prepared)
    key = month_key(prepared.timestamp)
    if key not in monthly:
        monthly[key] = UsageStats(month_label(key))
    monthly[key].add_prepared(prepared, detailed=False)


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


def fmt_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    if hours:
        return f"{hours}h {minutes:02d}m {seconds:02d}s"
    if minutes:
        return f"{minutes}m {seconds:02d}s"
    return f"{seconds}s"


def progress_message(message: str) -> None:
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[*] {timestamp} {message}", file=sys.stderr, flush=True)


class FileProgress:
    def __init__(self, label: str, path: Path, enabled: bool, interval: float) -> None:
        self.label = label
        self.path = path
        self.enabled = enabled
        self.interval = max(0.5, interval)
        self.started_at = time.monotonic()
        self.last_report_at = self.started_at
        self.lines = 0
        self.bytes_seen = 0
        self.pending_units = 0
        self.records = 0
        self.errors = 0
        self.total_records = 0
        self.bar = None
        self.closed = False

        self.total_bytes = None if path.suffix.lower() == ".gz" else path.stat().st_size
        self.byte_mode = self.total_bytes is not None

    def __enter__(self) -> "FileProgress":
        if not self.enabled:
            return self

        description = f"{self.label}: {self.path.name}"
        if tqdm is not None:
            kwargs = {
                "desc": description,
                "dynamic_ncols": True,
                "file": sys.stderr,
                "leave": True,
                "mininterval": self.interval,
            }
            if self.byte_mode:
                self.bar = tqdm(
                    total=self.total_bytes,
                    unit="B",
                    unit_divisor=1024,
                    unit_scale=True,
                    **kwargs,
                )
            else:
                self.bar = tqdm(unit="line", **kwargs)
        else:
            size = f" ({fmt_bytes(self.total_bytes)})" if self.byte_mode else ""
            progress_message(f"Parsing {description}{size}")

        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()

    def observe_line(self, line: str | bytes) -> None:
        self.lines += 1
        amount = len(line)
        self.bytes_seen += amount
        self.pending_units += amount if self.byte_mode else 1

    def maybe_report(self, parsed: ParsedFile, total_records: int, force: bool = False) -> None:
        self.records = parsed.records
        self.errors = parsed.errors
        self.total_records = total_records

        if not self.enabled:
            return

        now = time.monotonic()
        if not force and now - self.last_report_at < self.interval:
            return

        if self.bar is not None:
            if self.pending_units:
                self.bar.update(self.pending_units)
                self.pending_units = 0
            self.bar.set_postfix_str(self.summary(include_position=False))
        else:
            progress_message(f"{self.label}: {self.path.name} | {self.summary()}")

        self.last_report_at = now

    def finish(self, parsed: ParsedFile, total_records: int) -> None:
        self.maybe_report(parsed, total_records, force=True)
        if self.enabled and self.bar is None:
            progress_message(f"Finished {self.label}: {self.path.name} | {self.summary()}")
        self.close()

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        if self.bar is not None:
            self.bar.close()

    def summary(self, include_position: bool = True) -> str:
        elapsed = max(0.001, time.monotonic() - self.started_at)
        rate = self.records / elapsed
        parts = [
            f"lines={fmt_int(self.lines)}",
            f"records={fmt_int(self.records)}",
            f"errors={fmt_int(self.errors)}",
        ]
        if include_position:
            if self.byte_mode:
                seen = min(self.bytes_seen, self.total_bytes or self.bytes_seen)
                parts.append(f"read={fmt_bytes(seen)}/{fmt_bytes(self.total_bytes or 0)}")
                parts.append(f"{pct(seen, self.total_bytes or 0)}")
            else:
                parts.append(f"read~{fmt_bytes(self.bytes_seen)}")
        parts.extend([f"rate={fmt_int(rate)}/s", f"elapsed={fmt_duration(elapsed)}"])
        return ", ".join(parts)


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
        try:
            parsed = urlparse(path)
            path = parsed.path or "/"
        except ValueError:
            path = "/"
    path = path.split("?", 1)[0] or "/"
    if not path.startswith("/"):
        path = "/" + path
    return path


@lru_cache(maxsize=262_144)
def normalize_path_for_grouping(path: str) -> str:
    if not isinstance(path, str) or not path.startswith("/"):
        path = clean_path(path)
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    parts = []
    for part in path.strip("/").split("/"):
        if not part:
            continue
        if part.isdigit() or UUID_PATH_PART_RE.match(part) or LONG_HEX_PATH_PART_RE.match(part):
            parts.append(":id")
        elif len(part) > 80:
            parts.append(":value")
        else:
            parts.append(part)
    return "/" + "/".join(parts) if parts else "/"


@lru_cache(maxsize=262_144)
def classify_content_type(path: str) -> str:
    lower = path.lower()
    filename = lower.rsplit("/", 1)[-1]
    dot_index = filename.rfind(".")
    suffix = filename[dot_index:] if dot_index >= 0 else ""
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


@lru_cache(maxsize=16_384)
def classify_user_agent(user_agent: str) -> tuple[str, str, str]:
    ua = (user_agent or "").strip()
    low = ua.lower()
    if not ua or ua == "Unknown":
        return "Unknown", "Unknown", "Unknown"

    is_bot = any(marker in low for marker in BOT_MARKERS)

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


@lru_cache(maxsize=65_536)
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


def json_loads(value):
    return orjson.loads(value)


def timestamp_to_datetime(value, tz: ZoneInfo) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        numeric = value
        if numeric > 10_000_000_000:
            numeric = numeric / 1000
        return datetime.fromtimestamp(numeric, timezone.utc).astimezone(tz)

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


def query_key_names(query: str) -> tuple[str, ...]:
    if not query:
        return ()

    keys = set()
    for part in query.split("&"):
        if not part:
            continue
        key = part.split("=", 1)[0]
        if key:
            keys.add(unquote_plus(key))
    return tuple(sorted(keys))


def header_lookup(headers: list[dict]) -> dict[str, str]:
    lookup: dict[str, str] = {}
    for header in headers or []:
        if not isinstance(header, dict):
            continue
        name = header.get("name")
        if not name:
            continue
        value = header.get("value", "")
        lookup[str(name).lower()] = str(value).strip()
    return lookup


def header_value(headers: dict[str, str], *names: str) -> str:
    for name in names:
        value = headers.get(name.lower(), "")
        if value:
            return value
    return ""


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


def ip_address_category(value: str) -> str:
    if not value:
        return "Missing"
    try:
        parsed = ip_address(value)
    except ValueError:
        return "Invalid"
    if parsed.is_global:
        return "Public/global"
    if parsed.is_private:
        return "Private/internal"
    if parsed.is_loopback:
        return "Loopback"
    if parsed.is_link_local:
        return "Link-local"
    if parsed.is_reserved:
        return "Reserved"
    if parsed.is_multicast:
        return "Multicast"
    return "Non-global/other"


def selected_client_ip(request: dict, headers: dict[str, str], anonymize: bool) -> tuple[str, str]:
    candidates = [
        ("cf-connecting-ip", headers.get("cf-connecting-ip", "")),
        ("true-client-ip", headers.get("true-client-ip", "")),
        ("x-real-ip", headers.get("x-real-ip", "")),
        ("x-forwarded-for", first_forwarded_ip(headers.get("x-forwarded-for", ""))),
        ("waf-client-ip", request.get("clientIp", "")),
    ]
    for source, candidate in candidates:
        candidate = clean_value(candidate, "")
        if candidate:
            return (anonymize_ip(candidate) if anonymize else candidate, source)
    return "", ""


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

    headers = header_lookup(request.get("headers") or [])
    timestamp = timestamp_to_datetime(payload.get("timestamp", outer_timestamp), tz)
    host = clean_value(request.get("host"), header_value(headers, "host") or "Unknown")
    referrer = header_value(headers, "referer", "referrer")
    args = clean_value(request.get("args"), "")
    query_keys = query_key_names(args)

    country = clean_value(header_value(headers, "cf-ipcountry"), "")
    if not country or country == "XX":
        country = clean_value(request.get("country"), "Unknown")

    labels = [
        name
        for item in payload.get("labels") or []
        if isinstance(item, dict) and (name := clean_value(item.get("name"), ""))
    ]
    client_ip, client_ip_source = selected_client_ip(request, headers, anonymize)
    edge_client_ip = clean_value(request.get("clientIp"), "")
    if anonymize:
        edge_client_ip = anonymize_ip(edge_client_ip)

    return {
        "source": "AWS WAF",
        "timestamp": timestamp,
        "action": clean_value(payload.get("action"), "Observed").upper(),
        "method": clean_value(request.get("httpMethod"), "UNKNOWN").upper(),
        "host": host,
        "path": clean_path(request.get("uri")),
        "country": country,
        "client_ip": client_ip,
        "client_ip_source": client_ip_source,
        "edge_client_ip": edge_client_ip,
        "user_agent": header_value(headers, "user-agent") or "Unknown",
        "referrer": referrer,
        "query_keys": query_keys,
        "waf_rule": waf_terminating_rule(payload),
        "waf_labels": labels,
        "ja3_fingerprint": clean_value(payload.get("ja3Fingerprint"), ""),
        "ja4_fingerprint": clean_value(payload.get("ja4Fingerprint"), ""),
        "bytes_received": safe_int(payload.get("requestBodySize")),
    }


def parse_cloudwatch_waf_line(
    line: str | bytes,
    tz: ZoneInfo,
    anonymize: bool,
) -> dict | None:
    try:
        outer = json_loads(line)
    except JSON_DECODE_ERRORS:
        return None

    if not isinstance(outer, dict):
        return None

    if "httpRequest" in outer:
        return waf_event_from_payload(outer, outer.get("timestamp"), tz, anonymize)

    message = outer.get("message")
    if not isinstance(message, str) or not message.strip().startswith("{"):
        return None

    try:
        payload = json_loads(message)
    except JSON_DECODE_ERRORS:
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


def parse_alb_line(line: str | bytes, tz: ZoneInfo, anonymize: bool) -> dict | None:
    if isinstance(line, bytes):
        line = line.decode("utf-8", errors="replace")
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

    try:
        parsed_url = urlparse(raw_url)
        host = parsed_url.netloc or clean_value(fields[2], "Unknown")
        path = parsed_url.path or "/"
        query_keys = query_key_names(parsed_url.query)
    except ValueError:
        host = clean_value(fields[2], "Unknown")
        path = "/"
        query_keys = ()

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
        "client_ip_source": "alb-client",
        "edge_client_ip": "",
        "user_agent": user_agent or "Unknown",
        "query_keys": query_keys,
        "ja3_fingerprint": "",
        "ja4_fingerprint": "",
        "bytes_received": safe_int(fields[10]),
        "bytes_sent": safe_int(fields[11]),
    }


def is_blocked_event(event: dict) -> bool:
    action = clean_value(event.get("action"), "").upper()
    if action in {"BLOCK", "CAPTCHA", "CHALLENGE"}:
        return True
    status = clean_value(event.get("status_code"), "")
    return status.startswith("4") or status.startswith("5")


def parse_filter_datetime(value: str | None, tz: ZoneInfo) -> datetime | None:
    if not value:
        return None

    text = value.strip()
    if not text:
        return None

    if re.match(r"^\d{4}-\d{2}-\d{2}$", text):
        dt = datetime.fromisoformat(text)
    else:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        dt = datetime.fromisoformat(text)

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz)
    return dt.astimezone(tz)


def datetime_to_ms(dt: datetime) -> int:
    return int(dt.astimezone(timezone.utc).timestamp() * 1000)


def line_timestamp_ms(line: str | bytes) -> int | None:
    try:
        outer = json_loads(line)
    except JSON_DECODE_ERRORS:
        return None

    if not isinstance(outer, dict):
        return None

    value = outer.get("timestamp")
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


def seek_jsonl_timestamp(path: Path, target_ms: int) -> int:
    size = path.stat().st_size
    lo = 0
    hi = size
    best = size

    with path.open("rb") as handle:
        while lo < hi:
            mid = (lo + hi) // 2
            line_start, line = next_full_line(handle, mid)
            if not line:
                hi = mid
                continue

            timestamp_ms = line_timestamp_ms(line)
            if timestamp_ms is None:
                lo = handle.tell()
                continue

            if timestamp_ms < target_ms:
                lo = handle.tell()
            else:
                best = line_start
                hi = mid

    return best


def is_suppressed_log_level_line(line: str | bytes, suppressed_levels: set[str]) -> bool:
    if not suppressed_levels:
        return False

    try:
        outer = json_loads(line)
    except JSON_DECODE_ERRORS:
        return False

    if not isinstance(outer, dict):
        return False

    message = outer.get("message")
    if not isinstance(message, str):
        return False

    text = message.lstrip()
    if not text or text.startswith("{"):
        return False

    first_token = text.split(None, 1)[0].rstrip(":").upper()
    return first_token in suppressed_levels


def is_monitoring_event(event: dict) -> bool:
    path = clean_path(event.get("path")).lower()
    user_agent = clean_value(event.get("user_agent"), "").lower()

    if path in MONITORING_PATHS or path.startswith("/health/"):
        return True

    return any(marker in user_agent for marker in MONITORING_USER_AGENT_MARKERS)


def event_in_window(event: dict, start_dt: datetime | None, end_dt: datetime | None) -> bool:
    timestamp = event.get("timestamp")
    if timestamp is None:
        return True
    if start_dt and timestamp < start_dt:
        return False
    if end_dt and timestamp >= end_dt:
        return False
    return True


def has_public_client_ip(event: dict) -> bool:
    return ip_address_category(clean_value(event.get("client_ip"), "")) == "Public/global"


def iter_progress_lines(path: Path, progress: FileProgress, start_offset: int = 0) -> Iterable[str | bytes]:
    if path.suffix.lower() == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            if progress.enabled:
                for line in handle:
                    progress.observe_line(line)
                    yield line
            else:
                yield from handle
        return

    with path.open("rb") as handle:
        if start_offset:
            handle.seek(start_offset)
            progress.bytes_seen = start_offset
            if progress.bar is not None:
                progress.bar.n = start_offset
                progress.bar.refresh()
        if progress.enabled:
            for line in handle:
                progress.observe_line(line)
                yield line
        else:
            yield from handle


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
    show_progress: bool = True,
    progress_interval: float = 5.0,
    start_dt: datetime | None = None,
    end_dt: datetime | None = None,
    exclude_monitoring: bool = False,
    require_public_client_ip: bool = False,
    suppressed_log_levels: set[str] | None = None,
) -> tuple[UsageStats, dict[str, UsageStats], list[ParsedFile]]:
    stats = UsageStats("AWS WAF")
    monthly: dict[str, UsageStats] = {}
    parsed_files: list[ParsedFile] = []
    cloudwatch_dir = export_dir / "cloudwatch"
    suppressed_log_levels = suppressed_log_levels or set()

    paths = sorted(cloudwatch_dir.glob("*.jsonl"))
    if show_progress:
        progress_message(f"Found {fmt_int(len(paths))} CloudWatch JSONL file(s)")

    for path in paths:
        if max_records and stats.total >= max_records:
            return stats, monthly, parsed_files
        parsed = ParsedFile(path=path, kind="AWS WAF CloudWatch JSONL")
        parsed_files.append(parsed)
        start_offset = 0
        if start_dt and path.suffix.lower() != ".gz":
            start_offset = seek_jsonl_timestamp(path, datetime_to_ms(start_dt))
            if show_progress:
                progress_message(f"Seeking {path.name} to byte {fmt_int(start_offset)} for {format_datetime(start_dt)}")
        with FileProgress("WAF JSONL", path, show_progress, progress_interval) as progress:
            for line in iter_progress_lines(path, progress, start_offset=start_offset):
                line = line.strip()
                if not line:
                    progress.maybe_report(parsed, stats.total)
                    continue
                event = parse_cloudwatch_waf_line(line, tz, anonymize)
                if event is None:
                    if is_suppressed_log_level_line(line, suppressed_log_levels):
                        parsed.filtered += 1
                    else:
                        parsed.errors += 1
                    progress.maybe_report(parsed, stats.total)
                    continue
                if end_dt and event.get("timestamp") and event["timestamp"] >= end_dt:
                    progress.finish(parsed, stats.total)
                    return stats, monthly, parsed_files
                if not event_in_window(event, start_dt, end_dt):
                    parsed.filtered += 1
                    progress.maybe_report(parsed, stats.total)
                    continue
                if exclude_monitoring and is_monitoring_event(event):
                    parsed.filtered += 1
                    progress.maybe_report(parsed, stats.total)
                    continue
                if require_public_client_ip and not has_public_client_ip(event):
                    parsed.filtered += 1
                    progress.maybe_report(parsed, stats.total)
                    continue
                parsed.records += 1
                add_event(stats, monthly, event)
                progress.maybe_report(parsed, stats.total)
                if max_records and stats.total >= max_records:
                    progress.finish(parsed, stats.total)
                    if show_progress:
                        progress_message(f"Stopped WAF parsing at --max-records={fmt_int(max_records)}")
                    return stats, monthly, parsed_files
            progress.finish(parsed, stats.total)

    return stats, monthly, parsed_files


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
    show_progress: bool = True,
    progress_interval: float = 5.0,
    start_dt: datetime | None = None,
    end_dt: datetime | None = None,
    exclude_monitoring: bool = False,
    require_public_client_ip: bool = False,
) -> tuple[UsageStats, dict[str, UsageStats], list[ParsedFile]]:
    stats = UsageStats("ALB access logs")
    monthly: dict[str, UsageStats] = {}
    parsed_files: list[ParsedFile] = []

    for path in sorted(export_dir.rglob("*")):
        if not path.is_file() or not looks_like_alb_log(path, export_dir):
            continue
        if max_records and stats.total >= max_records:
            return stats, monthly, parsed_files
        parsed = ParsedFile(path=path, kind="ALB access log")
        parsed_files.append(parsed)
        with FileProgress("ALB log", path, show_progress, progress_interval) as progress:
            for line in iter_progress_lines(path, progress):
                line = line.strip()
                if not line:
                    progress.maybe_report(parsed, stats.total)
                    continue
                event = parse_alb_line(line, tz, anonymize)
                if event is None:
                    parsed.errors += 1
                    progress.maybe_report(parsed, stats.total)
                    continue
                if not event_in_window(event, start_dt, end_dt):
                    parsed.filtered += 1
                    progress.maybe_report(parsed, stats.total)
                    continue
                if exclude_monitoring and is_monitoring_event(event):
                    parsed.filtered += 1
                    progress.maybe_report(parsed, stats.total)
                    continue
                if require_public_client_ip and not has_public_client_ip(event):
                    parsed.filtered += 1
                    progress.maybe_report(parsed, stats.total)
                    continue
                parsed.records += 1
                add_event(stats, monthly, event)
                progress.maybe_report(parsed, stats.total)
                if max_records and stats.total >= max_records:
                    progress.finish(parsed, stats.total)
                    if show_progress:
                        progress_message(f"Stopped ALB parsing at --max-records={fmt_int(max_records)}")
                    return stats, monthly, parsed_files
            progress.finish(parsed, stats.total)

    return stats, monthly, parsed_files


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


def shared_ip_table(stats: UsageStats, limit: int = 12) -> str:
    rows = []
    for ip, user_agents in stats.ip_user_agents.items():
        request_count = stats.client_ips.get(ip, 0)
        rows.append((ip, len(user_agents), request_count))
    rows.sort(key=lambda item: (item[1], item[2]), reverse=True)

    if not rows:
        return empty_panel("No IP and user-agent combinations were available.")

    body = []
    for rank, (ip, user_agent_count, request_count) in enumerate(rows[:limit], start=1):
        body.append(
            "<tr>"
            f"<td>{rank}</td>"
            f"<td>{html_escape(ip)}</td>"
            f"<td class=\"num\">{fmt_int(user_agent_count)}</td>"
            f"<td class=\"num\">{fmt_int(request_count)}</td>"
            "</tr>"
        )

    return (
        '<table><thead><tr>'
        '<th class="rank">#</th><th>Client IP</th>'
        '<th class="num">Distinct user agents</th><th class="num">Requests</th>'
        '</tr></thead><tbody>'
        + "\n".join(body)
        + "</tbody></table>"
    )


def unique_users_section(stats: UsageStats, anonymized: bool) -> str:
    unique_ip_user_agents = sum(len(user_agents) for user_agents in stats.ip_user_agents.values())
    repeat_ips = sum(1 for count in stats.client_ips.values() if count > 1)
    single_request_ips = sum(1 for count in stats.client_ips.values() if count == 1)
    source_detail = "Anonymised network-level IPs" if anonymized else "Selected public IPs"

    metrics = [
        metric_card("Unique IPs", fmt_int(len(stats.unique_ips)), source_detail),
        metric_card("IP + user-agent pairs", fmt_int(unique_ip_user_agents), "Proxy/NAT-aware estimate"),
        metric_card("Unique user agents", fmt_int(len(stats.user_agents)), "Browser or automation signatures"),
        metric_card("Unique JA4 fingerprints", fmt_int(len(stats.ja4_fingerprints)), "TLS/client fingerprint where present"),
        metric_card("Unique JA3 fingerprints", fmt_int(len(stats.ja3_fingerprints)), "Legacy TLS fingerprint where present"),
        metric_card("Repeat IPs", fmt_int(repeat_ips), f"{fmt_int(single_request_ips)} IPs only appeared once"),
    ]

    return f"""
    <section>
      <h2>Unique User Signals</h2>
      <p class="note">These are best-effort log-based audience signals. They do not identify people: one person can use multiple IPs, and one IP can represent many users behind an office, mobile network, VPN, or bot fleet.</p>
      <div class="metrics">
        {"".join(metrics)}
      </div>
      <div class="grid two stack-panel">
        <div class="panel">
          <h3>Client IP Source Used</h3>
          {counter_table(stats.client_ip_sources, stats.total, "Selected IP source", 8)}
          <p class="note">Selection order is Cloudflare/forwarded public IP headers first, then WAF client IP only as a fallback.</p>
        </div>
        <div class="panel">
          <h3>Selected IP Address Type</h3>
          {counter_table(stats.client_ip_categories, stats.total, "IP address type", 8)}
          <p class="note">Private/internal entries here would indicate load balancer or network addresses being counted as client IPs.</p>
        </div>
        <div class="panel">
          <h3>Possible Shared IPs</h3>
          {shared_ip_table(stats, 12)}
        </div>
        <div class="panel">
          <h3>Top IP + User-Agent Pairs</h3>
          {counter_table(stats.ip_user_agent_pairs, stats.total, "IP and user agent", 10)}
        </div>
        <div class="panel">
          <h3>JA4 Fingerprints</h3>
          {counter_table(stats.ja4_fingerprints, stats.total, "JA4 fingerprint", 10)}
        </div>
        <div class="panel">
          <h3>JA3 Fingerprints</h3>
          {counter_table(stats.ja3_fingerprints, stats.total, "JA3 fingerprint", 10)}
        </div>
        <div class="panel">
          <h3>WAF Edge Client IPs</h3>
          {counter_table(stats.edge_client_ips, stats.total, "WAF clientIp value", 10)}
          <p class="note">This is the raw WAF client IP, often the CDN or proxy edge. It is shown here only to verify it was not used as the primary client IP when forwarded public IP headers were present.</p>
        </div>
      </div>
    </section>
    """


def event_table(events: Iterable[dict], empty_message: str) -> str:
    rows = list(events)
    if not rows:
        return empty_panel(empty_message)
    body = []
    for event in reversed(rows):
        outcome = event.get("status") or event.get("action") or ""
        event_time = event.get("time", "")
        if isinstance(event_time, datetime):
            event_time = format_datetime(event_time)
        body.append(
            "<tr>"
            f"<td>{html_escape(event_time)}</td>"
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
            f"<td class=\"num\">{fmt_int(item.filtered)}</td>"
            f"<td class=\"num\">{fmt_int(item.errors)}</td>"
            "</tr>"
        )
    return (
        '<table><thead><tr>'
        '<th>File</th><th>Type</th><th class="num">Parsed records</th>'
        '<th class="num">Filtered records</th><th class="num">Unreadable lines</th>'
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


def blocked_count(stats: UsageStats) -> int:
    return sum(stats.actions[action] for action in ["BLOCK", "CAPTCHA", "CHALLENGE"])


def http_error_count(stats: UsageStats) -> int:
    return sum(
        count for status, count in stats.statuses.items() if status.startswith("4") or status.startswith("5")
    )


def top_counter_value(counter: Counter, fallback: str = "None") -> tuple[str, int]:
    return counter.most_common(1)[0] if counter else (fallback, 0)


def monthly_keys_for_report(stats: UsageStats, monthly: dict[str, UsageStats]) -> list[str]:
    keys = month_keys_between(stats.first_seen, stats.last_seen)
    for key in monthly:
        if key not in keys:
            keys.append(key)
    return sorted((key for key in keys if key != "undated")) + (["undated"] if "undated" in monthly else [])


def monthly_chart_rows(monthly: dict[str, UsageStats], keys: list[str]) -> list[tuple[str, int]]:
    return [(month_label(key), monthly.get(key, UsageStats(month_label(key))).total) for key in keys]


def monthly_blocked_rows(monthly: dict[str, UsageStats], keys: list[str]) -> list[tuple[str, int]]:
    return [(month_label(key), blocked_count(monthly.get(key, UsageStats(month_label(key))))) for key in keys]


def monthly_summary_table(monthly: dict[str, UsageStats], keys: list[str], total: int) -> str:
    if not keys:
        return empty_panel("No monthly data available.")

    rows = []
    for key in keys:
        stats = monthly.get(key, UsageStats(month_label(key)))
        month_blocked = blocked_count(stats)
        peak_day, peak_count = peak_label(stats.daily)
        top_country, top_country_count = top_counter_value(stats.countries)
        top_path, top_path_count = top_counter_value(stats.normalized_paths)
        days = period_days(stats) or month_days(key)
        avg_per_day = stats.total / days if days else 0

        rows.append(
            "<tr>"
            f"<td>{html_escape(month_label(key))}</td>"
            f"<td class=\"num\">{fmt_int(stats.total)}</td>"
            f"<td class=\"num\">{pct(stats.total, total)}</td>"
            f"<td class=\"num\">{fmt_int(len(stats.unique_ips))}</td>"
            f"<td class=\"num\">{fmt_float(avg_per_day)}</td>"
            f"<td class=\"num\">{fmt_int(month_blocked)}</td>"
            f"<td class=\"num\">{pct(month_blocked, stats.total)}</td>"
            f"<td title=\"{html_escape(top_country)}\">{html_escape(truncate(top_country, 32))} ({fmt_int(top_country_count)})</td>"
            f"<td title=\"{html_escape(top_path)}\">{html_escape(truncate(top_path, 46))} ({fmt_int(top_path_count)})</td>"
            f"<td>{html_escape(peak_day)} ({fmt_int(peak_count)})</td>"
            "</tr>"
        )

    return (
        '<table><thead><tr>'
        '<th>Month</th>'
        '<th class="num">Requests</th>'
        '<th class="num">Share</th>'
        '<th class="num">Unique IPs</th>'
        '<th class="num">Avg/day</th>'
        '<th class="num">Blocked</th>'
        '<th class="num">Blocked rate</th>'
        '<th>Top country</th>'
        '<th>Top path</th>'
        '<th>Peak day</th>'
        '</tr></thead><tbody>'
        + "\n".join(rows)
        + "</tbody></table>"
    )


def month_panel(index: int, key: str, stats: UsageStats) -> str:
    days = period_days(stats) or month_days(key)
    avg_per_day = stats.total / days if days else 0
    month_blocked = blocked_count(stats)
    peak_day, peak_count = peak_label(stats.daily)
    top_country, _ = top_counter_value(stats.countries)
    top_path, _ = top_counter_value(stats.normalized_paths)
    daily_rows = sorted(stats.daily.items())
    hour_rows = ordered_counter_rows(stats.hour_of_day, [f"{hour:02d}:00" for hour in range(24)])

    month_metrics = [
        metric_card("Requests", fmt_int(stats.total), f"{fmt_float(avg_per_day)} average per day"),
        metric_card("Unique client IPs", fmt_int(len(stats.unique_ips)), "Selected public request IPs"),
        metric_card("Blocked / challenged", pct(month_blocked, stats.total), f"{fmt_int(month_blocked)} records"),
        metric_card("Countries", fmt_int(len(stats.countries)), f"Top: {top_country}"),
        metric_card("Paths requested", fmt_int(len(stats.normalized_paths)), f"Top: {truncate(top_path, 38)}"),
        metric_card("Peak day", peak_day, f"{fmt_int(peak_count)} requests"),
    ]

    return f"""
      <article class="tab-panel" id="month-panel-{index}">
        <h3>{html_escape(month_label(key))}</h3>
        <div class="metrics monthly-metrics">
          {"".join(month_metrics)}
        </div>
        <div class="grid two month-grid">
          <div class="panel">
            <h3>Daily Requests</h3>
            {line_chart(daily_rows, f"Daily requests for {month_label(key)}", CHART_COLORS[1])}
          </div>
          <div class="panel">
            <h3>Hour Of Day</h3>
            {vertical_bar_chart(hour_rows, f"Hour of day for {month_label(key)}", CHART_COLORS[0])}
          </div>
          <div class="panel">
            <h3>Top Paths</h3>
            {counter_table(stats.normalized_paths, stats.total, "Path", 10)}
          </div>
          <div class="panel">
            <h3>Countries</h3>
            {bar_chart(counter_rows(stats.countries, 10), f"Countries for {month_label(key)}", CHART_COLORS[0])}
          </div>
          <div class="panel">
            <h3>Actions</h3>
            {bar_chart(counter_rows(stats.actions, 8), f"Actions for {month_label(key)}", CHART_COLORS[3])}
          </div>
          <div class="panel">
            <h3>Referrer Hosts</h3>
            {counter_table(stats.referrer_hosts, stats.total, "Referrer host", 10)}
          </div>
        </div>
      </article>
    """


def monthly_tab_css(keys: list[str]) -> str:
    rules = []
    for index, _ in enumerate(keys):
        rules.append(
            f'#month-tab-{index}:checked ~ .tab-list label[for="month-tab-{index}"] '
            "{ background: var(--ink); border-color: var(--ink); color: #ffffff; }"
        )
        rules.append(
            f"#month-tab-{index}:checked ~ .tab-panels #month-panel-{index} "
            "{ display: block; }"
        )
    return "\n".join(rules)


def monthly_tabs(monthly: dict[str, UsageStats], keys: list[str]) -> str:
    if not keys:
        return empty_panel("No monthly data available.")

    inputs = []
    labels = []
    panels = []
    for index, key in enumerate(keys):
        checked = " checked" if index == 0 else ""
        stats = monthly.get(key, UsageStats(month_label(key)))
        inputs.append(
            f'<input class="tab-radio" type="radio" name="month-tabs" '
            f'id="month-tab-{index}"{checked}>'
        )
        labels.append(
            f'<label for="month-tab-{index}">'
            f'<span>{html_escape(month_label(key))}</span>'
            f'<strong>{fmt_int(stats.total)}</strong>'
            '</label>'
        )
        panels.append(month_panel(index, key, stats))

    return (
        '<div class="tabs">'
        + "\n".join(inputs)
        + '<div class="tab-list" role="tablist">'
        + "\n".join(labels)
        + '</div><div class="tab-panels">'
        + "\n".join(panels)
        + "</div></div>"
    )


def render_report(
    export_dir: Path,
    title: str,
    timezone_name: str,
    primary: UsageStats,
    primary_monthly: dict[str, UsageStats],
    waf_stats: UsageStats,
    waf_monthly: dict[str, UsageStats],
    alb_stats: UsageStats,
    alb_monthly: dict[str, UsageStats],
    parsed_files: list[ParsedFile],
    context: dict,
    anonymized: bool,
    filters: list[str],
) -> str:
    generated_at = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
    days = period_days(primary)
    avg_per_day = primary.total / days if days else 0
    blocked = blocked_count(primary)
    http_errors = http_error_count(primary)
    peak_day, peak_day_count = peak_label(primary.daily)
    peak_hour, peak_hour_count = peak_label(primary.hourly)
    month_keys = monthly_keys_for_report(primary, primary_monthly)
    months_with_data = sum(1 for key in month_keys if primary_monthly.get(key, UsageStats(month_label(key))).total)

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
        metric_card("Unique client IPs", fmt_int(len(primary.unique_ips)), "Selected public request IPs"),
        metric_card("Countries", fmt_int(len(primary.countries)), "Based on WAF or proxy country data"),
        metric_card("Paths requested", fmt_int(len(primary.normalized_paths)), "Normalised by common IDs"),
        metric_card(outcome_label, outcome_value, outcome_detail),
        metric_card("Average per day", fmt_float(avg_per_day), f"Across {fmt_int(days)} day(s)"),
        metric_card("Months observed", fmt_int(months_with_data), "Month tabs include every observed month"),
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
    .stack-panel {{
      margin-top: 16px;
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
    .tabs {{
      margin-top: 8px;
    }}
    .tab-radio {{
      position: absolute;
      opacity: 0;
      pointer-events: none;
    }}
    .tab-list {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 16px;
    }}
    .tab-list label {{
      min-width: 112px;
      padding: 10px 12px;
      border: 1px solid var(--line);
      border-radius: 8px;
      background: #ffffff;
      cursor: pointer;
      color: var(--ink);
    }}
    .tab-list span {{
      display: block;
      font-size: 13px;
      color: inherit;
    }}
    .tab-list strong {{
      display: block;
      margin-top: 3px;
      font-size: 15px;
    }}
    .tab-panel {{
      display: none;
    }}
    .monthly-metrics {{
      grid-template-columns: repeat(3, minmax(0, 1fr));
      margin-bottom: 16px;
    }}
    .month-grid {{
      margin-top: 16px;
    }}
    {monthly_tab_css(month_keys)}
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
      .monthly-metrics {{ grid-template-columns: 1fr; }}
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
      <p>Static yearly usage summary generated from AWS traffic evidence. Figures are log observations, not cookie-based analytics.</p>
      <div class="meta">
        <div><strong>Source directory:</strong> {html_escape(str(export_dir))}</div>
        <div><strong>Generated:</strong> {html_escape(generated_at)}</div>
        <div><strong>Reporting period:</strong> {html_escape(report_period(primary))}</div>
        <div><strong>Report timezone:</strong> {html_escape(timezone_name)}</div>
        <div><strong>AWS account:</strong> {html_escape(context.get("account", "Unknown"))}</div>
        <div><strong>Load balancers:</strong> {html_escape(list_text(context.get("load_balancers", [])))}</div>
        <div><strong>WAF ACLs:</strong> {html_escape(list_text(context.get("waf_acls", [])))}</div>
        <div><strong>Client IPs:</strong> {"Anonymised to network level" if anonymized else "Shown as observed in logs"}</div>
        <div><strong>Filters:</strong> {html_escape(list_text(filters, "None"))}</div>
      </div>
      <div class="metrics">
        {"".join(metrics)}
      </div>
    </div>
  </header>

  <main class="wrap">
    {no_data_message}

    <section>
      <h2>Yearly Summary</h2>
      <div class="grid two">
        <div class="panel">
          <h3>Requests By Month</h3>
          {vertical_bar_chart(monthly_chart_rows(primary_monthly, month_keys), "Requests by month", CHART_COLORS[1])}
        </div>
        <div class="panel">
          <h3>Blocked Or Challenged By Month</h3>
          {vertical_bar_chart(monthly_blocked_rows(waf_monthly if waf_stats.total else primary_monthly, month_keys), "Blocked or challenged requests by month", CHART_COLORS[3])}
        </div>
      </div>
      <div class="panel stack-panel">
        <h3>Month-By-Month Statistics</h3>
        {monthly_summary_table(primary_monthly, month_keys, primary.total)}
      </div>
    </section>

    <section>
      <h2>Monthly Breakdown</h2>
      {monthly_tabs(primary_monthly, month_keys)}
    </section>

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

    {unique_users_section(primary, anonymized)}

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
    Generated by web_stats.py. Store this HTML alongside the evidence export for an audit trail.
  </footer>
</body>
</html>
"""


def write_report(path: Path, html: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a static yearly HTML web usage report from AWS WAF and ALB evidence exports."
    )
    parser.add_argument(
        "export_dir",
        nargs="?",
        help="Evidence export directory. Defaults to the latest aws_web_traffic_export_* directory.",
    )
    parser.add_argument(
        "--out",
        help="Output HTML path. Defaults to <export_dir>/web_stats.html.",
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
    parser.add_argument(
        "--start-date",
        help="Inclusive start date/time for records, for example 2026-01-01 or 2026-01-01T00:00:00Z.",
    )
    parser.add_argument(
        "--end-date",
        help="Exclusive end date/time for records, for example 2026-05-01 or 2026-05-01T00:00:00Z.",
    )
    parser.add_argument(
        "--exclude-health-checks",
        action="store_true",
        help="Exclude health-check and Pingdom monitoring requests from the report.",
    )
    parser.add_argument(
        "--require-public-client-ip",
        action="store_true",
        help="Exclude records whose selected client IP is not public/global.",
    )
    parser.add_argument(
        "--exclude-log-levels",
        default="INFO,ERROR",
        help="Comma-separated raw CloudWatch message levels to skip when they are not WAF JSON. Default: INFO,ERROR.",
    )
    parser.add_argument(
        "--progress",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Show per-file parsing progress. Uses tqdm progress bars when tqdm is installed.",
    )
    parser.add_argument(
        "--progress-interval",
        type=float,
        default=5.0,
        help="Seconds between progress refreshes. Set to 0 to disable progress output.",
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
    out = Path(args.out).expanduser().resolve() if args.out else export_dir / "web_stats.html"
    show_progress = args.progress and args.progress_interval > 0
    start_dt = parse_filter_datetime(args.start_date, tz)
    end_dt = parse_filter_datetime(args.end_date, tz)
    if start_dt and end_dt and end_dt <= start_dt:
        print("[!] --end-date must be after --start-date.", file=sys.stderr)
        return 1
    suppressed_log_levels = {
        level.strip().upper()
        for level in args.exclude_log_levels.split(",")
        if level.strip()
    }

    filters = []
    if start_dt:
        filters.append(f"from {format_datetime(start_dt)}")
    if end_dt:
        filters.append(f"before {format_datetime(end_dt)}")
    if args.exclude_health_checks:
        filters.append("health and monitoring checks removed")
    if args.require_public_client_ip:
        filters.append("non-public selected client IPs removed")
    if suppressed_log_levels:
        filters.append("raw non-traffic log-level messages removed")

    print(f"[*] Reading evidence from {export_dir}", flush=True)
    print(f"[*] JSON parser: {JSON_PARSER}", flush=True)
    waf_stats, waf_monthly, waf_files = load_waf_stats(
        export_dir,
        tz,
        args.anonymize_ips,
        args.max_records,
        show_progress=show_progress,
        progress_interval=args.progress_interval,
        start_dt=start_dt,
        end_dt=end_dt,
        exclude_monitoring=args.exclude_health_checks,
        require_public_client_ip=args.require_public_client_ip,
        suppressed_log_levels=suppressed_log_levels,
    )
    print(f"[*] Parsed WAF records: {fmt_int(waf_stats.total)}", flush=True)
    alb_stats, alb_monthly, alb_files = load_alb_stats(
        export_dir,
        tz,
        args.anonymize_ips,
        args.max_records,
        show_progress=show_progress,
        progress_interval=args.progress_interval,
        start_dt=start_dt,
        end_dt=end_dt,
        exclude_monitoring=args.exclude_health_checks,
        require_public_client_ip=args.require_public_client_ip,
    )
    print(f"[*] Parsed ALB records: {fmt_int(alb_stats.total)}", flush=True)

    primary = waf_stats if waf_stats.total else alb_stats
    primary_monthly = waf_monthly if waf_stats.total else alb_monthly
    parsed_files = waf_files + alb_files
    context = load_export_context(export_dir)
    html = render_report(
        export_dir=export_dir,
        title=args.title,
        timezone_name=args.timezone,
        primary=primary,
        primary_monthly=primary_monthly,
        waf_stats=waf_stats,
        waf_monthly=waf_monthly,
        alb_stats=alb_stats,
        alb_monthly=alb_monthly,
        parsed_files=parsed_files,
        context=context,
        anonymized=args.anonymize_ips,
        filters=filters,
    )
    write_report(out, html)
    print(f"[+] Wrote report: {out}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
