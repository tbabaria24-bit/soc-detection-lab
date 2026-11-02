"""Log parsers.

Each parser turns one raw log format into a list of normalized ``Event`` objects,
so detection rules can use the same field names no matter where a log came from.

Normalized fields (not every source has every field):
    source        windows | linux | web
    host          machine the event happened on
    event_id      Windows event ID (e.g. 4625)
    action        short verb describing the event (e.g. ssh_failed, logon_failed)
    user          account the event is about
    src_ip        remote IP address involved
    command_line  process command line (Windows 4688)
    ...plus any original Windows EventData field, lower-cased
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import unquote_plus

# Friendly action names for the Windows Security event IDs we care about.
WINDOWS_ACTIONS = {
    4624: "logon_success",
    4625: "logon_failed",
    4657: "registry_value_modified",
    4688: "process_created",
    4698: "scheduled_task_created",
    4720: "user_created",
    4726: "user_deleted",
    4732: "member_added_to_local_group",
}


@dataclass
class Event:
    timestamp: datetime
    source: str
    fields: dict[str, Any]
    raw: str
    line_no: int = 0
    file: str = ""

    def get(self, name: str, default: Any = None) -> Any:
        return self.fields.get(name.lower(), default)


@dataclass
class ParseResult:
    events: list[Event] = field(default_factory=list)
    skipped: int = 0  # lines that could not be parsed


# --------------------------------------------------------------------------- #
# Windows Security events (JSON Lines, one event per line)
# --------------------------------------------------------------------------- #
def parse_windows_jsonl(path: Path) -> ParseResult:
    """Parse Windows Security events exported as JSON Lines.

    Expected keys follow the Windows EventData names, e.g.
    {"TimeCreated": "...", "EventID": 4625, "Computer": "WS01", "TargetUserName": "...", "IpAddress": "..."}
    """
    result = ParseResult()
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
            ts = _parse_iso(rec["TimeCreated"])
            event_id = int(rec["EventID"])
        except (ValueError, KeyError, TypeError):
            result.skipped += 1
            continue

        fields = {k.lower(): v for k, v in rec.items()}
        fields.update(
            source="windows",
            event_id=event_id,
            host=rec.get("Computer", ""),
            action=WINDOWS_ACTIONS.get(event_id, f"event_{event_id}"),
            src_ip=rec.get("IpAddress", ""),
            command_line=rec.get("CommandLine", ""),
        )
        # 4732 puts the *group* in TargetUserName and the account in MemberName.
        if event_id == 4732:
            fields["group_name"] = rec.get("TargetUserName", "")
            fields["user"] = rec.get("MemberName", "")
        else:
            fields["user"] = rec.get("TargetUserName") or rec.get("SubjectUserName", "")

        result.events.append(Event(ts, "windows", fields, line, n, str(path)))
    return result


# --------------------------------------------------------------------------- #
# Linux auth.log (syslog format)
# --------------------------------------------------------------------------- #
SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s(?P<time>\d{2}:\d{2}:\d{2})\s"
    r"(?P<host>\S+)\s(?P<program>[\w\-/]+)(?:\[\d+\])?:\s(?P<message>.*)$"
)
AUTH_PATTERNS = [
    ("ssh_failed", re.compile(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>[\d.]+)")),
    ("ssh_success", re.compile(r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<src_ip>[\d.]+)")),
    ("ssh_invalid_user", re.compile(r"Invalid user (?P<user>\S+) from (?P<src_ip>[\d.]+)")),
    ("sudo_command", re.compile(r"^\s*(?P<user>\S+) : .*COMMAND=(?P<command_line>.+)$")),
    ("user_created", re.compile(r"new user: name=(?P<user>[^,\s]+)")),
    ("member_added_to_group", re.compile(r"add '(?P<user>[^']+)' to group '(?P<group_name>[^']+)'")),
]


def parse_linux_auth(path: Path, year: int) -> ParseResult:
    """Parse a Linux auth.log. Syslog lines carry no year, so it is passed in."""
    result = ParseResult()
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        m = SYSLOG_RE.match(line)
        if not m:
            result.skipped += 1
            continue
        try:
            ts = datetime.strptime(
                f"{year} {m['month']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            result.skipped += 1
            continue

        fields: dict[str, Any] = {
            "source": "linux",
            "host": m["host"],
            "program": m["program"],
            "message": m["message"],
            "action": "other",
        }
        for action, pattern in AUTH_PATTERNS:
            hit = pattern.search(m["message"])
            if hit:
                fields["action"] = action
                fields.update({k: v.strip() for k, v in hit.groupdict().items()})
                break
        result.events.append(Event(ts, "linux", fields, line, n, str(path)))
    return result


# --------------------------------------------------------------------------- #
# Web server access log (Apache / Nginx "combined" format)
# --------------------------------------------------------------------------- #
ACCESS_RE = re.compile(
    r'^(?P<src_ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" (?P<status>\d{3}) (?P<size>\S+)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)")?'
)


def parse_web_access(path: Path, host: str = "") -> ParseResult:
    result = ParseResult()
    host = host or path.stem.split("_")[0]  # "web01_access.log" -> "web01"
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        m = ACCESS_RE.match(line)
        if not m:
            result.skipped += 1
            continue
        try:
            ts = datetime.strptime(m["time"], "%d/%b/%Y:%H:%M:%S %z").astimezone(timezone.utc)
        except ValueError:
            result.skipped += 1
            continue
        fields = {
            "source": "web",
            "host": host,
            "action": "http_request",
            "src_ip": m["src_ip"],
            "user": "" if m["user"] == "-" else m["user"],
            "method": m["method"],
            "path": m["path"],
            "decoded_path": unquote_plus(m["path"]),
            "status": int(m["status"]),
            "user_agent": m["user_agent"] or "",
        }
        result.events.append(Event(ts, "web", fields, line, n, str(path)))
    return result


# --------------------------------------------------------------------------- #
def _parse_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def detect_format(path: Path) -> str:
    """Guess a log's format from its first non-empty line."""
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            if line.startswith("{"):
                return "windows"
            if ACCESS_RE.match(line):
                return "web"
            if SYSLOG_RE.match(line):
                return "linux"
            break
    raise ValueError(f"Could not recognize the log format of {path}")


def load_logs(paths: list[Path], year: int) -> tuple[list[Event], dict[str, int]]:
    """Load every file (or every file in a folder), return events sorted by time."""
    files: list[Path] = []
    for p in paths:
        files.extend(sorted(f for f in p.iterdir() if f.is_file() and not f.name.startswith("."))
                     if p.is_dir() else [p])

    events: list[Event] = []
    stats: dict[str, int] = {"files": 0, "events": 0, "skipped_lines": 0}
    for f in files:
        fmt = detect_format(f)
        if fmt == "windows":
            res = parse_windows_jsonl(f)
        elif fmt == "linux":
            res = parse_linux_auth(f, year)
        else:
            res = parse_web_access(f)
        events.extend(res.events)
        stats["files"] += 1
        stats["skipped_lines"] += res.skipped
    events.sort(key=lambda e: e.timestamp)
    stats["events"] = len(events)
    return events, stats
