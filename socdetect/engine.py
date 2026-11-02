"""Rule loading and the detection engine.

Rules are YAML files (see ``rules/``). Three detection types are supported:

* ``match``     - every event that matches the selection raises an alert
                  (e.g. "a new user account was created").
* ``threshold`` - N matching events from the same key within a time window
                  (e.g. "5 failed logins from one IP in 5 minutes").
* ``sequence``  - a threshold burst followed by a second event with the same key
                  (e.g. "brute force, then a successful login from that IP").

Selections use Sigma-style field modifiers. All fields must match (AND);
a list of values means any one of them (OR):

    selection:
      event_id: 4625
      command_line|contains: ["-enc", "-encodedcommand"]
      path|re: "(?i)union\\s+select"
      status|gte: 400

An optional ``filter`` removes known-good events (tuning out false positives):

    filter:
      subjectusername: SYSTEM
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import yaml

from .parsers import Event

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
DETECTION_TYPES = {"match", "threshold", "sequence"}
MODIFIERS = {"equals", "contains", "startswith", "endswith", "re", "gte", "lte"}


class RuleError(ValueError):
    """Raised when a rule file is invalid."""


@dataclass
class Rule:
    id: str
    title: str
    description: str
    severity: str
    logsource: str
    tactic: str
    technique_id: str
    technique_name: str
    detection: dict[str, Any]
    response: list[str] = field(default_factory=list)
    false_positives: list[str] = field(default_factory=list)
    file: str = ""

    @property
    def type(self) -> str:
        return self.detection["type"]


@dataclass
class Alert:
    rule: Rule
    evidence: list[Event]
    group: dict[str, Any] = field(default_factory=dict)

    @property
    def first_seen(self) -> datetime:
        return self.evidence[0].timestamp

    @property
    def last_seen(self) -> datetime:
        return self.evidence[-1].timestamp

    @property
    def hosts(self) -> list[str]:
        return sorted({e.get("host", "") for e in self.evidence if e.get("host")})

    def summary(self) -> str:
        """One readable line describing what happened."""
        r, ev = self.rule, self.evidence
        who = ", ".join(f"{k}={v}" for k, v in self.group.items() if v)
        if r.type == "threshold":
            return f"{len(ev)} matching events ({who}) between {_hm(self.first_seen)} and {_hm(self.last_seen)}"
        if r.type == "sequence":
            last = ev[-1]
            user = f" as {last.get('user')}" if last.get("user") else ""
            return (f"{len(ev) - 1} matching events, then {last.get('action', 'a follow-up event')}{user} "
                    f"at {_hm(last.timestamp)} ({who})")
        e = ev[0]
        detail = e.get("command_line") or e.get("decoded_path") or e.get("message") or ""
        user = e.get("user")
        parts = [f"user={user}" if user else "", f"src_ip={e.get('src_ip')}" if e.get("src_ip") else ""]
        if e.get("group_name"):
            parts.append(f"group={e.get('group_name')}")
        if e.get("taskname"):
            parts.append(f"task={e.get('taskname')}")
        if detail and r.logsource != "linux":
            parts.append(_short(str(detail), 90))
        decoded = decode_powershell(e.get("command_line") or "")
        if decoded:
            parts.append(f"[decoded: {_short(decoded, 80)}]")
        return " ".join(p for p in parts if p) or e.raw[:120]

    def to_dict(self) -> dict[str, Any]:
        r = self.rule
        return {
            "rule_id": r.id,
            "title": r.title,
            "severity": r.severity,
            "mitre": {"tactic": r.tactic, "technique_id": r.technique_id, "technique": r.technique_name},
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "hosts": self.hosts,
            "group": self.group,
            "summary": self.summary(),
            "event_count": len(self.evidence),
            "decoded_command": decode_powershell(self.evidence[0].get("command_line") or "") or None,
            "evidence": [
                {"timestamp": e.timestamp.isoformat(), "file": Path(e.file).name, "line": e.line_no, "raw": e.raw}
                for e in self.evidence
            ],
            "response": r.response,
        }


# --------------------------------------------------------------------------- #
# Loading rules
# --------------------------------------------------------------------------- #
def load_rules(rules_dir: Path) -> list[Rule]:
    files = sorted([*rules_dir.glob("*.yml"), *rules_dir.glob("*.yaml")])
    if not files:
        raise RuleError(f"No rule files found in {rules_dir}")
    rules = [_load_rule(f) for f in files]
    ids = [r.id for r in rules]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise RuleError(f"Duplicate rule ids: {', '.join(sorted(dupes))}")
    return rules


def _load_rule(path: Path) -> Rule:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise RuleError(f"{path.name}: invalid YAML ({exc})") from exc

    def need(key: str, where: dict = data) -> Any:
        if not isinstance(where, dict) or key not in where:
            raise RuleError(f"{path.name}: missing required field '{key}'")
        return where[key]

    det = need("detection")
    dtype = need("type", det)
    if dtype not in DETECTION_TYPES:
        raise RuleError(f"{path.name}: detection type must be one of {sorted(DETECTION_TYPES)}")
    sel_keys = ["selection"] + (["followed_by"] if dtype == "sequence" else [])
    for sel_key in sel_keys + (["filter"] if "filter" in det else []):
        sel = need(sel_key, det)
        if not isinstance(sel, dict) or not sel:
            raise RuleError(f"{path.name}: '{sel_key}' must be a non-empty mapping")
        for fkey, value in sel.items():
            _, _, mod = fkey.partition("|")
            if mod and mod not in MODIFIERS:
                raise RuleError(f"{path.name}: unknown modifier '{mod}' in '{fkey}'")
            if mod == "re":
                for v in value if isinstance(value, list) else [value]:
                    try:
                        re.compile(v)
                    except re.error as exc:
                        raise RuleError(f"{path.name}: bad regex in '{fkey}': {exc}") from exc
    if dtype in {"threshold", "sequence"}:
        th = need("threshold", det)
        for k in ("group_by", "count", "window_seconds"):
            need(k, th)

    severity = str(need("severity")).lower()
    if severity not in SEVERITY_ORDER:
        raise RuleError(f"{path.name}: severity must be one of {list(SEVERITY_ORDER)}")
    mitre = need("mitre")
    return Rule(
        id=str(need("id")),
        title=str(need("title")),
        description=str(data.get("description", "")).strip(),
        severity=severity,
        logsource=str(need("logsource")).lower(),
        tactic=str(need("tactic", mitre)),
        technique_id=str(need("technique_id", mitre)),
        technique_name=str(need("technique", mitre)),
        detection=det,
        response=list(data.get("response", [])),
        false_positives=list(data.get("false_positives", [])),
        file=path.name,
    )


# --------------------------------------------------------------------------- #
# Matching
# --------------------------------------------------------------------------- #
def matches(event: Event, selection: dict[str, Any]) -> bool:
    """True when the event satisfies every field condition in the selection."""
    for key, expected in selection.items():
        name, _, mod = key.partition("|")
        actual = event.get(name)
        if actual is None or actual == "":
            return False
        options = expected if isinstance(expected, list) else [expected]
        if not any(_compare(actual, opt, mod or "equals") for opt in options):
            return False
    return True


def selects(rule: Rule, event: Event) -> bool:
    """True when the event matches the rule's selection and is not removed by its filter."""
    det = rule.detection
    if not matches(event, det["selection"]):
        return False
    return not ("filter" in det and matches(event, det["filter"]))


def _compare(actual: Any, expected: Any, mod: str) -> bool:
    if mod in {"gte", "lte"}:
        try:
            a, b = float(actual), float(expected)
        except (TypeError, ValueError):
            return False
        return a >= b if mod == "gte" else a <= b
    if mod == "re":
        return re.search(str(expected), str(actual)) is not None
    a, b = str(actual).lower(), str(expected).lower()
    if mod == "contains":
        return b in a
    if mod == "startswith":
        return a.startswith(b)
    if mod == "endswith":
        return a.endswith(b)
    return a == b


# --------------------------------------------------------------------------- #
# Running rules
# --------------------------------------------------------------------------- #
def run_rules(rules: list[Rule], events: list[Event]) -> list[Alert]:
    alerts: list[Alert] = []
    for rule in rules:
        scoped = [e for e in events if rule.logsource in ("any", e.source)]
        if rule.type == "match":
            alerts += [Alert(rule, [e]) for e in scoped if selects(rule, e)]
        elif rule.type == "threshold":
            alerts += _run_threshold(rule, scoped)
        else:
            alerts += _run_sequence(rule, scoped)
    alerts.sort(key=lambda a: (a.first_seen, a.last_seen))
    return alerts


def _group_key(event: Event, group_by: list[str]) -> tuple:
    return tuple(event.get(g, "") for g in group_by)


def _bursts(rule: Rule, events: list[Event]) -> list[tuple[tuple, list[Event], datetime]]:
    """Find groups of matching events that reach the threshold.

    Returns (group key, every event in the burst, time the threshold was reached).
    Events in one group are split into clusters wherever the gap between
    two events is longer than the window, so one long attack gives one alert.
    """
    th = rule.detection["threshold"]
    group_by = th["group_by"] if isinstance(th["group_by"], list) else [th["group_by"]]
    count, window = int(th["count"]), timedelta(seconds=int(th["window_seconds"]))

    groups: dict[tuple, list[Event]] = {}
    for e in events:
        if selects(rule, e):
            groups.setdefault(_group_key(e, group_by), []).append(e)

    found = []
    for key, evs in groups.items():
        clusters: list[list[Event]] = [[evs[0]]]
        for e in evs[1:]:
            if e.timestamp - clusters[-1][-1].timestamp > window:
                clusters.append([e])
            else:
                clusters[-1].append(e)
        for cluster in clusters:
            # Sliding window: does any span of `window` hold `count` events?
            start = 0
            for end, e in enumerate(cluster):
                while e.timestamp - cluster[start].timestamp > window:
                    start += 1
                if end - start + 1 >= count:
                    found.append((key, cluster, e.timestamp))
                    break
    return found


def _run_threshold(rule: Rule, events: list[Event]) -> list[Alert]:
    group_by = _as_list(rule.detection["threshold"]["group_by"])
    return [Alert(rule, cluster, dict(zip(group_by, key))) for key, cluster, _ in _bursts(rule, events)]


def _run_sequence(rule: Rule, events: list[Event]) -> list[Alert]:
    th = rule.detection["threshold"]
    group_by = _as_list(th["group_by"])
    follow_window = timedelta(seconds=int(rule.detection.get("followed_within_seconds", th["window_seconds"])))
    alerts = []
    for key, cluster, triggered_at in _bursts(rule, events):
        for e in events:
            if (
                triggered_at < e.timestamp <= cluster[-1].timestamp + follow_window
                and _group_key(e, group_by) == key
                and matches(e, rule.detection["followed_by"])
            ):
                alerts.append(Alert(rule, [*cluster, e], dict(zip(group_by, key))))
                break
    return alerts


ENCODED_ARG = re.compile(r"(?i)\s-e(?:nc(?:odedcommand)?|c)?\s+([A-Za-z0-9+/=]{16,})")


def decode_powershell(command_line: str) -> str:
    """Decode a PowerShell -EncodedCommand argument (Base64 of UTF-16LE text)."""
    m = ENCODED_ARG.search(command_line)
    if not m:
        return ""
    try:
        return base64.b64decode(m.group(1), validate=True).decode("utf-16-le").strip()
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return ""


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else [value]


def _hm(ts: datetime) -> str:
    return ts.strftime("%H:%M:%S")


def _short(text: str, n: int) -> str:
    return text if len(text) <= n else text[: n - 1] + "…"
