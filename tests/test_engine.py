import base64

import pytest

from socdetect.engine import RuleError, _load_rule, decode_powershell, matches, run_rules

from .conftest import make_event, make_rule

BRUTE = {"type": "threshold", "selection": {"action": "ssh_failed"},
         "threshold": {"group_by": ["src_ip"], "count": 5, "window_seconds": 300}}


@pytest.mark.parametrize("selection, expected", [
    ({"user": "ROOT"}, True),                       # equals is case-insensitive
    ({"user": ["admin", "root"]}, True),            # a list means OR
    ({"user": "admin"}, False),
    ({"message|contains": "password"}, True),
    ({"message|startswith": "failed"}, True),
    ({"message|endswith": "ssh2"}, True),
    ({"message|re": r"port \d+"}, True),
    ({"status|gte": 400}, True),
    ({"status|lte": 399}, False),
    ({"user": "root", "status|gte": 500}, False),   # every field must match (AND)
    ({"missing_field": "x"}, False),
])
def test_field_modifiers(selection, expected):
    ev = make_event(user="root", status=404, message="Failed password for root port 22 ssh2")
    assert matches(ev, selection) is expected


def test_threshold_fires_once_per_burst():
    events = [make_event(i * 10, action="ssh_failed", src_ip="203.0.113.45") for i in range(8)]
    alerts = run_rules([make_rule(BRUTE)], events)
    assert len(alerts) == 1
    assert len(alerts[0].evidence) == 8
    assert alerts[0].group == {"src_ip": "203.0.113.45"}


def test_threshold_not_reached():
    events = [make_event(i * 10, action="ssh_failed", src_ip="10.0.0.22") for i in range(4)]
    assert run_rules([make_rule(BRUTE)], events) == []


def test_threshold_respects_window():
    # 5 failures, but 2 minutes apart: never 5 inside 300 seconds.
    events = [make_event(i * 120, action="ssh_failed", src_ip="203.0.113.45") for i in range(5)]
    assert run_rules([make_rule(BRUTE)], events) == []


def test_threshold_groups_by_ip():
    events = [make_event(i, action="ssh_failed", src_ip=f"192.0.2.{i}") for i in range(10)]
    assert run_rules([make_rule(BRUTE)], events) == []


def test_sequence_needs_the_follow_up_event():
    rule = make_rule({**BRUTE, "type": "sequence", "followed_by": {"action": "ssh_success"}})
    failures = [make_event(i * 5, action="ssh_failed", src_ip="203.0.113.45") for i in range(6)]
    assert run_rules([rule], failures) == []

    other_ip = make_event(60, action="ssh_success", src_ip="10.0.0.5")
    assert run_rules([rule], [*failures, other_ip]) == []

    success = make_event(70, action="ssh_success", src_ip="203.0.113.45", user="webadmin")
    alerts = run_rules([rule], [*failures, success])
    assert len(alerts) == 1 and alerts[0].evidence[-1] is success
    assert "as webadmin" in alerts[0].summary()


def test_filter_removes_known_good_events():
    rule = make_rule({"type": "match", "selection": {"event_id": 4698},
                      "filter": {"subjectusername": "SYSTEM"}}, logsource="windows")
    events = [make_event(0, "windows", event_id=4698, subjectusername="SYSTEM"),
              make_event(1, "windows", event_id=4698, subjectusername="Administrator")]
    alerts = run_rules([rule], events)
    assert len(alerts) == 1 and alerts[0].evidence[0].get("subjectusername") == "Administrator"


def test_rules_only_see_their_log_source():
    rule = make_rule({"type": "match", "selection": {"action": "user_created"}}, logsource="linux")
    assert run_rules([rule], [make_event(0, "windows", action="user_created")]) == []


def test_decode_powershell():
    encoded = base64.b64encode("whoami /all".encode("utf-16-le")).decode()
    assert decode_powershell(f"powershell.exe -NoP -Enc {encoded}") == "whoami /all"
    assert decode_powershell(f"powershell.exe -EncodedCommand {encoded}") == "whoami /all"
    assert decode_powershell("powershell.exe -Command Get-Process") == ""


@pytest.mark.parametrize("body, message", [
    ("id: x\ntitle: x\nseverity: high\nlogsource: linux\nmitre: {tactic: a, technique_id: b, technique: c}\n",
     "missing required field 'detection'"),
    ("id: x\ntitle: x\nseverity: high\nlogsource: linux\nmitre: {tactic: a, technique_id: b, technique: c}\n"
     "detection: {type: match, selection: {user|fuzzy: x}}\n", "unknown modifier"),
    ("id: x\ntitle: x\nseverity: high\nlogsource: linux\nmitre: {tactic: a, technique_id: b, technique: c}\n"
     "detection: {type: match, selection: {user|re: '(unclosed'}}\n", "bad regex"),
    ("id: x\ntitle: x\nseverity: extreme\nlogsource: linux\nmitre: {tactic: a, technique_id: b, technique: c}\n"
     "detection: {type: match, selection: {user: x}}\n", "severity must be"),
    ("id: x\ntitle: x\nseverity: high\nlogsource: linux\nmitre: {tactic: a, technique_id: b, technique: c}\n"
     "detection: {type: threshold, selection: {user: x}}\n", "missing required field 'threshold'"),
])
def test_invalid_rules_are_rejected(tmp_path, body, message):
    f = tmp_path / "bad.yml"
    f.write_text(body)
    with pytest.raises(RuleError, match=message):
        _load_rule(f)
