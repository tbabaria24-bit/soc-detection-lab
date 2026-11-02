"""End-to-end test: the sample attack scenario must produce exactly the expected detections."""

import json

from socdetect.__main__ import main
from socdetect.engine import load_rules, run_rules
from socdetect.parsers import load_logs

EXPECTED = {
    "web_scanning_404_burst": 1,
    "web_sqli_attempt": 3,
    "linux_ssh_bruteforce": 1,
    "linux_ssh_login_after_bruteforce": 1,
    "linux_user_created": 1,
    "linux_user_added_to_sudo": 1,
    "win_bruteforce": 1,
    "win_logon_after_bruteforce": 1,
    "win_encoded_powershell": 1,
    "win_powershell_download_cradle": 1,
    "win_user_created": 1,
    "win_added_to_admin_group": 1,
    "win_scheduled_task_created": 1,
    "win_run_key_persistence": 1,
    "win_security_log_cleared": 1,
}
ATTACKERS = {"203.0.113.45", "198.51.100.23"}


def _alerts(root):
    rules = load_rules(root / "rules")
    events, stats = load_logs([root / "sample_logs"], 2026)
    return rules, run_rules(rules, events), stats


def test_every_rule_fires_as_expected(root):
    rules, alerts, stats = _alerts(root)
    assert stats["skipped_lines"] == 0
    counts = {}
    for a in alerts:
        counts[a.rule.id] = counts.get(a.rule.id, 0) + 1
    assert counts == EXPECTED
    assert {r.id for r in rules} == set(EXPECTED)  # every rule is covered by the scenario


def test_no_false_positives_on_normal_activity(root):
    """Benign events (typo'd passwords, deploys, Windows' own tasks) must not raise alerts."""
    _, alerts, _ = _alerts(root)
    for a in alerts:
        ips = {e.get("src_ip") for e in a.evidence if e.get("src_ip")} - {"127.0.0.1"}
        users = {e.get("user") for e in a.evidence}
        assert ips <= ATTACKERS, f"{a.rule.id} fired on non-attacker IPs {ips}"
        assert not users & {"jlee", "jsmith", "deploy"}, f"{a.rule.id} fired on a normal user"


def test_cli_writes_all_reports(root, tmp_path):
    out = tmp_path / "reports"
    assert main(["analyze", str(root / "sample_logs"), "--year", "2026", "--out", str(out)]) == 0
    alerts = json.loads((out / "alerts.json").read_text())
    assert len(alerts) == sum(EXPECTED.values())
    report = (out / "incident_report.md").read_text()
    assert "Successful SSH login after brute force" in report
    assert "whoami /all" in report  # encoded PowerShell is decoded in the report
    layer = json.loads((out / "attack_navigator_layer.json").read_text())
    assert {t["techniqueID"] for t in layer["techniques"]} >= {"T1078", "T1110.001", "T1059.001"}


def test_cli_fail_on_and_min_severity(root, tmp_path):
    args = ["analyze", str(root / "sample_logs"), "--year", "2026", "--out", str(tmp_path)]
    assert main([*args, "--fail-on", "critical"]) == 1
    assert main([*args, "--min-severity", "critical"]) == 0
    assert len(json.loads((tmp_path / "alerts.json").read_text())) == 2


def test_cli_validate(root):
    assert main(["--rules", str(root / "rules"), "validate"]) == 0
