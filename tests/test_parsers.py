import json

import pytest

from socdetect.parsers import detect_format, parse_linux_auth, parse_web_access, parse_windows_jsonl


def test_windows_failed_logon_is_normalized(tmp_path):
    f = tmp_path / "sec.jsonl"
    f.write_text(json.dumps({"TimeCreated": "2026-10-14T10:20:02Z", "EventID": 4625, "Computer": "WS01",
                             "TargetUserName": "Administrator", "IpAddress": "198.51.100.23"}) + "\n")
    ev = parse_windows_jsonl(f).events[0]
    assert ev.get("event_id") == 4625
    assert ev.get("action") == "logon_failed"
    assert ev.get("user") == "Administrator"
    assert ev.get("src_ip") == "198.51.100.23"
    assert ev.get("host") == "WS01"


def test_windows_4732_maps_group_and_member(tmp_path):
    f = tmp_path / "sec.jsonl"
    f.write_text(json.dumps({"TimeCreated": "2026-10-14T10:25:30Z", "EventID": 4732,
                             "TargetUserName": "Administrators", "MemberName": "svc_backup"}) + "\n")
    ev = parse_windows_jsonl(f).events[0]
    assert ev.get("group_name") == "Administrators"
    assert ev.get("user") == "svc_backup"


def test_windows_bad_lines_are_skipped(tmp_path):
    f = tmp_path / "sec.jsonl"
    f.write_text('not json\n{"EventID": 4625}\n')
    res = parse_windows_jsonl(f)
    assert res.events == [] and res.skipped == 2


@pytest.mark.parametrize("line, action, user, ip", [
    ("Oct 14 09:10:05 web01 sshd[2001]: Failed password for root from 203.0.113.45 port 40000 ssh2",
     "ssh_failed", "root", "203.0.113.45"),
    ("Oct 14 09:10:12 web01 sshd[2002]: Failed password for invalid user admin from 203.0.113.45 port 1 ssh2",
     "ssh_failed", "admin", "203.0.113.45"),
    ("Oct 14 09:11:52 web01 sshd[2101]: Accepted password for webadmin from 203.0.113.45 port 2 ssh2",
     "ssh_success", "webadmin", "203.0.113.45"),
])
def test_linux_ssh_lines(tmp_path, line, action, user, ip):
    f = tmp_path / "auth.log"
    f.write_text(line + "\n")
    ev = parse_linux_auth(f, 2026).events[0]
    assert (ev.get("action"), ev.get("user"), ev.get("src_ip")) == (action, user, ip)
    assert ev.timestamp.year == 2026


def test_linux_group_change(tmp_path):
    f = tmp_path / "auth.log"
    f.write_text("Oct 14 09:13:21 web01 usermod[2161]: add 'sysupdate' to group 'sudo'\n")
    ev = parse_linux_auth(f, 2026).events[0]
    assert ev.get("action") == "member_added_to_group"
    assert ev.get("user") == "sysupdate" and ev.get("group_name") == "sudo"


def test_web_line_is_parsed_and_url_decoded(tmp_path):
    f = tmp_path / "web01_access.log"
    f.write_text('203.0.113.45 - - [14/Oct/2026:09:05:27 +0000] "GET /products?id=7%20UNION%20SELECT%201 '
                 'HTTP/1.1" 500 512 "-" "sqlmap/1.8"\n')
    ev = parse_web_access(f).events[0]
    assert ev.get("host") == "web01"
    assert ev.get("status") == 500
    assert ev.get("decoded_path") == "/products?id=7 UNION SELECT 1"


def test_detect_format(root):
    logs = root / "sample_logs"
    assert detect_format(logs / "ws01_security.jsonl") == "windows"
    assert detect_format(logs / "web01_auth.log") == "linux"
    assert detect_format(logs / "web01_access.log") == "web"
