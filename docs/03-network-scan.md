# Network Vulnerability Scan

## What it does
Runs an `nmap -sV` service/version scan against a target IP and scores
each detected service against a curated severity reference table
(`data/vuln_severity.json`). Each matched service deducts points based
on its severity (critical = -40, high = -25, medium = -10, low = -2).

## Target
Tested against **Metasploitable 2** — a deliberately vulnerable Ubuntu
VM used as the lab target.

## Usage (CLI)

```bash
python3 main.py
# Select option 2
# Enter target IP: 192.168.56.102
```

## Key findings against Metasploitable 2

| Port | Service | Severity | Finding |
|------|---------|----------|---------|
| 21 | vsftpd 2.3.4 | Critical | Known backdoored version (CVE-2011-2523) |
| 6667 | UnrealIRCd | Critical | Historically shipped with a backdoored download |
| 22 | OpenSSH 4.7p1 | High | Very outdated release, multiple known CVEs |
| 23 | Telnet | High | Transmits credentials in plaintext |
| 139/445 | Samba 3.X | High | Multiple known RCE vulnerabilities |
| 2121 | ProFTPD 1.3.1 | High | Known remote code execution CVEs |
| 80 | Apache 2.2 | Medium | End-of-life, missing modern security patches |
| 3306 | MySQL 5.0 | Medium | End-of-life, no longer receives security patches |
| 5900 | VNC | Medium | Often configured with weak or no authentication |

**Network Score: 0/100** — 22 open ports, 2 critical backdoors, multiple
high-severity outdated services.

## Screenshots

| | |
|---|---|
| ![Network scan results CLI](../screenshots/03-cli-full-composite/04-network-scan-result.png) | Full network scan output against Metasploitable 2, showing all 22 open ports with severity classifications |
