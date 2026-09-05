# Security Scoring Framework

A lightweight, composite security assessment tool that combines **OS
hardening**, **network vulnerability scanning**, and **web application
testing** into a single weighted risk score — with ranked, prioritized
remediation recommendations across all three layers.

Built as the practical component of a research paper on unified
security scoring methodologies. Available as both a CLI tool and a
Flask web interface.

⚠️ **Only run this against systems you own or have explicit permission
to test.**

## Why this exists

Most security tools focus on a single layer — Lynis for OS hardening,
Nmap/Nessus for network services, ZAP/Burp for web apps. Real systems
have all three attack surfaces at once, and a critical finding in one
layer (e.g. a backdoored FTP service) matters more than several minor
findings in another. This tool aggregates all three into one score and
tells you **which layer to fix first**, rather than three separate,
disconnected reports.

## Contents

- [`docs/01-setup.md`](./docs/01-setup.md) — Installation and usage
- [`docs/02-os-hardening.md`](./docs/02-os-hardening.md) — OS hardening module results
- [`docs/03-network-scan.md`](./docs/03-network-scan.md) — Network vulnerability scan against Metasploitable 2
- [`docs/04-composite-scan.md`](./docs/04-composite-scan.md) — Full composite scan results and scoring breakdown
- [`docs/05-flask-ui.md`](./docs/05-flask-ui.md) — Flask web UI walkthrough

## Architecture

```
security-scorer/
├── main.py                  # CLI entry point
├── app.py                   # Flask web UI
├── modules/
│   ├── os_hardening.py      # Local config checks (SSH, firewall, updates, etc.)
│   ├── network_scan.py      # Nmap-based service scan + severity matching
│   ├── webapp_scan.py       # Header/cookie checks + basic SQLi/XSS heuristics
│   └── scoring.py           # Composite scoring + ranked recommendations
├── data/
│   └── vuln_severity.json   # Known-service severity reference table
├── templates/                # Flask HTML templates
├── static/                   # CSS
└── reports/                  # Saved JSON reports (CLI mode)
```

## How scoring works

Each layer returns a score out of 100 based on the proportion of
checks passed (weighted by severity for network/webapp). The composite
score combines all layers actually run, using configurable weights
(default: OS 30%, Network 35%, Web App 35%). Weights are re-normalized
if only some layers are selected.

All failed findings across every layer are merged into a single list
and sorted by severity (critical → high → medium → low), so the
highest-impact fix — regardless of which layer it came from — always
appears first.

## Installation

```bash
git clone https://github.com/Dhruv-parihar/security-scorer.git
cd security-scorer
pip install -r requirements.txt --break-system-packages
```

Requires `nmap` to be installed on the system for the network scan
module (`sudo apt install nmap`).

## Usage

### CLI

```bash
python3 main.py
```

Follow the menu to select which layers to run. A full JSON report is
saved to `reports/` after each run.

### Web UI

```bash
python3 app.py
```

Open `http://127.0.0.1:5000` in a browser, select layers and targets,
and view results with ranked recommendations.

## Validation

This framework was validated against a self-hosted lab environment
(Parrot Security OS attacking Metasploitable2 + DVWA) — see the
companion repo [`parrot-pentest-lab`](https://github.com/Dhruv-parihar/parrot-pentest-lab)
for the raw exploitation data this tool's severity table and scoring
logic were built from.

## Limitations

- The web app scanner uses simple reflected heuristics (payload
  reflection / error-message matching), not deep parameter fuzzing —
  it will not catch blind or second-order SQL injection.
- The network severity table is a curated reference list, not a live
  CVE feed.
- OS hardening checks assume a Debian/Ubuntu-based target.

## Future Work

- Live CVE feed integration (NVD API) instead of a static severity table
- Multi-distro support for OS hardening checks
- Authenticated web app scanning (session/cookie-aware)
- Historical trend tracking across repeated scans
