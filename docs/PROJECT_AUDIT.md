# PROJECT AUDIT — Security Scoring Framework
**Audit date:** 2026-09-18
**Auditor:** Claude (implementation agent)
**Baseline commit:** 6edab0a
**Audit branch:** phase/0-audit

---

## 1. Repository Structure

```
security-scorer/
├── .agent/                     # Agent coordination (new, this audit)
│   ├── AGENT_PROTOCOL.md
│   ├── DECISIONS.md
│   └── PROJECT_STATE.md
├── data/
│   └── vuln_severity.json      # Static severity reference (10 entries + default)
├── docs/
│   ├── 01-setup.md
│   ├── 02-os-hardening.md
│   ├── 03-network-scan.md
│   ├── 04-composite-scan.md
│   ├── 05-flask-ui.md
│   └── PROJECT_AUDIT.md        # This file
├── modules/
│   ├── __init__.py             # Empty
│   ├── os_hardening.py
│   ├── network_scan.py
│   ├── webapp_scan.py
│   └── scoring.py
├── screenshots/                # Documentation screenshots only
├── static/style.css
├── templates/
│   ├── index.html
│   └── results.html
├── .gitignore
├── README.md
├── app.py                      # Flask web UI
├── main.py                     # CLI entry point
└── requirements.txt            # flask>=3.0.0, requests>=2.31.0
```

---

## 2. Current Architecture

```
User Input (CLI / Flask form)
         ↓
    main.py / app.py
         ↓
  ┌──────┴──────────────┐
  ↓         ↓           ↓
os_hardening  network_scan  webapp_scan
  ↓         ↓           ↓
  └──────┬──────────────┘
         ↓
     scoring.py
     (composite score + ranked recommendations)
         ↓
  JSON report (ephemeral, gitignored)
  + Flask HTML results page
```

**Data flow:** Scanner → Dict result → Scoring → Dict composite → CLI print / HTML render / JSON file

---

## 3. Module-by-Module Audit

### 3.1 os_hardening.py
- **Checks:** 6 (ssh_root_login, password_max_days, firewall_active, world_writable_files, automatic_updates, guest_account_disabled)
- **Score calculation:** `round((passed_count / total_checks) * 100)` — simple proportion, no severity weighting within module
- **Finding format:** `{id, description, passed: bool, severity, recommendation}`
- **Issues:**
  - All checks are Linux/Debian-specific. Running on Windows gives 33/100 due to missing files, not actual insecurity — research validity bug.
  - `passed: bool` only — no NOT_APPLICABLE, NOT_TESTED, ERROR, UNKNOWN states.
  - `check_guest_account_disabled` returns PASS when lightdm.conf is absent (Linux default) — logically correct for Linux, but misleading on non-lightdm systems.
  - `check_world_writable_files` runs `find /` which can be slow and noisy.
  - No OS detection — same checks run regardless of platform.
  - Score is not severity-weighted (a failed HIGH check counts same as failed LOW).

### 3.2 network_scan.py
- **Method:** Nmap -sV, regex-parsed, matched against static JSON table.
- **Severity table:** 10 named entries + 1 default. Covers vsftpd, UnrealIRCd, OpenSSH 4.7p1, telnetd, ProFTPD 1.3.1, Samba 3.X, MySQL 5.0, VNC, Apache 2.2, default.
- **Score:** `max(0, 100 - sum(penalties))` — penalty per matched service.
- **Finding format:** `{port, service, version, matched_signature, severity, note, recommendation}` — no `passed` field (inconsistency with other modules).
- **Issues:**
  - Static severity table is not a CVE feed — will miss newly disclosed vulnerabilities.
  - Penalty accumulation means 3+ critical services → score = 0 with no differentiation.
  - No data source versioning — not reproducible when table is updated.
  - `raw_output` stored in result dict — useful for audit but large and unstructured.
  - No authorization check before scanning.
  - No UDP scan — misses DNS, SNMP, NTP exposure.
  - Finding format inconsistency: no `passed` field, uses `note` not `description`.
  - `SEVERITY_WEIGHT` defined locally (not shared with webapp_scan or scoring).

### 3.3 webapp_scan.py
- **Checks:** 4 headers (CSP, X-Frame-Options, HSTS, X-Content-Type-Options), cookie flags (HttpOnly, Secure per cookie), reflected SQLi heuristic, reflected XSS heuristic.
- **Score:** `max(0, 100 - sum(penalties for failed findings))`
- **Finding format:** `{id, description, passed: bool, severity, recommendation}` — consistent with os_hardening.
- **Issues:**
  - Injection probes use basic error-string matching — DVWA at Low security did not trigger (confirmed in real testing).
  - `_check_sqli` and `_check_xss` only probe URL query parameters — form fields, JSON bodies, headers not tested.
  - `_inject_param` returns None if no query params → checks silently skipped, not marked NOT_APPLICABLE.
  - `has_httponly` detection uses non-standard attribute check — unreliable across cookie implementations.
  - No TLS/certificate checks.
  - No authenticated scanning.
  - No rate limiting or request throttling.
  - `SEVERITY_WEIGHT` defined locally (duplicate of network_scan.py's dict, different values).

### 3.4 scoring.py
- **Method:** Weighted sum, re-normalized to present layers.
- **Weights:** os_hardening=0.30, network=0.35, webapp=0.35 (expert judgment, no empirical basis).
- **Weakest layer:** `min(layer_summary, key=score)` — correct.
- **Recommendations:** Cross-layer merge, sorted by `SEVERITY_RANK`.
- **Issues:**
  - `compute_composite` takes `layer_results` dict but does not validate structure.
  - No sensitivity analysis — weights are fixed with no alternative models.
  - `finding.get("passed", True)` default is True — silently ignores findings with no `passed` key (network findings).
  - Network findings are therefore EXCLUDED from composite recommendations — critical bug for research validity.
  - No confidence score on composite.

### 3.5 main.py / app.py
- **main.py:** Interactive CLI, menu-driven, saves JSON report to `reports/` dir.
- **app.py:** Flask, debug=True hardcoded — not production-safe.
- **Issues:**
  - No authorization record check before active scanning.
  - No target logging — scans leave no audit trail.
  - `reports/` is gitignored — ephemeral, no persistent research storage.
  - Flask runs with `debug=True` — must be changed before any deployment.
  - No input validation on IP/URL fields (Flask form).

---

## 4. Dependencies

| Package | Version constraint | Used for |
|---------|-------------------|----------|
| flask | >=3.0.0 | Web UI |
| requests | >=2.31.0 | Web app scanning |
| nmap (system) | any | Network scanning (not in requirements.txt) |

**Missing from requirements.txt:** nmap system binary (undocumented dependency).
**No dev/test dependencies declared.**

---

## 5. Tests

**No test suite exists.** Zero test files. No pytest, unittest, or equivalent.

Manual validation performed during this audit:
```
python3 -c "from modules import os_hardening, network_scan, webapp_scan, scoring; ..."
```
Results:
- Imports: PASS
- os_hardening.run(): PASS (6 findings, score computed)
- scoring.compute_composite(fake_data): PASS (composite=32, weakest=network)
- webapp_scan import via modules: PASS

---

## 6. Research Validity Issues (Priority Order)

| # | Issue | Impact | Module |
|---|-------|--------|--------|
| R1 | Network findings excluded from composite recommendations | HIGH | scoring.py |
| R2 | OS checks give FAIL on Windows for Linux-specific configs | HIGH | os_hardening.py |
| R3 | No NOT_APPLICABLE state — unsupported checks silently pass | HIGH | all |
| R4 | No authorization check before active scanning | HIGH | main.py, app.py |
| R5 | Scoring weights have no empirical basis, no sensitivity analysis | MEDIUM | scoring.py |
| R6 | Static severity table, no versioning | MEDIUM | network_scan.py |
| R7 | No persistent research database — reports ephemeral | MEDIUM | main.py |
| R8 | SQLi/XSS heuristics ineffective (confirmed in real testing) | MEDIUM | webapp_scan.py |
| R9 | SEVERITY_WEIGHT defined independently in 2 modules, inconsistently | LOW | network_scan.py, webapp_scan.py |
| R10 | No test suite | LOW | — |

---

## 7. Security Issues in the Testing Kit Itself

- `debug=True` in app.py exposes Werkzeug debugger — remote code execution risk if exposed
- No input sanitization on network target IP or web target URL in Flask form
- No rate limiting on scan endpoint — trivial to abuse
- Shell injection possible in `_run()` via `shell=True` if OS check commands are ever made configurable

---

## 8. Current Research Capabilities

The tool can currently produce:
- Per-layer scores (OS, network, web) for a single target per run
- A composite score with weakest-layer identification
- A ranked recommendation list (with the noted R1 bug excluding network findings)
- Ephemeral JSON reports

It cannot currently:
- Store findings in a persistent research database
- Track findings across multiple assessments of the same target
- Enforce target authorization before scanning
- Distinguish NOT_APPLICABLE from FAIL
- Perform sensitivity analysis on weights
- Produce prevalence or pattern statistics across multiple targets

---

## 9. Proposed Migration Plan

### Immediate (fix before any data collection)
1. Fix R1: network findings must flow into composite recommendations
2. Fix R4: add authorization record check (OWNED/LAB/EXPLICITLY_AUTHORIZED/CONSENTED)
3. Fix R2/R3: add OS detection + NOT_APPLICABLE state

### Phase 1 (data model, before collecting data)
4. Design and implement SQLite research database (targets, assessments, findings, remediations)
5. Scanner output → structured findings → database write pipeline
6. Replace ephemeral JSON reports with DB-backed persistence

### Phase 2 (expand coverage)
7. Add sensitivity analysis to scoring.py
8. Add finding taxonomy (PATCHING, AUTHENTICATION, etc.)
9. Expand OS checks with severity weighting
10. Add TLS/certificate checks to webapp_scan

### Phase 3 (research analysis)
11. Prevalence, co-occurrence, longitudinal analysis modules
12. Research dashboard

---

## 10. Baseline Git State

```
Branch: phase/0-audit
Baseline: main @ 6edab0a
Commits on main:
  6edab0a Add screenshots and documentation for all modules
  93b1ce0 Add watermark with author credit and GitHub link
  f0b5e87 Add .gitignore, remove pycache and local reports
  4d9a72a Security Scoring Framework: initial implementation
```
