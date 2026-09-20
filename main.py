#!/usr/bin/env python3
"""
Security Scorer — CLI
------------------------
A menu-driven tool that runs OS hardening, network vulnerability, and
web application checks, then produces a composite risk score with
ranked remediation recommendations.

Phase 3: End-to-end research pipeline integration.
- Active network/web scans require an explicit authorization record in
  the research database before the scanner is invoked.
- Successful assessments are persisted to the research database via
  db/adapters.py.
- Existing JSON/report output and CLI behavior are preserved.

Usage:
    python3 main.py
"""

import json
import os
import sys
from datetime import datetime

from modules import os_hardening, network_scan, webapp_scan, scoring
from modules.authorization import check_authorization, AuthorizationError
from db.schema import initialize, seed_taxonomy
from db.adapters import store_assessment_results
from db.repository import create_target, list_targets

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
DB_PATH = os.path.join(os.path.dirname(__file__), "research.db")


# ── DB helpers ────────────────────────────────────────────────────────────────

def get_db():
    """Return an initialized DB connection. Seeds taxonomy if first run."""
    conn, _ = initialize(DB_PATH)
    seed_taxonomy(conn)
    return conn


def _resolve_target_id(conn, identifier):
    """
    Resolve a target identifier to a target_id from the DB.
    Returns (target_id, None) on success, (None, error_message) on failure.
    Never infers authorization.
    """
    authorized, target_id, message = check_authorization(conn, identifier)
    if not authorized:
        return None, message
    return target_id, None


def _persist(conn, target_id, layer_results, composite):
    """
    Persist assessment results to the research database.
    Swallows non-critical DB errors so a DB failure never breaks the
    existing CLI output — but prints a warning.
    """
    try:
        assessment_id = store_assessment_results(
            conn, target_id, layer_results, composite
        )
        print(f"\n[DB] Assessment persisted: {assessment_id[:8]}...")
        return assessment_id
    except Exception as e:
        print(f"\n[DB WARNING] Could not persist assessment: {e}")
        return None


# ── Printers ──────────────────────────────────────────────────────────────────

def print_header(title):
    print("\n" + "=" * 60)
    print(title.center(60))
    print("=" * 60)


def print_findings(findings):
    for f in findings:
        # Handle PASS/FAIL/NOT_APPLICABLE/None
        status_val = f.get("status") or ("PASS" if f.get("passed") else "FAIL")
        sev = (f.get("severity") or "-").upper()
        desc = f.get("description") or f.get("note") or f.get("id")
        print(f"  [{status_val:15}] [{sev:8}] {desc}")


def print_composite(composite):
    print_header("COMPOSITE RESULT")
    print(f"Composite Score: {composite['composite_score']}/100\n")
    for layer, info in composite["layers"].items():
        print(f"  {layer:15} score={info['score']:>3}  weight={info['weight_used']}")
    print(f"\nWeakest layer: {composite['weakest_layer']} — fix this first.\n")
    print("Top Recommendations (ranked by severity):")
    for i, rec in enumerate(composite["recommendations"][:10], 1):
        print(f"  {i}. [{rec['severity'].upper():8}] ({rec['layer']}) {rec['recommendation']}")


def save_report(layer_results, composite):
    """Save JSON report — preserves existing output format."""
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(REPORTS_DIR, f"report_{timestamp}.json")
    with open(path, "w") as f:
        json.dump({"layers": layer_results, "composite": composite}, f, indent=2)
    print(f"\nFull report saved to: {path}")
    return path


# ── Scanners ──────────────────────────────────────────────────────────────────

def run_os_hardening():
    """OS hardening — no network target, no authorization check required."""
    print_header("OS HARDENING SCAN")
    result = os_hardening.run()
    print(f"Score: {result['score']}/100  "
          f"(applicable: {result.get('applicable_checks', '?')}, "
          f"n/a: {result.get('not_applicable_checks', 0)})\n")
    print_findings(result["findings"])
    return result


def run_network(conn, target):
    """Network scan — requires authorization record."""
    print_header("NETWORK VULNERABILITY SCAN")
    target_id, error = _resolve_target_id(conn, target)
    if error:
        print(f"\n[BLOCKED] {error}")
        print("  → Add a target record with valid authorization before scanning.")
        return None, None
    print(f"Target: {target}  [authorized]\nScanning... (this may take a moment)\n")
    result = network_scan.run(target)
    if result.get("error"):
        print(f"Error: {result['error']}")
        return None, target_id
    print(f"Score: {result['score']}/100 ({result.get('open_ports', 0)} open ports found)\n")
    print_findings(result["findings"])
    return result, target_id


def run_webapp(conn, target):
    """Web scan — requires authorization record."""
    print_header("WEB APPLICATION SCAN")
    target_id, error = _resolve_target_id(conn, target)
    if error:
        print(f"\n[BLOCKED] {error}")
        print("  → Add a target record with valid authorization before scanning.")
        return None, None
    print(f"Target: {target}  [authorized]\n")
    result = webapp_scan.run(target)
    if result.get("error"):
        print(f"Error: {result['error']}")
        return None, target_id
    print(f"Score: {result['score']}/100\n")
    print_findings(result["findings"])
    return result, target_id


# ── Target management ─────────────────────────────────────────────────────────

def manage_targets(conn):
    """Sub-menu for listing and creating authorized targets."""
    print_header("TARGET MANAGEMENT")
    targets = list_targets(conn)
    if targets:
        print(f"{'Alias':40} {'Type':12} {'Auth':25} {'OS'}")
        print("-" * 90)
        for t in targets:
            print(f"{t['target_alias'][:40]:40} {t['target_type'][:12]:12} "
                  f"{t['authorization_status']:25} {t['os_family'] or '-'}")
    else:
        print("No targets registered yet.")

    print("\nOptions:")
    print("  a) Add a new target")
    print("  b) Back to main menu")
    sub = input("\nChoice: ").strip().lower()

    if sub == "a":
        alias = input("Target alias (e.g. IP, hostname, URL — used for auth lookup): ").strip()
        ttype = input("Type [lab_vm/server/workstation/web_app/network_device]: ").strip() or "lab_vm"
        env   = input("Environment [lab/owned/authorized/consented]: ").strip() or "lab"
        auth  = input("Authorization status [OWNED/LAB/EXPLICITLY_AUTHORIZED/CONSENTED_RESEARCH]: ").strip() or "LAB"
        os_f  = input("OS family [linux/windows/macos/unknown]: ").strip() or "unknown"
        os_n  = input("OS name (optional): ").strip() or None
        ref   = input("Authorization reference (doc/ticket, optional): ").strip() or None
        try:
            tid = create_target(conn, alias=alias, target_type=ttype,
                                environment=env, authorization_status=auth,
                                os_family=os_f, os_name=os_n,
                                authorization_ref=ref)
            print(f"\n[OK] Target created: {tid[:8]}... alias='{alias}'")
        except Exception as e:
            print(f"\n[ERROR] {e}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    conn = get_db()
    print_header("SECURITY SCORING FRAMEWORK")
    print("1. OS Hardening only")
    print("2. Network Vulnerability Scan only")
    print("3. Web Application Scan only")
    print("4. All layers (composite score)")
    print("5. Manage authorized targets")
    choice = input("\nSelect an option: ").strip()

    layer_results = {}
    target_id = None

    if choice == "1":
        layer_results["os_hardening"] = run_os_hardening()

    elif choice == "2":
        target = input("Target IP: ").strip()
        net_result, target_id = run_network(conn, target)
        if net_result:
            layer_results["network"] = net_result

    elif choice == "3":
        target = input("Target URL: ").strip()
        web_result, target_id = run_webapp(conn, target)
        if web_result:
            layer_results["webapp"] = web_result

    elif choice == "4":
        layer_results["os_hardening"] = run_os_hardening()
        net_target = input("\nTarget IP for network scan: ").strip()
        net_result, net_tid = run_network(conn, net_target)
        if net_result:
            layer_results["network"] = net_result
            target_id = net_tid
        web_target = input("\nTarget URL for web app scan: ").strip()
        web_result, web_tid = run_webapp(conn, web_target)
        if web_result:
            layer_results["webapp"] = web_result
            if not target_id:
                target_id = web_tid

    elif choice == "5":
        manage_targets(conn)
        conn.close()
        return

    else:
        print("Invalid choice.")
        conn.close()
        sys.exit(1)

    if not layer_results:
        print("\nNo scan results to report.")
        conn.close()
        return

    composite = scoring.compute_composite(layer_results)
    print_composite(composite)
    save_report(layer_results, composite)

    # Persist to research DB if we have a target_id
    if target_id:
        _persist(conn, target_id, layer_results, composite)
    elif any(k in layer_results for k in ("network", "webapp")):
        print("\n[DB] No target_id resolved — results not persisted to research DB.")

    conn.close()


if __name__ == "__main__":
    main()
