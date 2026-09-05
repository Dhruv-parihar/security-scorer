#!/usr/bin/env python3
"""
Security Scorer — CLI
------------------------
A menu-driven tool that runs OS hardening, network vulnerability, and
web application checks, then produces a composite risk score with
ranked remediation recommendations.

Usage:
    python3 main.py
"""

import json
import os
import sys
from datetime import datetime

from modules import os_hardening, network_scan, webapp_scan, scoring

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")


def print_header(title):
    print("\n" + "=" * 60)
    print(title.center(60))
    print("=" * 60)


def print_findings(findings):
    for f in findings:
        status = "PASS" if f.get("passed") else "FAIL"
        sev = f.get("severity", "-").upper()
        desc = f.get("description") or f.get("note") or f.get("id")
        print(f"  [{status:4}] [{sev:8}] {desc}")


def run_os_hardening():
    print_header("OS HARDENING SCAN")
    result = os_hardening.run()
    print(f"Score: {result['score']}/100\n")
    print_findings(result["findings"])
    return result


def run_network(target):
    print_header("NETWORK VULNERABILITY SCAN")
    print(f"Target: {target}\nScanning... (this may take a moment)\n")
    result = network_scan.run(target)
    if result.get("error"):
        print(f"Error: {result['error']}")
        return None
    print(f"Score: {result['score']}/100 ({result.get('open_ports', 0)} open ports found)\n")
    print_findings(result["findings"])
    return result


def run_webapp(target):
    print_header("WEB APPLICATION SCAN")
    print(f"Target: {target}\n")
    result = webapp_scan.run(target)
    if result.get("error"):
        print(f"Error: {result['error']}")
        return None
    print(f"Score: {result['score']}/100\n")
    print_findings(result["findings"])
    return result


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
    os.makedirs(REPORTS_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = os.path.join(REPORTS_DIR, f"report_{timestamp}.json")
    with open(path, "w") as f:
        json.dump({"layers": layer_results, "composite": composite}, f, indent=2)
    print(f"\nFull report saved to: {path}")


def main():
    print_header("SECURITY SCORING FRAMEWORK")
    print("1. OS Hardening only")
    print("2. Network Vulnerability Scan only")
    print("3. Web Application Scan only")
    print("4. All layers (composite score)")
    choice = input("\nSelect an option: ").strip()

    layer_results = {}

    if choice == "1":
        layer_results["os_hardening"] = run_os_hardening()
    elif choice == "2":
        target = input("Target IP: ").strip()
        layer_results["network"] = run_network(target)
    elif choice == "3":
        target = input("Target URL (e.g. http://192.168.56.102/dvwa/vulnerabilities/sqli/?id=1): ").strip()
        layer_results["webapp"] = run_webapp(target)
    elif choice == "4":
        layer_results["os_hardening"] = run_os_hardening()
        net_target = input("\nTarget IP for network scan: ").strip()
        layer_results["network"] = run_network(net_target)
        web_target = input("\nTarget URL for web app scan: ").strip()
        layer_results["webapp"] = run_webapp(web_target)
    else:
        print("Invalid choice.")
        sys.exit(1)

    composite = scoring.compute_composite(layer_results)
    print_composite(composite)
    save_report(layer_results, composite)


if __name__ == "__main__":
    main()
