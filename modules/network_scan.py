"""
Network Vulnerability Scan Module
----------------------------------
Runs an Nmap service/version scan against a target and scores exposed
services against a known-severity reference table.
"""

import json
import os
import re
import subprocess

DATA_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "vuln_severity.json")

from modules.scoring_config import NETWORK_SEVERITY_WEIGHT as SEVERITY_WEIGHT


def _load_severity_data():
    with open(DATA_PATH, "r") as f:
        return json.load(f)


def _match_service(service_string, severity_data):
    """Find the best matching entry for a given service/version string."""
    for key in severity_data:
        if key != "default" and key.lower() in service_string.lower():
            return key, severity_data[key]
    return "default", severity_data["default"]


def run(target_ip, nmap_binary="nmap"):
    """
    Run an Nmap -sV scan against target_ip and score the results.
    Requires nmap to be installed and reachable on the system PATH.
    """
    severity_data = _load_severity_data()
    findings = []

    try:
        result = subprocess.run(
            [nmap_binary, "-sV", target_ip],
            capture_output=True, text=True, timeout=120
        )
        output = result.stdout
    except FileNotFoundError:
        return {
            "layer": "network",
            "score": None,
            "findings": [],
            "error": "nmap not found — install nmap and ensure it is on PATH",
        }
    except subprocess.TimeoutExpired:
        return {
            "layer": "network",
            "score": None,
            "findings": [],
            "error": "Nmap scan timed out",
        }

    if result.returncode != 0:
        return {'layer': 'network', 'score': None, 'findings': [],
                'error': f'Nmap exited with code {result.returncode}',
                'raw_output': output}

    # Parse versioned and versionless open service lines without crossing lines.
    port_line = re.compile(
        r"^(\d+)/tcp[ \t]+open[ \t]+(\S+)(?:[ \t]+([^\r\n]*))?$", re.MULTILINE
    )
    matches = port_line.findall(output)

    total_penalty = 0
    for port, service_name, version_string in matches:
        version_string = version_string or ''
        full_string = f"{service_name} {version_string}".strip()
        matched_key, info = _match_service(full_string, severity_data)
        weight = SEVERITY_WEIGHT.get(info["severity"], 2)
        total_penalty += weight
        findings.append({
            "port": port,
            "service": service_name,
            "version": version_string,
            "matched_signature": matched_key,
            "severity": info["severity"],
            "note": info["note"],
            "recommendation": info["recommendation"],
        })

    score = max(0, 100 - total_penalty)

    return {
        "layer": "network",
        "score": score,
        "open_ports": len(matches),
        "findings": findings,
        "raw_output": output,
    }


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    print(json.dumps(run(target), indent=2))
