"""
OS Hardening Module
--------------------
Runs a set of local configuration checks (inspired by CIS Benchmark
categories) and returns a score out of 100 plus a list of findings.

Each check returns:
    {
        "id": str,
        "description": str,
        "passed": bool,
        "severity": "low" | "medium" | "high" | "critical",
        "recommendation": str
    }
"""

import subprocess
import os


def _run(cmd):
    """Run a shell command and return stdout, or '' on failure."""
    try:
        return subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        ).stdout.strip()
    except Exception:
        return ""


def check_ssh_root_login():
    content = _run("cat /etc/ssh/sshd_config 2>/dev/null")
    passed = "PermitRootLogin no" in content
    return {
        "id": "ssh_root_login",
        "description": "SSH root login is disabled",
        "passed": passed,
        "severity": "high",
        "recommendation": "Set 'PermitRootLogin no' in /etc/ssh/sshd_config",
    }


def check_password_max_days():
    content = _run("grep PASS_MAX_DAYS /etc/login.defs 2>/dev/null")
    passed = False
    if content:
        try:
            days = int(content.split()[-1])
            passed = 0 < days <= 90
        except ValueError:
            passed = False
    return {
        "id": "password_max_days",
        "description": "Password expiration is set to 90 days or fewer",
        "passed": passed,
        "severity": "medium",
        "recommendation": "Set PASS_MAX_DAYS to 90 or fewer in /etc/login.defs",
    }


def check_firewall_active():
    ufw = _run("sudo ufw status 2>/dev/null")
    iptables = _run("sudo iptables -L 2>/dev/null")
    passed = "Status: active" in ufw or "Chain INPUT" in iptables
    return {
        "id": "firewall_active",
        "description": "A firewall (ufw/iptables) is active",
        "passed": passed,
        "severity": "high",
        "recommendation": "Enable ufw ('sudo ufw enable') or configure iptables rules",
    }


def check_world_writable_files():
    result = _run(
        "find / -xdev -type f -perm -0002 2>/dev/null | head -n 5"
    )
    passed = result == ""
    return {
        "id": "world_writable_files",
        "description": "No world-writable files in common directories",
        "passed": passed,
        "severity": "medium",
        "recommendation": "Review and remove world-writable permissions "
        "('chmod o-w <file>') on flagged files",
    }


def check_automatic_updates():
    exists = os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades")
    content = _run("cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null")
    passed = exists and "1" in content
    return {
        "id": "automatic_updates",
        "description": "Automatic security updates are enabled",
        "passed": passed,
        "severity": "medium",
        "recommendation": "Install and enable 'unattended-upgrades'",
    }


def check_guest_account_disabled():
    content = _run("cat /etc/lightdm/lightdm.conf 2>/dev/null")
    passed = "allow-guest=false" in content or content == ""
    return {
        "id": "guest_account_disabled",
        "description": "Guest login account is disabled",
        "passed": passed,
        "severity": "low",
        "recommendation": "Set 'allow-guest=false' under [Seat:*] in lightdm.conf",
    }


CHECKS = [
    check_ssh_root_login,
    check_password_max_days,
    check_firewall_active,
    check_world_writable_files,
    check_automatic_updates,
    check_guest_account_disabled,
]


def run():
    """Run all OS hardening checks and return a score + findings."""
    findings = [check() for check in CHECKS]
    passed_count = sum(1 for f in findings if f["passed"])
    score = round((passed_count / len(findings)) * 100)
    return {
        "layer": "os_hardening",
        "score": score,
        "findings": findings,
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))
