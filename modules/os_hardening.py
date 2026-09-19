"""
OS Hardening Module
--------------------
Runs a set of local configuration checks (inspired by CIS Benchmark
categories) and returns a score out of 100 plus a list of findings.

R2/R3 FIX (Phase 2):
- Detects the host OS at runtime.
- Linux-specific checks on non-Linux systems now return NOT_APPLICABLE
  instead of FAIL.
- NOT_APPLICABLE findings are excluded from score calculation and must
  never reduce the score.
- A check not evaluated is NOT_APPLICABLE, never PASS.

Finding format:
    {
        "id": str,
        "description": str,
        "passed": bool | None,   # None = NOT_APPLICABLE
        "status": "PASS" | "FAIL" | "NOT_APPLICABLE" | "ERROR",
        "severity": str | None,  # None when NOT_APPLICABLE
        "recommendation": str | None,
        "not_applicable_reason": str | None,
    }

Backward compatibility: "passed" is preserved as bool for PASS/FAIL
findings so existing CLI/Flask rendering is unaffected.
"""

import platform
import subprocess
import os


# ── OS detection ─────────────────────────────────────────────────────────────

def _detect_os():
    """Return 'linux', 'windows', 'macos', or 'unknown'."""
    s = platform.system().lower()
    if s == "linux":
        return "linux"
    if s == "windows":
        return "windows"
    if s == "darwin":
        return "macos"
    return "unknown"


def _run(cmd):
    """Run a shell command and return stdout, or '' on failure."""
    try:
        return subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=10
        ).stdout.strip()
    except Exception:
        return ""


# ── Finding constructors ──────────────────────────────────────────────────────

def _pass(check_id, description, severity, recommendation):
    return {
        "id": check_id,
        "description": description,
        "passed": True,
        "status": "PASS",
        "severity": severity,
        "recommendation": recommendation,
        "not_applicable_reason": None,
    }


def _fail(check_id, description, severity, recommendation):
    return {
        "id": check_id,
        "description": description,
        "passed": False,
        "status": "FAIL",
        "severity": severity,
        "recommendation": recommendation,
        "not_applicable_reason": None,
    }


def _not_applicable(check_id, description, reason):
    """
    NOT_APPLICABLE: check does not apply to this OS/environment.
    severity is None — NOT_APPLICABLE must never reduce a score.
    passed is None — not True, not False.
    """
    return {
        "id": check_id,
        "description": description,
        "passed": None,
        "status": "NOT_APPLICABLE",
        "severity": None,
        "recommendation": None,
        "not_applicable_reason": reason,
    }


def _error(check_id, description, severity, recommendation, reason):
    return {
        "id": check_id,
        "description": description,
        "passed": False,
        "status": "ERROR",
        "severity": severity,
        "recommendation": recommendation,
        "not_applicable_reason": reason,
    }


# ── Checks ────────────────────────────────────────────────────────────────────

def check_ssh_root_login(os_family):
    cid = "ssh_root_login"
    desc = "SSH root login is disabled"
    sev = "high"
    rec = "Set 'PermitRootLogin no' in /etc/ssh/sshd_config"

    if os_family not in ("linux",):
        return _not_applicable(cid, desc,
            f"sshd_config check is Linux-specific (detected OS: {os_family})")

    content = _run("cat /etc/ssh/sshd_config 2>/dev/null")
    if not content and not os.path.exists("/etc/ssh/sshd_config"):
        return _not_applicable(cid, desc,
            "sshd_config not found — SSH may not be installed")

    passed = "PermitRootLogin no" in content
    return _pass(cid, desc, sev, rec) if passed else _fail(cid, desc, sev, rec)


def check_password_max_days(os_family):
    cid = "password_max_days"
    desc = "Password expiration is set to 90 days or fewer"
    sev = "medium"
    rec = "Set PASS_MAX_DAYS to 90 or fewer in /etc/login.defs"

    if os_family not in ("linux",):
        return _not_applicable(cid, desc,
            f"/etc/login.defs is Linux-specific (detected OS: {os_family})")

    if not os.path.exists("/etc/login.defs"):
        return _not_applicable(cid, desc,
            "/etc/login.defs not found")

    content = _run("grep PASS_MAX_DAYS /etc/login.defs 2>/dev/null")
    passed = False
    if content:
        try:
            days = int(content.split()[-1])
            passed = 0 < days <= 90
        except ValueError:
            passed = False
    return _pass(cid, desc, sev, rec) if passed else _fail(cid, desc, sev, rec)


def check_firewall_active(os_family):
    cid = "firewall_active"
    desc = "A firewall (ufw/iptables) is active"
    sev = "high"
    rec = "Enable ufw ('sudo ufw enable') or configure iptables rules"

    if os_family not in ("linux",):
        return _not_applicable(cid, desc,
            f"ufw/iptables check is Linux-specific (detected OS: {os_family})")

    ufw = _run("sudo ufw status 2>/dev/null")
    iptables = _run("sudo iptables -L 2>/dev/null")
    passed = "Status: active" in ufw or "Chain INPUT" in iptables
    return _pass(cid, desc, sev, rec) if passed else _fail(cid, desc, sev, rec)


def check_world_writable_files(os_family):
    cid = "world_writable_files"
    desc = "No world-writable files in common directories"
    sev = "medium"
    rec = "Review and remove world-writable permissions ('chmod o-w <file>') on flagged files"

    if os_family not in ("linux",):
        return _not_applicable(cid, desc,
            f"find -perm check is Linux-specific (detected OS: {os_family})")

    result = _run("find / -xdev -type f -perm -0002 2>/dev/null | head -n 5")
    passed = result == ""
    return _pass(cid, desc, sev, rec) if passed else _fail(cid, desc, sev, rec)


def check_automatic_updates(os_family):
    cid = "automatic_updates"
    desc = "Automatic security updates are enabled"
    sev = "medium"
    rec = "Install and enable 'unattended-upgrades'"

    if os_family not in ("linux",):
        return _not_applicable(cid, desc,
            f"apt/unattended-upgrades check is Linux-specific (detected OS: {os_family})")

    exists = os.path.exists("/etc/apt/apt.conf.d/20auto-upgrades")
    content = _run("cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null")
    passed = exists and "1" in content
    return _pass(cid, desc, sev, rec) if passed else _fail(cid, desc, sev, rec)


def check_guest_account_disabled(os_family):
    cid = "guest_account_disabled"
    desc = "Guest login account is disabled"
    sev = "low"
    rec = "Set 'allow-guest=false' under [Seat:*] in lightdm.conf"

    if os_family not in ("linux",):
        return _not_applicable(cid, desc,
            f"lightdm.conf check is Linux-specific (detected OS: {os_family})")

    content = _run("cat /etc/lightdm/lightdm.conf 2>/dev/null")
    # On Linux without lightdm, absent config means guest login not applicable
    if content == "" and not os.path.exists("/etc/lightdm/lightdm.conf"):
        return _not_applicable(cid, desc,
            "lightdm not found — check not applicable to this display manager")

    passed = "allow-guest=false" in content or content == ""
    return _pass(cid, desc, sev, rec) if passed else _fail(cid, desc, sev, rec)


CHECKS = [
    check_ssh_root_login,
    check_password_max_days,
    check_firewall_active,
    check_world_writable_files,
    check_automatic_updates,
    check_guest_account_disabled,
]


def run():
    """
    Run all OS hardening checks and return a score + findings.

    Score is based only on PASS/FAIL findings.
    NOT_APPLICABLE findings are excluded from both numerator and denominator.
    This ensures NOT_APPLICABLE never reduces the score.
    """
    os_family = _detect_os()
    findings = [check(os_family) for check in CHECKS]

    applicable = [f for f in findings if f["status"] in ("PASS", "FAIL")]
    passed_count = sum(1 for f in applicable if f["status"] == "PASS")
    score = round((passed_count / len(applicable)) * 100) if applicable else 0

    return {
        "layer": "os_hardening",
        "os_family": os_family,
        "score": score,
        "findings": findings,
        "applicable_checks": len(applicable),
        "not_applicable_checks": sum(
            1 for f in findings if f["status"] == "NOT_APPLICABLE"
        ),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))
