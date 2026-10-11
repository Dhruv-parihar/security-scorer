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
import re
from modules.scoring_config import OS_SEVERITY_WEIGHT, OS_SCORING_METHOD
from modules.scoring_config import SCORING_MODEL_VERSION


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


def _run_readonly_command(argv):
    """Run a fixed, read-only platform query without a shell."""
    try:
        completed = subprocess.run(
            argv, shell=False, capture_output=True, text=True, timeout=10,
            errors="replace",
        )
    except Exception:
        return False, "", None
    return completed.returncode == 0, completed.stdout.strip(), completed.returncode


def _run_windows_powershell(script):
    return _run_readonly_command([
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script
    ])


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


# ── Windows checks (read-only, local machine only) ───────────────────────────

def check_windows_firewall(os_family):
    cid = "windows_firewall_profiles"
    desc = "Windows Firewall is enabled for Domain, Private, and Public profiles"
    sev = "high"
    rec = "Review the applicable Microsoft security baseline and enable the required firewall profiles."
    if os_family != "windows":
        return _not_applicable(cid, desc, f"Windows-only check (detected OS: {os_family})")

    script = (
        "$ErrorActionPreference='Stop'; "
        "$p=Get-NetFirewallProfile -Profile Domain,Private,Public; "
        "if (@($p).Count -ne 3) { throw 'Expected three firewall profiles' }; "
        "$p | ForEach-Object { '{0}:{1}' -f $_.Name, $_.Enabled.ToString().ToLowerInvariant() }"
    )
    ok, output, returncode = _run_windows_powershell(script)
    if not ok:
        return _error(cid, desc, sev, rec, f"Read-only firewall query failed (exit code: {returncode})")

    profiles = {}
    for line in output.splitlines():
        name, separator, enabled = line.strip().partition(":")
        if separator and name in {"Domain", "Private", "Public"}:
            profiles[name] = enabled.lower()
    if set(profiles) != {"Domain", "Private", "Public"} or any(
        value not in {"true", "false"} for value in profiles.values()
    ):
        return _error(cid, desc, sev, rec, "Firewall query returned incomplete or unrecognized profile data")
    passed = all(value == "true" for value in profiles.values())
    return _pass(cid, desc, sev, rec) if passed else _fail(cid, desc, sev, rec)


def check_windows_uac_enabled(os_family):
    cid = "windows_uac_enabled"
    desc = "Windows User Account Control is enabled (EnableLUA=1)"
    sev = "high"
    rec = "Review the Microsoft UAC guidance and enable administrator approval mode using approved policy."
    if os_family != "windows":
        return _not_applicable(cid, desc, f"Windows-only check (detected OS: {os_family})")

    script = (
        "$ErrorActionPreference='Stop'; "
        "$v=(Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-Name EnableLUA -ErrorAction Stop).EnableLUA; "
        "if ($null -eq $v) { throw 'EnableLUA is unavailable' }; [string]$v"
    )
    ok, output, returncode = _run_windows_powershell(script)
    if not ok:
        return _error(cid, desc, sev, rec, f"Read-only UAC query failed (exit code: {returncode})")
    value = output.strip()
    if value not in {"0", "1"}:
        return _error(cid, desc, sev, rec, "UAC query returned an unrecognized value")
    return _pass(cid, desc, sev, rec) if value == "1" else _fail(cid, desc, sev, rec)


def check_windows_guest_disabled(os_family):
    cid = "windows_guest_account_disabled"
    desc = "The built-in Windows Guest account is disabled or absent"
    sev = "low"
    rec = "Review local account policy and prevent interactive sign-in to the built-in Guest account."
    if os_family != "windows":
        return _not_applicable(cid, desc, f"Windows-only check (detected OS: {os_family})")

    script = (
        "$ErrorActionPreference='Stop'; "
        "$a=@(Get-CimInstance -ClassName Win32_UserAccount -Filter 'LocalAccount=True' | "
        "Where-Object { $_.SID -match '-501$' }); "
        "if ($a.Count -eq 0) { 'absent' } "
        "elseif ($a.Count -ne 1) { throw 'Guest account query was ambiguous' } "
        "else { $a[0].Disabled.ToString().ToLowerInvariant() }"
    )
    ok, output, returncode = _run_windows_powershell(script)
    if not ok:
        return _error(cid, desc, sev, rec, f"Read-only Guest account query failed (exit code: {returncode})")
    value = output.strip().lower()
    if value == "absent":
        return _pass(cid, desc, sev, rec)
    if value not in {"true", "false"}:
        return _error(cid, desc, sev, rec, "Guest account query returned an unrecognized value")
    return _pass(cid, desc, sev, rec) if value == "true" else _fail(cid, desc, sev, rec)


# ── macOS checks (read-only, local machine only) ─────────────────────────────

def _run_macos_query(argv):
    return _run_readonly_command(argv)


def _macos_boolean_check(os_family, cid, desc, severity, recommendation,
                         argv, positive_patterns, negative_patterns):
    if os_family != "macos":
        return _not_applicable(cid, desc, f"macOS-only check (detected OS: {os_family})")
    ok, output, returncode = _run_macos_query(argv)
    if not ok:
        return _error(cid, desc, severity, recommendation,
                      f"Read-only macOS query failed (exit code: {returncode})")
    normalized = output.strip().lower()
    if any(re.search(pattern, normalized) for pattern in positive_patterns):
        return _pass(cid, desc, severity, recommendation)
    if any(re.search(pattern, normalized) for pattern in negative_patterns):
        return _fail(cid, desc, severity, recommendation)
    return _error(cid, desc, severity, recommendation,
                  "macOS query returned unrecognized status text")


def check_macos_firewall(os_family):
    return _macos_boolean_check(
        os_family, "macos_firewall_enabled",
        "The macOS Application Firewall is enabled", "high",
        "Review macOS Firewall settings and enable the Application Firewall if appropriate.",
        ["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"],
        [r"firewall is enabled", r"state\s*=\s*1\b"],
        [r"firewall is disabled", r"state\s*=\s*0\b"],
    )


def check_macos_filevault(os_family):
    return _macos_boolean_check(
        os_family, "macos_filevault_enabled",
        "FileVault preboot authentication is enabled", "medium",
        "Review Apple FileVault guidance and enable it through an approved recovery-key process.",
        ["/usr/bin/fdesetup", "status"],
        [r"filevault is on\b"], [r"filevault is off\b"],
    )


def check_macos_gatekeeper(os_family):
    return _macos_boolean_check(
        os_family, "macos_gatekeeper_enabled",
        "macOS Gatekeeper assessments are enabled", "high",
        "Review Gatekeeper policy and require trusted or identified applications as appropriate.",
        ["/usr/sbin/spctl", "--status"],
        [r"assessments enabled\b"], [r"assessments disabled\b"],
    )


def check_macos_sip(os_family):
    return _macos_boolean_check(
        os_family, "macos_sip_enabled",
        "macOS System Integrity Protection is enabled", "high",
        "Review Apple System Integrity Protection guidance; do not disable it without a documented need.",
        ["/usr/bin/csrutil", "status"],
        [r"system integrity protection status:\s*enabled\b"],
        [r"system integrity protection status:\s*disabled\b"],
    )


CHECKS = [
    check_ssh_root_login,
    check_password_max_days,
    check_firewall_active,
    check_world_writable_files,
    check_automatic_updates,
    check_guest_account_disabled,
]

OS_CHECK_PROFILES = {
    "linux": ("linux_local_v1", CHECKS),
    "windows": ("windows_local_v1", [
        check_windows_firewall,
        check_windows_uac_enabled,
        check_windows_guest_disabled,
    ]),
    "macos": ("macos_local_v1", [
        check_macos_firewall,
        check_macos_filevault,
        check_macos_gatekeeper,
        check_macos_sip,
    ]),
}


def calculate_score(findings):
    """Return the normalized severity-weighted PASS percentage.

    Only PASS/FAIL checks contribute. Unknown/missing severity on an evaluated
    check is rejected rather than silently assigned a weight.
    """
    applicable = [f for f in findings if f.get("status") in ("PASS", "FAIL")]
    if not applicable:
        return None

    total_weight = 0
    passed_weight = 0
    for finding in applicable:
        severity = finding.get("severity")
        if severity not in OS_SEVERITY_WEIGHT:
            raise ValueError(
                f"Evaluated OS finding {finding.get('id', '<unknown>')} "
                f"has unsupported severity {severity!r}"
            )
        weight = OS_SEVERITY_WEIGHT[severity]
        total_weight += weight
        if finding["status"] == "PASS":
            passed_weight += weight
    return round(100 * passed_weight / total_weight)


def run():
    """
    Run all OS hardening checks and return a score + findings.

    Score is based only on PASS/FAIL findings.
    NOT_APPLICABLE findings are excluded from both numerator and denominator.
    This ensures NOT_APPLICABLE never reduces the score.
    """
    os_family = _detect_os()
    profile = OS_CHECK_PROFILES.get(os_family)
    if profile is None:
        profile_id, checks = ("unsupported_local_v1", [])
    else:
        profile_id, checks = profile
    findings = [check(os_family) for check in checks]
    # The versioned profile is the unit of OS detector semantics used for
    # longitudinal matching; bump the profile ID when its check logic changes.
    for finding in findings:
        finding.setdefault("check_version", profile_id)

    applicable = [f for f in findings if f["status"] in ("PASS", "FAIL")]
    error_count = sum(1 for f in findings if f["status"] == "ERROR")
    # A partial score can look deceptively strong when one or more controls
    # could not be queried. Preserve findings, but suppress the layer score.
    score = None if error_count else calculate_score(findings)

    return {
        "layer": "os_hardening",
        "os_family": os_family,
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "control_profile": profile_id,
        "scoring_model_version": SCORING_MODEL_VERSION,
        "score": score,
        "score_suppressed_reason": (
            "One or more checks could not be evaluated; resolve ERROR findings before scoring."
            if error_count else ("No PASS/FAIL checks were evaluated." if score is None else None)
        ),
        "scoring_method": OS_SCORING_METHOD,
        "severity_weights": dict(OS_SEVERITY_WEIGHT),
        "findings": findings,
        "applicable_checks": len(applicable),
        "total_checks": len(findings),
        "error_checks": error_count,
        "not_applicable_checks": sum(
            1 for f in findings if f["status"] == "NOT_APPLICABLE"
        ),
    }


if __name__ == "__main__":
    import json
    print(json.dumps(run(), indent=2))
