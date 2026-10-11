"""Deterministic unit coverage for local Windows and macOS OS profiles."""

from types import SimpleNamespace

import pytest

from modules import os_hardening


def test_readonly_runner_never_uses_a_shell(monkeypatch):
    captured = {}

    def fake_run(argv, **kwargs):
        captured["argv"] = argv
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="ok\n", stderr="")

    monkeypatch.setattr(os_hardening.subprocess, "run", fake_run)
    assert os_hardening._run_readonly_command(["tool", "--status"]) == (True, "ok", 0)
    assert captured["argv"] == ["tool", "--status"]
    assert captured["shell"] is False
    assert captured["timeout"] == 10


def test_windows_firewall_requires_all_three_profiles(monkeypatch):
    monkeypatch.setattr(
        os_hardening, "_run_windows_powershell",
        lambda _script: (True, "Domain:true\nPrivate:true\nPublic:true", 0),
    )
    assert os_hardening.check_windows_firewall("windows")["status"] == "PASS"

    monkeypatch.setattr(
        os_hardening, "_run_windows_powershell",
        lambda _script: (True, "Domain:true\nPrivate:false\nPublic:true", 0),
    )
    assert os_hardening.check_windows_firewall("windows")["status"] == "FAIL"


@pytest.mark.parametrize("output", ["", "Domain:true\nPrivate:true", "unexpected"])
def test_windows_firewall_incomplete_output_is_error(monkeypatch, output):
    monkeypatch.setattr(
        os_hardening, "_run_windows_powershell",
        lambda _script: (True, output, 0),
    )
    result = os_hardening.check_windows_firewall("windows")
    assert result["status"] == "ERROR"
    assert result["severity"] == "high"


@pytest.mark.parametrize(("output", "expected"), [("1", "PASS"), ("0", "FAIL")])
def test_windows_uac_result(monkeypatch, output, expected):
    monkeypatch.setattr(
        os_hardening, "_run_windows_powershell",
        lambda _script: (True, output, 0),
    )
    assert os_hardening.check_windows_uac_enabled("windows")["status"] == expected


def test_windows_uac_query_failure_and_bad_value_are_errors(monkeypatch):
    monkeypatch.setattr(
        os_hardening, "_run_windows_powershell",
        lambda _script: (False, "", 1),
    )
    assert os_hardening.check_windows_uac_enabled("windows")["status"] == "ERROR"
    monkeypatch.setattr(
        os_hardening, "_run_windows_powershell",
        lambda _script: (True, "enabled", 0),
    )
    assert os_hardening.check_windows_uac_enabled("windows")["status"] == "ERROR"


@pytest.mark.parametrize(
    ("output", "expected"),
    [("true", "PASS"), ("false", "FAIL"), ("absent", "PASS")],
)
def test_windows_guest_account_result(monkeypatch, output, expected):
    monkeypatch.setattr(
        os_hardening, "_run_windows_powershell",
        lambda _script: (True, output, 0),
    )
    assert os_hardening.check_windows_guest_disabled("windows")["status"] == expected


@pytest.mark.parametrize(
    ("check", "output"),
    [
        (os_hardening.check_macos_firewall, "Firewall is enabled. (State = 1)"),
        (os_hardening.check_macos_filevault, "FileVault is On."),
        (os_hardening.check_macos_gatekeeper, "assessments enabled"),
        (os_hardening.check_macos_sip, "System Integrity Protection status: enabled."),
    ],
)
def test_macos_positive_readonly_results(monkeypatch, check, output):
    monkeypatch.setattr(
        os_hardening, "_run_macos_query",
        lambda _argv: (True, output, 0),
    )
    assert check("macos")["status"] == "PASS"


@pytest.mark.parametrize(
    ("check", "output"),
    [
        (os_hardening.check_macos_firewall, "Firewall is disabled. (State = 0)"),
        (os_hardening.check_macos_filevault, "FileVault is Off."),
        (os_hardening.check_macos_gatekeeper, "assessments disabled"),
        (os_hardening.check_macos_sip, "System Integrity Protection status: disabled."),
    ],
)
def test_macos_negative_readonly_results(monkeypatch, check, output):
    monkeypatch.setattr(
        os_hardening, "_run_macos_query",
        lambda _argv: (True, output, 0),
    )
    assert check("macos")["status"] == "FAIL"


def test_macos_query_error_and_unrecognized_output_are_not_failures(monkeypatch):
    monkeypatch.setattr(
        os_hardening, "_run_macos_query",
        lambda _argv: (False, "", 1),
    )
    assert os_hardening.check_macos_firewall("macos")["status"] == "ERROR"
    monkeypatch.setattr(
        os_hardening, "_run_macos_query",
        lambda _argv: (True, "status unavailable", 0),
    )
    assert os_hardening.check_macos_firewall("macos")["status"] == "ERROR"


@pytest.mark.parametrize(
    ("check", "other_os"),
    [
        (os_hardening.check_windows_firewall, "linux"),
        (os_hardening.check_windows_uac_enabled, "macos"),
        (os_hardening.check_windows_guest_disabled, "linux"),
        (os_hardening.check_macos_firewall, "windows"),
        (os_hardening.check_macos_filevault, "linux"),
        (os_hardening.check_macos_gatekeeper, "windows"),
        (os_hardening.check_macos_sip, "linux"),
    ],
)
def test_platform_specific_checks_are_not_applicable_elsewhere(monkeypatch, check, other_os):
    def unexpected_query(_value):
        pytest.fail("A platform-specific command ran on the wrong OS")

    monkeypatch.setattr(os_hardening, "_run_windows_powershell", unexpected_query)
    monkeypatch.setattr(os_hardening, "_run_macos_query", unexpected_query)
    result = check(other_os)
    assert result["status"] == "NOT_APPLICABLE"
    assert result["passed"] is None
    assert result["severity"] is None


def test_run_selects_windows_profile_and_reports_denominators(monkeypatch):
    monkeypatch.setattr(os_hardening, "_detect_os", lambda: "windows")

    def fake_powershell(script):
        if "Get-NetFirewallProfile" in script:
            return True, "Domain:true\nPrivate:true\nPublic:true", 0
        if "EnableLUA" in script:
            return True, "1", 0
        if "Win32_UserAccount" in script:
            return True, "true", 0
        raise AssertionError("Unexpected PowerShell query")

    monkeypatch.setattr(os_hardening, "_run_windows_powershell", fake_powershell)
    result = os_hardening.run()
    assert result["control_profile"] == "windows_local_v1"
    assert result["scoring_model_version"] == "1.3"
    assert result["score"] == 100
    assert result["applicable_checks"] == result["total_checks"] == 3
    assert result["error_checks"] == 0
    assert len(result["findings"]) == 3


def test_run_suppresses_partial_score_when_a_check_has_error(monkeypatch):
    monkeypatch.setattr(os_hardening, "_detect_os", lambda: "windows")

    def partial_powershell(script):
        if "Get-NetFirewallProfile" in script:
            return True, "Domain:true\nPrivate:true\nPublic:true", 0
        if "EnableLUA" in script:
            return True, "1", 0
        if "Win32_UserAccount" in script:
            return False, "", 1
        raise AssertionError("Unexpected PowerShell query")

    monkeypatch.setattr(os_hardening, "_run_windows_powershell", partial_powershell)
    result = os_hardening.run()
    assert result["score"] is None
    assert result["applicable_checks"] == 2
    assert result["total_checks"] == 3
    assert result["error_checks"] == 1
    assert result["score_suppressed_reason"]


def test_unknown_os_does_not_receive_a_fabricated_score(monkeypatch):
    monkeypatch.setattr(os_hardening, "_detect_os", lambda: "unknown")
    result = os_hardening.run()
    assert result["score"] is None
    assert result["findings"] == []
    assert result["total_checks"] == 0
    assert result["control_profile"] == "unsupported_local_v1"
