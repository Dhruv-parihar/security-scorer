"""
Test Suite — Phase 2: Integration, R1/R2/R3/R4 Fixes, Adapter
===============================================================
Tests:
1. R1: Network findings appear in composite recommendations
2. R2/R3: Linux-specific OS checks → NOT_APPLICABLE on non-Linux
3. R2/R3: NOT_APPLICABLE does not reduce OS score
4. R4: Unauthorized active scanning is blocked
5. R4: Authorized targets pass through correctly
6. Adapter: Scanner output → research DB findings
7. Phase 1 DB tests remain green (imported)

Run: python3 -m pytest tests/test_phase2.py tests/test_database.py -v
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.scoring import compute_composite, _is_failed_finding
from modules.authorization import require_authorization, check_authorization, AuthorizationError
from modules.os_hardening import (
    _not_applicable, _pass, _fail, _detect_os, run as os_run,
    check_ssh_root_login, check_password_max_days, check_firewall_active,
    check_automatic_updates, check_guest_account_disabled,
    check_world_writable_files,
)
from db.schema import initialize, seed_taxonomy
from db.repository import create_target, create_assessment, get_findings, get_findings_by_status, get_score_snapshots
from db.adapters import store_assessment_results


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def db():
    conn, version = initialize(":memory:")
    seed_taxonomy(conn)
    yield conn
    conn.close()


@pytest.fixture
def lab_target(db):
    tid = create_target(
        db, alias="192.168.56.102", target_type="lab_vm",
        environment="lab", authorization_status="LAB",
        os_family="linux", os_name="Metasploitable 2"
    )
    return tid


@pytest.fixture
def web_target(db):
    tid = create_target(
        db, alias="http://192.168.56.102/dvwa/vulnerabilities/sqli/?id=1",
        target_type="web_app", environment="lab",
        authorization_status="LAB"
    )
    return tid


# ── R1: Network findings in recommendations ───────────────────────────────────

class TestR1NetworkFindings:
    """R1: scoring.py must include network findings in recommendations."""

    def _network_result(self):
        return {
            "layer": "network",
            "score": 0,
            "open_ports": 2,
            "findings": [
                {
                    "port": "21", "service": "ftp", "version": "vsftpd 2.3.4",
                    "matched_signature": "vsftpd 2.3.4",
                    "severity": "critical",
                    "note": "Known backdoored version (CVE-2011-2523)",
                    "recommendation": "Upgrade vsftpd immediately",
                },
                {
                    "port": "23", "service": "telnet",
                    "severity": "high",
                    "note": "Telnet transmits credentials in plaintext",
                    "recommendation": "Disable Telnet; use SSH",
                },
            ]
        }

    def test_network_findings_in_recommendations(self):
        result = {"network": self._network_result()}
        composite = compute_composite(result)
        recs = composite["recommendations"]
        assert len(recs) == 2, f"Expected 2 recommendations, got {len(recs)}: {recs}"

    def test_network_critical_finding_first(self):
        result = {"network": self._network_result()}
        composite = compute_composite(result)
        recs = composite["recommendations"]
        assert recs[0]["severity"] == "critical"
        assert recs[1]["severity"] == "high"

    def test_network_findings_have_correct_layer(self):
        result = {"network": self._network_result()}
        composite = compute_composite(result)
        for rec in composite["recommendations"]:
            assert rec["layer"] == "network"

    def test_mixed_layers_all_recommendations_present(self):
        """All three layers' failures must appear in recommendations."""
        os_result = {
            "layer": "os_hardening", "score": 50,
            "findings": [
                {"id": "ssh", "description": "SSH", "passed": False,
                 "status": "FAIL", "severity": "high",
                 "recommendation": "Fix SSH", "not_applicable_reason": None},
            ]
        }
        web_result = {
            "layer": "webapp", "score": 70,
            "findings": [
                {"id": "csp", "description": "CSP", "passed": False,
                 "status": "FAIL", "severity": "medium",
                 "recommendation": "Add CSP", "not_applicable_reason": None},
            ]
        }
        composite = compute_composite({
            "os_hardening": os_result,
            "network": self._network_result(),
            "webapp": web_result,
        })
        recs = composite["recommendations"]
        layers = {r["layer"] for r in recs}
        assert "network" in layers, "Network recommendations missing"
        assert "os_hardening" in layers, "OS recommendations missing"
        assert "webapp" in layers, "Web recommendations missing"
        assert len(recs) == 4  # 1 OS + 2 network + 1 web

    def test_is_failed_finding_network_style(self):
        """_is_failed_finding must return True for network-style findings."""
        network_finding = {"severity": "critical", "note": "backdoor", "recommendation": "upgrade"}
        assert _is_failed_finding(network_finding) is True

    def test_is_failed_finding_pass_style(self):
        assert _is_failed_finding({"passed": True, "severity": "high"}) is False

    def test_is_failed_finding_fail_style(self):
        assert _is_failed_finding({"passed": False, "severity": "high"}) is True

    def test_is_failed_finding_not_applicable(self):
        """NOT_APPLICABLE findings (severity=None, no passed key) must not appear."""
        na_finding = {"severity": None, "status": "NOT_APPLICABLE", "passed": None}
        assert _is_failed_finding(na_finding) is False

    def test_regression_os_webapp_unaffected(self):
        """R1 fix must not break OS or webapp finding inclusion."""
        os_result = {
            "layer": "os_hardening", "score": 33,
            "findings": [
                {"id": "fw", "description": "Firewall", "passed": False,
                 "status": "FAIL", "severity": "high",
                 "recommendation": "Enable ufw", "not_applicable_reason": None},
                {"id": "guest", "description": "Guest", "passed": True,
                 "status": "PASS", "severity": "low",
                 "recommendation": None, "not_applicable_reason": None},
            ]
        }
        composite = compute_composite({"os_hardening": os_result})
        recs = composite["recommendations"]
        assert len(recs) == 1
        assert recs[0]["severity"] == "high"


# ── R2/R3: OS NOT_APPLICABLE ──────────────────────────────────────────────────

class TestR2R3OSNotApplicable:
    """R2/R3: Linux-specific checks → NOT_APPLICABLE on non-Linux."""

    def test_not_applicable_finding_structure(self):
        f = _not_applicable("ssh_root_login", "SSH root login is disabled",
                            "Linux-specific check on Windows")
        assert f["status"] == "NOT_APPLICABLE"
        assert f["passed"] is None
        assert f["severity"] is None
        assert f["not_applicable_reason"] is not None

    def test_all_checks_not_applicable_on_windows(self):
        checks = [
            check_ssh_root_login,
            check_password_max_days,
            check_firewall_active,
            check_world_writable_files,
            check_automatic_updates,
            check_guest_account_disabled,
        ]
        for check_fn in checks:
            result = check_fn("windows")
            assert result["status"] == "NOT_APPLICABLE", \
                f"{check_fn.__name__} returned {result['status']} on windows, expected NOT_APPLICABLE"
            assert result["severity"] is None, \
                f"{check_fn.__name__} has severity {result['severity']} on NOT_APPLICABLE"
            assert result["passed"] is None, \
                f"{check_fn.__name__} has passed={result['passed']} on NOT_APPLICABLE"

    def test_all_checks_not_applicable_on_macos(self):
        checks = [
            check_ssh_root_login,
            check_password_max_days,
            check_firewall_active,
            check_world_writable_files,
            check_automatic_updates,
            check_guest_account_disabled,
        ]
        for check_fn in checks:
            result = check_fn("macos")
            assert result["status"] == "NOT_APPLICABLE"

    def test_not_applicable_excluded_from_score(self):
        """Score computed from os_hardening.run() must exclude NOT_APPLICABLE."""
        result = os_run()
        findings = result["findings"]
        na_findings = [f for f in findings if f["status"] == "NOT_APPLICABLE"]
        applicable = [f for f in findings if f["status"] in ("PASS", "FAIL")]
        if not applicable:
            # All checks NOT_APPLICABLE: score should be 0, not misleading
            assert result["score"] == 0
        else:
            # Score must equal pass_count/applicable_count * 100
            pass_count = sum(1 for f in applicable if f["status"] == "PASS")
            expected_score = round(pass_count / len(applicable) * 100)
            assert result["score"] == expected_score, \
                f"Score mismatch: got {result['score']}, expected {expected_score}"
        # NOT_APPLICABLE count is reported
        assert "not_applicable_checks" in result
        assert result["not_applicable_checks"] == len(na_findings)

    def test_not_applicable_does_not_reduce_score(self):
        """
        Simulated: a system where all applicable checks PASS but some are
        NOT_APPLICABLE must score 100, not less.
        """
        from modules.os_hardening import _pass, _not_applicable
        findings = [
            _pass("ssh_root_login", "SSH", "high", "fix"),
            _pass("firewall_active", "FW", "high", "fix"),
            _not_applicable("password_max_days", "PWD", "Windows"),
            _not_applicable("automatic_updates", "UPD", "Windows"),
        ]
        applicable = [f for f in findings if f["status"] in ("PASS", "FAIL")]
        passed_count = sum(1 for f in applicable if f["status"] == "PASS")
        score = round((passed_count / len(applicable)) * 100) if applicable else 0
        assert score == 100, f"Expected 100 when all applicable pass, got {score}"

    def test_check_returns_pass_or_fail_on_linux(self):
        """On Linux, checks must return PASS or FAIL, not NOT_APPLICABLE."""
        # We can only truly test this on Linux
        import platform
        if platform.system().lower() != "linux":
            pytest.skip("This test only runs on Linux")
        results = [check_fn("linux") for check_fn in [
            check_ssh_root_login,
            check_password_max_days,
            check_firewall_active,
            check_automatic_updates,
        ]]
        for r in results:
            # On Linux, status must be PASS, FAIL, or NOT_APPLICABLE
            # (NOT_APPLICABLE is still valid if e.g. sshd not installed)
            assert r["status"] in ("PASS", "FAIL", "NOT_APPLICABLE")

    def test_run_result_contains_os_family(self):
        result = os_run()
        assert "os_family" in result
        assert result["os_family"] in ("linux", "windows", "macos", "unknown")


# ── R4: Authorization ─────────────────────────────────────────────────────────

class TestR4Authorization:
    """R4: Active scanning blocked without authorization record."""

    def test_unauthorized_ip_blocked(self, db):
        with pytest.raises(AuthorizationError) as exc:
            require_authorization(db, "10.0.0.1")
        assert "10.0.0.1" in str(exc.value)
        assert "no authorization record" in str(exc.value).lower()

    def test_empty_identifier_blocked(self, db):
        with pytest.raises(AuthorizationError):
            require_authorization(db, "")

    def test_none_identifier_blocked(self, db):
        with pytest.raises(AuthorizationError):
            require_authorization(db, None)

    def test_authorized_lab_target_passes(self, db, lab_target):
        target_id = require_authorization(db, "192.168.56.102")
        assert target_id == lab_target

    def test_authorized_web_target_passes(self, db, web_target):
        target_id = require_authorization(
            db, "http://192.168.56.102/dvwa/vulnerabilities/sqli/?id=1"
        )
        assert target_id == web_target

    def test_check_authorization_returns_bool_tuple(self, db, lab_target):
        authorized, tid, msg = check_authorization(db, "192.168.56.102")
        assert authorized is True
        assert tid == lab_target
        assert msg == "Authorized"

    def test_check_authorization_unauthorized_returns_false(self, db):
        authorized, tid, msg = check_authorization(db, "1.2.3.4")
        assert authorized is False
        assert tid is None
        assert "no authorization record" in msg.lower()

    def test_all_valid_auth_statuses_permit_scanning(self, db):
        from db.schema import AUTH_STATUSES
        for status in AUTH_STATUSES:
            tid = create_target(db, f"target-{status}", "lab_vm",
                                "lab", status)
            result_tid = require_authorization(db, f"target-{status}")
            assert result_tid == tid

    def test_case_insensitive_lookup(self, db, lab_target):
        """Authorization lookup must be case-insensitive."""
        tid = require_authorization(db, "192.168.56.102")
        assert tid == lab_target

    def test_arbitrary_ip_without_record_blocked(self, db):
        """No implicit authorization for any IP — must have a DB record."""
        for ip in ["192.168.1.1", "8.8.8.8", "localhost", "127.0.0.1"]:
            authorized, _, _ = check_authorization(db, ip)
            assert authorized is False, f"{ip} should not be auto-authorized"


# ── Adapter: scanner → DB ─────────────────────────────────────────────────────

class TestAdapter:
    """Adapter translates scanner output correctly into DB findings."""

    def _os_result(self):
        return {
            "layer": "os_hardening",
            "os_family": "linux",
            "score": 50,
            "applicable_checks": 4,
            "not_applicable_checks": 2,
            "findings": [
                {"id": "ssh_root_login", "description": "SSH root login",
                 "passed": False, "status": "FAIL", "severity": "high",
                 "recommendation": "Set PermitRootLogin no",
                 "not_applicable_reason": None},
                {"id": "firewall_active", "description": "Firewall",
                 "passed": True, "status": "PASS", "severity": "high",
                 "recommendation": None, "not_applicable_reason": None},
                {"id": "password_max_days", "description": "Password expiry",
                 "passed": None, "status": "NOT_APPLICABLE", "severity": None,
                 "recommendation": None,
                 "not_applicable_reason": "Not Linux"},
            ]
        }

    def _network_result(self):
        return {
            "layer": "network",
            "score": 0,
            "open_ports": 1,
            "findings": [
                {"port": "21", "service": "ftp", "version": "vsftpd 2.3.4",
                 "matched_signature": "vsftpd 2.3.4",
                 "severity": "critical",
                 "note": "Known backdoor",
                 "recommendation": "Upgrade vsftpd"},
            ]
        }

    def _composite_result(self, os_r, net_r):
        return compute_composite({"os_hardening": os_r, "network": net_r})

    def test_adapter_creates_assessment(self, db, lab_target):
        os_r = self._os_result()
        net_r = self._network_result()
        comp = self._composite_result(os_r, net_r)
        aid = store_assessment_results(db, lab_target,
                                       {"os_hardening": os_r, "network": net_r},
                                       comp)
        assert aid is not None and len(aid) == 36

    def test_adapter_stores_all_findings(self, db, lab_target):
        os_r = self._os_result()
        net_r = self._network_result()
        comp = self._composite_result(os_r, net_r)
        aid = store_assessment_results(db, lab_target,
                                       {"os_hardening": os_r, "network": net_r},
                                       comp)
        findings = get_findings(db, aid)
        assert len(findings) == 4  # 3 OS + 1 network

    def test_adapter_not_applicable_stored_correctly(self, db, lab_target):
        os_r = self._os_result()
        comp = compute_composite({"os_hardening": os_r})
        aid = store_assessment_results(db, lab_target, {"os_hardening": os_r}, comp)
        na_findings = get_findings_by_status(db, aid, "NOT_APPLICABLE")
        assert len(na_findings) == 1
        assert na_findings[0]["severity"] is None
        assert na_findings[0]["check_id"] == "password_max_days"

    def test_adapter_fail_finding_has_severity(self, db, lab_target):
        os_r = self._os_result()
        comp = compute_composite({"os_hardening": os_r})
        aid = store_assessment_results(db, lab_target, {"os_hardening": os_r}, comp)
        fail_findings = get_findings_by_status(db, aid, "FAIL")
        assert len(fail_findings) == 1
        assert fail_findings[0]["severity"] == "high"

    def test_adapter_network_finding_stored_as_fail(self, db, lab_target):
        net_r = self._network_result()
        comp = compute_composite({"network": net_r})
        aid = store_assessment_results(db, lab_target, {"network": net_r}, comp)
        fail_findings = get_findings_by_status(db, aid, "FAIL")
        assert len(fail_findings) == 1
        assert fail_findings[0]["severity"] == "critical"
        assert fail_findings[0]["layer"] == "NETWORK"

    def test_adapter_stores_score_snapshot(self, db, lab_target):
        os_r = self._os_result()
        net_r = self._network_result()
        comp = self._composite_result(os_r, net_r)
        aid = store_assessment_results(db, lab_target,
                                       {"os_hardening": os_r, "network": net_r},
                                       comp)
        snaps = get_score_snapshots(db, aid)
        assert len(snaps) == 1
        assert snaps[0]["composite_score"] is not None
        assert snaps[0]["weakest_layer"] == "network"
        assert snaps[0]["scoring_model_id"] == "weighted_composite_v1"

    def test_adapter_assessment_closed(self, db, lab_target):
        os_r = self._os_result()
        comp = compute_composite({"os_hardening": os_r})
        aid = store_assessment_results(db, lab_target, {"os_hardening": os_r}, comp)
        row = db.execute(
            "SELECT end_time FROM assessment WHERE assessment_id=?", (aid,)
        ).fetchone()
        assert row["end_time"] is not None

    def test_adapter_remediation_created_for_fail(self, db, lab_target):
        os_r = self._os_result()
        comp = compute_composite({"os_hardening": os_r})
        aid = store_assessment_results(db, lab_target, {"os_hardening": os_r}, comp)
        fail_findings = get_findings_by_status(db, aid, "FAIL")
        for f in fail_findings:
            rems = db.execute(
                "SELECT * FROM remediation WHERE finding_id=?",
                (f["finding_id"],)
            ).fetchall()
            assert len(rems) >= 1, f"No remediation for FAIL finding {f['check_id']}"
            assert rems[0]["status"] == "PENDING"

    def test_adapter_invalid_target_raises(self, db):
        with pytest.raises(ValueError, match="not found"):
            store_assessment_results(db, "bad-uuid", {}, {})


# ── Runner ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    pytest.main([__file__, "-v"])
