"""Tests for the approved scoring, TLS, and dashboard improvements."""
import json
import socket
import ssl

import pytest

from modules.os_hardening import _fail, _not_applicable, _pass, calculate_score
from modules.webapp_scan import _check_tls


def test_os_severity_weighted_score_gives_high_findings_more_weight():
    findings = [
        _fail("high_check", "High", "high", "fix"),
        _pass("low_check", "Low", "low", "fix"),
    ]
    assert calculate_score(findings) == 25


def test_os_score_excludes_unevaluated_checks_and_returns_none_if_empty():
    assert calculate_score([
        _pass("medium_check", "Medium", "medium", "fix"),
        _not_applicable("na_check", "N/A", "Not relevant"),
    ]) == 100
    assert calculate_score([_not_applicable("na", "N/A", "Not relevant")]) is None


def test_os_score_rejects_unknown_severity_for_evaluated_check():
    with pytest.raises(ValueError, match="unsupported severity"):
        calculate_score([_pass("bad", "Bad", "critical", "fix")])


def test_http_tls_checks_fail_transport_and_exclude_certificate_checks():
    findings = {item["id"]: item for item in _check_tls("http://lab.example.test/")}
    assert findings["https_transport"]["status"] == "FAIL"
    assert findings["tls_certificate_valid"]["status"] == "NOT_APPLICABLE"
    assert findings["tls_protocol_version"]["status"] == "NOT_APPLICABLE"


def test_invalid_https_port_is_reported_as_error_not_uncaught_exception():
    findings = {item["id"]: item for item in _check_tls("https://lab.example.test:notaport/")}
    assert {finding["status"] for finding in findings.values()} == {"ERROR"}


def test_https_tls_records_verified_protocol(monkeypatch):
    class FakeTLSSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def version(self):
            return "TLSv1.3"

    class FakeContext:
        def wrap_socket(self, raw, server_hostname):
            assert server_hostname == "lab.example.test"
            return FakeTLSSocket()

    class FakeRawSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    monkeypatch.setattr(ssl, "create_default_context", lambda: FakeContext())
    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: FakeRawSocket())
    findings = {item["id"]: item for item in _check_tls("https://lab.example.test/")}
    assert findings["https_transport"]["status"] == "PASS"
    assert findings["tls_certificate_valid"]["status"] == "PASS"
    assert findings["tls_protocol_version"]["status"] == "PASS"
    assert findings["tls_protocol_version"]["evidence"] == "Negotiated protocol: TLSv1.3"
    assert findings["tls_protocol_version"]["check_version"] == "1.0"


def test_https_certificate_error_is_fail_but_other_tls_checks_are_not_assumed():
    class FakeContext:
        def wrap_socket(self, *_args, **_kwargs):
            raise ssl.SSLCertVerificationError(1, "certificate verify failed")

    class FakeRawSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    from unittest.mock import patch
    with patch("modules.webapp_scan.ssl.create_default_context", return_value=FakeContext()), \
         patch("modules.webapp_scan.socket.create_connection", return_value=FakeRawSocket()):
        findings = {item["id"]: item for item in _check_tls("https://lab.example.test/")}
    assert findings["tls_certificate_valid"]["status"] == "FAIL"
    assert findings["https_transport"]["status"] == "ERROR"
    assert findings["tls_protocol_version"]["status"] == "ERROR"


def test_research_dashboard_reads_aggregate_data_without_exposing_target_alias(tmp_path, monkeypatch):
    from db.adapters import store_assessment_results
    from db.repository import create_target
    from db.schema import initialize, seed_taxonomy
    import app as app_module

    db_path = tmp_path / "dashboard.sqlite"
    conn, _ = initialize(str(db_path))
    seed_taxonomy(conn)
    target_id = create_target(
        conn,
        alias="private-lab-alias-should-not-render",
        target_type="lab_vm",
        environment="lab",
        authorization_status="LAB",
        authorization_ref="TEST-AUTH-REF",
    )
    web = {
        "layer": "webapp",
        "score": 75,
        "findings": [{
            "id": "https_transport", "description": "HTTPS transport",
            "status": "FAIL", "passed": False, "severity": "high",
            "recommendation": "Use HTTPS", "check_version": "1.0",
        }],
    }
    from modules.scoring import compute_composite
    store_assessment_results(conn, target_id, {"webapp": web}, compute_composite({"webapp": web}))
    before = conn.execute("SELECT COUNT(*) FROM assessment").fetchone()[0]
    stored_check_version = conn.execute(
        "SELECT check_version FROM finding WHERE check_id='https_transport'"
    ).fetchone()[0]
    snapshot = conn.execute(
        "SELECT scoring_model_ver, model_metadata FROM score_snapshot"
    ).fetchone()
    conn.close()
    assert stored_check_version == "1.0"
    assert snapshot["scoring_model_ver"] == "1.2"
    metadata = json.loads(snapshot["model_metadata"])
    assert metadata["os_scoring_method"] == "severity_weighted_normalized_v1"

    monkeypatch.setattr(app_module, "DB_PATH", str(db_path))
    app_module.app.config["TESTING"] = True
    response = app_module.app.test_client().get("/research")
    assert response.status_code == 200
    assert b"1</strong>" in response.data and b"Assessments" in response.data
    assert b"WEB" in response.data and b"100.0%" in response.data
    assert b"private-lab-alias-should-not-render" not in response.data

    verify, _ = initialize(str(db_path))
    assert verify.execute("SELECT COUNT(*) FROM assessment").fetchone()[0] == before
    verify.close()


def test_research_dashboard_missing_db_does_not_create_it(tmp_path, monkeypatch):
    import app as app_module

    db_path = tmp_path / "not-created.sqlite"
    monkeypatch.setattr(app_module, "DB_PATH", str(db_path))
    app_module.app.config["TESTING"] = True
    response = app_module.app.test_client().get("/research")
    assert response.status_code == 200
    assert b"No local research database was found" in response.data
    assert not db_path.exists()
