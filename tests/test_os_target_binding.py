"""Local OS observations require an explicit target ID for DB persistence."""

from unittest.mock import patch
import json

from db.adapters import store_assessment_results
from db.repository import create_target, get_assessment
from db.schema import initialize, seed_taxonomy
import main
from modules.scoring import compute_composite


def make_db():
    conn, _ = initialize(":memory:")
    seed_taxonomy(conn)
    return conn


def test_local_os_bind_requires_an_authorized_record(monkeypatch):
    conn = make_db()
    target_id = create_target(
        conn,
        alias="local-windows-study",
        target_type="workstation",
        environment="owned",
        authorization_status="OWNED",
        os_family="windows",
        os_name="Windows study host",
        authorization_ref="RESEARCHER-OWNERSHIP-APPROVAL-TEST",
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: "local-windows-study")
    assert main.bind_local_os_target(conn, "windows") == target_id

    monkeypatch.setattr("builtins.input", lambda _prompt: "unregistered-host")
    assert main.bind_local_os_target(conn, "windows") is None
    conn.close()


def test_local_os_bind_rejects_registered_family_mismatch(monkeypatch):
    conn = make_db()
    create_target(
        conn,
        alias="registered-linux-host",
        target_type="workstation",
        environment="owned",
        authorization_status="OWNED",
        os_family="linux",
        authorization_ref="RESEARCHER-OWNERSHIP-APPROVAL-TEST",
    )
    monkeypatch.setattr("builtins.input", lambda _prompt: "registered-linux-host")
    assert main.bind_local_os_target(conn, "windows") is None
    conn.close()


def test_cli_persists_os_only_run_when_binding_is_explicit(monkeypatch):
    conn = make_db()
    layer_result = {
        "layer": "os_hardening", "score": 80, "findings": [],
        "applicable_checks": 2, "total_checks": 2, "error_checks": 0,
    }
    monkeypatch.setattr("builtins.input", lambda _prompt: "1")
    with (
        patch.object(main, "get_db", return_value=conn),
        patch.object(main, "run_os_hardening", return_value=layer_result),
        patch.object(main, "bind_local_os_target", return_value="bound-target"),
        patch.object(main, "save_report"),
        patch.object(main, "_persist") as persist,
    ):
        main.main()
    persist.assert_called_once()
    assert persist.call_args.args[1] == "bound-target"
    conn.close()


def test_cli_local_os_run_is_report_only_without_binding(monkeypatch):
    conn = make_db()
    layer_result = {
        "layer": "os_hardening", "score": 80, "findings": [],
        "applicable_checks": 2, "total_checks": 2, "error_checks": 0,
    }
    monkeypatch.setattr("builtins.input", lambda _prompt: "1")
    with (
        patch.object(main, "get_db", return_value=conn),
        patch.object(main, "run_os_hardening", return_value=layer_result),
        patch.object(main, "bind_local_os_target", return_value=None),
        patch.object(main, "save_report"),
        patch.object(main, "_persist") as persist,
    ):
        main.main()
    persist.assert_not_called()
    conn.close()


def test_os_profile_context_and_version_persist_without_a_score_snapshot():
    conn = make_db()
    target_id = create_target(
        conn, alias="local-windows-study", target_type="workstation",
        environment="owned", authorization_status="OWNED",
        os_family="windows", os_version="11-build-26200",
        authorization_ref="LOCAL-OWNERSHIP-TEST-003",
    )
    os_result = {
        "layer": "os_hardening", "os_family": "windows",
        "platform_identity": {
            "system": "Windows", "display_version": "25H2",
            "edition_id": "CoreSingleLanguage", "current_build": "26200",
        },
        "platform_release": "11", "platform_version": "10.0.26200",
        "architecture": "AMD64", "control_profile": "windows_local_v1",
        "scoring_model_version": "1.3",
        "scoring_method": "severity_weighted_normalized_v1",
        "severity_weights": {"high": 3, "medium": 2, "low": 1},
        "score": None, "total_checks": 3, "applicable_checks": 2,
        "error_checks": 1, "not_applicable_checks": 0,
        "score_suppressed_reason": "One query returned ERROR.",
        "findings": [{
            "id": "windows_guest_account_disabled",
            "description": "Guest account is disabled",
            "status": "ERROR", "passed": False, "severity": "low",
            "recommendation": "Inspect account policy.",
            "not_applicable_reason": "Read-only query denied",
            "check_version": "windows_local_v1",
        }],
    }
    layers = {"os_hardening": os_result}
    composite = compute_composite(layers)
    assessment_id = store_assessment_results(
        conn, target_id, layers, composite
    )

    assessment = get_assessment(conn, assessment_id)
    metadata = json.loads(assessment["metadata_json"])
    assert metadata["layers"]["os_hardening"]["control_profile"] == "windows_local_v1"
    assert metadata["layers"]["os_hardening"]["platform_version"] == "10.0.26200"
    assert metadata["layers"]["os_hardening"]["platform_identity"]["display_version"] == "25H2"
    assert metadata["layers"]["os_hardening"]["error_checks"] == 1
    finding = conn.execute(
        "SELECT check_version, status FROM finding WHERE assessment_id=?",
        (assessment_id,),
    ).fetchone()
    assert finding["check_version"] == "windows_local_v1"
    assert finding["status"] == "ERROR"
    assert conn.execute(
        "SELECT COUNT(*) FROM score_snapshot WHERE assessment_id=?",
        (assessment_id,),
    ).fetchone()[0] == 0
    conn.close()
