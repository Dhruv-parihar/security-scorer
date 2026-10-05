"""Tests for the read-only controlled-lab ground-truth evaluator."""
import hashlib
import json

from db.repository import create_assessment, create_finding, create_target
from db.schema import initialize
from tools.evaluate_controlled_validation import (
    GROUND_TRUTH_LABEL,
    evaluate_controlled_validation,
)


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _controlled_dataset(tmp_path, *, duplicate_observation=False):
    database = tmp_path / "controlled-lab.db"
    conn, _ = initialize(database)
    try:
        target_id = create_target(
            conn,
            "controlled-lab-target",
            "lab_vm",
            "lab",
            "LAB",
            authorization_ref="LAB-APPROVAL-VALIDATION-001",
        )
        assessment_id = create_assessment(conn, target_id, "ALL", "LAB")
        create_finding(
            conn,
            assessment_id,
            "WEB",
            "reflected_sqli_heuristic",
            "FAIL",
            "Controlled lab response reflects the SQLi probe.",
            severity="high",
            evidence="raw-web-output: reflected-sqli",
        )
        create_finding(
            conn,
            assessment_id,
            "WEB",
            "header_content_security_policy",
            "PASS",
            "Controlled lab response has a Content-Security-Policy header.",
            evidence="raw-web-output: content-security-policy",
        )
        if duplicate_observation:
            create_finding(
                conn,
                assessment_id,
                "WEB",
                "header_content_security_policy",
                "PASS",
                "Duplicate fixture observation.",
                evidence="raw-web-output: duplicate-content-security-policy",
            )
    finally:
        conn.close()

    raw_output = tmp_path / "controlled-raw-output.txt"
    raw_output.write_text("controlled lab raw output\n", encoding="utf-8")
    raw_manifest = tmp_path / "raw-output-manifest.json"
    raw_manifest.write_text(json.dumps({
        "dataset_sha256": _sha256(database),
        "raw_artifacts": [{
            "assessment_id": assessment_id,
            "path": raw_output.name,
            "sha256": _sha256(raw_output),
        }],
    }), encoding="utf-8")
    ground_truth = tmp_path / "controlled-ground-truth.json"
    ground_truth.write_text(json.dumps({
        "label": GROUND_TRUTH_LABEL,
        "protocol_id": "controlled-lab-protocol-001",
        "dataset_sha256": _sha256(database),
        "cases": [
            {
                "assessment_id": assessment_id,
                "layer": "WEB",
                "check_id": "reflected_sqli_heuristic",
                "ground_truth_status": "FAIL",
                "rationale": "The local fixture intentionally reflects the probe in its response body.",
                "evidence_ref": "controlled-raw-output.txt#reflected-sqli",
            },
            {
                "assessment_id": assessment_id,
                "layer": "WEB",
                "check_id": "header_content_security_policy",
                "ground_truth_status": "PASS",
                "rationale": "The local fixture explicitly emits the header before the assessment.",
                "evidence_ref": "controlled-raw-output.txt#content-security-policy",
            },
        ],
    }), encoding="utf-8")
    return database, raw_manifest, ground_truth


def _errors(report):
    return {check["id"] for check in report["checks"] if check["status"] == "ERROR"}


def test_controlled_validation_reports_perfect_labelled_cases_without_mutation(tmp_path):
    database, raw_manifest, ground_truth = _controlled_dataset(tmp_path)
    before = database.read_bytes()
    report = evaluate_controlled_validation(database, raw_manifest, ground_truth)

    assert report["ready_for_validation_results"] is True
    assert report["summary"]["confusion_matrix"] == {
        "true_positive": 1,
        "false_positive": 0,
        "false_negative": 0,
        "true_negative": 1,
    }
    assert report["summary"]["metrics"] == {
        "sensitivity": 1.0,
        "specificity": 1.0,
        "precision": 1.0,
        "negative_predictive_value": 1.0,
        "accuracy": 1.0,
    }
    assert database.read_bytes() == before


def test_controlled_validation_reports_false_positive_and_false_negative(tmp_path):
    database, raw_manifest, ground_truth = _controlled_dataset(tmp_path)
    document = json.loads(ground_truth.read_text(encoding="utf-8"))
    document["cases"][0]["ground_truth_status"] = "PASS"
    document["cases"][1]["ground_truth_status"] = "FAIL"
    ground_truth.write_text(json.dumps(document), encoding="utf-8")

    report = evaluate_controlled_validation(database, raw_manifest, ground_truth)

    assert report["ready_for_validation_results"] is True
    assert report["summary"]["confusion_matrix"] == {
        "true_positive": 0,
        "false_positive": 1,
        "false_negative": 1,
        "true_negative": 0,
    }
    assert report["summary"]["metrics"]["sensitivity"] == 0.0
    assert report["summary"]["metrics"]["specificity"] == 0.0


def test_controlled_validation_rejects_unlabelled_evaluated_observation(tmp_path):
    database, raw_manifest, ground_truth = _controlled_dataset(tmp_path)
    document = json.loads(ground_truth.read_text(encoding="utf-8"))
    document["cases"].pop()
    ground_truth.write_text(json.dumps(document), encoding="utf-8")

    report = evaluate_controlled_validation(database, raw_manifest, ground_truth)

    assert report["ready_for_validation_results"] is False
    assert "ground_truth_coverage" in _errors(report)
    assert "summary" not in report


def test_controlled_validation_rejects_duplicate_observations(tmp_path):
    database, raw_manifest, ground_truth = _controlled_dataset(
        tmp_path, duplicate_observation=True
    )

    report = evaluate_controlled_validation(database, raw_manifest, ground_truth)

    assert report["ready_for_validation_results"] is False
    assert "unique_observations" in _errors(report)
    assert "summary" not in report


def test_controlled_validation_withholds_metrics_when_preflight_fails(tmp_path):
    database, raw_manifest, ground_truth = _controlled_dataset(tmp_path)
    manifest = json.loads(raw_manifest.read_text(encoding="utf-8"))
    manifest["dataset_sha256"] = "0" * 64
    raw_manifest.write_text(json.dumps(manifest), encoding="utf-8")

    report = evaluate_controlled_validation(database, raw_manifest, ground_truth)

    assert report["ready_for_validation_results"] is False
    assert "provenance_preflight" in _errors(report)
    assert "summary" not in report
