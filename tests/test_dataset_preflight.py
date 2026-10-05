"""Tests for the read-only empirical-dataset provenance preflight."""
import hashlib
import json

from db.repository import (
    create_assessment,
    create_finding,
    create_score_snapshot,
    create_target,
)
from db.schema import initialize
from tools.generate_synthetic_dataset import generate
from tools.validate_research_dataset import validate_research_dataset


def _sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _authorized_dataset(tmp_path):
    database = tmp_path / "research.db"
    conn, _ = initialize(database)
    try:
        target_id = create_target(
            conn,
            "lab-target-01",
            "lab_vm",
            "lab",
            "LAB",
            authorization_ref="LAB-APPROVAL-001",
        )
        assessment_id = create_assessment(conn, target_id, "NETWORK", "LAB")
        create_finding(
            conn,
            assessment_id,
            "NETWORK",
            "port_443_https",
            "FAIL",
            "TLS configuration requires review",
            severity="medium",
            evidence="raw-scan-output: finding-1",
        )
        create_score_snapshot(
            conn,
            assessment_id,
            {"composite_score": 80, "layers": {"network": {"score": 80}}},
        )
    finally:
        conn.close()

    raw_output = tmp_path / "raw-network-output.txt"
    raw_output.write_text("controlled raw scan output\n", encoding="utf-8")
    manifest = tmp_path / "raw-output-manifest.json"
    manifest.write_text(json.dumps({
        "dataset_sha256": _sha256(database),
        "raw_artifacts": [{
            "assessment_id": assessment_id,
            "path": raw_output.name,
            "sha256": _sha256(raw_output),
        }],
    }), encoding="utf-8")
    return database, manifest


def test_authorized_dataset_and_manifest_are_ready_without_mutation(tmp_path):
    database, manifest = _authorized_dataset(tmp_path)
    before = database.read_bytes()
    report = validate_research_dataset(database, manifest)
    assert report["ready_for_empirical_analysis"] is True
    assert report["ready_for_paper_results"] is True
    assert database.read_bytes() == before


def test_missing_manifest_blocks_paper_readiness_not_analysis_readiness(tmp_path):
    database, _ = _authorized_dataset(tmp_path)
    report = validate_research_dataset(database)
    assert report["ready_for_empirical_analysis"] is True
    assert report["ready_for_paper_results"] is False
    assert any(check["id"] == "raw_output_manifest" for check in report["checks"])


def test_hash_mismatch_blocks_paper_readiness(tmp_path):
    database, manifest = _authorized_dataset(tmp_path)
    data = json.loads(manifest.read_text(encoding="utf-8"))
    data["dataset_sha256"] = "0" * 64
    manifest.write_text(json.dumps(data), encoding="utf-8")
    report = validate_research_dataset(database, manifest)
    assert report["ready_for_empirical_analysis"] is False
    assert report["ready_for_paper_results"] is False
    assert any(
        check["id"] == "manifest_database_hash" and check["status"] == "ERROR"
        for check in report["checks"]
    )


def test_synthetic_fixture_is_rejected_as_empirical_evidence(tmp_path):
    database, _ = generate(tmp_path / "synthetic.db")
    report = validate_research_dataset(database)
    assert report["ready_for_empirical_analysis"] is False
    assert any(
        check["id"] == "synthetic_data" and check["status"] == "ERROR"
        for check in report["checks"]
    )
