"""Read-only provenance preflight for an empirical Security Scorer dataset.

This command never scans a target and never modifies the supplied SQLite
database or its raw-output manifest. It is deliberately strict about evidence
that must exist before a dataset can support empirical claims.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
from pathlib import Path

from analysis.common import open_readonly
from db.schema import AUTH_STATUSES, SCHEMA_VERSION

VALIDATOR_VERSION = "1.0.0"
SYNTHETIC_LABEL = "SYNTHETIC_FIXTURE_NOT_EMPIRICAL"
REQUIRED_TABLES = {
    "schema_migrations",
    "target",
    "target_identifier",
    "assessment",
    "finding",
    "score_snapshot",
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _check(check_id, status, message, **details):
    return {"id": check_id, "status": status, "message": message, **details}


def _add_database_checks(conn, database_path: Path, checks):
    tables = {
        row["name"] for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        )
    }
    missing_tables = sorted(REQUIRED_TABLES - tables)
    checks.append(_check(
        "required_tables",
        "PASS" if not missing_tables else "ERROR",
        "All required current-schema tables are present."
        if not missing_tables else "Required tables are missing.",
        missing_tables=missing_tables,
    ))
    if missing_tables:
        return {"tables": sorted(tables)}

    integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
    checks.append(_check(
        "sqlite_integrity",
        "PASS" if integrity == "ok" else "ERROR",
        "SQLite integrity check passed." if integrity == "ok" else integrity,
    ))

    migration = conn.execute(
        "SELECT MAX(version) AS version FROM schema_migrations"
    ).fetchone()["version"]
    observed_schema = (migration + 1) if migration is not None else 0
    checks.append(_check(
        "schema_version",
        "PASS" if observed_schema >= SCHEMA_VERSION else "ERROR",
        "Schema version is current." if observed_schema >= SCHEMA_VERSION
        else "Dataset schema is older than the current provenance controls.",
        observed=observed_schema,
        required=SCHEMA_VERSION,
    ))

    counts = {
        table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        for table in ("target", "target_identifier", "assessment", "finding", "score_snapshot")
    }
    for table in ("target", "assessment", "finding"):
        checks.append(_check(
            f"nonempty_{table}",
            "PASS" if counts[table] else "ERROR",
            f"{table} contains {counts[table]} record(s)."
            if counts[table] else f"{table} contains no records.",
            count=counts[table],
        ))
    checks.append(_check(
        "score_snapshots",
        "PASS" if counts["score_snapshot"] else "WARNING",
        f"score_snapshot contains {counts['score_snapshot']} record(s)."
        if counts["score_snapshot"] else "No derived score snapshots were found.",
        count=counts["score_snapshot"],
    ))

    synthetic_count = sum((
        conn.execute("SELECT COUNT(*) FROM target WHERE COALESCE(notes, '') LIKE ?", (f"%{SYNTHETIC_LABEL}%",)).fetchone()[0],
        conn.execute("SELECT COUNT(*) FROM assessment WHERE COALESCE(notes, '') LIKE ?", (f"%{SYNTHETIC_LABEL}%",)).fetchone()[0],
        conn.execute("SELECT COUNT(*) FROM finding WHERE COALESCE(detector_notes, '') LIKE ?", (f"%{SYNTHETIC_LABEL}%",)).fetchone()[0],
        conn.execute("SELECT COUNT(*) FROM score_snapshot WHERE COALESCE(notes, '') LIKE ? OR COALESCE(model_metadata, '') LIKE ?", (f"%{SYNTHETIC_LABEL}%", f"%{SYNTHETIC_LABEL}%")).fetchone()[0],
    ))
    checks.append(_check(
        "synthetic_data",
        "ERROR" if synthetic_count else "PASS",
        "Synthetic fixture markers were found; this database cannot support empirical claims."
        if synthetic_count else "No synthetic fixture markers were found.",
        marked_records=synthetic_count,
    ))

    invalid_statuses = conn.execute(
        "SELECT COUNT(*) FROM target WHERE authorization_status NOT IN ({})".format(
            ",".join("?" for _ in AUTH_STATUSES)
        ), AUTH_STATUSES,
    ).fetchone()[0]
    missing_references = conn.execute("""
        SELECT COUNT(*) FROM target
        WHERE authorization_ref IS NULL OR TRIM(authorization_ref) = ''
    """).fetchone()[0]
    unbound_targets = conn.execute("""
        SELECT COUNT(*) FROM target AS t
        WHERE NOT EXISTS (
            SELECT 1 FROM target_identifier AS ti WHERE ti.target_id = t.target_id
        )
    """).fetchone()[0]
    mismatched_assessments = conn.execute("""
        SELECT COUNT(*) FROM assessment AS a
        JOIN target AS t ON t.target_id = a.target_id
        WHERE a.authorization_status <> t.authorization_status
    """).fetchone()[0]
    findings_without_evidence = conn.execute("""
        SELECT COUNT(*) FROM finding
        WHERE evidence IS NULL OR TRIM(evidence) = ''
    """).fetchone()[0]
    for check_id, count, message in (
        ("valid_authorization_status", invalid_statuses, "Invalid target authorization status found."),
        ("authorization_reference", missing_references, "Target(s) missing authorization references."),
        ("explicit_target_identifier", unbound_targets, "Target(s) without explicit scan identifiers."),
        ("assessment_authorization_match", mismatched_assessments, "Assessment authorization does not match target authorization."),
        ("finding_evidence", findings_without_evidence, "Finding(s) missing raw evidence."),
    ):
        checks.append(_check(
            check_id,
            "ERROR" if count else "PASS",
            message if count else "Requirement satisfied.",
            affected_records=count,
        ))

    return {
        "tables": sorted(tables),
        "counts": counts,
        "database_filename": database_path.name,
        "database_sha256": _sha256(database_path),
    }


def _validate_manifest(manifest_path: Path, database_sha256: str, assessment_ids, checks):
    if not manifest_path.is_file():
        checks.append(_check(
            "raw_output_manifest", "ERROR", "Raw-output manifest is missing.",
            manifest_filename=manifest_path.name,
        ))
        return
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        checks.append(_check("raw_output_manifest", "ERROR", f"Invalid manifest: {error}"))
        return

    if manifest.get("dataset_sha256") != database_sha256:
        checks.append(_check(
            "manifest_database_hash", "ERROR", "Manifest database hash does not match the supplied database."
        ))
    else:
        checks.append(_check("manifest_database_hash", "PASS", "Manifest database hash matches."))

    artifacts = manifest.get("raw_artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        checks.append(_check("raw_artifacts", "ERROR", "Manifest has no raw artifacts."))
        return

    manifest_dir = manifest_path.parent.resolve()
    covered_assessments = set()
    artifact_errors = []
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            artifact_errors.append("Artifact entry is not an object")
            continue
        assessment_id = artifact.get("assessment_id")
        relative_path = artifact.get("path")
        expected_hash = artifact.get("sha256")
        if assessment_id not in assessment_ids:
            artifact_errors.append(f"Unknown assessment id: {assessment_id}")
            continue
        if not isinstance(relative_path, str) or not isinstance(expected_hash, str):
            artifact_errors.append(f"Malformed artifact for assessment {assessment_id}")
            continue
        candidate = (manifest_dir / relative_path).resolve()
        if manifest_dir not in candidate.parents or not candidate.is_file():
            artifact_errors.append(f"Missing or out-of-scope artifact for assessment {assessment_id}")
            continue
        if _sha256(candidate) != expected_hash.lower():
            artifact_errors.append(f"Hash mismatch for assessment {assessment_id}")
            continue
        covered_assessments.add(assessment_id)

    missing_coverage = sorted(assessment_ids - covered_assessments)
    if missing_coverage:
        artifact_errors.append("At least one assessment has no verified raw artifact")
    checks.append(_check(
        "raw_artifacts",
        "PASS" if not artifact_errors else "ERROR",
        "All raw artifacts are present, hash-verified, and cover every assessment."
        if not artifact_errors else "; ".join(artifact_errors),
        artifact_count=len(artifacts),
        covered_assessments=len(covered_assessments),
    ))


def validate_research_dataset(database_path, manifest_path=None):
    """Return a serializable, read-only dataset-provenance validation report."""
    path = Path(database_path).expanduser().resolve()
    checks = []
    report = {
        "validator_version": VALIDATOR_VERSION,
        "database_filename": path.name,
        "checks": checks,
    }
    if not path.is_file():
        checks.append(_check("database_exists", "ERROR", "Database file was not found."))
        report["ready_for_empirical_analysis"] = False
        report["ready_for_paper_results"] = False
        return report

    try:
        conn = open_readonly(path)
    except sqlite3.Error as error:
        checks.append(_check("database_open_readonly", "ERROR", str(error)))
        report["ready_for_empirical_analysis"] = False
        report["ready_for_paper_results"] = False
        return report

    try:
        checks.append(_check("database_open_readonly", "PASS", "Opened database read-only."))
        report.update(_add_database_checks(conn, path, checks))
        if manifest_path is None:
            checks.append(_check(
                "raw_output_manifest", "WARNING",
                "No raw-output manifest supplied; paper-result readiness cannot be established."
            ))
        elif "database_sha256" in report:
            assessment_ids = {
                row["assessment_id"] for row in conn.execute("SELECT assessment_id FROM assessment")
            }
            _validate_manifest(
                Path(manifest_path).expanduser().resolve(),
                report["database_sha256"], assessment_ids, checks,
            )
    finally:
        conn.close()

    errors = [check for check in checks if check["status"] == "ERROR"]
    report["ready_for_empirical_analysis"] = not errors
    report["ready_for_paper_results"] = not errors and any(
        check["id"] == "raw_artifacts" and check["status"] == "PASS"
        for check in checks
    )
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Validate an authorized Security Scorer database without modifying it."
    )
    parser.add_argument("--db", required=True, help="Path to a SQLite research database")
    parser.add_argument(
        "--manifest",
        help="Optional raw-output manifest; required for paper-result readiness",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON only")
    args = parser.parse_args()
    report = validate_research_dataset(args.db, args.manifest)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"Dataset: {report['database_filename']}")
        for check in report["checks"]:
            print(f"[{check['status']}] {check['id']}: {check['message']}")
        print(f"Ready for empirical analysis: {report['ready_for_empirical_analysis']}")
        print(f"Ready for paper results: {report['ready_for_paper_results']}")


if __name__ == "__main__":
    main()
