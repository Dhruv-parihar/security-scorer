"""Create a deterministic, clearly labelled synthetic research database.

This utility is only for exercising database and analysis code. It must never
be used as an empirical dataset or merged with authorized observations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from db.repository import create_assessment, create_finding, create_score_snapshot, create_target
from db.schema import initialize
from modules.scoring import compute_composite
from modules.scoring_config import SCORING_MODEL_VERSION

GENERATOR_VERSION = "1.0.0"
SYNTHETIC_LABEL = "SYNTHETIC_FIXTURE_NOT_EMPIRICAL"


def _store_assessment(conn, target_id, timestamp, layer_scores, findings, notes):
    assessment_id = create_assessment(
        conn,
        target_id,
        "ALL",
        "LAB",
        tool_version=f"synthetic-generator-{GENERATOR_VERSION}",
        methodology_version="synthetic-1.0",
        notes=f"{SYNTHETIC_LABEL}; {notes}",
    )
    conn.execute(
        "UPDATE assessment SET assessment_date=?, start_time=?, end_time=? WHERE assessment_id=?",
        (timestamp, timestamp, timestamp, assessment_id),
    )
    conn.commit()
    for layer, check_id, status, severity in findings:
        create_finding(
            conn,
            assessment_id,
            layer,
            check_id,
            status,
            f"Synthetic fixture observation for {check_id}",
            severity=severity,
            detector_notes=SYNTHETIC_LABEL,
        )
    composite = compute_composite({
        "os_hardening": {"score": layer_scores["os_hardening"]},
        "network": {"score": layer_scores["network"]},
        "webapp": {"score": layer_scores["webapp"]},
    })
    create_score_snapshot(
        conn,
        assessment_id,
        composite,
        scoring_model_ver=SCORING_MODEL_VERSION,
        model_metadata={"synthetic": True, "generator_version": GENERATOR_VERSION},
        notes=SYNTHETIC_LABEL,
    )
    return assessment_id


def generate(output_path, manifest_path=None):
    """Generate a new fixture DB and sidecar manifest without overwriting files."""
    output = Path(output_path).resolve()
    manifest = Path(manifest_path).resolve() if manifest_path else output.with_suffix(".manifest.json")
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite existing database: {output}")
    if manifest.exists():
        raise FileExistsError(f"Refusing to overwrite existing manifest: {manifest}")
    output.parent.mkdir(parents=True, exist_ok=True)
    conn, schema_version = initialize(str(output))
    try:
        target_a = create_target(
            conn, "synthetic-lab-a", "lab_vm", "synthetic", "LAB",
            notes=SYNTHETIC_LABEL,
        )
        _store_assessment(
            conn, target_a, "2026-01-10T09:00:00+00:00",
            {"os_hardening": 40, "network": 60, "webapp": 50},
            [
                ("OS", "ssh_root_login", "FAIL", "high"),
                ("OS", "firewall_active", "PASS", None),
                ("WEB", "header_content_security_policy", "FAIL", "medium"),
                ("WEB", "reflected_sqli_heuristic", "NOT_TESTED", None),
            ],
            "Baseline fixture assessment",
        )
        _store_assessment(
            conn, target_a, "2026-02-10T09:00:00+00:00",
            {"os_hardening": 80, "network": 60, "webapp": 50},
            [
                ("OS", "ssh_root_login", "PASS", None),
                ("OS", "firewall_active", "PASS", None),
                ("WEB", "header_content_security_policy", "FAIL", "medium"),
                ("WEB", "reflected_sqli_heuristic", "ERROR", None),
            ],
            "Follow-up fixture assessment",
        )
        target_b = create_target(
            conn, "synthetic-lab-b", "web_app", "synthetic", "LAB",
            notes=SYNTHETIC_LABEL,
        )
        _store_assessment(
            conn, target_b, "2026-01-20T09:00:00+00:00",
            {"os_hardening": 100, "network": 80, "webapp": 70},
            [
                ("OS", "ssh_root_login", "PASS", None),
                ("NETWORK", "port_443_https", "FAIL", "low"),
                ("WEB", "header_content_security_policy", "PASS", None),
            ],
            "Single fixture assessment",
        )
    finally:
        conn.close()
    database_sha256 = hashlib.sha256(output.read_bytes()).hexdigest()
    manifest.write_text(json.dumps({
        "label": SYNTHETIC_LABEL,
        "generator_version": GENERATOR_VERSION,
        "schema_version": schema_version,
        "database_file": output.name,
        "database_sha256": database_sha256,
        "target_count": 2,
        "assessment_count": 3,
        "purpose": "Deterministic analysis and test fixture only; not empirical evidence.",
    }, indent=2) + "\n", encoding="utf-8")
    return output, manifest


def main():
    parser = argparse.ArgumentParser(description="Generate a non-empirical fixture database")
    parser.add_argument("--output", required=True, help="New SQLite output path; must not exist")
    parser.add_argument("--manifest", help="New JSON manifest path; defaults beside the database")
    args = parser.parse_args()
    database, manifest = generate(args.output, args.manifest)
    print(f"Created synthetic fixture database: {database}")
    print(f"Created synthetic fixture manifest: {manifest}")


if __name__ == "__main__":
    main()
