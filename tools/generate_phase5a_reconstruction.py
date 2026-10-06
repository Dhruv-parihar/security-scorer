"""Create a traceable, non-empirical reconstruction of the legacy Phase 5A case study.

The original Phase 5A result bundle retained derived results but not its source
database, raw scanner outputs, authorization references, or a same-target
before/after assessment. This command reconstructs the six case records from
the retained documentation and result summary. It never performs a scan.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from analysis.longitudinal import run_longitudinal_analysis
from analysis.prevalence import run_full_analysis as run_prevalence
from analysis.scoring_sensitivity import WEIGHT_SCENARIOS, run_full_analysis as run_sensitivity
from db.adapters import store_assessment_results
from db.repository import create_target
from db.schema import initialize, seed_taxonomy
from modules.scoring import compute_composite
from tools.validate_research_dataset import RECONSTRUCTED_LABEL, validate_research_dataset

GENERATOR_VERSION = "1.0.0"
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _source(description):
    return f"{RECONSTRUCTED_LABEL}; {description}"


def _finding(check_id, status, severity, source):
    return {
        "id": check_id,
        "description": check_id.replace("_", " "),
        "passed": status == "PASS",
        "status": status,
        "severity": severity,
        "recommendation": None,
        "not_applicable_reason": (
            "Not applicable in the retained case-study record"
            if status == "NOT_APPLICABLE" else None
        ),
        "evidence": source,
    }


def _network(port, service, severity, source):
    return {
        "port": str(port),
        "service": service,
        "severity": severity,
        "note": f"Legacy reconstructed network observation: {service} on {port}",
        "recommendation": None,
        "evidence": source,
    }


def _cases():
    lab = _source(
        "Retained project documentation: docs/02-os-hardening.md, "
        "docs/03-network-scan.md, docs/04-composite-scan.md, and screenshots."
    )
    windows = _source(
        "Retained project documentation: docs/02-os-hardening.md and "
        "screenshots/02-cli-os-hardening/01-os-hardening-result.png."
    )
    legacy = _source(
        "Legacy result-summary value. Original raw output and authorization "
        "reference are not retained in the tracked repository."
    )
    return [
        {
            "alias": "metasploitable-2-lab-01",
            "target_type": "lab_vm",
            "environment": "lab",
            "authorization_status": "LAB",
            "os_family": "linux",
            "os_name": "Ubuntu 8.04",
            "timestamp": "2026-09-27T09:00:00+00:00",
            "layers": {
                "os_hardening": {
                    "score": 50,
                    "findings": [
                        _finding("ssh_root_login", "FAIL", "high", lab),
                        _finding("password_max_days", "FAIL", "medium", lab),
                        _finding("firewall_active", "PASS", "high", lab),
                        _finding("world_writable_files", "PASS", "medium", lab),
                        _finding("automatic_updates", "FAIL", "medium", lab),
                        _finding("guest_account_disabled", "NOT_APPLICABLE", None, lab),
                    ],
                },
                "network": {
                    "score": 0,
                    "findings": [
                        _network(21, "ftp", "critical", lab),
                        _network(6667, "irc", "critical", lab),
                        _network(22, "ssh", "high", lab),
                        _network(23, "telnet", "high", lab),
                        _network(139, "netbios-ssn", "high", lab),
                        _network(2121, "ftp", "high", lab),
                        _network(3306, "mysql", "medium", lab),
                        _network(445, "netbios-ssn", "high", lab),
                        _network(5900, "vnc", "medium", lab),
                        _network(80, "http", "medium", lab),
                    ],
                },
                "webapp": {
                    "score": 50,
                    "findings": [
                        _finding("header_content_security_policy", "FAIL", "medium", lab),
                        _finding("header_x_frame_options", "FAIL", "medium", legacy),
                        _finding("header_strict_transport_security", "FAIL", "low", legacy),
                        _finding("header_x_content_type_options", "FAIL", "low", legacy),
                        _finding("cookie_security_httponly", "FAIL", "medium", legacy),
                        _finding("cookie_security_secure", "FAIL", "medium", legacy),
                        _finding("reflected_sqli_heuristic", "PASS", None, lab),
                        _finding("reflected_xss_heuristic", "PASS", None, legacy),
                    ],
                },
            },
        },
        {
            "alias": "windows-host-baseline",
            "target_type": "workstation",
            "environment": "owned",
            "authorization_status": "OWNED",
            "os_family": "windows",
            "os_name": "Windows 11",
            "timestamp": "2026-09-27T10:00:00+00:00",
            "layers": {
                "os_hardening": {
                    "score": 33,
                    "findings": [
                        _finding("world_writable_files", "PASS", "medium", windows),
                        _finding("guest_account_disabled", "PASS", "low", windows),
                        _finding("ssh_root_login", "NOT_APPLICABLE", None, windows),
                        _finding("password_max_days", "NOT_APPLICABLE", None, windows),
                        _finding("firewall_active", "NOT_APPLICABLE", None, windows),
                        _finding("automatic_updates", "NOT_APPLICABLE", None, windows),
                    ],
                },
            },
        },
        {
            "alias": "parrot-os-hardened",
            "target_type": "workstation",
            "environment": "owned",
            "authorization_status": "OWNED",
            "os_family": "linux",
            "os_name": "Parrot OS",
            "timestamp": "2026-09-27T11:00:00+00:00",
            "layers": {
                "os_hardening": {
                    "score": 100,
                    "findings": [
                        _finding("ssh_root_login", "PASS", "high", legacy),
                        _finding("password_max_days", "PASS", "medium", legacy),
                        _finding("firewall_active", "PASS", "high", legacy),
                        _finding("world_writable_files", "PASS", "medium", legacy),
                        _finding("automatic_updates", "PASS", "medium", legacy),
                        _finding("guest_account_disabled", "PASS", "low", legacy),
                    ],
                },
            },
        },
        {
            "alias": "university-website-public",
            "target_type": "web_app",
            "environment": "consented",
            "authorization_status": "CONSENTED_RESEARCH",
            "os_family": "unknown",
            "os_name": None,
            "timestamp": "2026-09-27T12:00:00+00:00",
            "layers": {
                "webapp": {
                    "score": 90,
                    "findings": [
                        _finding("header_content_security_policy", "FAIL", "medium", legacy),
                        _finding("header_x_frame_options", "PASS", "medium", legacy),
                        _finding("header_strict_transport_security", "PASS", "low", legacy),
                        _finding("header_x_content_type_options", "PASS", "low", legacy),
                    ],
                },
            },
        },
        {
            "alias": "inxt-student-portal",
            "target_type": "web_app",
            "environment": "consented",
            "authorization_status": "CONSENTED_RESEARCH",
            "os_family": "unknown",
            "os_name": None,
            "timestamp": "2026-09-27T13:00:00+00:00",
            "layers": {
                "webapp": {
                    "score": 70,
                    "findings": [
                        _finding("header_content_security_policy", "FAIL", "medium", legacy),
                        _finding("header_x_frame_options", "FAIL", "medium", legacy),
                        _finding("header_strict_transport_security", "FAIL", "low", legacy),
                        _finding("header_x_content_type_options", "FAIL", "low", legacy),
                    ],
                },
            },
        },
        {
            "alias": "home-router-consumer",
            "target_type": "network_device",
            "environment": "owned",
            "authorization_status": "OWNED",
            "os_family": "unknown",
            "os_name": None,
            "timestamp": "2026-09-27T14:00:00+00:00",
            "layers": {"network": {"score": 100, "findings": []}},
        },
    ]


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _figure_data(prevalence, sensitivity):
    layers = prevalence["layer_prevalence"]
    top = prevalence["finding_prevalence"][:10]
    stats = sensitivity["summary"]["scenario_stats"]
    scenarios = [scenario_id for scenario_id, _, _ in WEIGHT_SCENARIOS]
    severity = prevalence["severity_distribution"]["severity_counts"]
    severity_order = [name for name in ("critical", "high", "medium", "low") if name in severity]
    return {
        "layer_prevalence_chart": {
            "labels": [row["layer"] for row in layers],
            "fail_pct": [row["overall_fail_pct"] for row in layers],
            "total_evaluations": [row["total_check_evaluations"] for row in layers],
        },
        "top_findings_chart": {
            "labels": [row["check_id"] for row in top],
            "fail_pct": [row["fail_pct"] for row in top],
            "n_applicable": [row["n_applicable"] for row in top],
            "layer": [row["layer"] for row in top],
        },
        "severity_distribution_chart": {
            "labels": severity_order,
            "counts": [severity[name] for name in severity_order],
        },
        "sensitivity_range_chart": {
            "scenarios": scenarios,
            "min_composite": [stats[name]["min_composite"] for name in scenarios],
            "max_composite": [stats[name]["max_composite"] for name in scenarios],
            "assessment_count": [stats[name]["assessment_count"] for name in scenarios],
        },
    }


def _source_manifest(database, cases):
    sources = [
        "docs/02-os-hardening.md",
        "docs/03-network-scan.md",
        "docs/04-composite-scan.md",
        "screenshots/02-cli-os-hardening/01-os-hardening-result.png",
        "screenshots/03-cli-full-composite/04-network-scan-result.png",
        "screenshots/03-cli-full-composite/05-composite-result.png",
    ]
    retained = []
    for relative in sources:
        candidate = PROJECT_ROOT / relative
        retained.append({
            "path": relative,
            "present": candidate.is_file(),
            "sha256": _sha256(candidate) if candidate.is_file() else None,
        })
    return {
        "generator_version": GENERATOR_VERSION,
        "classification": RECONSTRUCTED_LABEL,
        "database_file": database.name,
        "database_sha256": _sha256(database),
        "case_count": len(cases),
        "retained_repository_sources": retained,
        "not_retained": [
            "Original raw scanner outputs for the two external web targets.",
            "Original authorization references for every target.",
            "A same-target pre-remediation assessment for parrot-os-hardened.",
        ],
        "allowed_claim": (
            "Reconstructed legacy case-study calculations only; not empirical "
            "prevalence, accuracy, authorization, or remediation-effect evidence."
        ),
    }


def _readme():
    return """# Reconstructed Phase 5A Case Study

Classification: RECONSTRUCTED_LEGACY_CASE_STUDY_NOT_EMPIRICALLY_VERIFIED

The original Phase 5A bundle did not retain its source database, raw scanner
outputs, authorization references, or a same-target before/after Parrot
assessment. This reconstruction makes its historical calculations rerunnable,
but it is not an empirical dataset.

The provenance preflight is expected to fail for paper-result readiness. Do not
remove the marker or use this output for prevalence, accuracy, authorization,
or remediation-effect claims.
"""


def generate(output_dir):
    """Create a fresh bundle and refuse to overwrite an existing directory."""
    output = Path(output_dir).expanduser().resolve()
    if output.exists():
        raise FileExistsError(f"Refusing to overwrite existing output directory: {output}")
    output.mkdir(parents=True)
    database = output / "phase5a-reconstructed.db"
    cases = _cases()
    conn, _ = initialize(database)
    try:
        seed_taxonomy(conn)
        for case in cases:
            target_id = create_target(
                conn,
                case["alias"],
                case["target_type"],
                case["environment"],
                case["authorization_status"],
                os_family=case["os_family"],
                os_name=case["os_name"],
                notes=(
                    f"{RECONSTRUCTED_LABEL}; source status is recorded in "
                    "reconstruction-manifest.json"
                ),
            )
            assessment_id = store_assessment_results(
                conn,
                target_id,
                case["layers"],
                compute_composite(case["layers"]),
                tool_version=f"phase5a-reconstruction-{GENERATOR_VERSION}",
                methodology_version="reconstructed-legacy-1.0",
                notes=(
                    f"{RECONSTRUCTED_LABEL}; no raw scanner output or "
                    "authorization reference retained."
                ),
            )
            conn.execute(
                "UPDATE assessment SET assessment_date=?, start_time=?, end_time=? WHERE assessment_id=?",
                (case["timestamp"], case["timestamp"], case["timestamp"], assessment_id),
            )
            conn.commit()
        prevalence = run_prevalence(conn)
        sensitivity = run_sensitivity(conn, include_sweep=False)
        longitudinal = run_longitudinal_analysis(conn)
    finally:
        conn.close()

    _write_json(output / "prevalence_results.json", prevalence)
    _write_json(output / "cooccurrence_results.json", {
        "analysis_version": prevalence["analysis_version"],
        "empirical_limitation": prevalence["empirical_limitation"],
        "causal_inference_warning": prevalence["causal_inference_warning"],
        "denominator_definitions": prevalence["denominator_definitions"],
        "cooccurrence": prevalence["cooccurrence"],
    })
    _write_json(output / "sensitivity_results.json", sensitivity)
    _write_json(output / "longitudinal_results.json", longitudinal)
    _write_json(output / "figure_data.json", _figure_data(prevalence, sensitivity))
    _write_json(output / "reconstruction-manifest.json", _source_manifest(database, cases))
    _write_json(output / "provenance-preflight.json", validate_research_dataset(database))
    (output / "README.md").write_text(_readme(), encoding="utf-8")
    return output


def main():
    parser = argparse.ArgumentParser(
        description="Create a labelled non-empirical legacy Phase 5A reconstruction."
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="New directory to create; it must not already exist.",
    )
    args = parser.parse_args()
    print(f"Created reconstructed Phase 5A bundle: {generate(args.output_dir)}")


if __name__ == "__main__":
    main()
