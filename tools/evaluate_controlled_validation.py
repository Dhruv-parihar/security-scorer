"""Evaluate labelled controlled-lab detector cases without scanning or writing.

This tool compares PASS/FAIL observations in a preflight-approved research
database against a separately reviewed controlled-lab ground-truth file. It
does not create ground truth, alter a database, or make claims about a broader
population. A result is ready only when provenance is complete and every
evaluated observation is explicitly labelled.
"""
from __future__ import annotations

import argparse
import json
import sqlite3
from collections import Counter, defaultdict
from pathlib import Path

from analysis.common import open_readonly
from db.schema import FINDING_LAYERS
from tools.validate_research_dataset import validate_research_dataset

EVALUATOR_VERSION = "1.0.0"
GROUND_TRUTH_LABEL = "CONTROLLED_LAB_GROUND_TRUTH"
COMPARABLE_STATUSES = ("PASS", "FAIL")


def _check(check_id, status, message, **details):
    return {"id": check_id, "status": status, "message": message, **details}


def _case_key(case):
    return (case["assessment_id"], case["layer"], case["check_id"])


def _rate(numerator, denominator):
    return round(numerator / denominator, 6) if denominator else None


def _summary(rows):
    matrix = Counter()
    for row in rows:
        expected_fail = row["ground_truth_status"] == "FAIL"
        observed_fail = row["observed_status"] == "FAIL"
        if expected_fail and observed_fail:
            matrix["true_positive"] += 1
        elif expected_fail:
            matrix["false_negative"] += 1
        elif observed_fail:
            matrix["false_positive"] += 1
        else:
            matrix["true_negative"] += 1
    tp = matrix["true_positive"]
    fp = matrix["false_positive"]
    fn = matrix["false_negative"]
    tn = matrix["true_negative"]
    total = tp + fp + fn + tn
    return {
        "case_count": total,
        "confusion_matrix": {
            "true_positive": tp,
            "false_positive": fp,
            "false_negative": fn,
            "true_negative": tn,
        },
        "metrics": {
            "sensitivity": _rate(tp, tp + fn),
            "specificity": _rate(tn, tn + fp),
            "precision": _rate(tp, tp + fp),
            "negative_predictive_value": _rate(tn, tn + fn),
            "accuracy": _rate(tp + tn, total),
        },
    }


def _load_ground_truth(path, database_sha256, checks):
    if not path.is_file():
        checks.append(_check(
            "ground_truth_file", "ERROR", "Controlled-lab ground-truth file is missing.",
            filename=path.name,
        ))
        return {}
    try:
        ground_truth = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        checks.append(_check("ground_truth_file", "ERROR", f"Invalid ground-truth file: {error}"))
        return {}
    if not isinstance(ground_truth, dict):
        checks.append(_check("ground_truth_file", "ERROR", "Ground truth must be a JSON object."))
        return {}

    checks.append(_check(
        "ground_truth_label",
        "PASS" if ground_truth.get("label") == GROUND_TRUTH_LABEL else "ERROR",
        "Controlled-lab ground-truth label is present."
        if ground_truth.get("label") == GROUND_TRUTH_LABEL
        else "Ground truth is missing the required controlled-lab label.",
    ))
    protocol_id = ground_truth.get("protocol_id")
    checks.append(_check(
        "ground_truth_protocol",
        "PASS" if isinstance(protocol_id, str) and protocol_id.strip() else "ERROR",
        "Controlled-lab protocol identifier is present."
        if isinstance(protocol_id, str) and protocol_id.strip()
        else "Ground truth requires a non-empty protocol_id.",
    ))
    checks.append(_check(
        "ground_truth_database_hash",
        "PASS" if ground_truth.get("dataset_sha256") == database_sha256 else "ERROR",
        "Ground truth is bound to the supplied database hash."
        if ground_truth.get("dataset_sha256") == database_sha256
        else "Ground-truth database hash does not match the supplied database.",
    ))
    return ground_truth


def _validate_cases(cases, checks):
    if not isinstance(cases, list) or not cases:
        checks.append(_check("ground_truth_cases", "ERROR", "Ground truth has no cases."))
        return {}
    parsed = {}
    errors = []
    for position, case in enumerate(cases, start=1):
        if not isinstance(case, dict):
            errors.append(f"case {position} is not an object")
            continue
        required_strings = ("assessment_id", "layer", "check_id", "ground_truth_status", "rationale", "evidence_ref")
        missing = [field for field in required_strings if not isinstance(case.get(field), str) or not case[field].strip()]
        if missing:
            errors.append(f"case {position} is missing {', '.join(missing)}")
            continue
        if case["layer"] not in FINDING_LAYERS:
            errors.append(f"case {position} has invalid layer {case['layer']!r}")
            continue
        if case["ground_truth_status"] not in COMPARABLE_STATUSES:
            errors.append(f"case {position} has non-comparable ground_truth_status")
            continue
        key = _case_key(case)
        if key in parsed:
            errors.append(f"duplicate ground-truth case for {key}")
            continue
        parsed[key] = case
    checks.append(_check(
        "ground_truth_cases",
        "PASS" if not errors else "ERROR",
        "Ground-truth cases are complete and uniquely identified."
        if not errors else "; ".join(errors),
        case_count=len(parsed),
    ))
    return parsed


def _read_observations(database_path, checks):
    try:
        conn = open_readonly(database_path)
    except sqlite3.Error as error:
        checks.append(_check("observations_open_readonly", "ERROR", str(error)))
        return {}
    try:
        rows = conn.execute("""
            SELECT assessment_id, layer, check_id, status
            FROM finding
            ORDER BY assessment_id, layer, check_id, finding_id
        """).fetchall()
    finally:
        conn.close()
    grouped = defaultdict(list)
    for row in rows:
        grouped[(row["assessment_id"], row["layer"], row["check_id"])].append(row["status"])
    checks.append(_check(
        "observations_open_readonly", "PASS", "Observations were read without modifying the database.",
        finding_count=len(rows),
    ))
    return grouped


def evaluate_controlled_validation(database_path, raw_manifest_path, ground_truth_path):
    """Return a serializable controlled-lab validation report.

    ``raw_manifest_path`` is required: this evaluator refuses to compute
    publishable validation metrics unless the data-provenance preflight reports
    that every assessment has hash-verified raw output.
    """
    database = Path(database_path).expanduser().resolve()
    checks = []
    report = {
        "evaluator_version": EVALUATOR_VERSION,
        "database_filename": database.name,
        "checks": checks,
        "ready_for_validation_results": False,
    }
    preflight = validate_research_dataset(database, raw_manifest_path)
    report["provenance_preflight"] = {
        "ready_for_empirical_analysis": preflight["ready_for_empirical_analysis"],
        "ready_for_paper_results": preflight["ready_for_paper_results"],
    }
    database_sha256 = preflight.get("database_sha256")
    checks.append(_check(
        "provenance_preflight",
        "PASS" if preflight["ready_for_paper_results"] else "ERROR",
        "Dataset provenance is complete for paper results."
        if preflight["ready_for_paper_results"]
        else "Dataset provenance is incomplete; controlled-validation results are withheld.",
    ))
    if not database_sha256 or not preflight["ready_for_paper_results"]:
        return report

    ground_truth = _load_ground_truth(
        Path(ground_truth_path).expanduser().resolve(), database_sha256, checks
    )
    cases = _validate_cases(ground_truth.get("cases"), checks)
    observations = _read_observations(database, checks)
    if not cases or not observations:
        return report

    duplicate_keys = sorted(key for key, statuses in observations.items() if len(statuses) != 1)
    checks.append(_check(
        "unique_observations",
        "PASS" if not duplicate_keys else "ERROR",
        "Every controlled-lab observation is unique."
        if not duplicate_keys else "Duplicate observations make controlled-lab labels ambiguous.",
        affected_records=len(duplicate_keys),
    ))
    evaluated_observations = {
        key: statuses[0]
        for key, statuses in observations.items()
        if len(statuses) == 1 and statuses[0] in COMPARABLE_STATUSES
    }
    unlabelled = sorted(key for key in evaluated_observations if key not in cases)
    checks.append(_check(
        "ground_truth_coverage",
        "PASS" if not unlabelled else "ERROR",
        "Every evaluated observation has a controlled-lab ground-truth label."
        if not unlabelled else "At least one evaluated observation lacks a ground-truth label.",
        unlabelled_observations=len(unlabelled),
    ))
    missing_observations = sorted(key for key in cases if key not in observations)
    noncomparable_observations = sorted(
        key for key in cases
        if key in observations and len(observations[key]) == 1
        and observations[key][0] not in COMPARABLE_STATUSES
    )
    checks.append(_check(
        "ground_truth_observation_match",
        "PASS" if not missing_observations and not noncomparable_observations else "ERROR",
        "Every ground-truth case has one comparable observed status."
        if not missing_observations and not noncomparable_observations
        else "A ground-truth case is missing an observation or has a non-comparable observed status.",
        missing_observations=len(missing_observations),
        noncomparable_observations=len(noncomparable_observations),
    ))

    # Do not expose partial metrics for an incompletely labelled or otherwise
    # invalid controlled-lab protocol. The caller must fix all gate errors and
    # rerun against the same hash-bound database and raw-output manifest.
    if any(check["status"] == "ERROR" for check in checks):
        return report

    rows = []
    for key, case in sorted(cases.items()):
        statuses = observations.get(key, [])
        if len(statuses) != 1 or statuses[0] not in COMPARABLE_STATUSES:
            continue
        rows.append({
            "assessment_id": key[0],
            "layer": key[1],
            "check_id": key[2],
            "ground_truth_status": case["ground_truth_status"],
            "observed_status": statuses[0],
        })
    report["summary"] = _summary(rows)
    by_layer = {}
    by_check = {}
    for layer in FINDING_LAYERS:
        layer_rows = [row for row in rows if row["layer"] == layer]
        if layer_rows:
            by_layer[layer] = _summary(layer_rows)
    for layer, check_id in sorted({(row["layer"], row["check_id"]) for row in rows}):
        by_check[f"{layer}:{check_id}"] = _summary([
            row for row in rows if row["layer"] == layer and row["check_id"] == check_id
        ])
    report["by_layer"] = by_layer
    report["by_check"] = by_check
    report["ready_for_validation_results"] = not any(
        check["status"] == "ERROR" for check in checks
    )
    return report


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate pre-authorized controlled-lab scanner labels without scanning or writing."
    )
    parser.add_argument("--db", required=True, help="Path to a SQLite research database")
    parser.add_argument(
        "--raw-manifest", required=True,
        help="Raw-output manifest required by the provenance preflight",
    )
    parser.add_argument(
        "--ground-truth", required=True,
        help="Controlled-lab ground-truth JSON file",
    )
    parser.add_argument("--json", action="store_true", help="Print JSON only")
    args = parser.parse_args()
    report = evaluate_controlled_validation(args.db, args.raw_manifest, args.ground_truth)
    if args.json:
        print(json.dumps(report, indent=2, sort_keys=True))
    else:
        print(f"Dataset: {report['database_filename']}")
        for check in report["checks"]:
            print(f"[{check['status']}] {check['id']}: {check['message']}")
        print(f"Ready for validation results: {report['ready_for_validation_results']}")


if __name__ == "__main__":
    main()
