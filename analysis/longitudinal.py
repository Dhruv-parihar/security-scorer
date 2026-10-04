"""Read-only, same-target longitudinal comparison of assessment observations.

This module reports descriptive changes between consecutive assessments of a
single target. It deliberately does not infer that remediation caused a change,
and it never treats an absent, untested, errored, or non-applicable check as a
resolved finding.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone

from analysis.common import LATEST_SNAPSHOTS, open_readonly, validate_evaluations

ANALYSIS_ID = "longitudinal_v1"
ANALYSIS_VERSION = "1.0.0"
EVALUATED_STATUSES = frozenset(("PASS", "FAIL"))


def _assessment_rows(conn, target_id=None):
    where = ""
    params = []
    if target_id is not None:
        where = "WHERE a.target_id=?"
        params.append(target_id)
    return conn.execute(f"""
        SELECT a.assessment_id, a.target_id, a.assessment_date, a.scope,
               a.tool_version, a.methodology_version, a.schema_version,
               t.target_alias
        FROM assessment a
        JOIN target t ON t.target_id=a.target_id
        {where}
        ORDER BY a.target_id, a.assessment_date, a.assessment_id
    """, params).fetchall()


def _observations(conn, assessment_id):
    rows = conn.execute("""
        SELECT layer, check_id, status
        FROM finding
        WHERE assessment_id=?
        ORDER BY layer, check_id, finding_id
    """, (assessment_id,)).fetchall()
    return {(row["layer"], row["check_id"]): row["status"] for row in rows}


def _snapshot(conn, assessment_id):
    row = conn.execute(f"""
        SELECT scoring_model_id, scoring_model_ver, composite_score,
               weight_os, weight_network, weight_web, calculated_at
        FROM ({LATEST_SNAPSHOTS})
        WHERE assessment_id=?
    """, (assessment_id,)).fetchone()
    if row is None:
        return None
    return {key: row[key] for key in row.keys()}


def _score_comparison(before, after):
    before_snapshot = before["snapshot"]
    after_snapshot = after["snapshot"]
    if before_snapshot is None or after_snapshot is None:
        return {
            "comparable": False,
            "reason": "A latest score snapshot is missing for one or both assessments.",
        }

    comparable_fields = (
        "scoring_model_id", "scoring_model_ver", "weight_os", "weight_network", "weight_web",
    )
    if any(before_snapshot[field] != after_snapshot[field] for field in comparable_fields):
        return {
            "comparable": False,
            "reason": "Scoring model or weights differ; composite-score delta is not directly comparable.",
        }
    if before_snapshot["composite_score"] is None or after_snapshot["composite_score"] is None:
        return {
            "comparable": False,
            "reason": "A composite score is absent for one or both assessments.",
        }
    return {
        "comparable": True,
        "before_score": before_snapshot["composite_score"],
        "after_score": after_snapshot["composite_score"],
        "delta": round(after_snapshot["composite_score"] - before_snapshot["composite_score"], 4),
        "scoring_model_id": after_snapshot["scoring_model_id"],
        "scoring_model_ver": after_snapshot["scoring_model_ver"],
    }


def compare_assessments(conn, before_id, after_id):
    """Compare two assessments of the same target without modifying the database."""
    validate_evaluations(conn)
    rows = conn.execute("""
        SELECT assessment_id, target_id, assessment_date, scope, tool_version,
               methodology_version, schema_version
        FROM assessment WHERE assessment_id IN (?, ?)
    """, (before_id, after_id)).fetchall()
    metadata = {row["assessment_id"]: dict(row) for row in rows}
    if set(metadata) != {before_id, after_id}:
        raise ValueError("Both assessment IDs must exist")
    if metadata[before_id]["target_id"] != metadata[after_id]["target_id"]:
        raise ValueError("Longitudinal comparisons require assessments of the same target")

    before_observations = _observations(conn, before_id)
    after_observations = _observations(conn, after_id)
    changes = {
        "resolved": [],
        "introduced": [],
        "persistent_failures": [],
        "persistent_passes": [],
        "not_comparable": [],
    }
    for layer, check_id in sorted(set(before_observations) | set(after_observations)):
        before_status = before_observations.get((layer, check_id), "MISSING")
        after_status = after_observations.get((layer, check_id), "MISSING")
        item = {"layer": layer, "check_id": check_id,
                "before_status": before_status, "after_status": after_status}
        if before_status not in EVALUATED_STATUSES or after_status not in EVALUATED_STATUSES:
            item["reason"] = "Both observations must be explicitly evaluated as PASS or FAIL."
            changes["not_comparable"].append(item)
        elif before_status == "FAIL" and after_status == "PASS":
            changes["resolved"].append(item)
        elif before_status == "PASS" and after_status == "FAIL":
            changes["introduced"].append(item)
        elif before_status == "FAIL":
            changes["persistent_failures"].append(item)
        else:
            changes["persistent_passes"].append(item)

    before = {"metadata": metadata[before_id], "snapshot": _snapshot(conn, before_id)}
    after = {"metadata": metadata[after_id], "snapshot": _snapshot(conn, after_id)}
    protocol_comparable = (
        before["metadata"]["scope"] == after["metadata"]["scope"]
        and before["metadata"]["methodology_version"] == after["metadata"]["methodology_version"]
    )
    return {
        "before_assessment": before["metadata"],
        "after_assessment": after["metadata"],
        "protocol_comparable": protocol_comparable,
        "protocol_note": (
            "Scope and methodology version match. Tool-version changes should still be considered when interpreting changes."
            if protocol_comparable else
            "Scope or methodology version differs; interpret observation changes with extra caution."
        ),
        "score_comparison": _score_comparison(before, after),
        "changes": changes,
        "counts": {key: len(value) for key, value in changes.items()},
        "causal_inference_warning": (
            "Observed changes between assessments do not establish that a remediation, scanner change, "
            "or other intervention caused the change."
        ),
    }


def run_longitudinal_analysis(conn, target_id=None):
    """Build consecutive same-target comparisons for all eligible targets or one target."""
    validate_evaluations(conn)
    targets = {}
    for row in _assessment_rows(conn, target_id):
        targets.setdefault(row["target_id"], {"target_alias": row["target_alias"], "assessments": []})
        targets[row["target_id"]]["assessments"].append(row["assessment_id"])

    target_results = []
    for current_target_id, info in targets.items():
        comparisons = [
            compare_assessments(conn, before_id, after_id)
            for before_id, after_id in zip(info["assessments"], info["assessments"][1:])
        ]
        target_results.append({
            "target_id": current_target_id,
            "target_alias": info["target_alias"],
            "assessment_count": len(info["assessments"]),
            "comparison_count": len(comparisons),
            "comparisons": comparisons,
        })
    return {
        "analysis_id": ANALYSIS_ID,
        "analysis_version": ANALYSIS_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "target_count": len(target_results),
        "comparison_count": sum(item["comparison_count"] for item in target_results),
        "limitation": (
            "Only consecutive assessments of the same target are compared. A status transition is descriptive; "
            "it is not a causal remediation-effect estimate."
        ),
        "targets": target_results,
    }


def main():
    parser = argparse.ArgumentParser(description="Read-only longitudinal assessment analysis")
    parser.add_argument("--db", required=True, help="Path to an existing research SQLite database")
    parser.add_argument("--target-id", help="Optional target UUID to limit the analysis")
    parser.add_argument("--json", action="store_true", help="Print JSON (the only supported output format)")
    args = parser.parse_args()
    conn = open_readonly(args.db)
    try:
        result = run_longitudinal_analysis(conn, args.target_id)
    finally:
        conn.close()
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
