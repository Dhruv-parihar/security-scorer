"""
Prevalence and Co-occurrence Analysis — Phase 4B
=================================================
Pure research-analysis module. Queries the research database to produce:

1. Finding prevalence — FAIL rate per check_id across all applicable assessments.
2. Layer-level prevalence — aggregate FAIL rate per security layer.
3. Finding co-occurrence — which check pairs appear together in the same
   assessment.
4. Assessment-level distributions — score ranges, severity counts.

DENOMINATOR DEFINITIONS (critical for research validity):
  For every prevalence statistic the denominator is:
    N_applicable = number of assessments where the check was evaluated as
    PASS or FAIL (i.e. was applicable and ran to completion).
  Excluded from N_applicable and from all prevalence calculations:
    NOT_APPLICABLE — check does not apply to this target.
    NOT_TESTED     — check was not run during this assessment.
    ERROR          — check attempted but failed to execute.
    UNKNOWN        — result indeterminate.
  Rationale: treating these as PASS would undercount failures;
  treating them as FAIL would overcount. They are simply excluded.

CO-OCCURRENCE DEFINITION:
  Two checks A and B co-occur in an assessment if:
    - Both A and B appear in that assessment with status = FAIL.
    - Counted once per assessment regardless of how many finding records
      exist (unique assessment-level presence).
  This avoids evidence-row inflation.
  Co-occurrence is descriptive and observational.
  No causal inference is drawn or should be inferred from these results.

SMALL-SAMPLE LIMITATION:
  All statistics are accompanied by sample sizes.
  The module does not suppress statistics for small N, but callers
  are expected to treat any result where N_applicable < 10 as
  preliminary / insufficient for reliable conclusions.
  The empirical_limitation field in every result communicates this.

Analysis version: 1.0.0
"""

from __future__ import annotations

import json
import sys
import os
import itertools
from datetime import datetime, timezone
from typing import Optional

ANALYSIS_VERSION = "1.0.0"
ANALYSIS_ID = "prevalence_v1"

# Statuses that count in prevalence denominators (actually evaluated checks)
EVALUATED_STATUSES = ("PASS", "FAIL")

# Statuses excluded from all denominators
EXCLUDED_STATUSES = ("NOT_APPLICABLE", "NOT_TESTED", "ERROR", "UNKNOWN")

SMALL_SAMPLE_THRESHOLD = 10  # assessments below this = preliminary


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _empirical_note(n_assessments: int) -> str:
    if n_assessments == 0:
        return (
            "No assessments found. Populate the research database by running "
            "authorized scans before performing prevalence analysis."
        )
    if n_assessments < SMALL_SAMPLE_THRESHOLD:
        return (
            f"Small sample ({n_assessments} assessment(s)). Results are "
            f"preliminary. Reliable prevalence estimates require N ≥ {SMALL_SAMPLE_THRESHOLD}. "
            "Do not draw generalizable conclusions from this dataset."
        )
    return (
        f"Dataset: {n_assessments} assessment(s). "
        "Results are descriptive and observational. "
        "Co-occurrence does not imply causation."
    )


# ── 1. Finding Prevalence ─────────────────────────────────────────────────────

def finding_prevalence(conn, layer: Optional[str] = None) -> list[dict]:
    """
    Compute FAIL prevalence per check_id.

    Denominator: assessments where status IN ('PASS', 'FAIL') for this check.
    NOT_APPLICABLE, NOT_TESTED, ERROR, UNKNOWN are excluded from denominator.

    Parameters:
        conn:  open DB connection
        layer: optional filter ('OS', 'NETWORK', 'WEB'); None = all layers

    Returns list of dicts sorted by fail_pct descending:
        {
            check_id, layer, n_applicable, n_fail, n_pass,
            fail_pct, severity_when_failing, denominator_note
        }
    """
    where = "f.status IN ('PASS','FAIL')"
    params: list = []
    if layer:
        where += " AND f.layer = ?"
        params.append(layer)

    rows = conn.execute(f"""
        SELECT
            f.check_id,
            f.layer,
            COUNT(DISTINCT f.assessment_id)                          AS n_applicable,
            COUNT(DISTINCT CASE WHEN f.status='FAIL'
                  THEN f.assessment_id END)                          AS n_fail,
            COUNT(DISTINCT CASE WHEN f.status='PASS'
                  THEN f.assessment_id END)                          AS n_pass,
            ROUND(
                100.0 * COUNT(DISTINCT CASE WHEN f.status='FAIL'
                    THEN f.assessment_id END)
                / NULLIF(COUNT(DISTINCT f.assessment_id), 0),
            1)                                                       AS fail_pct,
            GROUP_CONCAT(DISTINCT f.severity)                        AS severities
        FROM finding f
        WHERE {where}
        GROUP BY f.check_id, f.layer
        ORDER BY fail_pct DESC, n_fail DESC, f.check_id
    """, params).fetchall()

    results = []
    for r in rows:
        results.append({
            "check_id": r["check_id"],
            "layer": r["layer"],
            "n_applicable": r["n_applicable"],
            "n_fail": r["n_fail"],
            "n_pass": r["n_pass"],
            "fail_pct": r["fail_pct"] if r["fail_pct"] is not None else 0.0,
            "severity_when_failing": r["severities"],
            "denominator_note": (
                "Denominator = assessments where check produced PASS or FAIL. "
                "NOT_APPLICABLE, NOT_TESTED, ERROR, UNKNOWN excluded."
            ),
            "preliminary": r["n_applicable"] < SMALL_SAMPLE_THRESHOLD,
        })
    return results


# ── 2. Layer-Level Prevalence ─────────────────────────────────────────────────

def layer_prevalence(conn) -> list[dict]:
    """
    Compute aggregate FAIL prevalence per security layer.

    Denominator per layer: total (assessment × check_id) pairs where
    status IN ('PASS', 'FAIL') for that layer.

    Returns list of dicts per layer:
        {
            layer, total_check_evaluations, total_fail, total_pass,
            overall_fail_pct, unique_checks_evaluated,
            unique_checks_failing, denominator_note
        }
    """
    rows = conn.execute("""
        SELECT
            f.layer,
            COUNT(*)                                                AS total_check_evaluations,
            SUM(CASE WHEN f.status='FAIL' THEN 1 ELSE 0 END)      AS total_fail,
            SUM(CASE WHEN f.status='PASS' THEN 1 ELSE 0 END)      AS total_pass,
            COUNT(DISTINCT f.check_id)                             AS unique_checks_evaluated,
            COUNT(DISTINCT CASE WHEN f.status='FAIL'
                  THEN f.check_id END)                             AS unique_checks_failing,
            ROUND(
                100.0 * SUM(CASE WHEN f.status='FAIL' THEN 1 ELSE 0 END)
                / NULLIF(COUNT(*), 0),
            1)                                                     AS overall_fail_pct
        FROM finding f
        WHERE f.status IN ('PASS', 'FAIL')
        GROUP BY f.layer
        ORDER BY overall_fail_pct DESC
    """).fetchall()

    results = []
    for r in rows:
        results.append({
            "layer": r["layer"],
            "total_check_evaluations": r["total_check_evaluations"],
            "total_fail": r["total_fail"],
            "total_pass": r["total_pass"],
            "overall_fail_pct": r["overall_fail_pct"]
                if r["overall_fail_pct"] is not None else 0.0,
            "unique_checks_evaluated": r["unique_checks_evaluated"],
            "unique_checks_failing": r["unique_checks_failing"],
            "denominator_note": (
                "Denominator = total finding records with status PASS or FAIL "
                "for this layer. Each (assessment × check_id) pair counted once."
            ),
        })
    return results


# ── 3. Severity Distribution ──────────────────────────────────────────────────

def severity_distribution(conn, layer: Optional[str] = None) -> dict:
    """
    Count FAIL findings per severity level.

    Only FAIL findings are counted (severity is only meaningful for failures).
    NOT_APPLICABLE findings have NULL severity and are excluded.

    Returns:
        {
            severity_counts: {severity: count},
            total_fail_findings: int,
            denominator_note: str
        }
    """
    where = "f.status = 'FAIL' AND f.severity IS NOT NULL"
    params: list = []
    if layer:
        where += " AND f.layer = ?"
        params.append(layer)

    rows = conn.execute(f"""
        SELECT
            f.severity,
            COUNT(*) AS n
        FROM finding f
        WHERE {where}
        GROUP BY f.severity
        ORDER BY CASE f.severity
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
            ELSE 5
        END
    """, params).fetchall()

    counts = {r["severity"]: r["n"] for r in rows}
    total = conn.execute(f"""
        SELECT COUNT(*) AS c FROM finding f WHERE {where}
    """, params).fetchone()["c"]

    return {
        "severity_counts": counts,
        "total_fail_findings": total,
        "denominator_note": (
            "Counts FAIL findings with non-NULL severity. "
            "NOT_APPLICABLE (severity=NULL) excluded."
        ),
    }


# ── 4. Status Distribution ────────────────────────────────────────────────────

def status_distribution(conn, layer: Optional[str] = None) -> dict:
    """
    Count findings per status value across all findings.
    Useful for understanding how much of the dataset is NOT_APPLICABLE
    vs actually evaluated.
    """
    where = "1=1"
    params: list = []
    if layer:
        where += " AND f.layer = ?"
        params.append(layer)

    rows = conn.execute(f"""
        SELECT f.status, COUNT(*) AS n
        FROM finding f
        WHERE {where}
        GROUP BY f.status
        ORDER BY n DESC
    """, params).fetchall()

    counts = {r["status"]: r["n"] for r in rows}
    total = sum(counts.values())

    return {
        "status_counts": counts,
        "total_findings": total,
        "evaluated_count": sum(
            n for s, n in counts.items() if s in EVALUATED_STATUSES
        ),
        "excluded_count": sum(
            n for s, n in counts.items() if s in EXCLUDED_STATUSES
        ),
    }


# ── 5. Assessment-Level Distribution ─────────────────────────────────────────

def assessment_distribution(conn) -> dict:
    """
    Summary statistics at the assessment level.

    Returns:
        {
            total_assessments, assessments_with_findings,
            assessments_with_fail, total_targets,
            composite_score_distribution (from score_snapshots)
        }
    """
    total = conn.execute(
        "SELECT COUNT(*) AS c FROM assessment"
    ).fetchone()["c"]

    with_findings = conn.execute("""
        SELECT COUNT(DISTINCT assessment_id) AS c FROM finding
    """).fetchone()["c"]

    with_fail = conn.execute("""
        SELECT COUNT(DISTINCT assessment_id) AS c
        FROM finding WHERE status = 'FAIL'
    """).fetchone()["c"]

    total_targets = conn.execute(
        "SELECT COUNT(*) AS c FROM target"
    ).fetchone()["c"]

    # Score snapshot distribution
    snap_rows = conn.execute("""
        SELECT composite_score FROM score_snapshot
        WHERE composite_score IS NOT NULL
    """).fetchall()
    scores = [r["composite_score"] for r in snap_rows]
    score_dist = {}
    if scores:
        score_dist = {
            "n": len(scores),
            "min": round(min(scores), 2),
            "max": round(max(scores), 2),
            "mean": round(sum(scores) / len(scores), 2),
            "median": round(sorted(scores)[len(scores) // 2], 2),
            "buckets": {
                "0-20":  sum(1 for s in scores if s <= 20),
                "21-40": sum(1 for s in scores if 21 <= s <= 40),
                "41-60": sum(1 for s in scores if 41 <= s <= 60),
                "61-80": sum(1 for s in scores if 61 <= s <= 80),
                "81-100": sum(1 for s in scores if s >= 81),
            },
        }

    return {
        "total_assessments": total,
        "assessments_with_findings": with_findings,
        "assessments_with_fail": with_fail,
        "total_targets": total_targets,
        "composite_score_distribution": score_dist or None,
    }


# ── 6. Co-occurrence Analysis ─────────────────────────────────────────────────

def finding_cooccurrence(
    conn,
    min_cooccurrence: int = 1,
    max_pairs: int = 50,
    layer_filter: Optional[str] = None,
) -> list[dict]:
    """
    Compute co-occurrence of FAIL findings at the assessment level.

    For each pair (check_a, check_b):
        - n_a: assessments where check_a = FAIL
        - n_b: assessments where check_b = FAIL
        - n_both: assessments where BOTH = FAIL (unique assessment count)
        - cooccurrence_rate: n_both / max(n_a, n_b)

    Rules:
        - Only FAIL findings counted (co-occurring failures are what matters).
        - Unique assessment-level presence (evidence-row inflation avoided).
        - No self-pairs (a, a).
        - Pairs ordered alphabetically for determinism: (a, b) where a < b.
        - No causal language — use "co-occurs with / associated with".
        - Cross-layer pairs are included unless layer_filter is set.

    Parameters:
        conn:             open DB connection
        min_cooccurrence: only return pairs where n_both >= this value
        max_pairs:        cap on returned pairs (sorted by n_both desc)
        layer_filter:     restrict to one layer (or None for all)

    Returns list of dicts sorted by n_both desc, cooccurrence_rate desc:
        {
            check_a, layer_a, check_b, layer_b,
            n_assessments_with_a, n_assessments_with_b,
            n_assessments_with_both, cooccurrence_rate,
            cross_layer, caution_note
        }
    """
    where = "status = 'FAIL'"
    if layer_filter:
        where += f" AND layer = '{layer_filter}'"

    # Build (assessment_id, check_id, layer) presence table
    fail_pairs = conn.execute(f"""
        SELECT DISTINCT assessment_id, check_id, layer
        FROM finding
        WHERE {where}
        ORDER BY check_id
    """).fetchall()

    if not fail_pairs:
        return []

    # Group by assessment
    assessment_checks: dict[str, list[tuple[str, str]]] = {}
    for row in fail_pairs:
        aid = row["assessment_id"]
        assessment_checks.setdefault(aid, []).append(
            (row["check_id"], row["layer"])
        )

    # Count per check_id (unique assessments)
    check_counts: dict[str, int] = {}
    check_layers: dict[str, str] = {}
    for check_list in assessment_checks.values():
        seen = set()
        for check_id, layer in check_list:
            if check_id not in seen:
                check_counts[check_id] = check_counts.get(check_id, 0) + 1
                check_layers[check_id] = layer
                seen.add(check_id)

    # All unique check_ids
    all_checks = sorted(check_counts.keys())

    # Count co-occurrences
    pair_counts: dict[tuple[str, str], int] = {}
    for aid, check_list in assessment_checks.items():
        unique_checks = list({c for c, _ in check_list})
        for i in range(len(unique_checks)):
            for j in range(i + 1, len(unique_checks)):
                a, b = sorted([unique_checks[i], unique_checks[j]])
                pair_counts[(a, b)] = pair_counts.get((a, b), 0) + 1

    results = []
    for (a, b), n_both in pair_counts.items():
        if n_both < min_cooccurrence:
            continue
        n_a = check_counts.get(a, 0)
        n_b = check_counts.get(b, 0)
        denom = max(n_a, n_b)
        rate = round(n_both / denom, 4) if denom > 0 else 0.0
        layer_a = check_layers.get(a, "?")
        layer_b = check_layers.get(b, "?")
        results.append({
            "check_a": a,
            "layer_a": layer_a,
            "check_b": b,
            "layer_b": layer_b,
            "n_assessments_with_a": n_a,
            "n_assessments_with_b": n_b,
            "n_assessments_with_both": n_both,
            "cooccurrence_rate": rate,
            "cross_layer": layer_a != layer_b,
            "caution_note": (
                "Co-occurrence is descriptive and observational. "
                "It does not imply causation or a dependency relationship "
                "between these findings."
            ),
        })

    results.sort(key=lambda r: (-r["n_assessments_with_both"],
                                 -r["cooccurrence_rate"]))
    return results[:max_pairs]


# ── 7. Full Analysis ──────────────────────────────────────────────────────────

def run_full_analysis(conn) -> dict:
    """
    Run the complete Phase 4B analysis and return a structured result.
    Does NOT create assessment records or modify any data.
    """
    n_assessments = conn.execute(
        "SELECT COUNT(*) AS c FROM assessment"
    ).fetchone()["c"]

    return {
        "analysis_version": ANALYSIS_VERSION,
        "analysis_id": ANALYSIS_ID,
        "timestamp": _now(),
        "empirical_limitation": _empirical_note(n_assessments),
        "assessment_distribution": assessment_distribution(conn),
        "layer_prevalence": layer_prevalence(conn),
        "finding_prevalence": finding_prevalence(conn),
        "severity_distribution": severity_distribution(conn),
        "status_distribution": status_distribution(conn),
        "cooccurrence": finding_cooccurrence(conn),
        "denominator_definitions": {
            "prevalence_denominator": (
                "Assessments where the check produced status PASS or FAIL. "
                "NOT_APPLICABLE, NOT_TESTED, ERROR, UNKNOWN are excluded."
            ),
            "cooccurrence_denominator": (
                "max(n_a, n_b): the larger of the two check fail counts. "
                "Counts unique assessment-level FAIL presence only."
            ),
            "layer_prevalence_denominator": (
                "Total finding records (per layer) with status PASS or FAIL."
            ),
        },
        "causal_inference_warning": (
            "All statistics in this report are descriptive and observational. "
            "Co-occurrence does not imply causation. "
            "Prevalence rates reflect only the tested dataset."
        ),
    }


# ── Output ────────────────────────────────────────────────────────────────────

def print_results(analysis: dict) -> None:
    print("\n" + "=" * 70)
    print("PREVALENCE & CO-OCCURRENCE ANALYSIS".center(70))
    print(f"Analysis version: {analysis['analysis_version']}".center(70))
    print("=" * 70)
    print(f"\n⚠  {analysis['empirical_limitation']}")

    dist = analysis.get("assessment_distribution", {})
    print(f"\nDATASET SUMMARY:")
    print(f"  Total assessments:        {dist.get('total_assessments', 0)}")
    print(f"  Assessments with findings:{dist.get('assessments_with_findings', 0)}")
    print(f"  Assessments with FAIL:    {dist.get('assessments_with_fail', 0)}")
    print(f"  Total targets:            {dist.get('total_targets', 0)}")

    score_dist = dist.get("composite_score_distribution")
    if score_dist:
        print(f"\nCOMPOSITE SCORE DISTRIBUTION (n={score_dist['n']}):")
        print(f"  Min={score_dist['min']:.1f}  Max={score_dist['max']:.1f}"
              f"  Mean={score_dist['mean']:.1f}  Median={score_dist['median']:.1f}")
        for bucket, count in score_dist.get("buckets", {}).items():
            bar = "█" * min(count, 40)
            print(f"  {bucket:7}: {bar} ({count})")

    layer_prev = analysis.get("layer_prevalence", [])
    if layer_prev:
        print(f"\nLAYER-LEVEL PREVALENCE:")
        print(f"  {'Layer':10} {'Evaluations':13} {'FAIL':7} {'PASS':7} {'FAIL%':7} {'Unique Failing':15}")
        print("  " + "-" * 60)
        for r in layer_prev:
            print(f"  {r['layer']:10} {r['total_check_evaluations']:<13}"
                  f"{r['total_fail']:<7} {r['total_pass']:<7}"
                  f"{r['overall_fail_pct']:<7.1f} {r['unique_checks_failing']}")

    fp = analysis.get("finding_prevalence", [])
    if fp:
        print(f"\nFINDING PREVALENCE (top 10, FAIL% desc):")
        print(f"  {'Check ID':30} {'Layer':8} {'N_appl':7} {'N_fail':7} {'FAIL%':7} {'Prelim':6}")
        print("  " + "-" * 68)
        for r in fp[:10]:
            prelim = "yes" if r.get("preliminary") else "no"
            print(f"  {r['check_id'][:30]:30} {r['layer']:8} "
                  f"{r['n_applicable']:<7} {r['n_fail']:<7}"
                  f"{r['fail_pct']:<7.1f} {prelim}")

    sev = analysis.get("severity_distribution", {})
    if sev.get("severity_counts"):
        print(f"\nSEVERITY DISTRIBUTION (FAIL findings only):")
        for sev_level, count in sev["severity_counts"].items():
            print(f"  {sev_level:12}: {count}")

    cooc = analysis.get("cooccurrence", [])
    if cooc:
        print(f"\nCO-OCCURRENCE (top 10 by n_both):")
        print(f"  {'Check A':25} {'Check B':25} {'n_A':5} {'n_B':5} {'n_both':7} {'rate':6}")
        print("  " + "-" * 75)
        for r in cooc[:10]:
            print(f"  {r['check_a'][:25]:25} {r['check_b'][:25]:25}"
                  f"{r['n_assessments_with_a']:<5} {r['n_assessments_with_b']:<5}"
                  f"{r['n_assessments_with_both']:<7} {r['cooccurrence_rate']:.3f}")
        print(f"\n  ⚠ Co-occurrence is descriptive. It does not imply causation.")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Prevalence & Co-occurrence Analysis — Phase 4B"
    )
    parser.add_argument("--db", default=None)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--layer", choices=["OS", "NETWORK", "WEB"], default=None)
    args = parser.parse_args()

    if args.db:
        db_path = args.db
    else:
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db_path = os.path.join(project_root, "research.db")

    if not os.path.exists(db_path):
        print(f"Research database not found: {db_path}")
        sys.exit(1)

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from db.schema import get_connection
    conn = get_connection(db_path)

    analysis = run_full_analysis(conn)
    conn.close()

    if args.json:
        print(json.dumps(analysis, indent=2))
    else:
        print_results(analysis)


if __name__ == "__main__":
    main()
