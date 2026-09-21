"""
Scoring Sensitivity Analysis — Phase 4A
=========================================
Evaluates how the composite security score changes under different
layer-weight configurations, using stored assessment data from the
research database.

Purpose:
  1. Measure sensitivity of composite scores to reasonable weight changes.
  2. Determine whether relative security-posture conclusions (ordering)
     change under alternative weights.
  3. Identify which layers have greatest influence on the composite.
  4. Determine whether the current 0.30/0.35/0.35 weighting is robust.

IMPORTANT RESEARCH RULE:
  This module evaluates mathematical/model robustness across predefined
  weight scenarios. It does NOT claim any alternative weighting is
  empirically superior. Empirical calibration requires a sufficiently
  sized benchmark dataset that does not yet exist in this project.

  Do not interpret sensitivity results as weight recommendations.

Analysis version: 1.0.0

Usage:
  python3 -m analysis.scoring_sensitivity [--db PATH] [--json]
  python3 -m analysis.scoring_sensitivity --help
"""

from __future__ import annotations

import json
import sys
import os
import itertools
from datetime import datetime, timezone
from typing import Optional

# ── Constants ─────────────────────────────────────────────────────────────────

ANALYSIS_VERSION = "1.0.0"
ANALYSIS_ID = "scoring_sensitivity_v1"

KNOWN_LAYERS = ("os_hardening", "network", "webapp")

# Baseline weights — must match production default in modules/scoring.py
BASELINE_WEIGHTS = {
    "os_hardening": 0.30,
    "network":      0.35,
    "webapp":       0.35,
}

# Step size for one-layer sensitivity sweep
SWEEP_STEP = 0.05

# Predefined alternative weight configurations
# Each entry: (scenario_id, description, weights_dict)
WEIGHT_SCENARIOS: list[tuple[str, str, dict]] = [
    (
        "baseline",
        "Current production weights (OS=0.30, NET=0.35, WEB=0.35)",
        {"os_hardening": 0.30, "network": 0.35, "webapp": 0.35},
    ),
    (
        "equal",
        "Equal weighting across all three layers (1/3 each)",
        {"os_hardening": 1/3, "network": 1/3, "webapp": 1/3},
    ),
    (
        "os_heavy",
        "OS-weighted: OS=0.50, NET=0.25, WEB=0.25",
        {"os_hardening": 0.50, "network": 0.25, "webapp": 0.25},
    ),
    (
        "network_heavy",
        "Network-weighted: OS=0.20, NET=0.60, WEB=0.20",
        {"os_hardening": 0.20, "network": 0.60, "webapp": 0.20},
    ),
    (
        "web_heavy",
        "Web-weighted: OS=0.20, NET=0.20, WEB=0.60",
        {"os_hardening": 0.20, "network": 0.20, "webapp": 0.60},
    ),
    (
        "network_web_only",
        "Exclude OS layer: NET=0.50, WEB=0.50 (simulates network+web only assessment)",
        {"os_hardening": 0.00, "network": 0.50, "webapp": 0.50},
    ),
    (
        "os_network_only",
        "Exclude WEB layer: OS=0.50, NET=0.50",
        {"os_hardening": 0.50, "network": 0.50, "webapp": 0.00},
    ),
]


def _generate_sweep_scenarios() -> list[tuple[str, str, dict]]:
    """
    Generate one-layer sensitivity sweep scenarios.
    For each layer, vary its weight from 0.05 to 0.90 in SWEEP_STEP increments,
    distributing the remainder equally across the other two layers.
    Total weight always sums to 1.0.
    """
    scenarios = []
    other_layers = {
        "os_hardening": ["network", "webapp"],
        "network": ["os_hardening", "webapp"],
        "webapp": ["os_hardening", "network"],
    }
    for target_layer, others in other_layers.items():
        w = SWEEP_STEP
        while w <= 1.0 - 2 * SWEEP_STEP + 1e-9:
            remainder = round(1.0 - w, 10)
            w1 = round(remainder / 2, 10)
            w2 = round(remainder - w1, 10)
            weights = {
                target_layer: round(w, 10),
                others[0]: w1,
                others[1]: w2,
            }
            scenario_id = f"sweep_{target_layer}_{int(round(w * 100)):03d}"
            desc = (
                f"Sweep: {target_layer}={w:.2f}, "
                f"{others[0]}={w1:.2f}, {others[1]}={w2:.2f}"
            )
            scenarios.append((scenario_id, desc, weights))
            w = round(w + SWEEP_STEP, 10)
    return scenarios


ALL_SCENARIOS = WEIGHT_SCENARIOS + _generate_sweep_scenarios()


# ── Core computation ──────────────────────────────────────────────────────────

def compute_weighted_composite(
    layer_scores: dict[str, float],
    weights: dict[str, float],
) -> Optional[float]:
    """
    Compute a composite score from layer scores and weights.

    layer_scores: {layer_name: score} — only present/available layers.
    weights: {layer_name: weight} — can include layers not in layer_scores.

    Rules (matching production scoring.py):
    - Only layers present in BOTH layer_scores and weights contribute.
    - Weights for absent layers are excluded; remaining weights re-normalized.
    - A zero weight for a present layer excludes it from the composite.
    - Returns None if no layers contribute after filtering.
    - NOT_APPLICABLE layers must NOT be in layer_scores at all.
    - Unavailable layers are not silently treated as zero score.
    """
    contributing = {
        layer: (score, weights.get(layer, 0.0))
        for layer, score in layer_scores.items()
        if weights.get(layer, 0.0) > 0.0
    }
    if not contributing:
        return None

    total_weight = sum(w for _, w in contributing.values())
    if total_weight <= 0.0:
        return None

    composite = sum(score * w for score, w in contributing.values()) / total_weight
    return round(composite, 4)


def layer_influence(
    layer_scores: dict[str, float],
    weights: dict[str, float],
) -> dict[str, float]:
    """
    Compute each layer's proportional influence on the composite.
    Influence = (weight × score) / sum(weight × score for all contributing layers).
    Returns dict of {layer: influence_fraction} summing to 1.0.
    """
    contributing = {
        layer: (score, weights.get(layer, 0.0))
        for layer, score in layer_scores.items()
        if weights.get(layer, 0.0) > 0.0
    }
    total = sum(score * w for score, w in contributing.values())
    if total == 0.0:
        return {layer: 0.0 for layer in contributing}
    return {
        layer: round((score * w) / total, 4)
        for layer, (score, w) in contributing.items()
    }


# ── Assessment data loading ───────────────────────────────────────────────────

def load_assessment_layer_scores(conn) -> list[dict]:
    """
    Load available layer scores from stored score_snapshots.

    Returns a list of dicts:
        {
            "assessment_id": str,
            "assessment_date": str,
            "target_alias": str,
            "layer_scores": {layer: score},  # only non-None layers
            "available_layers": [str],
        }

    Layers with NULL score in the snapshot are excluded from layer_scores
    (they were not assessed, not NOT_APPLICABLE zero).
    """
    rows = conn.execute("""
        SELECT
            ss.snapshot_id,
            ss.assessment_id,
            ss.os_score,
            ss.network_score,
            ss.web_score,
            ss.composite_score,
            ss.weight_os,
            ss.weight_network,
            ss.weight_web,
            ss.scoring_model_id,
            ss.calculated_at,
            a.assessment_date,
            a.target_id,
            t.target_alias
        FROM score_snapshot ss
        JOIN assessment a ON ss.assessment_id = a.assessment_id
        JOIN target t ON a.target_id = t.target_id
        ORDER BY a.assessment_date, ss.calculated_at
    """).fetchall()

    results = []
    for row in rows:
        layer_scores = {}
        if row["os_score"] is not None:
            layer_scores["os_hardening"] = float(row["os_score"])
        if row["network_score"] is not None:
            layer_scores["network"] = float(row["network_score"])
        if row["web_score"] is not None:
            layer_scores["webapp"] = float(row["web_score"])

        results.append({
            "assessment_id": row["assessment_id"],
            "snapshot_id": row["snapshot_id"],
            "assessment_date": row["assessment_date"],
            "target_alias": row["target_alias"],
            "original_composite": float(row["composite_score"])
                if row["composite_score"] is not None else None,
            "original_weights": {
                "os_hardening": row["weight_os"],
                "network": row["weight_network"],
                "webapp": row["weight_web"],
            },
            "scoring_model_id": row["scoring_model_id"],
            "layer_scores": layer_scores,
            "available_layers": list(layer_scores.keys()),
        })
    return results


# ── Scenario runner ───────────────────────────────────────────────────────────

def run_scenario(
    assessment: dict,
    scenario_id: str,
    description: str,
    weights: dict[str, float],
    baseline_composite: Optional[float],
) -> dict:
    """
    Apply one weight scenario to one assessment.
    Returns a scenario result dict.
    """
    composite = compute_weighted_composite(assessment["layer_scores"], weights)
    diff_from_baseline = (
        round(composite - baseline_composite, 4)
        if (composite is not None and baseline_composite is not None)
        else None
    )
    abs_diff = abs(diff_from_baseline) if diff_from_baseline is not None else None
    influence = layer_influence(assessment["layer_scores"], weights)

    return {
        "assessment_id": assessment["assessment_id"],
        "target_alias": assessment["target_alias"],
        "scenario_id": scenario_id,
        "scenario_description": description,
        "weights": {k: round(v, 6) for k, v in weights.items()},
        "available_layers": assessment["available_layers"],
        "composite_score": composite,
        "baseline_composite": baseline_composite,
        "diff_from_baseline": diff_from_baseline,
        "abs_diff_from_baseline": abs_diff,
        "layer_influence": influence,
        "analysis_version": ANALYSIS_VERSION,
        "calculated_at": datetime.now(timezone.utc).isoformat(),
    }


def run_full_analysis(
    conn,
    scenarios: Optional[list] = None,
    include_sweep: bool = True,
) -> dict:
    """
    Run the full sensitivity analysis over all stored assessments.

    Returns a structured analysis result dict suitable for JSON output
    or human-readable printing.
    """
    if scenarios is None:
        if include_sweep:
            scenarios = ALL_SCENARIOS
        else:
            scenarios = WEIGHT_SCENARIOS

    assessments = load_assessment_layer_scores(conn)

    if not assessments:
        return {
            "analysis_version": ANALYSIS_VERSION,
            "analysis_id": ANALYSIS_ID,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "assessment_count": 0,
            "scenario_count": len(scenarios),
            "empirical_limitation": (
                "No stored assessments found. The sensitivity analysis evaluates "
                "mathematical/model robustness; empirical calibration requires a "
                "sufficiently sized benchmark dataset."
            ),
            "results": [],
            "summary": None,
        }

    all_results = []
    for assessment in assessments:
        # Baseline composite for this assessment
        baseline_composite = compute_weighted_composite(
            assessment["layer_scores"], BASELINE_WEIGHTS
        )
        for scenario_id, description, weights in scenarios:
            result = run_scenario(
                assessment, scenario_id, description, weights, baseline_composite
            )
            all_results.append(result)

    summary = _build_summary(assessments, all_results, scenarios)

    return {
        "analysis_version": ANALYSIS_VERSION,
        "analysis_id": ANALYSIS_ID,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "baseline_weights": BASELINE_WEIGHTS,
        "assessment_count": len(assessments),
        "scenario_count": len(scenarios),
        "empirical_limitation": (
            "The implemented sensitivity analysis evaluates mathematical/model "
            "robustness across predefined weight scenarios. Empirical calibration "
            "requires a sufficiently sized benchmark dataset. "
            f"Current dataset: {len(assessments)} assessment(s) — "
            "insufficient for definitive empirical conclusions."
        ),
        "results": all_results,
        "summary": summary,
    }


def _build_summary(assessments, all_results, scenarios) -> dict:
    """Build aggregate summary statistics across all assessments and scenarios."""
    scenario_ids = [s[0] for s in scenarios]
    non_sweep = [s for s in scenarios if not s[0].startswith("sweep_")]
    non_sweep_ids = {s[0] for s in non_sweep}

    # Per-scenario stats (non-sweep only for readability)
    scenario_stats = {}
    for sid in non_sweep_ids:
        scenario_results = [r for r in all_results if r["scenario_id"] == sid]
        composites = [r["composite_score"] for r in scenario_results
                      if r["composite_score"] is not None]
        diffs = [r["abs_diff_from_baseline"] for r in scenario_results
                 if r["abs_diff_from_baseline"] is not None]
        if composites:
            scenario_stats[sid] = {
                "assessment_count": len(composites),
                "min_composite": round(min(composites), 2),
                "max_composite": round(max(composites), 2),
                "mean_composite": round(sum(composites) / len(composites), 2),
                "mean_abs_diff_from_baseline": round(sum(diffs) / len(diffs), 4)
                    if diffs else None,
                "max_abs_diff_from_baseline": round(max(diffs), 4) if diffs else None,
            }

    # Robustness: for pairs of assessments, does ordering change?
    ordering_analysis = _robustness_ordering(assessments, non_sweep, all_results)

    # Sweep: per-layer influence at sweep extremes
    sweep_layer_influence = _sweep_influence_summary(all_results)

    return {
        "scenario_stats": scenario_stats,
        "ordering_analysis": ordering_analysis,
        "sweep_layer_influence": sweep_layer_influence,
        "robustness_verdict": ordering_analysis.get("verdict", "INSUFFICIENT_DATA"),
    }


def _robustness_ordering(assessments, scenarios, all_results) -> dict:
    """
    For each pair of assessments, check whether their relative ordering
    (A > B by composite score) is stable across all non-sweep scenarios.
    """
    if len(assessments) < 2:
        return {
            "verdict": "INSUFFICIENT_DATA",
            "note": "Need at least 2 assessments to evaluate ordering robustness.",
            "pairs_analyzed": 0,
        }

    assessment_ids = [a["assessment_id"] for a in assessments]
    pairs = list(itertools.combinations(assessment_ids, 2))
    stable = 0
    sensitive = 0
    pair_details = []

    for aid1, aid2 in pairs[:10]:  # cap at 10 pairs for readability
        scenario_results = {}
        for r in all_results:
            if r["assessment_id"] in (aid1, aid2) and r["scenario_id"] in {
                s[0] for s in scenarios
            }:
                scenario_results.setdefault(r["scenario_id"], {})[
                    r["assessment_id"]
                ] = r["composite_score"]

        orderings = set()
        for sid, scores in scenario_results.items():
            s1 = scores.get(aid1)
            s2 = scores.get(aid2)
            if s1 is None or s2 is None:
                continue
            if s1 > s2:
                orderings.add("A>B")
            elif s2 > s1:
                orderings.add("B>A")
            else:
                orderings.add("EQUAL")

        is_stable = len(orderings) <= 1
        if is_stable:
            stable += 1
        else:
            sensitive += 1

        pair_details.append({
            "assessment_a": aid1[:8],
            "assessment_b": aid2[:8],
            "ordering_stable": is_stable,
            "orderings_observed": list(orderings),
        })

    total = stable + sensitive
    if total == 0:
        verdict = "INSUFFICIENT_DATA"
    elif sensitive == 0:
        verdict = "STABLE"
    elif stable == 0:
        verdict = "SENSITIVE"
    else:
        verdict = "MIXED"

    return {
        "verdict": verdict,
        "pairs_analyzed": total,
        "stable_pairs": stable,
        "sensitive_pairs": sensitive,
        "pair_details": pair_details,
        "interpretation": {
            "STABLE": "Relative ordering of assessments is consistent across all tested weight scenarios.",
            "SENSITIVE": "Relative ordering changes under at least some alternative weight scenarios.",
            "MIXED": "Some pairs stable, some sensitive to weight changes.",
            "INSUFFICIENT_DATA": "Not enough assessments to evaluate ordering robustness.",
        }.get(verdict, ""),
    }


def _sweep_influence_summary(all_results) -> dict:
    """
    Summarize how composite score changes as each layer's weight is swept.
    For each layer, report the range of composite scores seen.
    """
    summary = {}
    for layer in KNOWN_LAYERS:
        sweep_results = [
            r for r in all_results
            if r["scenario_id"].startswith(f"sweep_{layer}_")
        ]
        if not sweep_results:
            continue
        composites = [r["composite_score"] for r in sweep_results
                      if r["composite_score"] is not None]
        diffs = [r["abs_diff_from_baseline"] for r in sweep_results
                 if r["abs_diff_from_baseline"] is not None]
        if composites:
            summary[layer] = {
                "composite_min": round(min(composites), 2),
                "composite_max": round(max(composites), 2),
                "composite_range": round(max(composites) - min(composites), 2),
                "max_abs_diff_from_baseline": round(max(diffs), 4) if diffs else None,
            }
    return summary


# ── Output formatters ─────────────────────────────────────────────────────────

def print_results(analysis: dict, include_sweep: bool = False) -> None:
    """Print human-readable sensitivity analysis results."""
    print("\n" + "=" * 70)
    print("SCORING SENSITIVITY ANALYSIS".center(70))
    print(f"Analysis version: {analysis['analysis_version']}".center(70))
    print("=" * 70)

    print(f"\nAssessments analyzed: {analysis['assessment_count']}")
    print(f"Scenarios evaluated:  {analysis['scenario_count']}")
    print(f"\n⚠  EMPIRICAL LIMITATION:")
    print(f"   {analysis['empirical_limitation']}")

    if analysis["assessment_count"] == 0:
        print("\nNo assessments to analyze.")
        return

    print(f"\nBASELINE WEIGHTS:")
    for layer, w in analysis["baseline_weights"].items():
        print(f"  {layer:15} = {w:.4f}")

    summary = analysis.get("summary", {})

    print(f"\nSCENARIO RESULTS (predefined configurations):")
    print(f"{'Scenario':25} {'Assessments':12} {'Min':8} {'Max':8} {'Mean':8} {'Max|Δ|':8}")
    print("-" * 75)
    for sid, stats in (summary.get("scenario_stats") or {}).items():
        print(
            f"{sid:25} {stats['assessment_count']:<12} "
            f"{stats['min_composite']:<8.1f} {stats['max_composite']:<8.1f} "
            f"{stats['mean_composite']:<8.1f} "
            f"{stats.get('max_abs_diff_from_baseline') or 0.0:<8.4f}"
        )

    rob = summary.get("ordering_analysis", {})
    print(f"\nROBUSTNESS (ordering stability across scenarios):")
    print(f"  Verdict:         {rob.get('verdict', 'N/A')}")
    print(f"  Pairs analyzed:  {rob.get('pairs_analyzed', 0)}")
    print(f"  Stable pairs:    {rob.get('stable_pairs', 0)}")
    print(f"  Sensitive pairs: {rob.get('sensitive_pairs', 0)}")
    if rob.get("verdict"):
        print(f"  Interpretation:  {rob.get('interpretation', '')}")

    sweep_inf = summary.get("sweep_layer_influence", {})
    if sweep_inf:
        print(f"\nLAYER INFLUENCE SWEEP SUMMARY:")
        print(f"  (range of composite scores as each layer's weight is varied)")
        print(f"  {'Layer':15} {'Min':8} {'Max':8} {'Range':8} {'Max|Δ|':8}")
        print("  " + "-" * 50)
        for layer, stats in sweep_inf.items():
            print(
                f"  {layer:15} {stats['composite_min']:<8.1f} "
                f"{stats['composite_max']:<8.1f} "
                f"{stats['composite_range']:<8.2f} "
                f"{stats.get('max_abs_diff_from_baseline') or 0.0:<8.4f}"
            )


# ── CLI entry point ───────────────────────────────────────────────────────────

def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Security Scoring Sensitivity Analysis — Phase 4A"
    )
    parser.add_argument("--db", default=None,
                        help="Path to research.db (default: project root)")
    parser.add_argument("--json", action="store_true",
                        help="Output raw JSON result")
    parser.add_argument("--no-sweep", action="store_true",
                        help="Skip one-layer sweep scenarios (faster)")
    parser.add_argument("--baseline-only", action="store_true",
                        help="Run baseline scenario only (verification)")
    args = parser.parse_args()

    # Locate DB
    if args.db:
        db_path = args.db
    else:
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        db_path = os.path.join(project_root, "research.db")

    if not os.path.exists(db_path):
        print(f"Research database not found: {db_path}")
        print("Run a scan first to populate the database, or specify --db PATH")
        sys.exit(1)

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from db.schema import get_connection
    conn = get_connection(db_path)

    scenarios = None
    if args.baseline_only:
        scenarios = [s for s in WEIGHT_SCENARIOS if s[0] == "baseline"]

    analysis = run_full_analysis(
        conn,
        scenarios=scenarios,
        include_sweep=not args.no_sweep and not args.baseline_only,
    )
    conn.close()

    if args.json:
        print(json.dumps(analysis, indent=2))
    else:
        print_results(analysis, include_sweep=not args.no_sweep)


if __name__ == "__main__":
    main()
