"""
Test Suite — Phase 4A: Scoring Sensitivity Analysis
====================================================
Tests:
1. Mathematical correctness
2. Sensitivity: scenarios deterministic and directionally correct
3. Research semantics: NOT_APPLICABLE, unavailable layers, no fabrication
4. Reproducibility: identical input → identical output
5. Regression: all Phase 1-3 tests remain green

Run: python3 -m pytest tests/ -v
"""

import pytest
import sys
import os
import json
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analysis.scoring_sensitivity import (
    compute_weighted_composite,
    layer_influence,
    run_full_analysis,
    run_scenario,
    load_assessment_layer_scores,
    BASELINE_WEIGHTS,
    WEIGHT_SCENARIOS,
    ALL_SCENARIOS,
    ANALYSIS_VERSION,
    _generate_sweep_scenarios,
)
from db.schema import initialize, seed_taxonomy
from db.repository import create_target, create_assessment
from db.adapters import store_assessment_results
from modules.scoring import compute_composite


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def db():
    conn, _ = initialize(":memory:")
    seed_taxonomy(conn)
    yield conn
    conn.close()


@pytest.fixture
def populated_db(db):
    """DB with two assessments for robustness testing."""
    for alias, os_s, net_s, web_s in [
        ("target-A", 50.0, 0.0, 50.0),
        ("target-B", 80.0, 60.0, 70.0),
    ]:
        tid = create_target(db, alias, "lab_vm", "lab", "LAB",
                            os_family="linux")
        aid = create_assessment(db, tid, "ALL", "LAB")
        layer_results = {
            "os_hardening": {
                "layer": "os_hardening", "score": os_s,
                "os_family": "linux", "applicable_checks": 4,
                "not_applicable_checks": 2, "findings": []
            },
            "network": {
                "layer": "network", "score": net_s,
                "open_ports": 1, "findings": [
                    {"port": "21", "service": "ftp", "severity": "critical",
                     "note": "backdoor", "recommendation": "upgrade"}
                ] if net_s == 0.0 else []
            },
            "webapp": {
                "layer": "webapp", "score": web_s, "findings": [
                    {"id": "csp", "description": "CSP missing",
                     "passed": False, "status": "FAIL",
                     "severity": "medium",
                     "recommendation": "Add CSP",
                     "not_applicable_reason": None}
                ] if web_s < 100.0 else []
            },
        }
        composite = compute_composite(layer_results)
        store_assessment_results(db, tid, layer_results, composite)
    yield db


# ── Mathematical Correctness ──────────────────────────────────────────────────

class TestMathematicalCorrectness:

    def test_baseline_reproduces_production_composite(self):
        """Baseline weights must produce identical result to production scoring.py."""
        layer_scores = {"os_hardening": 50.0, "network": 0.0, "webapp": 50.0}
        sensitivity_result = compute_weighted_composite(layer_scores, BASELINE_WEIGHTS)
        # Production formula: C = Σ(wᵢ × Sᵢ) / Σwᵢ (weights already sum to 1)
        expected = round(
            (50.0 * 0.30 + 0.0 * 0.35 + 50.0 * 0.35) /
            (0.30 + 0.35 + 0.35), 4
        )
        assert sensitivity_result == pytest.approx(expected, abs=0.01), \
            f"Got {sensitivity_result}, expected {expected}"

    def test_equal_weights_correct(self):
        layer_scores = {"os_hardening": 60.0, "network": 30.0, "webapp": 90.0}
        weights = {"os_hardening": 1/3, "network": 1/3, "webapp": 1/3}
        result = compute_weighted_composite(layer_scores, weights)
        expected = round((60.0 + 30.0 + 90.0) / 3, 4)
        assert result == pytest.approx(expected, abs=0.01)

    def test_single_layer_returns_that_score(self):
        """If only one layer is available, composite = that layer's score."""
        result = compute_weighted_composite(
            {"network": 42.0},
            {"os_hardening": 0.30, "network": 0.35, "webapp": 0.35}
        )
        assert result == pytest.approx(42.0, abs=0.01)

    def test_two_layers_renormalized(self):
        """Missing layer weight is excluded; remaining renormalized."""
        layer_scores = {"os_hardening": 80.0, "webapp": 40.0}
        weights = {"os_hardening": 0.30, "network": 0.35, "webapp": 0.35}
        result = compute_weighted_composite(layer_scores, weights)
        expected = round((80.0 * 0.30 + 40.0 * 0.35) / (0.30 + 0.35), 4)
        assert result == pytest.approx(expected, abs=0.01)

    def test_zero_weight_layer_excluded(self):
        """A layer with zero weight must not contribute to composite."""
        layer_scores = {"os_hardening": 100.0, "network": 0.0, "webapp": 100.0}
        weights = {"os_hardening": 0.50, "network": 0.00, "webapp": 0.50}
        result = compute_weighted_composite(layer_scores, weights)
        assert result == pytest.approx(100.0, abs=0.01)

    def test_all_zero_weights_returns_none(self):
        result = compute_weighted_composite(
            {"os_hardening": 50.0},
            {"os_hardening": 0.0, "network": 0.0, "webapp": 0.0}
        )
        assert result is None

    def test_empty_layer_scores_returns_none(self):
        result = compute_weighted_composite({}, BASELINE_WEIGHTS)
        assert result is None

    def test_composite_score_within_0_100(self):
        for os_s, net_s, web_s in [(0, 0, 0), (100, 100, 100), (33, 67, 50)]:
            scores = {"os_hardening": os_s, "network": net_s, "webapp": web_s}
            result = compute_weighted_composite(scores, BASELINE_WEIGHTS)
            assert 0.0 <= result <= 100.0, f"Score {result} out of range"

    def test_weights_need_not_sum_to_one_exactly(self):
        """Renormalization handles floating-point imprecision."""
        weights = {"os_hardening": 0.3, "network": 0.35, "webapp": 0.35}
        # sum = 1.0 exactly in this case — verify no crash at boundary
        result = compute_weighted_composite(
            {"os_hardening": 50.0, "network": 50.0, "webapp": 50.0},
            weights
        )
        assert result == pytest.approx(50.0, abs=0.1)


# ── Layer Influence ───────────────────────────────────────────────────────────

class TestLayerInfluence:

    def test_influence_sums_to_one(self):
        scores = {"os_hardening": 50.0, "network": 20.0, "webapp": 80.0}
        inf = layer_influence(scores, BASELINE_WEIGHTS)
        total = sum(inf.values())
        assert total == pytest.approx(1.0, abs=0.001)

    def test_higher_weight_more_influence_same_score(self):
        """With equal scores, higher weight → higher influence."""
        scores = {"os_hardening": 50.0, "network": 50.0, "webapp": 50.0}
        inf = layer_influence(scores, BASELINE_WEIGHTS)
        # network and webapp (0.35) > os_hardening (0.30)
        assert inf["network"] > inf["os_hardening"]
        assert inf["webapp"] > inf["os_hardening"]

    def test_zero_score_zero_influence(self):
        scores = {"os_hardening": 0.0, "network": 50.0, "webapp": 50.0}
        inf = layer_influence(scores, BASELINE_WEIGHTS)
        assert inf["os_hardening"] == 0.0

    def test_all_zero_scores_returns_zero_influence(self):
        scores = {"os_hardening": 0.0, "network": 0.0, "webapp": 0.0}
        inf = layer_influence(scores, BASELINE_WEIGHTS)
        assert all(v == 0.0 for v in inf.values())


# ── Sensitivity Scenarios ─────────────────────────────────────────────────────

class TestSensitivityScenarios:

    def test_baseline_scenario_exists(self):
        sids = [s[0] for s in WEIGHT_SCENARIOS]
        assert "baseline" in sids

    def test_equal_scenario_exists(self):
        sids = [s[0] for s in WEIGHT_SCENARIOS]
        assert "equal" in sids

    def test_all_predefined_scenarios_weights_sum_to_one(self):
        for sid, desc, weights in WEIGHT_SCENARIOS:
            total = sum(weights.values())
            assert total == pytest.approx(1.0, abs=0.001), \
                f"Scenario {sid} weights sum to {total}"

    def test_sweep_scenarios_generated(self):
        sweep = _generate_sweep_scenarios()
        assert len(sweep) > 0
        # Each sweep scenario weights must sum to 1.0
        for sid, desc, weights in sweep:
            total = sum(weights.values())
            assert total == pytest.approx(1.0, abs=0.001), \
                f"Sweep {sid} weights sum to {total}"

    def test_scenarios_deterministic(self):
        """Same assessment produces same result on repeated calls."""
        assessment = {
            "assessment_id": "test-123",
            "target_alias": "target-A",
            "layer_scores": {"os_hardening": 50.0, "network": 0.0, "webapp": 50.0},
            "available_layers": ["os_hardening", "network", "webapp"],
        }
        baseline = compute_weighted_composite(
            assessment["layer_scores"], BASELINE_WEIGHTS
        )
        sid, desc, weights = WEIGHT_SCENARIOS[1]  # equal
        r1 = run_scenario(assessment, sid, desc, weights, baseline)
        r2 = run_scenario(assessment, sid, desc, weights, baseline)
        assert r1["composite_score"] == r2["composite_score"]
        assert r1["diff_from_baseline"] == r2["diff_from_baseline"]

    def test_heavier_weight_on_better_layer_increases_composite(self):
        """Increasing weight on highest-scoring layer must increase composite."""
        scores = {"os_hardening": 80.0, "network": 10.0, "webapp": 50.0}
        baseline = compute_weighted_composite(scores, BASELINE_WEIGHTS)
        # OS is highest; increase OS weight
        os_heavy = {"os_hardening": 0.70, "network": 0.15, "webapp": 0.15}
        heavy_result = compute_weighted_composite(scores, os_heavy)
        assert heavy_result > baseline, \
            f"Expected {heavy_result} > {baseline} when weighting best layer"

    def test_heavier_weight_on_worst_layer_decreases_composite(self):
        """Increasing weight on lowest-scoring layer must decrease composite."""
        scores = {"os_hardening": 80.0, "network": 0.0, "webapp": 50.0}
        baseline = compute_weighted_composite(scores, BASELINE_WEIGHTS)
        net_heavy = {"os_hardening": 0.15, "network": 0.70, "webapp": 0.15}
        heavy_result = compute_weighted_composite(scores, net_heavy)
        assert heavy_result < baseline, \
            f"Expected {heavy_result} < {baseline} when weighting worst layer"

    def test_diff_from_baseline_correct(self):
        assessment = {
            "assessment_id": "x",
            "target_alias": "t",
            "layer_scores": {"os_hardening": 60.0, "network": 40.0, "webapp": 70.0},
            "available_layers": ["os_hardening", "network", "webapp"],
        }
        baseline = compute_weighted_composite(
            assessment["layer_scores"], BASELINE_WEIGHTS
        )
        sid, desc, weights = [s for s in WEIGHT_SCENARIOS if s[0] == "equal"][0]
        result = run_scenario(assessment, sid, desc, weights, baseline)
        expected_diff = round(result["composite_score"] - baseline, 4)
        assert result["diff_from_baseline"] == pytest.approx(expected_diff, abs=0.001)

    def test_baseline_scenario_diff_is_zero(self):
        """Baseline scenario must have zero diff from itself."""
        assessment = {
            "assessment_id": "x",
            "target_alias": "t",
            "layer_scores": {"os_hardening": 50.0, "network": 0.0, "webapp": 50.0},
            "available_layers": ["os_hardening", "network", "webapp"],
        }
        baseline = compute_weighted_composite(
            assessment["layer_scores"], BASELINE_WEIGHTS
        )
        sid, desc, weights = [s for s in WEIGHT_SCENARIOS if s[0] == "baseline"][0]
        result = run_scenario(assessment, sid, desc, weights, baseline)
        assert result["diff_from_baseline"] == pytest.approx(0.0, abs=0.001)


# ── Research Semantics ────────────────────────────────────────────────────────

class TestResearchSemantics:

    def test_not_applicable_layer_excluded(self):
        """
        NOT_APPLICABLE findings must not appear as zero-score layers.
        If a layer was not assessed, it must be absent from layer_scores,
        not present as 0.
        """
        # Simulate: OS was assessed, network was NOT_APPLICABLE (not a zero)
        # Correct: layer_scores only contains os_hardening
        layer_scores = {"os_hardening": 75.0}  # network absent = not assessed
        result = compute_weighted_composite(layer_scores, BASELINE_WEIGHTS)
        # Renormalized: only os_hardening contributes
        assert result == pytest.approx(75.0, abs=0.01)

    def test_unavailable_layer_not_silently_zero(self):
        """
        An absent layer must be excluded via renormalization, not treated as
        having a score of 0.
        """
        # If network were treated as 0, composite would be lower
        scores_with_network_zero = {
            "os_hardening": 80.0, "network": 0.0, "webapp": 80.0
        }
        scores_without_network = {
            "os_hardening": 80.0, "webapp": 80.0
        }
        composite_with_zero = compute_weighted_composite(
            scores_with_network_zero, BASELINE_WEIGHTS
        )
        composite_without = compute_weighted_composite(
            scores_without_network, BASELINE_WEIGHTS
        )
        # Without network (renormalized) should give higher composite
        assert composite_without > composite_with_zero, \
            "Absent layer must not be treated as zero score"

    def test_no_fabricated_assessment_data(self, db):
        """Analysis must not create assessment records in the DB."""
        count_before = db.execute(
            "SELECT COUNT(*) as c FROM assessment"
        ).fetchone()["c"]
        run_full_analysis(db, scenarios=WEIGHT_SCENARIOS, include_sweep=False)
        count_after = db.execute(
            "SELECT COUNT(*) as c FROM assessment"
        ).fetchone()["c"]
        assert count_after == count_before, \
            "Analysis must not create assessment records"

    def test_empty_db_returns_empirical_limitation(self, db):
        result = run_full_analysis(db, scenarios=WEIGHT_SCENARIOS,
                                   include_sweep=False)
        assert result["assessment_count"] == 0
        assert "empirical_limitation" in result
        assert len(result["empirical_limitation"]) > 0
        assert result["results"] == []

    def test_populated_db_returns_results(self, populated_db):
        result = run_full_analysis(
            populated_db, scenarios=WEIGHT_SCENARIOS, include_sweep=False
        )
        assert result["assessment_count"] == 2
        assert len(result["results"]) > 0

    def test_empirical_limitation_always_present(self, populated_db):
        """Limitation statement must always appear, even with data."""
        result = run_full_analysis(
            populated_db, scenarios=WEIGHT_SCENARIOS, include_sweep=False
        )
        assert "empirical_limitation" in result
        assert len(result["empirical_limitation"]) > 50


# ── Reproducibility ───────────────────────────────────────────────────────────

class TestReproducibility:

    def test_identical_input_identical_output(self, populated_db):
        """Same DB state + same scenarios → identical results."""
        r1 = run_full_analysis(
            populated_db, scenarios=WEIGHT_SCENARIOS, include_sweep=False
        )
        r2 = run_full_analysis(
            populated_db, scenarios=WEIGHT_SCENARIOS, include_sweep=False
        )
        # Compare scores (timestamps will differ)
        scores1 = [(r["assessment_id"], r["scenario_id"], r["composite_score"])
                   for r in r1["results"]]
        scores2 = [(r["assessment_id"], r["scenario_id"], r["composite_score"])
                   for r in r2["results"]]
        assert scores1 == scores2

    def test_analysis_version_in_output(self, populated_db):
        result = run_full_analysis(
            populated_db, scenarios=WEIGHT_SCENARIOS, include_sweep=False
        )
        assert result["analysis_version"] == ANALYSIS_VERSION
        assert result["analysis_id"] is not None

    def test_result_is_json_serializable(self, populated_db):
        result = run_full_analysis(
            populated_db, scenarios=WEIGHT_SCENARIOS, include_sweep=False
        )
        serialized = json.dumps(result)
        deserialized = json.loads(serialized)
        assert deserialized["analysis_version"] == ANALYSIS_VERSION

    def test_scenario_weights_preserved_in_output(self, populated_db):
        result = run_full_analysis(
            populated_db,
            scenarios=[s for s in WEIGHT_SCENARIOS if s[0] == "baseline"],
            include_sweep=False
        )
        for r in result["results"]:
            if r["scenario_id"] == "baseline":
                assert r["weights"]["os_hardening"] == pytest.approx(0.30, abs=0.001)
                assert r["weights"]["network"] == pytest.approx(0.35, abs=0.001)


# ── Robustness Analysis ───────────────────────────────────────────────────────

class TestRobustnessAnalysis:

    def test_ordering_stable_when_one_clearly_better(self):
        """
        When one target scores higher on ALL layers, ordering must be
        stable across all weight scenarios.
        """
        # Target B is better on every layer than Target A
        scores_a = {"os_hardening": 30.0, "network": 10.0, "webapp": 40.0}
        scores_b = {"os_hardening": 80.0, "network": 70.0, "webapp": 80.0}
        for sid, desc, weights in WEIGHT_SCENARIOS:
            ca = compute_weighted_composite(scores_a, weights)
            cb = compute_weighted_composite(scores_b, weights)
            if ca is not None and cb is not None:
                assert cb > ca, \
                    f"Ordering reversed in scenario {sid}: A={ca}, B={cb}"

    def test_ordering_can_change_when_layers_differ(self):
        """
        When targets score better on different layers, ordering CAN change
        across weight configurations.
        """
        # A is better at OS, B is better at Network
        scores_a = {"os_hardening": 90.0, "network": 10.0, "webapp": 50.0}
        scores_b = {"os_hardening": 10.0, "network": 90.0, "webapp": 50.0}
        os_heavy = {"os_hardening": 0.80, "network": 0.10, "webapp": 0.10}
        net_heavy = {"os_hardening": 0.10, "network": 0.80, "webapp": 0.10}
        ca_os = compute_weighted_composite(scores_a, os_heavy)
        cb_os = compute_weighted_composite(scores_b, os_heavy)
        ca_net = compute_weighted_composite(scores_a, net_heavy)
        cb_net = compute_weighted_composite(scores_b, net_heavy)
        # Under OS-heavy: A should win; under Network-heavy: B should win
        assert ca_os > cb_os, "A should lead under OS-heavy weights"
        assert cb_net > ca_net, "B should lead under Network-heavy weights"

    def test_summary_contains_robustness_verdict(self, populated_db):
        result = run_full_analysis(
            populated_db, scenarios=WEIGHT_SCENARIOS, include_sweep=False
        )
        assert result["summary"] is not None
        assert "robustness_verdict" in result["summary"]
        assert result["summary"]["robustness_verdict"] in (
            "STABLE", "SENSITIVE", "MIXED", "INSUFFICIENT_DATA"
        )


# ── Load Assessment Data ──────────────────────────────────────────────────────

class TestLoadAssessmentData:

    def test_empty_db_returns_empty_list(self, db):
        assessments = load_assessment_layer_scores(db)
        assert assessments == []

    def test_populated_db_returns_assessments(self, populated_db):
        assessments = load_assessment_layer_scores(populated_db)
        assert len(assessments) == 2

    def test_layer_scores_populated(self, populated_db):
        assessments = load_assessment_layer_scores(populated_db)
        for a in assessments:
            assert "layer_scores" in a
            assert "available_layers" in a
            assert len(a["layer_scores"]) > 0

    def test_none_score_not_in_layer_scores(self, populated_db):
        """Layers with NULL score must be absent from layer_scores."""
        assessments = load_assessment_layer_scores(populated_db)
        for a in assessments:
            for layer, score in a["layer_scores"].items():
                assert score is not None, \
                    f"NULL score for {layer} in assessment {a['assessment_id']}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
