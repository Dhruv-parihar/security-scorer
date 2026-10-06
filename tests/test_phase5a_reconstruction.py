"""Tests for the explicitly non-empirical legacy Phase 5A reconstruction."""
import json

import pytest

from analysis.scoring_sensitivity import compute_weighted_composite
from modules.scoring import compute_composite
from modules.scoring_config import DEFAULT_WEIGHTS
from tools.generate_phase5a_reconstruction import generate
from tools.validate_research_dataset import RECONSTRUCTED_LABEL, validate_research_dataset


def test_sensitivity_retains_precision_beyond_the_production_display_score():
    layers = {
        "os_hardening": {"score": 50},
        "network": {"score": 0},
        "webapp": {"score": 50},
    }
    expected = compute_composite(layers)["composite_score"]
    assert compute_weighted_composite(
        {name: result["score"] for name, result in layers.items()},
        DEFAULT_WEIGHTS,
    ) == pytest.approx(32.5)
    assert expected == 32


def test_reconstruction_creates_consistent_non_empirical_bundle(tmp_path):
    output = generate(tmp_path / "phase5a")
    prevalence = json.loads((output / "prevalence_results.json").read_text(encoding="utf-8"))
    sensitivity = json.loads((output / "sensitivity_results.json").read_text(encoding="utf-8"))
    longitudinal = json.loads((output / "longitudinal_results.json").read_text(encoding="utf-8"))
    manifest = json.loads((output / "reconstruction-manifest.json").read_text(encoding="utf-8"))

    assert prevalence["assessment_distribution"]["total_assessments"] == 6
    assert prevalence["status_distribution"]["status_counts"] == {
        "FAIL": 24, "PASS": 15, "NOT_APPLICABLE": 5,
    }
    assert prevalence["assessment_distribution"]["composite_score_distribution"]["mean"] == 70.83
    baseline = sensitivity["summary"]["scenario_stats"]["baseline"]
    assert baseline["min_composite"] == 32.5
    assert baseline["mean_composite"] == 70.92
    assert sensitivity["score_precision"]["production_composite"] == "nearest integer"
    assert longitudinal["comparison_count"] == 0
    assert manifest["classification"] == RECONSTRUCTED_LABEL

    preflight = validate_research_dataset(output / "phase5a-reconstructed.db")
    assert preflight["ready_for_paper_results"] is False
    assert any(
        check["id"] == "synthetic_data" and check["status"] == "ERROR"
        for check in preflight["checks"]
    )


def test_reconstruction_refuses_to_overwrite_output(tmp_path):
    output = tmp_path / "phase5a"
    generate(output)
    with pytest.raises(FileExistsError):
        generate(output)
