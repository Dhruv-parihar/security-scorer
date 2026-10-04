"""Synthetic tests for read-only same-target longitudinal analysis."""
import json
import pytest

from analysis.longitudinal import compare_assessments, run_longitudinal_analysis
from db.repository import create_assessment, create_finding, create_score_snapshot, create_target
from db.schema import initialize


@pytest.fixture
def conn():
    db, _ = initialize(":memory:")
    yield db
    db.close()


def make_target(conn, alias="lab-target"):
    return create_target(conn, alias, "lab_vm", "lab", "LAB")


def make_assessment(conn, target_id, scope="ALL", method="1.0"):
    return create_assessment(conn, target_id, scope, "LAB", methodology_version=method)


def observation(conn, assessment_id, layer, check_id, status):
    return create_finding(conn, assessment_id, layer, check_id, status, "Synthetic observation",
                          severity="high" if status == "FAIL" else None)


def score(conn, assessment_id, value, version="1.0", weights=(0.3, 0.35, 0.35)):
    return create_score_snapshot(conn, assessment_id, {
        "composite_score": value, "layers": {"os_hardening": {"score": value}},
    }, scoring_model_ver=version, weight_os=weights[0], weight_network=weights[1], weight_web=weights[2])


def test_status_changes_are_classified_conservatively(conn):
    target = make_target(conn)
    before, after = make_assessment(conn, target), make_assessment(conn, target)
    observation(conn, before, "OS", "resolved_check", "FAIL")
    observation(conn, after, "OS", "resolved_check", "PASS")
    observation(conn, before, "WEB", "introduced_check", "PASS")
    observation(conn, after, "WEB", "introduced_check", "FAIL")
    observation(conn, before, "OS", "persistent_fail", "FAIL")
    observation(conn, after, "OS", "persistent_fail", "FAIL")
    observation(conn, before, "OS", "not_run_after", "FAIL")
    observation(conn, after, "OS", "not_run_after", "NOT_TESTED")
    result = compare_assessments(conn, before, after)
    assert result["counts"] == {"resolved": 1, "introduced": 1, "persistent_failures": 1,
                                "persistent_passes": 0, "not_comparable": 1}
    assert result["changes"]["not_comparable"][0]["before_status"] == "FAIL"
    assert result["changes"]["not_comparable"][0]["after_status"] == "NOT_TESTED"


def test_missing_check_is_not_claimed_resolved(conn):
    target = make_target(conn)
    before, after = make_assessment(conn, target), make_assessment(conn, target)
    observation(conn, before, "OS", "only_before", "FAIL")
    result = compare_assessments(conn, before, after)
    assert result["counts"]["resolved"] == 0
    item = result["changes"]["not_comparable"][0]
    assert item["after_status"] == "MISSING"


def test_cross_target_comparison_is_rejected(conn):
    first = make_assessment(conn, make_target(conn, "first"))
    second = make_assessment(conn, make_target(conn, "second"))
    with pytest.raises(ValueError, match="same target"):
        compare_assessments(conn, first, second)


def test_score_delta_requires_matching_model_and_weights(conn):
    target = make_target(conn)
    before, after = make_assessment(conn, target), make_assessment(conn, target)
    score(conn, before, 40)
    score(conn, after, 70)
    result = compare_assessments(conn, before, after)["score_comparison"]
    assert result["comparable"] is True
    assert result["delta"] == 30


def test_score_delta_rejects_configuration_change(conn):
    target = make_target(conn)
    before, after = make_assessment(conn, target), make_assessment(conn, target)
    score(conn, before, 40, version="1.0")
    score(conn, after, 70, version="2.0")
    result = compare_assessments(conn, before, after)["score_comparison"]
    assert result["comparable"] is False
    assert "differ" in result["reason"]


def test_latest_snapshot_is_used(conn):
    target = make_target(conn)
    before, after = make_assessment(conn, target), make_assessment(conn, target)
    score(conn, before, 20)
    score(conn, before, 45)
    score(conn, after, 70)
    result = compare_assessments(conn, before, after)["score_comparison"]
    assert result["before_score"] == 45
    assert result["delta"] == 25


def test_protocol_difference_is_flagged(conn):
    target = make_target(conn)
    before = make_assessment(conn, target, scope="OS")
    after = make_assessment(conn, target, scope="ALL")
    result = compare_assessments(conn, before, after)
    assert result["protocol_comparable"] is False


def test_full_analysis_groups_consecutive_pairs_and_never_writes(conn):
    target = make_target(conn)
    first = make_assessment(conn, target)
    second = make_assessment(conn, target)
    third = make_assessment(conn, target)
    before = conn.execute("SELECT COUNT(*) AS c FROM finding").fetchone()["c"]
    result = run_longitudinal_analysis(conn)
    after = conn.execute("SELECT COUNT(*) AS c FROM finding").fetchone()["c"]
    assert before == after
    assert result["comparison_count"] == 2
    assert result["targets"][0]["assessment_count"] == 3
    assert json.loads(json.dumps(result))["analysis_id"] == "longitudinal_v1"
