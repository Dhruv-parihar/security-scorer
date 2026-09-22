"""
Test Suite — Phase 4B: Prevalence + Co-occurrence Analysis
==========================================================
Run: python3 -m pytest tests/ -q
"""

import pytest
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db.schema import initialize, seed_taxonomy
from db.repository import create_target, create_assessment, create_finding
from analysis.prevalence import (
    finding_prevalence, layer_prevalence, severity_distribution,
    status_distribution, assessment_distribution,
    finding_cooccurrence, run_full_analysis,
    ANALYSIS_VERSION, EVALUATED_STATUSES, EXCLUDED_STATUSES,
    SMALL_SAMPLE_THRESHOLD, _empirical_note,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def db():
    conn, _ = initialize(":memory:")
    seed_taxonomy(conn)
    yield conn
    conn.close()


def _target(conn, alias="t1"):
    return create_target(conn, alias, "lab_vm", "lab", "LAB",
                         os_family="linux")


def _assessment(conn, target_id):
    return create_assessment(conn, target_id, "ALL", "LAB")


def _finding(conn, aid, check_id, status, layer="OS",
             severity=None, description=None):
    if status in ("NOT_APPLICABLE", "NOT_TESTED"):
        severity = None
    return create_finding(
        conn, aid, layer, check_id, status,
        description or f"desc for {check_id}",
        severity=severity
    )


# ── Rich fixtures for multi-assessment tests ──────────────────────────────────

@pytest.fixture
def single_assessment_db(db):
    """One target, one assessment, 3 OS findings (PASS, FAIL, NOT_APPLICABLE)."""
    tid = _target(db, "target-1")
    aid = _assessment(db, tid)
    _finding(db, aid, "ssh_root_login", "FAIL", "OS", "high")
    _finding(db, aid, "firewall_active", "PASS", "OS", None)
    _finding(db, aid, "password_max_days", "NOT_APPLICABLE", "OS", None)
    return db, aid, tid


@pytest.fixture
def multi_assessment_db(db):
    """
    Three targets, three assessments for prevalence testing.
    ssh_root_login: FAIL in 2, PASS in 1
    firewall_active: FAIL in 1, PASS in 2
    csp_header: FAIL in all 3 (WEB layer)
    not_tested_check: NOT_TESTED in 1 (excluded from denominator)
    """
    for i in range(3):
        tid = _target(db, f"target-{i}")
        aid = _assessment(db, tid)
        # SSH: FAIL for targets 0,1; PASS for target 2
        if i < 2:
            _finding(db, aid, "ssh_root_login", "FAIL", "OS", "high")
        else:
            _finding(db, aid, "ssh_root_login", "PASS", "OS", None)
        # Firewall: FAIL for target 0; PASS for 1,2
        if i == 0:
            _finding(db, aid, "firewall_active", "FAIL", "OS", "high")
        else:
            _finding(db, aid, "firewall_active", "PASS", "OS", None)
        # CSP header: FAIL for all three (WEB layer)
        _finding(db, aid, "csp_header", "FAIL", "WEB", "medium")
        # NOT_TESTED: only for target 0
        if i == 0:
            _finding(db, aid, "not_tested_check", "NOT_TESTED", "OS", None)
        # NOT_APPLICABLE: only for target 1
        if i == 1:
            _finding(db, aid, "windows_only_check", "NOT_APPLICABLE", "OS", None)
        # ERROR: only for target 2
        if i == 2:
            _finding(db, aid, "error_check", "ERROR", "OS", None)
    return db


@pytest.fixture
def cooccurrence_db(db):
    """
    Four assessments for co-occurrence testing.
    A and B co-occur in assessments 0, 1 (2 times).
    A and C co-occur in assessment 0 only (1 time).
    B alone in assessment 2.
    D alone in assessment 3.
    """
    checks = [
        # (assessment_idx, check_id, status)
        (0, "check_a", "FAIL"), (0, "check_b", "FAIL"), (0, "check_c", "FAIL"),
        (1, "check_a", "FAIL"), (1, "check_b", "FAIL"),
        (2, "check_b", "FAIL"),
        (3, "check_d", "FAIL"),
    ]
    aids = []
    for i in range(4):
        tid = _target(db, f"co-target-{i}")
        aids.append(_assessment(db, tid))
    for aid_idx, check_id, status in checks:
        _finding(db, aids[aid_idx], check_id, status, "OS", "medium")
    return db, aids


# ── Finding Prevalence ────────────────────────────────────────────────────────

class TestFindingPrevalence:

    def test_empty_db_returns_empty_list(self, db):
        assert finding_prevalence(db) == []

    def test_fail_count_correct(self, multi_assessment_db):
        results = finding_prevalence(multi_assessment_db)
        ssh = next(r for r in results if r["check_id"] == "ssh_root_login")
        assert ssh["n_fail"] == 2
        assert ssh["n_pass"] == 1
        assert ssh["n_applicable"] == 3

    def test_fail_pct_correct(self, multi_assessment_db):
        results = finding_prevalence(multi_assessment_db)
        ssh = next(r for r in results if r["check_id"] == "ssh_root_login")
        assert ssh["fail_pct"] == pytest.approx(66.7, abs=0.1)

    def test_not_applicable_excluded_from_denominator(self, multi_assessment_db):
        """windows_only_check is NOT_APPLICABLE in 1 assessment — must not appear."""
        results = finding_prevalence(multi_assessment_db)
        check_ids = [r["check_id"] for r in results]
        assert "windows_only_check" not in check_ids

    def test_not_tested_excluded_from_denominator(self, multi_assessment_db):
        """not_tested_check is NOT_TESTED — must not appear in prevalence."""
        results = finding_prevalence(multi_assessment_db)
        check_ids = [r["check_id"] for r in results]
        assert "not_tested_check" not in check_ids

    def test_error_excluded_from_denominator(self, multi_assessment_db):
        """error_check is ERROR — must not appear in prevalence."""
        results = finding_prevalence(multi_assessment_db)
        check_ids = [r["check_id"] for r in results]
        assert "error_check" not in check_ids

    def test_layer_filter_works(self, multi_assessment_db):
        """Layer filter must restrict results to that layer."""
        os_results = finding_prevalence(multi_assessment_db, layer="OS")
        web_results = finding_prevalence(multi_assessment_db, layer="WEB")
        os_ids = {r["check_id"] for r in os_results}
        web_ids = {r["check_id"] for r in web_results}
        assert "ssh_root_login" in os_ids
        assert "csp_header" not in os_ids
        assert "csp_header" in web_ids
        assert "ssh_root_login" not in web_ids

    def test_sorted_by_fail_pct_desc(self, multi_assessment_db):
        results = finding_prevalence(multi_assessment_db)
        pcts = [r["fail_pct"] for r in results]
        assert pcts == sorted(pcts, reverse=True)

    def test_denominator_note_present(self, multi_assessment_db):
        results = finding_prevalence(multi_assessment_db)
        for r in results:
            assert "denominator_note" in r
            assert len(r["denominator_note"]) > 0

    def test_preliminary_flag_set_for_small_n(self, single_assessment_db):
        db, aid, tid = single_assessment_db
        results = finding_prevalence(db)
        for r in results:
            # n_applicable = 1 < SMALL_SAMPLE_THRESHOLD
            assert r["preliminary"] is True

    def test_unique_assessment_counting(self, db):
        """Multiple FAIL findings for same check in same assessment count once."""
        tid = _target(db)
        aid = _assessment(db, tid)
        # Two FAIL finding records for same check in same assessment
        create_finding(db, aid, "OS", "dup_check", "FAIL",
                       "duplicate 1", severity="high")
        create_finding(db, aid, "OS", "dup_check", "FAIL",
                       "duplicate 2", severity="high")
        results = finding_prevalence(db)
        dup = next(r for r in results if r["check_id"] == "dup_check")
        # Should count as 1 assessment, not 2
        assert dup["n_fail"] == 1
        assert dup["n_applicable"] == 1


# ── Layer Prevalence ──────────────────────────────────────────────────────────

class TestLayerPrevalence:

    def test_empty_db_returns_empty_list(self, db):
        assert layer_prevalence(db) == []

    def test_layers_present(self, multi_assessment_db):
        results = layer_prevalence(multi_assessment_db)
        layers = {r["layer"] for r in results}
        assert "OS" in layers
        assert "WEB" in layers

    def test_os_fail_count_correct(self, multi_assessment_db):
        results = layer_prevalence(multi_assessment_db)
        os_row = next(r for r in results if r["layer"] == "OS")
        # ssh_root FAIL×2 + firewall FAIL×1 = 3 OS FAILs
        assert os_row["total_fail"] == 3

    def test_excluded_statuses_not_counted(self, multi_assessment_db):
        """NOT_APPLICABLE, NOT_TESTED, ERROR must not appear in total_check_evaluations."""
        results = layer_prevalence(multi_assessment_db)
        os_row = next(r for r in results if r["layer"] == "OS")
        # OS has: ssh(FAIL×2,PASS×1) + firewall(FAIL×1,PASS×2) = 6 evaluations
        # NOT_APPLICABLE(1), NOT_TESTED(1), ERROR(1) are excluded
        assert os_row["total_check_evaluations"] == 6

    def test_fail_pct_within_range(self, multi_assessment_db):
        results = layer_prevalence(multi_assessment_db)
        for r in results:
            assert 0.0 <= r["overall_fail_pct"] <= 100.0

    def test_denominator_note_present(self, multi_assessment_db):
        results = layer_prevalence(multi_assessment_db)
        for r in results:
            assert "denominator_note" in r


# ── Severity Distribution ─────────────────────────────────────────────────────

class TestSeverityDistribution:

    def test_empty_db(self, db):
        result = severity_distribution(db)
        assert result["severity_counts"] == {}
        assert result["total_fail_findings"] == 0

    def test_counts_only_fail(self, single_assessment_db):
        db, aid, tid = single_assessment_db
        result = severity_distribution(db)
        # Only ssh_root_login (FAIL, high) should appear
        assert "high" in result["severity_counts"]
        assert result["severity_counts"]["high"] == 1

    def test_not_applicable_excluded(self, single_assessment_db):
        db, aid, tid = single_assessment_db
        # NOT_APPLICABLE finding has severity=None — must not inflate counts
        result = severity_distribution(db)
        # PASS finding has no severity — must not appear
        total = sum(result["severity_counts"].values())
        assert total == result["total_fail_findings"]

    def test_layer_filter(self, multi_assessment_db):
        os_sev = severity_distribution(multi_assessment_db, layer="OS")
        web_sev = severity_distribution(multi_assessment_db, layer="WEB")
        # OS has high severity FAILs; WEB has medium
        os_sevs = set(os_sev["severity_counts"].keys())
        web_sevs = set(web_sev["severity_counts"].keys())
        assert "high" in os_sevs
        assert "medium" in web_sevs

    def test_denominator_note_present(self, db):
        result = severity_distribution(db)
        assert "denominator_note" in result


# ── Status Distribution ───────────────────────────────────────────────────────

class TestStatusDistribution:

    def test_empty_db(self, db):
        result = status_distribution(db)
        assert result["total_findings"] == 0
        assert result["evaluated_count"] == 0
        assert result["excluded_count"] == 0

    def test_all_statuses_counted(self, multi_assessment_db):
        result = status_distribution(multi_assessment_db)
        counts = result["status_counts"]
        # Should have FAIL, PASS, NOT_APPLICABLE, NOT_TESTED, ERROR
        assert "FAIL" in counts
        assert "PASS" in counts
        assert "NOT_APPLICABLE" in counts
        assert "NOT_TESTED" in counts
        assert "ERROR" in counts

    def test_evaluated_vs_excluded_counts(self, multi_assessment_db):
        result = status_distribution(multi_assessment_db)
        evaluated = result["evaluated_count"]
        excluded = result["excluded_count"]
        total = result["total_findings"]
        assert evaluated + excluded == total

    def test_evaluated_statuses_only_pass_fail(self, multi_assessment_db):
        result = status_distribution(multi_assessment_db)
        counts = result["status_counts"]
        evaluated = result["evaluated_count"]
        expected = counts.get("PASS", 0) + counts.get("FAIL", 0)
        assert evaluated == expected


# ── Assessment Distribution ───────────────────────────────────────────────────

class TestAssessmentDistribution:

    def test_empty_db(self, db):
        result = assessment_distribution(db)
        assert result["total_assessments"] == 0
        assert result["total_targets"] == 0
        assert result["composite_score_distribution"] is None

    def test_counts_correct(self, multi_assessment_db):
        result = assessment_distribution(multi_assessment_db)
        assert result["total_assessments"] == 3
        assert result["total_targets"] == 3
        assert result["assessments_with_findings"] == 3
        assert result["assessments_with_fail"] == 3

    def test_score_distribution_present_when_snapshots_exist(self, db):
        from db.adapters import store_assessment_results
        from modules.scoring import compute_composite
        tid = _target(db)
        aid = _assessment(db, tid)
        layer_results = {
            "os_hardening": {
                "layer": "os_hardening", "score": 50,
                "os_family": "linux", "applicable_checks": 2,
                "not_applicable_checks": 0, "findings": []
            }
        }
        composite = compute_composite(layer_results)
        store_assessment_results(db, tid, layer_results, composite)
        result = assessment_distribution(db)
        assert result["composite_score_distribution"] is not None
        assert "mean" in result["composite_score_distribution"]
        assert "buckets" in result["composite_score_distribution"]


# ── Co-occurrence ─────────────────────────────────────────────────────────────

class TestCooccurrence:

    def test_empty_db_returns_empty_list(self, db):
        assert finding_cooccurrence(db) == []

    def test_correct_cooccurrence_count(self, cooccurrence_db):
        db, aids = cooccurrence_db
        results = finding_cooccurrence(db)
        ab = next((r for r in results
                   if set([r["check_a"], r["check_b"]]) == {"check_a", "check_b"}),
                  None)
        assert ab is not None, "check_a / check_b pair not found"
        assert ab["n_assessments_with_both"] == 2

    def test_no_self_pairs(self, cooccurrence_db):
        db, aids = cooccurrence_db
        results = finding_cooccurrence(db)
        for r in results:
            assert r["check_a"] != r["check_b"]

    def test_pairs_ordered_alphabetically(self, cooccurrence_db):
        db, aids = cooccurrence_db
        results = finding_cooccurrence(db)
        for r in results:
            assert r["check_a"] <= r["check_b"], \
                f"Pair not ordered: {r['check_a']} / {r['check_b']}"

    def test_unique_assessment_counting(self, db):
        """
        Multiple FAIL finding records for same check in same assessment
        must count as ONE assessment, not multiple.
        """
        tid = _target(db)
        aid = _assessment(db, tid)
        # Two finding records for check_x in the same assessment
        create_finding(db, aid, "OS", "check_x", "FAIL", "dup1", severity="high")
        create_finding(db, aid, "OS", "check_x", "FAIL", "dup2", severity="high")
        create_finding(db, aid, "OS", "check_y", "FAIL", "desc", severity="medium")
        results = finding_cooccurrence(db)
        pair = next((r for r in results
                     if set([r["check_a"], r["check_b"]]) == {"check_x", "check_y"}),
                    None)
        assert pair is not None
        assert pair["n_assessments_with_both"] == 1
        assert pair["n_assessments_with_a"] == 1  # not 2

    def test_min_cooccurrence_filter(self, cooccurrence_db):
        db, aids = cooccurrence_db
        # Only pairs with n_both >= 2
        results = finding_cooccurrence(db, min_cooccurrence=2)
        for r in results:
            assert r["n_assessments_with_both"] >= 2

    def test_sorted_by_n_both_desc(self, cooccurrence_db):
        db, aids = cooccurrence_db
        results = finding_cooccurrence(db)
        counts = [r["n_assessments_with_both"] for r in results]
        assert counts == sorted(counts, reverse=True)

    def test_caution_note_present(self, cooccurrence_db):
        db, aids = cooccurrence_db
        results = finding_cooccurrence(db)
        for r in results:
            assert "caution_note" in r
            assert "does not imply causation" in r["caution_note"]

    def test_cross_layer_flag_correct(self, db):
        """cross_layer=True when checks are from different layers."""
        tid = _target(db)
        aid = _assessment(db, tid)
        _finding(db, aid, "os_check", "FAIL", "OS", "high")
        _finding(db, aid, "web_check", "FAIL", "WEB", "medium")
        results = finding_cooccurrence(db)
        pair = next((r for r in results
                     if set([r["check_a"], r["check_b"]]) == {"os_check", "web_check"}),
                    None)
        assert pair is not None
        assert pair["cross_layer"] is True

    def test_only_fail_included(self, db):
        """PASS findings must not appear in co-occurrence."""
        tid = _target(db)
        aid = _assessment(db, tid)
        _finding(db, aid, "check_pass_a", "PASS", "OS", None)
        _finding(db, aid, "check_pass_b", "PASS", "OS", None)
        _finding(db, aid, "check_fail_a", "FAIL", "OS", "high")
        results = finding_cooccurrence(db)
        # No pair involving PASS-only checks
        for r in results:
            assert "check_pass_a" not in (r["check_a"], r["check_b"])
            assert "check_pass_b" not in (r["check_a"], r["check_b"])

    def test_deterministic_results(self, cooccurrence_db):
        db, aids = cooccurrence_db
        r1 = finding_cooccurrence(db)
        r2 = finding_cooccurrence(db)
        assert [(r["check_a"], r["check_b"], r["n_assessments_with_both"])
                for r in r1] == \
               [(r["check_a"], r["check_b"], r["n_assessments_with_both"])
                for r in r2]


# ── Research Semantics ────────────────────────────────────────────────────────

class TestResearchSemantics:

    def test_no_records_created_by_analysis(self, multi_assessment_db):
        """Analysis must never create assessment/target/finding records."""
        count_before = {
            "assessment": multi_assessment_db.execute(
                "SELECT COUNT(*) AS c FROM assessment").fetchone()["c"],
            "finding": multi_assessment_db.execute(
                "SELECT COUNT(*) AS c FROM finding").fetchone()["c"],
            "target": multi_assessment_db.execute(
                "SELECT COUNT(*) AS c FROM target").fetchone()["c"],
        }
        run_full_analysis(multi_assessment_db)
        count_after = {
            "assessment": multi_assessment_db.execute(
                "SELECT COUNT(*) AS c FROM assessment").fetchone()["c"],
            "finding": multi_assessment_db.execute(
                "SELECT COUNT(*) AS c FROM finding").fetchone()["c"],
            "target": multi_assessment_db.execute(
                "SELECT COUNT(*) AS c FROM target").fetchone()["c"],
        }
        assert count_before == count_after

    def test_causal_inference_warning_in_full_analysis(self, db):
        result = run_full_analysis(db)
        assert "causal_inference_warning" in result
        assert "does not imply causation" in result["causal_inference_warning"]

    def test_empirical_limitation_empty_db(self, db):
        result = run_full_analysis(db)
        assert "empirical_limitation" in result
        assert len(result["empirical_limitation"]) > 20

    def test_empirical_limitation_small_sample(self, single_assessment_db):
        db, aid, tid = single_assessment_db
        result = run_full_analysis(db)
        assert "preliminary" in result["empirical_limitation"].lower() or \
               "small sample" in result["empirical_limitation"].lower()

    def test_denominator_definitions_present(self, db):
        result = run_full_analysis(db)
        defs = result.get("denominator_definitions", {})
        assert "prevalence_denominator" in defs
        assert "cooccurrence_denominator" in defs
        assert "layer_prevalence_denominator" in defs

    def test_analysis_version_present(self, db):
        result = run_full_analysis(db)
        assert result["analysis_version"] == ANALYSIS_VERSION
        assert result["analysis_id"] is not None

    def test_not_applicable_missing_absent_from_prevalence(self, multi_assessment_db):
        """Checks that never produced PASS or FAIL must not appear in prevalence."""
        results = finding_prevalence(multi_assessment_db)
        ids = {r["check_id"] for r in results}
        # These only appeared as NOT_APPLICABLE / NOT_TESTED / ERROR
        for excluded_check in ("windows_only_check", "not_tested_check", "error_check"):
            assert excluded_check not in ids, \
                f"{excluded_check} should not appear in prevalence"

    def test_small_sample_threshold_constant(self):
        assert SMALL_SAMPLE_THRESHOLD == 10

    def test_empirical_note_zero_assessments(self):
        note = _empirical_note(0)
        assert "no assessments" in note.lower() or "populate" in note.lower()

    def test_empirical_note_small_sample(self):
        note = _empirical_note(3)
        assert "preliminary" in note.lower() or "small sample" in note.lower()

    def test_empirical_note_adequate_sample(self):
        note = _empirical_note(15)
        assert "descriptive" in note.lower() or "observational" in note.lower()


# ── Reproducibility ───────────────────────────────────────────────────────────

class TestReproducibility:

    def test_identical_output_same_db(self, multi_assessment_db):
        r1 = run_full_analysis(multi_assessment_db)
        r2 = run_full_analysis(multi_assessment_db)
        # Exclude timestamp from comparison
        for key in ("finding_prevalence", "layer_prevalence",
                    "status_distribution", "cooccurrence"):
            assert r1[key] == r2[key], f"Mismatch in {key}"

    def test_json_serializable(self, multi_assessment_db):
        result = run_full_analysis(multi_assessment_db)
        serialized = json.dumps(result)
        deserialized = json.loads(serialized)
        assert deserialized["analysis_version"] == ANALYSIS_VERSION

    def test_finding_prevalence_deterministic(self, multi_assessment_db):
        r1 = finding_prevalence(multi_assessment_db)
        r2 = finding_prevalence(multi_assessment_db)
        assert [(r["check_id"], r["n_fail"], r["fail_pct"]) for r in r1] == \
               [(r["check_id"], r["n_fail"], r["fail_pct"]) for r in r2]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
