# ARCHITECTURAL / RESEARCH DECISIONS

## D-001 — Do not rebuild from scratch
**Date:** 2026-09-18
**Decision:** Preserve existing architecture. Extend, do not replace.
**Rationale:** Working CLI + Flask UI exists. Scores are reproducible.
Destroying baseline breaks research continuity.

## D-002 — Phase 0 audit before any implementation
**Date:** 2026-09-18
**Decision:** Complete full audit and produce PROJECT_AUDIT.md before
touching any module.
**Rationale:** Cannot make safe architectural decisions without
understanding current state. Confirmed: no tests, no DB, no auth,
no taxonomy, no NOT_APPLICABLE handling exist yet.

## D-003 — Branch strategy
**Date:** 2026-09-18
**Decision:** Each phase gets its own branch: phase/N-name.
Main branch remains stable baseline at all times.
**Rationale:** Research reproducibility requires a clean baseline.

## D-004 — Raw findings are primary research observations; scores are derived artifacts
**Date:** 2026-09-18
**Decision:** The database stores raw findings as the primary unit of research
data. Scores are computed from findings and stored as score_snapshots with
explicit model ID, version, and weights. Old snapshots are retained when
scoring models change.
**Rationale:** Research validity requires that the underlying observations
remain accessible independently of the scoring methodology. Different scoring
models can be compared against the same underlying finding dataset.

## D-005 — NOT_APPLICABLE is semantically distinct from FAIL
**Date:** 2026-09-18
**Decision:** NOT_APPLICABLE status is enforced at the application layer
(repository.py raises ValueError if severity is set on NOT_APPLICABLE/NOT_TESTED
findings). NOT_APPLICABLE findings are excluded from prevalence denominators
and do not reduce scores. Confirmed by tests: test_not_applicable_severity_must_be_none,
test_not_applicable_excluded_from_prevalence.
**Rationale:** Treating NOT_APPLICABLE as FAIL would systematically bias
cross-OS and cross-environment comparisons. A Windows system must not receive
FAIL for a Linux SSH configuration check.

## D-006 — SQLite for Phase 1; schema migration via MIGRATIONS list
**Date:** 2026-09-18
**Decision:** SQLite chosen for portability and zero-dependency deployment.
Migrations are stored as a list of SQL strings in schema.py, indexed 0-based.
schema_migrations table tracks applied migrations. migrate() is idempotent.
**Rationale:** SQLite requires no server, no configuration, is portable with
the repo, and is sufficient for a single-researcher dataset of hundreds to
thousands of assessments. Migration to PostgreSQL is possible later if scale
requires it.

## D-007 — Scanner modules unchanged in Phase 1
**Date:** 2026-09-18
**Decision:** os_hardening.py, network_scan.py, webapp_scan.py, scoring.py
were NOT modified in Phase 1. The DB layer is standalone.
**Rationale:** Phase 0 audit identified R1 (network findings excluded from
recommendations) and R2/R3 (NOT_APPLICABLE missing) as bugs to fix in Phase 2.
Fixing them requires careful integration testing. Phase 1 establishes the
data layer first so fixes can be validated by writing to DB.

## D-008 — R1 Fix: _is_failed_finding() replaces finding.get("passed", True)
**Date:** 2026-09-18
**Decision:** Introduced _is_failed_finding(finding) in scoring.py.
Logic: passed=False → FAIL; passed=None + severity≠None → network-style FAIL;
severity=None + no passed key → NOT_APPLICABLE, excluded.
**Rationale:** Network findings have no "passed" key. The original default
of True silently excluded all network findings from recommendations.
**Tests:** test_is_failed_finding_* (5 tests), test_network_findings_in_recommendations,
test_mixed_layers_all_recommendations_present.

## D-009 — R2/R3 Fix: OS detection + NOT_APPLICABLE state in os_hardening.py
**Date:** 2026-09-18
**Decision:** _detect_os() added. Each check receives os_family parameter.
Linux-specific checks return _not_applicable() on non-Linux OS.
Score denominator = applicable checks only (PASS+FAIL). NOT_APPLICABLE
findings excluded. result dict now includes os_family, applicable_checks,
not_applicable_checks for research traceability.
**Tests:** test_all_checks_not_applicable_on_windows/macos (12 checks),
test_not_applicable_does_not_reduce_score, test_not_applicable_excluded_from_score.

## D-010 — R4 Fix: modules/authorization.py — explicit DB record required
**Date:** 2026-09-18
**Decision:** Active scanning requires a target record in research.db with
valid authorization_status. require_authorization(conn, identifier) raises
AuthorizationError if no record found. check_authorization() is the
non-raising form for Flask form validation. Authorization is never inferred.
**Tests:** test_unauthorized_ip_blocked, test_arbitrary_ip_without_record_blocked,
test_authorized_lab_target_passes, test_all_valid_auth_statuses_permit_scanning.

## D-011 — Adapter: db/adapters.py — thin translation layer
**Date:** 2026-09-18
**Decision:** store_assessment_results() translates scanner dicts → DB records
without modifying scanner modules. Finding status inferred by _infer_status()
which handles both os/webapp (passed bool + status field) and network
(no passed key, severity present = FAIL). Existing JSON output format
preserved. FAIL findings get pending remediation records automatically.
**Tests:** TestAdapter (9 tests).

## D-012 — Scanner modules backward-compatible, JSON output unchanged
**Date:** 2026-09-18
**Decision:** The existing JSON output format from all three scanner modules
is preserved for CLI/Flask backward compatibility. os_hardening.py adds
os_family, applicable_checks, not_applicable_checks to result dict (additive,
not breaking). network_scan.py and webapp_scan.py unchanged.

## D-013 — Phase 3: main.py wired to authorization + DB (option 5 for target mgmt)
**Date:** 2026-09-18
**Decision:** main.py now requires authorization before network/web scans.
Added option 5 (manage authorized targets) to CLI. DB persistence via
_persist() which swallows non-critical DB errors so CLI output is never
broken by DB failure. OS hardening proceeds without authorization check
(local only). debug=False in app.py.
**Tests:** TestCLIPath (8 tests), TestFlaskPath (9 tests).

## D-014 — Phase 3: app.py wired to authorization + DB + target management
**Date:** 2026-09-18
**Decision:** Flask /scan route checks authorization before calling any active
scanner. auth_blocks list returned to template. /targets/add route for
registering new authorized targets. assessment_id shown in results when
persistence succeeds. debug=False.
**Tests:** TestFlaskPath (9 tests).

## D-015 — debug=False in production app.py
**Date:** 2026-09-18
**Decision:** app.py changed from debug=True to debug=False, host restricted
to 127.0.0.1. Werkzeug debugger was a remote code execution risk.
**Rationale:** R9 (security issue in kit itself) from Phase 0 audit.

## D-016 — Phase 4A: analysis/scoring_sensitivity.py — mathematical sensitivity only
**Date:** 2026-09-18
**Decision:** Sensitivity analysis evaluates mathematical/model robustness
across predefined weight scenarios. Does NOT claim any alternative weighting
is empirically superior. Empirical limitation statement always included in
output. Analysis never creates assessment records in the DB.
**Tests:** TestResearchSemantics.test_no_fabricated_assessment_data,
test_empty_db_returns_empirical_limitation,
test_empirical_limitation_always_present (3 tests).

## D-017 — Phase 4A: NOT_APPLICABLE means absent from layer_scores, not zero
**Date:** 2026-09-18
**Decision:** compute_weighted_composite() excludes absent layers via
renormalization. An absent layer (NOT_APPLICABLE or not assessed) must
not be treated as a zero score. test_unavailable_layer_not_silently_zero
confirms this property is enforced.

## D-018 — Phase 4A: Sweep scenarios cover ±SWEEP_STEP increments per layer
**Date:** 2026-09-18
**Decision:** _generate_sweep_scenarios() varies each layer's weight from
0.05 to 0.90 in 0.05 increments, distributing remainder equally across
the other two layers. Weights always sum to 1.0. 54 sweep scenarios total
(18 per layer × 3 layers). All validated by test_sweep_scenarios_generated.

## D-019 — Phase 4B: Denominator definition — PASS+FAIL only
**Date:** 2026-09-18
**Decision:** Prevalence denominator = assessments where check produced
PASS or FAIL. NOT_APPLICABLE, NOT_TESTED, ERROR, UNKNOWN excluded.
This is enforced in SQL (WHERE status IN ('PASS','FAIL')) and verified
by 4 tests: test_not_applicable_excluded_from_denominator,
test_not_tested_excluded_from_denominator, test_error_excluded_from_denominator,
test_not_applicable_missing_absent_from_prevalence.

## D-020 — Phase 4B: Co-occurrence uses unique assessment-level FAIL presence
**Date:** 2026-09-18
**Decision:** Co-occurrence counts unique assessment-level FAIL presence,
not finding record count. Multiple FAIL records for the same check in the
same assessment count as 1. Enforced by DISTINCT in SQL grouping and
verified by test_unique_assessment_counting.
No causal language. caution_note field present on every co-occurrence result.

## D-021 — Phase 4B: Small sample threshold = 10; preliminary flag always set
**Date:** 2026-09-18
**Decision:** SMALL_SAMPLE_THRESHOLD = 10. Any prevalence result where
n_applicable < 10 is flagged preliminary=True. empirical_limitation field
always present in run_full_analysis() output regardless of dataset size.
