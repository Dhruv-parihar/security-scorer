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
