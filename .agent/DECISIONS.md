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
