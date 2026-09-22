# PROJECT STATE

**Last updated:** 2026-09-18
**Updated by:** Claude (implementation agent)
**Current branch:** phase/4b-prevalence
**Baseline branch:** main @ 6edab0a

---

## Current Phase
PHASE 4B — PREVALENCE + CO-OCCURRENCE ANALYSIS: COMPLETE

## Completed Work
- [x] Phase 0: Repo audit (phase/0-audit @ d4977a1)
- [x] Phase 1: SQLite schema + repository + 38 tests (phase/1-data-model @ bcd4d20)
- [x] Phase 2: R1/R2/R3/R4 fixes + adapter + 35 tests (phase/2-integration @ 90c16db)
- [x] Phase 3: CLI/Flask wiring + 29 tests (phase/3-pipeline @ 62806fe)
- [x] Phase 4A: Sensitivity analysis + 39 tests (phase/4a-sensitivity @ df25f0b)
- [x] Phase 4B: Prevalence + co-occurrence + 54 tests (phase/4b-prevalence)

## Phase 4B Deliverables
- analysis/prevalence.py:
  - finding_prevalence() — FAIL rate per check_id, denominator=PASS+FAIL only
  - layer_prevalence() — aggregate FAIL rate per layer
  - severity_distribution() — FAIL findings by severity
  - status_distribution() — all findings by status (shows NOT_APPLICABLE ratio)
  - assessment_distribution() — dataset summary + score distribution
  - finding_cooccurrence() — FAIL pair co-occurrence, assessment-level unique
  - run_full_analysis() — full structured output, never modifies DB
  - CLI: python3 -m analysis.prevalence [--db PATH] [--json] [--layer OS|NETWORK|WEB]
- tests/test_phase4b.py: 54 tests across 6 test classes

## Test Suite
- tests/test_database.py:  38 tests — PASS (Phase 1)
- tests/test_phase2.py:    35 tests — PASS (Phase 2)
- tests/test_phase3.py:    29 tests — PASS (Phase 3)
- tests/test_phase4a.py:   39 tests — PASS (Phase 4A)
- tests/test_phase4b.py:   54 tests — PASS (Phase 4B)
- Total: 195/195 PASS
- Command: python3 -m pytest tests/ -v

## Key Research Properties (all verified by tests)
- Denominator = PASS+FAIL only; NOT_APPLICABLE/NOT_TESTED/ERROR/UNKNOWN excluded
- Co-occurrence = unique assessment-level FAIL presence (not finding record count)
- No causal language; caution_note on every co-occurrence result
- Analysis never creates assessment/target/finding records
- empirical_limitation and causal_inference_warning always present
- preliminary flag when n_applicable < 10
- All results JSON-serializable and deterministic

## Pending
- Phase 5: Research paper update (sensitivity + prevalence results)
- Phase 5: Longitudinal tracking queries
- R8, R9: Minor technical debt
Requires human approval before beginning.
