# PROJECT STATE

**Last updated:** 2026-09-18
**Updated by:** Claude (implementation agent)
**Current branch:** phase/4a-sensitivity
**Baseline branch:** main @ 6edab0a

---

## Current Phase
PHASE 4A — SCORING SENSITIVITY ANALYSIS: COMPLETE

## Completed Work
- [x] Phase 0: Repo audit (phase/0-audit @ d4977a1)
- [x] Phase 1: SQLite schema + repository + 38 tests (phase/1-data-model @ bcd4d20)
- [x] Phase 2: R1/R2/R3/R4 fixes + adapter + 35 tests (phase/2-integration @ 90c16db)
- [x] Phase 3: CLI/Flask wiring + 29 tests (phase/3-pipeline @ 62806fe)
- [x] Phase 4A: Sensitivity analysis module + 39 tests (phase/4a-sensitivity)

## Phase 4A Deliverables
- analysis/__init__.py
- analysis/scoring_sensitivity.py:
  - compute_weighted_composite() — pure math, no side effects
  - layer_influence() — proportional influence per layer
  - 7 predefined weight scenarios (WEIGHT_SCENARIOS)
  - 54 sweep scenarios (18 per layer × 3 layers, step=0.05)
  - run_full_analysis() — full DB-backed analysis
  - print_results() — human-readable output
  - CLI: python3 -m analysis.scoring_sensitivity [--db PATH] [--json]
- tests/test_phase4a.py: 39 tests across 6 test classes

## Test Suite
- tests/test_database.py:  38 tests — PASS (Phase 1)
- tests/test_phase2.py:    35 tests — PASS (Phase 2)
- tests/test_phase3.py:    29 tests — PASS (Phase 3)
- tests/test_phase4a.py:   39 tests — PASS (Phase 4A)
- Total: 141/141 PASS
- Command: python3 -m pytest tests/ -v

## Sensitivity Scenarios
| Scenario | Description |
|----------|-------------|
| baseline | OS=0.30, NET=0.35, WEB=0.35 (current production) |
| equal | 1/3 each |
| os_heavy | OS=0.50, NET=0.25, WEB=0.25 |
| network_heavy | OS=0.20, NET=0.60, WEB=0.20 |
| web_heavy | OS=0.20, NET=0.20, WEB=0.60 |
| network_web_only | NET=0.50, WEB=0.50 (OS excluded) |
| os_network_only | OS=0.50, NET=0.50 (WEB excluded) |
| sweep_* (54) | One-layer sweeps in 0.05 increments |

## Empirical Limitation (always stated in output)
The sensitivity analysis evaluates mathematical/model robustness.
Empirical calibration requires a sufficiently sized benchmark dataset
that does not yet exist in this project.

## Pending
- Phase 4B: Prevalence + co-occurrence analysis (requires approval)
- R8: SQLi/XSS heuristic improvement
- R9: SEVERITY_WEIGHT shared constant
