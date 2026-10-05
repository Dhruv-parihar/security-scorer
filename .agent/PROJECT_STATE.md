# PROJECT STATE

**Last updated:** 2026-10-05
**Updated by:** Continuation audit
**Current branch:** phase/5a-results
**Baseline branch:** main @ 6edab0a

---

## Current Phase
CONTINUATION HARDENING — CODE AND CHECKPOINT COMPLETE; EMPIRICAL EVIDENCE PENDING

## Completed Work
- [x] Phase 0: Repo audit (phase/0-audit @ d4977a1)
- [x] Phase 1: SQLite schema + repository + 38 tests (phase/1-data-model @ bcd4d20)
- [x] Phase 2: R1/R2/R3/R4 fixes + adapter + 35 tests (phase/2-integration @ 90c16db)
- [x] Phase 3: CLI/Flask wiring + 29 tests (phase/3-pipeline @ 62806fe)
- [x] Phase 4A: Sensitivity analysis + 39 tests (phase/4a-sensitivity @ df25f0b)
- [x] Phase 4B: Prevalence + co-occurrence + 54 tests (phase/4b-prevalence)
- [x] Continuation R4--R8: applicability-aware scoring, duplicate-safe
  analysis, versioned scoring configuration, deterministic score snapshots,
  and same-target longitudinal analysis.
- [x] Continuation R10: deterministic labelled fixture generator and manifest.
- [x] Continuation R11: reproducibility guide, exact verified development
  dependency lock, canonical test discovery, and GitHub Actions test workflow.
- [x] Continuation scope guard: composite/persistence is blocked when active
  scan layers map to different targets, or local OS results are mixed with a
  remote target without an explicit binding.
- [x] Continuation schema v3: explicit, case-insensitive scan-identifier
  mappings allow an authorized IP and URL to resolve to one target without
  inference; ambiguous duplicate identifiers are rejected.
- [x] Continuation data preflight: read-only database and raw-output-manifest
  validation blocks synthetic, unprovenanced, or incomplete data from paper
  results.
- [x] Continuation R9 support: a read-only controlled-lab evaluator computes
  confusion matrices only for preflight-approved, independently labelled PASS
  and FAIL cases with complete ground-truth coverage.
- [x] Continuation R14 pre-empirical review: a requirement-by-requirement
  audit records the verified safeguards, artifact limits, and exact inputs
  needed before an empirical-completion claim.
- [x] Continuation authorization persistence: assessment creation rejects a
  status that differs from the parent target authorization record.
- [x] Continuation active-scan authorization: network and web scanning require
  both a valid target authorization status and a non-empty authorization
  reference.

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
- Historical Phase 4B count: 195/195 PASS. This is not the current count.
- Current continuation verification: 256 passed, 1 skipped.
- Command: python -m pytest -q -p no:cacheprovider

## Key Research Properties (all verified by tests)
- Denominator = PASS+FAIL only; NOT_APPLICABLE/NOT_TESTED/ERROR/UNKNOWN excluded
- Co-occurrence = unique assessment-level FAIL presence (not finding record count)
- No causal language; caution_note on every co-occurrence result
- Analysis never creates assessment/target/finding records
- empirical_limitation and causal_inference_warning always present
- preliminary flag when n_applicable < 10
- All results JSON-serializable and deterministic
- A composite assessment is attributable to only one target record
- Active scan identifiers are explicitly mapped and never relationship-inferred

## Pending
- Authorized raw research database and raw scan outputs for empirical results.
- Full original phase plan, if one exists; the continuation log contains a new,
  clearly labelled work-package plan instead.
- Controlled validation of scanner accuracy and an authorized observational
  dataset. The controlled-lab evaluator and label format are ready, but no
  authorized ground-truth experiment has been run. Synthetic fixtures cannot
  provide these results.
- Durable Git checkpoints `3ff69af`, `eea35e7`, `28b88ec`, `bc5096a`, and
  `9a48a70` were selectively staged and pushed to `origin/phase/5a-results`.
  The connected GitHub integration still cannot create a new branch, but
  elevated local Git access permitted the existing tracked branch to be
  updated. Archived handoff directories remain untracked.
