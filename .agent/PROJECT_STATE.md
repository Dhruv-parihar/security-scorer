# PROJECT STATE

**Last updated:** 2026-10-11
**Updated by:** Cross-platform OS study continuation and provenance hardening
**Current branch:** phase/5b-cross-platform-os
**Baseline branch:** main @ 6edab0a

---

## Current Phase
PHASE 5B CROSS-PLATFORM OS PILOT — IMPLEMENTATION IN PROGRESS; MEASUREMENTS PENDING

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
- [x] Approved continuation improvements: OS severity-weighted scoring (model
  version 1.2), verified TLS/certificate findings for web scans, and an
  aggregate read-only research dashboard. Historical scores remain unchanged.
- [ ] Phase 5B: platform-specific Windows and macOS OS profiles added in model
  1.3; Linux profile retained. The profile code and error-suppression rule pass
  unit tests, but native Mac validation and version-pinned benchmark mapping
  remain pending.
- [x] Phase 5B data linkage: CLI and Flask can explicitly bind a local OS-only
  run to an authorized target; report-only remains the default. Mixed local and
  remote layers can persist only when explicitly bound to the same target.
- [x] Phase 5B integrity guard: any OS profile query ERROR suppresses the
  aggregate score while retaining findings and denominator counts. Historical
  scores were not recomputed.
- [x] Phase 5B schema v4: persisted assessment metadata now captures OS family,
  release/build, architecture, control profile, scoring model/method, weights,
  and PASS/FAIL/error/N/A denominators. OS findings retain their versioned
  profile ID in `check_version`, including errored runs with no score snapshot.
  The migration preserves existing assessments and does not rewrite Phase 5A.

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
- Pre-change baseline on this checkout: 268 passed, 1 expected Linux-only skip.
- Latest full-suite verification after platform profiles, local-target linkage,
  OS-family mismatch protection, and schema-v4 collection metadata: 312 passed,
  1 expected Linux-only skip in 11.13 seconds (Python 3.12 on Windows).
- Fresh verification on 2026-10-10 used Python 3.12.14 on Windows; all
  installed packages matched `requirements-dev.lock`. Pytest used a fresh,
  writable workspace temp directory because the default Windows temp path was
  inaccessible to this execution session.
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
- New TLS checks are bounded checks, not a comprehensive protocol/cipher audit;
  legacy-only endpoints may yield ERROR under the host TLS policy.
- A user-supplied Lab 3 audit report was inspected and hash-archived in the
  separate local handoff workspace. Its screenshots add historical context
  only; the target `.102` mapping is unresolved against the later `.103`
  Metasploitable console check. It contains credential/hash material and was
  not copied into the repository. Its lab stages 0–7 do not resolve the
  missing canonical project phase plan.
- Current VM attempt (2026-10-11): VirtualBox reports Parrot Running, but its
  guest display remains black after a `vmwgfx` unsupported-hypervisor warning;
  no VM configuration has been changed. The checkout has no `research.db`, so
  no explicit target authorization record is available. Option 4 also runs OS
  checks locally on Parrot and is blocked from combining them with remote
  Metasploitable results by the one-target scope guard. No scan or observation
  was created; a web target URL is also unconfirmed.
- Phase 5B Windows smoke check (2026-10-11): local runtime identified Windows
  11 build `10.0.26200`, AMD64. The UAC registry query returned PASS; firewall
  and Guest-account queries returned Access Denied/ERROR. The revised model
  therefore returned `score: null` with 1/3 controls evaluated. This was a
  diagnostic smoke check only: no raw observation was persisted, no settings
  were changed, and it is not a paper result. Do not elevate the scanner process
  automatically; a researcher-run elevated read-only collection needs a
  separate explicit choice and provenance record.
- Phase 5B code is uncommitted on `phase/5b-cross-platform-os`. Initial Windows
  and macOS profile logic has mocked unit tests; no native Mac, Parrot, Ubuntu,
  or Metasploitable OS-hardening assessment was collected. Remember that remote
  Metasploitable network scans do not score its local OS configuration.
- The Windows/macOS profile checks still need pinned benchmark/control
  mappings and setting-specific evidence capture before provenance preflight
  can mark new cross-platform observations paper-ready. The new metadata field
  improves context preservation; it is not a substitute for raw command output
  artifacts or independent ground truth.
- Durable Git checkpoints `3ff69af`, `eea35e7`, `28b88ec`, `bc5096a`,
  `9a48a70`, `cf5525c`, and `34b7f3d` were selectively staged and pushed to
  `origin/phase/5a-results`. The connected GitHub integration still cannot
  create a new branch, but elevated local Git access permitted the existing
  tracked branch to be updated. Archived handoff directories remain untracked.
