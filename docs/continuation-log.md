# Research continuation log

Started 2 October 2026. The researcher requested end-to-end continuation, concise step and phase records, a workflow-efficiency report, and a research paper. Entries distinguish verified outcomes from historical claims. The supplied handoff does not define an authoritative fifteen-phase implementation plan.

## Completion criteria

Preserve the existing architecture and raw files. Verify the historical checkpoint and test baseline; audit the legacy Phase 5A evidence; repair reproducibility defects exposed by concrete tests; implement the documented longitudinal analysis extension; run explicitly synthetic, reproducible experiments; prepare a complete paper with evidence-qualified results and a workflow comparison; checkpoint reviewed code and documentation on a new branch. Real-world prevalence and longitudinal effectiveness require original observations and cannot be inferred from fixtures.

## Work packages

| Package | Purpose | State |
|---|---|---|
| R1 | Verify local and remote history | Complete |
| R2 | Establish executable regression baseline | Complete — 194 passed, 1 skipped before repairs; 245 passed, 1 skipped after repairs |
| R3 | Audit legacy Phase 5A artifacts and provenance | Complete — historical fixtures are unverified and cannot support empirical claims |
| R4 | Check applicability through scoring and persistence | Complete |
| R5 | Validate finding denominators and duplicate handling | Complete |
| R6 | Validate sensitivity ordering and snapshot selection | Complete |
| R7 | Version shared severity configuration | Complete |
| R8 | Add comparable same-target longitudinal analysis | Complete |
| R9 | Characterize scanner validity with controlled tests | Partial — controlled loopback web-heuristic case added; no general accuracy claim |
| R10 | Generate reproducible synthetic experiments | Complete — deterministic labelled fixture generator and manifest |
| R11 | Add reproducibility commands and automated CI | Complete — exact verified dependency lock, canonical test discovery, and CI workflow recorded |
| R12 | Review primary literature and write the paper | Partial — evidence-qualified IEEE source draft exists; empirical evidence and final rendering remain pending |
| R13 | Produce workflow-efficiency report | Complete — measured process facts and limitations recorded |
| R14 | Verify manuscript and artifact consistency | Partial — code, evidence records, and an executable data-provenance gate are rechecked; rendered PDF remains unverified |
| R15 | Commit and publish a reviewable branch and draft PR | Complete — checkpoint 3ff69af pushed to the existing reviewable branch; no pull request was requested or created |

These are new continuation work packages, not a reconstruction of an unavailable original phase plan. Phases 0–4B are retained as historical work.

## Step record

1. Located the repository and retained all seven untracked handoff directories. The local Phase 5A commit is e1b418fc1d72c66b5f42af19e23483c7cc2c4ad3.
2. Verified the same commit using the GitHub connector. Its only change is a DOCX Git LFS attribute; the message claiming results and 228 passing tests does not establish that those files were committed.
3. Verified connected GitHub repository read access. The local Git HTTPS transport failed with a Windows credential-provider error, and GitHub API branch creation was later rejected with HTTP 403; neither path currently permits a durable checkpoint.
4. Inspected Phase 5A tests. They construct records with hard-coded scores and authorization labels; such tests cannot establish the provenance of real observations. The Windows fixture reports 33 although its two evaluated checks both pass; all six current OS checks instead return NOT_APPLICABLE on Windows.
5. Found one legacy local report and no research database in the project. Asked the researcher asynchronously for raw-data locations, the full phase plan, and paper requirements. Independent engineering work continues.
6. Started an isolated Python 3.12 test environment. Local branch creation was blocked by Windows sandbox deny entries on Git metadata, despite requesting the narrow filesystem grant. No ACLs were changed. GitHub API creation of the planned codex/research-completion branch was also rejected; the local branch has not changed.
7. Added synthetic research-integrity tests covering applicability, explicit statuses, invalid weights, duplicate and conflicting findings, safe filtering, snapshot selection, sensitivity coverage, and scanner error semantics. Repaired production code and verified 220 passed, 1 skipped.
8. Added same-target longitudinal analysis and synthetic tests. Added schema version 2 with deterministic per-assessment snapshot ordering; corrected one-based schema-version provenance.
9. Added reproducibility instructions, development dependencies, and a GitHub Actions test workflow. No empirical database or scan output was created, modified, or claimed.
10. Added a deterministic fixture-database generator with a SHA-256 sidecar manifest. All generated records are labelled SYNTHETIC_FIXTURE_NOT_EMPIRICAL. Full suite: 232 passed, 1 skipped.
11. Added a loopback-only controlled web response test for the reflected SQLi and XSS heuristics. It verifies detector behavior against constructed strings, not scanner accuracy in real deployments.
12. Full regression after the controlled loopback case: 233 passed, 1 skipped.
13. Added an assessment-scope guard: network and web results must resolve to one target record, and local OS-hardening results cannot be merged with remote observations without an explicit target binding. Added a canonical pytest configuration to exclude untracked historical handoff copies from normal test discovery. Full regression: 237 passed, 1 skipped.
14. Added an exact Python 3.12 development dependency lock and aligned CI with the canonical test command. Created a fresh environment from that lock and reproduced 237 passed, 1 skipped; the skipped test is explicitly Linux-only.
15. Attempted a selective local checkpoint containing only continuation code, tests, CI, and documentation; the archived phase folders were deliberately excluded. Git was denied before staging because it could not create `.git/index.lock`. No commit, branch, ACL, or remote state was changed.
16. Added schema version 3 with explicit one-to-many target identifier mappings. This allows separately authorized IP and URL inputs to resolve to one target only through a recorded link; duplicate identifiers are rejected before ambiguous targets are created.
17. Recreated a clean Python 3.12 environment from `requirements-dev.lock` after the schema-v3 change.
18. Added migration tests that backfill only unique legacy aliases and deliberately leave ambiguous aliases unmapped. Final complete regression in the clean locked environment: 245 passed, 1 Linux-only skip.
19. Created the selective continuation checkpoint `3ff69af` (`codex: harden research integrity and reproducibility`) and pushed it to `origin/phase/5a-results`. The seven archived audit/phase handoff directories remain untracked and excluded. The connected GitHub API still cannot create a new branch, but the existing tracked branch accepted the authorized Git push. No pull request was created.
20. Added a read-only dataset-provenance preflight and a raw-output manifest format. It checks schema/integrity, authorization references, explicit target identifiers, evidence presence, synthetic markers, and per-assessment raw-output hashes before a dataset can be marked ready for paper results. Full regression: 249 passed, 1 Linux-only skip.

## Measurement policy

Record actual tool and test outcomes and required human interventions. The prior workflow is known from the researcher's description; historical timing and cost were not measured. Do not report an invented speedup, labor saving, or model-quality comparison.
