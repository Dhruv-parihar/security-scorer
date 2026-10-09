# Research continuation log

Started 2 October 2026. The researcher requested end-to-end continuation, concise step and phase records, a workflow-efficiency report, and a research paper. Entries distinguish verified outcomes from historical claims. The supplied handoff does not define an authoritative fifteen-phase implementation plan.

## Completion criteria

Preserve the existing architecture and raw files. Verify the historical checkpoint and test baseline; audit the legacy Phase 5A evidence; repair reproducibility defects exposed by concrete tests; implement the documented longitudinal analysis extension; run explicitly synthetic, reproducible experiments; prepare a complete paper with evidence-qualified results and a workflow comparison; checkpoint reviewed code and documentation on a new branch. Real-world prevalence and longitudinal effectiveness require original observations and cannot be inferred from fixtures.

## Work packages

| Package | Purpose | State |
|---|---|---|
| R1 | Verify local and remote history | Complete |
| R2 | Establish executable regression baseline | Complete — 194 passed, 1 skipped before repairs; 256 passed, 1 skipped after repairs |
| R3 | Audit legacy Phase 5A artifacts and provenance | Complete — historical fixtures are unverified and cannot support empirical claims |
| R4 | Check applicability through scoring and persistence | Complete |
| R5 | Validate finding denominators and duplicate handling | Complete |
| R6 | Validate sensitivity ordering and snapshot selection | Complete |
| R7 | Version shared severity configuration | Complete |
| R8 | Add comparable same-target longitudinal analysis | Complete |
| R9 | Characterize scanner validity with controlled tests | Partial — controlled loopback case, ground-truth protocol format, and read-only metric evaluator added; no authorized experiment or general accuracy claim |
| R10 | Generate reproducible synthetic experiments | Complete — deterministic labelled fixture generator and manifest |
| R11 | Add reproducibility commands and automated CI | Complete — exact verified dependency lock, canonical test discovery, and CI workflow recorded |
| R12 | Review primary literature and write the paper | Partial — evidence-qualified IEEE source and editable Word drafts exist; empirical evidence and final rendering remain pending |
| R13 | Produce workflow-efficiency report | Complete — measured process facts and limitations recorded |
| R14 | Verify manuscript and artifact consistency | Partial — code and evidence records were rechecked; the Word draft passed static structural validation, but rendered PDF and visual page verification remain unavailable in this environment |
| R15 | Commit and publish a reviewable branch and draft PR | Complete — checkpoints 3ff69af, eea35e7, and 28b88ec were pushed to the existing reviewable branch; no pull request was requested or created |

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
21. Created an evidence-qualified IEEE source draft and an editable IEEE-style Word draft. The drafts exclude historical Phase 5A numerical claims and identify empirical results as pending authorized data. The LaTeX compiler and supported DOCX renderer could not perform visual rendering in this environment; the Word file passed static structure checks only.
22. Pushed the data-provenance preflight checkpoint `28b88ec` to `origin/phase/5a-results`. The local and remote branch heads match; the seven archived handoff directories remain untracked and excluded.
23. Added the read-only controlled-lab evaluation gate and pushed it as `bc5096a`. It requires a provenance-approved database, hash-bound independent ground-truth labels, complete PASS/FAIL coverage, and unique observations before reporting a confusion matrix. Five evaluator tests passed; the full locked-environment suite passed with 254 tests and one expected Linux-only skip. The desktop test host required a project-scoped Python temporary directory because its default temporary path was unavailable; no project source behavior was changed.
24. Performed the pre-empirical final review. It verified the historical Phase 5A commit contains only `.gitattributes`, the current branch is tracked at the pushed checkpoint, and the data and controlled-lab gates are implemented. The review records that empirical data, ground truth, author metadata, and visual document rendering remain necessary before any empirical-completion claim.
25. Enforced authorization consistency at assessment creation and pushed it as `9a48a70`: an assessment must now use exactly the authorization status of its parent target, rather than allowing a mismatch for later preflight detection. Database tests passed 46/46; the full locked-environment suite passed with 255 tests and one expected Linux-only skip.
26. Tightened the active-scan authorization gate and pushed it as `cf5525c`: a target with a valid status but no `authorization_ref` is blocked before network or web scanning. Focused authorization, CLI, and Flask tests passed 68/68 with one expected Linux-only skip; the full locked-environment suite passed with 256 tests and one expected Linux-only skip.
27. Performed a read-only inventory of the supplied Desktop location. `scorer.zip` and `scorer (2).zip` each list only a folder and 15 PNG screenshots; neither contains a database, raw scanner output, or controlled-lab labels. The files are retained untouched and excluded as empirical evidence.
28. Reconstructed the retained six-case Phase 5A calculation as an explicit non-empirical generator rather than relying on an unavailable temporary script. The generator emits a labelled SQLite case-study database, analysis JSON, figure data, a source-hash manifest, and a provenance preflight that intentionally blocks empirical-paper use. It found no same-target longitudinal comparison, so no before/after remediation claim is reproduced. Sensitivity output now declares its four-decimal mathematical precision separately from the whole-number production display score. Full locked-environment regression: 259 passed, 1 expected Linux-only skip.
29. On 2026-10-10, rechecked local and GitHub `phase/5a-results` at the same commit (`15154a4e6fd8865be81aab5490d6668148526878`); the GitHub Actions run for that commit completed successfully. Re-ran the full suite in the existing Python 3.12.14 virtual environment after verifying installed versions against `requirements-dev.lock`: 259 passed, 1 expected Linux-only skip. The system Python 3.14 had no pytest; the first virtual-environment run hit access denied on the default pytest temp path, so a fresh isolated `--basetemp` under the approved Codex workspace was used. Seven untracked handoff folders were preserved. No scanner was run and no research database or empirical observation was created.

## Measurement policy

Record actual tool and test outcomes and required human interventions. The prior workflow is known from the researcher's description; historical timing and cost were not measured. Do not report an invented speedup, labor saving, or model-quality comparison.
