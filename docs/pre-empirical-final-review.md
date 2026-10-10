# Pre-Empirical Final Review

**Review date:** 2026-10-10
**Review scope:** The `phase/5a-results` working tree and its recorded remote
checkpoints. This review does not treat historical handoff files, synthetic
fixtures, or a passing test suite as empirical observations.

## Review conclusion

The repository is ready to receive and validate authorized data. It is not
ready to claim scanner accuracy, prevalence, remediation effectiveness, or any
other empirical research result. The paper is an evidence-qualified draft, not
a completed empirical study.

## Requirement audit

| Requirement | Evidence inspected | Result | Remaining condition |
|---|---|---|---|
| Verify the historical Phase 5A claim | Commit `e1b418f` changes only `.gitattributes`, despite its empirical-results message | Historical claim excluded | Locate original authorized database and raw outputs if they exist |
| Preserve non-authoritative handoff material | Seven `audit-files` and phase directories remain untracked | Preserved and excluded | Do not use them as evidence without provenance review |
| Test the implementation | Locked Python 3.12.14 / Windows run at commit `34b7f3d`: 268 passed, 1 expected Linux-only skip | Verified software behavior, including the approved score, TLS, and dashboard changes | Repeat on the final authorized dataset/software release |
| Keep observations distinct from derived claims | Schema, analysis modules, and tests distinguish PASS/FAIL from non-evaluated states | Verified in code tests | Use the same semantics in collected data |
| Verify data provenance before paper results | `tools.validate_research_dataset` checks integrity, authorization, target identifiers, evidence, synthetic markers, and raw-output hashes | Gate implemented and tested | Run against an authorized database and retained raw-output manifest |
| Validate detector accuracy | `tools.evaluate_controlled_validation` requires preflight approval, database-hash-bound labels, complete coverage, and unique observations | Gate implemented and tested | Conduct an authorized controlled-lab protocol with independent ground truth |
| Reproduce analysis | Dependency lock, canonical test discovery, read-only analysis commands, and CI workflow are present | Reproducibility package prepared | Reproduce on the final authorized dataset and retain command output |
| Produce IEEE manuscript | Evidence-qualified LaTeX source and editable IEEE-style Word draft exist; citation keys and bibliography keys match. LaTeX source now describes model 1.2 and retains older Phase 5A figures without rescoring | Draft prepared; source compilation is verified | Fill author email, create empirical tables only from approved data, synchronize the Word draft, and visually render the final document |
| Compare workflows honestly | A separate workflow-efficiency report distinguishes measured repository facts from unmeasured time or cost estimates | Prepared | Update only with actual recorded timing or cost observations |
| Create durable checkpoints | Commit `34b7f3ddeea264ffee65ac34820ec0d102a0a294` was pushed to `origin/phase/5a-results` and independently fetched through GitHub | Verified remote commit; no CI status was returned for this commit in the current check | Open a pull request only if review or merge is requested |
| Implement the three approved remaining code items | Model 1.2 severity-weighted OS score; bounded verified TLS checks; aggregate `/research` dashboard with read-only DB access; covered by the 268-test suite | Complete for the approved software scope | Empirical validation and protocol/cipher completeness remain out of scope |

## Evidence boundaries

The synthetic fixture generator labels every generated record
`SYNTHETIC_FIXTURE_NOT_EMPIRICAL`. The dataset preflight rejects that label for
empirical use. The controlled-loopback web test and controlled-lab evaluator
exercise software behavior and validation rules; neither supplies a measured
false-positive rate, false-negative rate, or field-effectiveness result.

A read-only Desktop inventory found `scorer.zip` and `scorer (2).zip`. Each
archive lists one folder and 15 PNG screenshots; neither contains a SQLite
database, raw scanner output, or ground-truth label file. The archive bytes are
not identical, so they are retained as separate screenshot archives, but their
listed contents cannot establish empirical provenance or reproduce a result.

The available environment could not compile the LaTeX draft or visually render
the Word draft because its supported rendering components were unavailable.
The Word file was statically checked for structure, table presence, two-column
body layout, expected test count, and absence of raw LaTeX tokens. That is not
a substitute for visual page review.

## Completion inputs

Before the research can be described as empirically complete, provide:

1. An authorized research database plus raw-output manifest and retained raw
   artifacts.
2. A controlled-lab ground-truth file with independent rationale and evidence
   for each evaluated case.
3. The original phase plan, if one exists, so its requirements can be mapped
   rather than inferred.
4. Author institution, location, and email for the manuscript title block.
5. A working renderer or a human visual review of the final manuscript.

Until then, the correct conclusion is that the implementation and
reproducibility safeguards are complete to their documented scope, while the
empirical study remains pending.
