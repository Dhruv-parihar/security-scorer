# Research Methodology
**Version:** 1.1
**Last updated:** 2026-10-05

---

## 1. Research Objective

Produce a legally authorized, empirically grounded dataset of security
findings across multiple system layers (OS, network, web application) to
investigate:

1. Which security weaknesses occur most frequently?
2. How do weaknesses differ between OS, network, and web layers?
3. Which findings commonly co-occur?
4. Which observable environmental factors are associated with recurring weaknesses?
5. Which remediation actions produce measurable improvements?
6. Can empirical data improve security-score calibration?

## 2. Ethical and Legal Framework

**Active testing is permitted ONLY against:**
- Systems owned by the researcher
- Controlled laboratory systems (e.g. Metasploitable 2, DVWA)
- Systems with explicit written authorization
- Consented research participants
- Datasets whose licensing permits security research use

**Before any assessment:**
- A `target` record must exist in the research database
- `authorization_status` must be set to one of:
  `OWNED`, `LAB`, `EXPLICITLY_AUTHORIZED`, `CONSENTED_RESEARCH`
- `authorization_ref` should reference the authorization document/ticket
- Every active scan input must have an explicit `target_identifier` mapping to
  that target; an IP, hostname, and URL are never assumed to refer to the same
  system solely because they look related

Even low-impact collection such as HTTP-header inspection must stay within a
documented authorization and scope decision. If that decision is absent, do
not collect against the target. All findings must retain scope metadata.

**Data minimization:** credentials are never stored. If an IP address,
hostname, or URL must be retained locally for authorization lookup, it is kept
only as a sensitive `target_identifier` mapping; research exports remove or
pseudonymize it. Assessments remain linked to a UUID and researcher-assigned
alias.

## 3. Assessment Protocol

### 3.1 Pre-Assessment
1. Verify target authorization record exists in database
2. Record assessment start time
3. Document tool version, methodology version, schema version, detector/check
   version, and scoring-configuration version
4. Record scope (OS / NETWORK / WEB / ALL)
5. Verify every active scan input is explicitly mapped to the intended target

### 3.2 During Assessment
- Each check produces exactly one finding with an explicit status
- Valid statuses: PASS, FAIL, NOT_APPLICABLE, NOT_TESTED, ERROR, UNKNOWN
- NOT_APPLICABLE must be used when a check does not apply to the target OS/environment
- NOT_TESTED must be used when a check was not run (never silently omit)
- Evidence strings must reference actual observed data, not assumptions
- A composite score may represent only one target record. Local OS hardening
  must not be merged with remote network/web observations without an explicit
  target binding, and active layers mapped to different target records must not
  be combined or persisted as one assessment.

### 3.3 Post-Assessment
1. Record assessment end time
2. Compute and store score snapshot (derived artifact, not primary data)
3. Create remediation records for all FAIL findings
4. Document any anomalies in assessment notes

## 4. Finding Classification

### 4.1 Status Definitions

| Status | Definition |
|--------|------------|
| PASS | Check was run and the condition was satisfied |
| FAIL | Check was run and the condition was NOT satisfied |
| NOT_APPLICABLE | Check does not apply to this target (e.g. Linux check on Windows) |
| NOT_TESTED | Check exists but was not run during this assessment |
| ERROR | Check attempted but failed to execute (tool error, permission denied, etc.) |
| UNKNOWN | Check ran but result could not be determined with confidence |

### 4.2 NOT_APPLICABLE Rule (CRITICAL)

NOT_APPLICABLE findings:
- Must have `severity = NULL`
- Are excluded from prevalence denominators
- Do not reduce layer scores
- Must never be treated as FAIL in any analysis

Rationale: A Windows system should not receive a FAIL finding for a
Linux-specific SSH configuration check. Treating NOT_APPLICABLE as FAIL
would systematically bias cross-OS comparisons.

### 4.3 Severity Scale

| Severity | Definition |
|----------|------------|
| critical | Direct, unauthenticated system compromise possible |
| high | Significant security impact with moderate effort to exploit |
| medium | Security impact but requires additional conditions |
| low | Defense-in-depth concern, minimal direct impact |
| informational | Notable but not a security weakness |

Severity is NULL for NOT_APPLICABLE, NOT_TESTED, ERROR, and UNKNOWN findings.

## 5. Scoring Model

### 5.1 Current Model: weighted_composite_v1 (version 1.1)

The current scoring model is preserved as a baseline. It is NOT claimed
to be empirically optimal — the weights were set by expert judgment.

**Layer weights (default):**
- OS Hardening: 0.30
- Network: 0.35
- Web Application: 0.35

**Composite formula:**
```
C = Σ(wᵢ × Sᵢ) / Σwᵢ
```
where the sum is over layers actually assessed (weights re-normalized).

**Score storage:**
Scores are stored as `score_snapshot` records alongside the model ID and
weights used. This allows future models to be compared against the current
baseline on the same underlying findings.

Layers with an assessment error, no evaluated checks, or no score are excluded
from the composite and recorded as excluded; they are never converted to a
score of zero. The network and web layers retain separately versioned severity
penalty tables because their historical penalty policies differ.

### 5.2 Known Limitations of Current Model

- Weights based on expert judgment, not empirical calibration
- Network layer penalty accumulation means 3+ critical services → score 0
  with no differentiation between "bad" and "catastrophically bad"
- OS module does not weight individual checks by severity
- The scanner is a bounded indicator tool, not a vulnerability-completeness
  guarantee; raw observations and detector limitations must accompany results

### 5.3 Sensitivity Analysis

Before drawing conclusions from composite scores, a sensitivity analysis
must be conducted showing how composite scores and weakest-layer
identification change across a range of plausible weight values.

Sensitivity analysis uses the latest score snapshot for each assessment. When
multiple snapshots have the same timestamp, an assessment-local
`snapshot_sequence` provides deterministic ordering. It evaluates mathematical
robustness only and does not calibrate weights empirically.

## 6. Statistical Claims

- **Do not claim causation** unless the research design explicitly supports
  causal inference (controlled experiment, not observational study)
- Use "associated with", "correlated with", "co-occurs with" for
  observational relationships
- Always report sample size, confidence intervals where applicable,
  and effect sizes where applicable
- All findings must be traceable: target → assessment → finding → evidence

## 7. Reproducibility Requirements

Every assessment must record:
- `tool_version` — version of the scanner tool
- `methodology_version` — version of this document
- `schema_version` — database schema version at assessment time
- `scoring_model_id` + `scoring_model_ver` — in score snapshots
- Assessment date/time

Research outputs (tables, figures, statistics) must reference the
dataset used, including date range of assessments and tool versions.

## 8. Longitudinal Protocol

For repeated assessments of the same target:
1. Create a new assessment record (do not modify previous findings)
2. After remediation, create a new assessment and link the score snapshot
   to the same target. Keep the original assessment immutable.
3. Update remediation records with `verification_assessment_id` and
   `verification_result`
4. Track: findings introduced, findings resolved, findings persistent,
   score changes over time

The implemented longitudinal analysis compares consecutive assessments of the
same target. A finding is described as resolved only after an explicit
FAIL-to-PASS transition for the same layer and check. Missing, NOT_TESTED,
ERROR, UNKNOWN, and NOT_APPLICABLE states are not comparable and cannot prove a
resolution. Composite-score deltas are reported only for matching scoring model
and weight configurations. These observations do not establish causation.

## 9. What This Methodology Does NOT Cover

- Comprehensive penetration testing
- Social engineering
- Physical security assessment
- Code review
- Insider threat assessment
- Red team operations

The framework assesses observable security configuration and known
vulnerability indicators. It does not claim to find all vulnerabilities
in a target system.
