# Research Methodology
**Version:** 1.0
**Last updated:** 2026-09-18

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

**Passive analysis** (HTTP header inspection of public web properties)
does not constitute active testing and does not require the same level
of authorization as active scanning. All passive findings must still be
documented with appropriate scope metadata.

**Data minimization:** IP addresses, hostnames, and credentials are NOT
stored in the research database. Targets are identified by UUID with a
researcher-assigned anonymized alias.

## 3. Assessment Protocol

### 3.1 Pre-Assessment
1. Verify target authorization record exists in database
2. Record assessment start time
3. Document tool version, methodology version, schema version
4. Record scope (OS / NETWORK / WEB / ALL)

### 3.2 During Assessment
- Each check produces exactly one finding with an explicit status
- Valid statuses: PASS, FAIL, NOT_APPLICABLE, NOT_TESTED, ERROR, UNKNOWN
- NOT_APPLICABLE must be used when a check does not apply to the target OS/environment
- NOT_TESTED must be used when a check was not run (never silently omit)
- Evidence strings must reference actual observed data, not assumptions

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

Severity is NULL for NOT_APPLICABLE and NOT_TESTED findings.

## 5. Scoring Model

### 5.1 Current Model: weighted_composite_v1

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

### 5.2 Known Limitations of Current Model

- Weights based on expert judgment, not empirical calibration
- Network layer penalty accumulation means 3+ critical services → score 0
  with no differentiation between "bad" and "catastrophically bad"
- OS module does not weight individual checks by severity
- NOT_APPLICABLE findings are handled inconsistently (Phase 1 fix pending)

### 5.3 Sensitivity Analysis (Phase 12)

Before drawing conclusions from composite scores, a sensitivity analysis
must be conducted showing how composite scores and weakest-layer
identification change across a range of plausible weight values.

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
   to the same target
3. Update remediation records with `verification_assessment_id` and
   `verification_result`
4. Track: findings introduced, findings resolved, findings persistent,
   score changes over time

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
