# Data Dictionary — Security Scoring Framework Research Database
**Schema version:** 1
**Last updated:** 2026-09-18

---

## Design Principles

1. **Raw findings are primary research observations. Scores are derived artifacts.**
   Findings must be stored before scores. Scores reference findings and are
   recomputable. Findings are not recomputable from scores.

2. **NOT_APPLICABLE is semantically distinct from FAIL and must not reduce scores.**
   A check that does not apply to a target (e.g. a Linux-specific check run on
   Windows) must be recorded as NOT_APPLICABLE, never coerced to PASS or FAIL.
   NOT_APPLICABLE findings are excluded from all prevalence denominators.

3. **A finding not evaluated is NOT_TESTED — never silently PASS.**
   If a check was not run, the finding status is NOT_TESTED. Absence of
   evidence is not evidence of absence.

4. **Target identity can be anonymized.**
   Targets are identified by UUID. The alias field is a human-readable label
   chosen by the researcher. IP addresses, hostnames, and credentials are not
   stored in the research database.

---

## Tables

### schema_migrations
Tracks applied database migrations. One row per migration.

| Column | Type | Description |
|--------|------|-------------|
| version | INTEGER PK | Migration index (0-based) |
| applied_at | TEXT | ISO-8601 timestamp |
| description | TEXT | Migration description |

---

### taxonomy
Finding category/subcategory reference. Findings reference taxonomy by id,
so the taxonomy can evolve without requiring data migration.

| Column | Type | Description |
|--------|------|-------------|
| taxonomy_id | INTEGER PK | Auto-increment |
| category | TEXT | Primary category (e.g. PATCHING, AUTHENTICATION) |
| subcategory | TEXT | Optional sub-category |
| description | TEXT | Human-readable description |
| reference | TEXT | External reference (e.g. CWE-89, OWASP-A03) |

**Valid categories:** PATCHING, AUTHENTICATION, AUTHORIZATION, ACCESS_CONTROL,
CONFIGURATION, EXPOSURE, CRYPTOGRAPHY, INPUT_VALIDATION, SESSION_SECURITY,
PRIVILEGE, LOGGING, INFORMATION_DISCLOSURE, OUTDATED_SOFTWARE,
UNNECESSARY_SERVICE, UNCATEGORIZED

---

### target
Anonymized research target. No IP addresses, hostnames, or credentials stored.

| Column | Type | Description |
|--------|------|-------------|
| target_id | TEXT PK | UUID |
| target_alias | TEXT | Researcher-assigned label (e.g. "metasploitable-2-lab-01") |
| target_type | TEXT | server / workstation / network_device / web_app / lab_vm |
| environment | TEXT | lab / owned / authorized / consented |
| os_family | TEXT | linux / windows / macos / unknown / not_applicable |
| os_name | TEXT | e.g. "Ubuntu 8.04", "Parrot OS 7.3" |
| os_version | TEXT | e.g. "8.04", "7.3" |
| deployment_type | TEXT | vm / bare_metal / container / cloud |
| technology_notes | TEXT | Free-text technology stack notes |
| authorization_status | TEXT | OWNED / LAB / EXPLICITLY_AUTHORIZED / CONSENTED_RESEARCH |
| authorization_ref | TEXT | Reference to authorization document/ticket |
| created_at | TEXT | ISO-8601 |
| notes | TEXT | Free-text notes |

---

### assessment
One assessment run against one target at one point in time.

| Column | Type | Description |
|--------|------|-------------|
| assessment_id | TEXT PK | UUID |
| target_id | TEXT FK→target | Target assessed |
| assessment_date | TEXT | ISO-8601 start date |
| start_time | TEXT | ISO-8601 start time |
| end_time | TEXT | ISO-8601 end time (set on close) |
| tool_version | TEXT | e.g. "1.0.0" |
| methodology_version | TEXT | e.g. "1.0" |
| schema_version | INTEGER | DB schema version at assessment time |
| scope | TEXT | OS / NETWORK / WEB / ALL / custom |
| authorization_status | TEXT | Must be valid AUTH_STATUS |
| assessor | TEXT | Anonymized assessor identifier |
| notes | TEXT | Free-text notes |

---

### finding
**PRIMARY RESEARCH OBSERVATION UNIT.**
One finding = one check result from one assessment.

| Column | Type | Description |
|--------|------|-------------|
| finding_id | TEXT PK | UUID |
| assessment_id | TEXT FK→assessment | Parent assessment |
| layer | TEXT | OS / NETWORK / WEB |
| check_id | TEXT | Machine-readable check name (e.g. "ssh_root_login") |
| check_version | TEXT | Version of detector/check logic |
| taxonomy_id | INTEGER FK→taxonomy | Taxonomy category (nullable) |
| status | TEXT | **PASS / FAIL / NOT_APPLICABLE / NOT_TESTED / ERROR / UNKNOWN** |
| severity | TEXT | critical / high / medium / low / informational (NULL if NOT_APPLICABLE/NOT_TESTED) |
| confidence | TEXT | HIGH / MEDIUM / LOW |
| description | TEXT | Human-readable finding description |
| evidence | TEXT | Raw evidence (string or JSON) |
| recommendation | TEXT | Remediation recommendation |
| standard_ref | TEXT | e.g. "CIS-1.1", "CVE-2011-2523", "CWE-89" |
| detector_notes | TEXT | Notes from detector (e.g. why NOT_APPLICABLE) |
| detected_at | TEXT | ISO-8601 |

**Status semantics:**

| Status | Meaning | Counts in prevalence? | Reduces score? |
|--------|---------|----------------------|---------------|
| PASS | Check passed | Yes | No |
| FAIL | Check failed | Yes | Yes |
| NOT_APPLICABLE | Check does not apply to this target | **No** | **No** |
| NOT_TESTED | Check was not run | No | No |
| ERROR | Check failed to execute | No | No |
| UNKNOWN | Result indeterminate | No | No |

---

### score_snapshot
Derived scoring artifact. Recomputable from findings + scoring model.
Stored for reproducibility and model comparison.

| Column | Type | Description |
|--------|------|-------------|
| snapshot_id | TEXT PK | UUID |
| assessment_id | TEXT FK→assessment | Source assessment |
| scoring_model_id | TEXT | e.g. "weighted_composite_v1" |
| scoring_model_ver | TEXT | e.g. "1.0" |
| os_score | REAL | 0–100 |
| network_score | REAL | 0–100 |
| web_score | REAL | 0–100 |
| composite_score | REAL | 0–100 |
| weight_os | REAL | Layer weight used |
| weight_network | REAL | Layer weight used |
| weight_web | REAL | Layer weight used |
| weakest_layer | TEXT | Identified weakest layer |
| model_metadata | TEXT | JSON: additional model parameters |
| calculated_at | TEXT | ISO-8601 |
| notes | TEXT | Free-text notes |

---

### remediation
Longitudinal remediation tracking. One finding may have multiple remediation
records across repeated assessment cycles.

| Column | Type | Description |
|--------|------|-------------|
| remediation_id | TEXT PK | UUID |
| finding_id | TEXT FK→finding | Finding being remediated |
| recommendation | TEXT | Specific action taken or recommended |
| status | TEXT | PENDING / IN_PROGRESS / VERIFIED_FIXED / WONT_FIX / FALSE_POSITIVE |
| remediation_date | TEXT | ISO-8601 when remediation was applied |
| effort_hours | REAL | Optional effort estimate |
| verification_assessment_id | TEXT FK→assessment | Assessment that verified the fix |
| verification_result | TEXT | VERIFIED_FIXED / STILL_PRESENT / REGRESSED |
| notes | TEXT | Free-text notes |
| created_at | TEXT | ISO-8601 |
