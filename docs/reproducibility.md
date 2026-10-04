# Reproducibility Guide

**Last updated:** 2026-10-05
**Code verification:** 245 passed, 1 skipped on Python 3.12 (Windows), using the command below.

## Scope and evidence boundary

This repository contains scanner code, database schema, analysis code, and
synthetic tests. It does **not** contain an authorized empirical research
database or raw scan outputs. Do not treat any fixture, JSON test input, or
historical Phase 5A directory as real-world evidence unless its provenance,
authorization, and raw observations are separately verified.

## Set up a clean environment

```bash
git clone https://github.com/Dhruv-parihar/security-scorer.git
cd security-scorer
python -m venv .venv
```

On Windows:

```powershell
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.lock
python -m pytest -q -p no:cacheprovider
```

On macOS/Linux:

```bash
source .venv/bin/activate
python -m pip install -r requirements-dev.lock
python -m pytest -q -p no:cacheprovider
```

The repository's `pytest.ini` limits normal discovery to the canonical `tests/`
suite, so archived handoff copies do not cause duplicate-module errors. The
current expected result is `245 passed, 1 skipped`. The exact count may
legitimately change with reviewed tests; a failure must be investigated rather
than hidden by changing the expected count.

The one skipped test is explicitly Linux-only (`tests/test_phase2.py`), so it
is expected on the verified Windows environment rather than a hidden failure.

`requirements-dev.lock` records the exact dependency set used for this
verification. The range-based `requirements-dev.txt` remains available for
development; any lock-file update should be reviewed and followed by a fresh
test run.

## Reproduce analysis from an authorized database

Do not initialize a database from synthetic test records and call the output
empirical. Work from a read-only copy of an authorized database and record its
SHA-256 hash, collection dates, methodology versions, and scoring-model
versions alongside every generated table or figure.

```bash
python -m analysis.prevalence --db path/to/research.db --json
python -m analysis.scoring_sensitivity --db path/to/research.db --json
python -m analysis.longitudinal --db path/to/research.db --json
```

All three analysis commands open the supplied database read-only. The
longitudinal command compares only consecutive assessments of the same target;
it never treats missing, errored, not-tested, or non-applicable observations as
a resolution. Composite-score deltas are withheld when scoring model or weights
differ.

## Generate a non-empirical fixture database

The deterministic fixture generator exists only to exercise code paths. Its
database, targets, assessments, findings, score snapshots, and sidecar manifest
are labelled SYNTHETIC_FIXTURE_NOT_EMPIRICAL. Do not merge it with research data
or report its output as empirical.

    python -m tools.generate_synthetic_dataset --output path/to/synthetic.db
    python -m analysis.prevalence --db path/to/synthetic.db --json
    python -m analysis.scoring_sensitivity --db path/to/synthetic.db --json
    python -m analysis.longitudinal --db path/to/synthetic.db --json

## Data release checklist

Before sharing a dataset or paper supplement:

1. Remove IP addresses, hostnames, credentials, tokens, and sensitive evidence.
2. Retain target aliases, authorization references, assessment scope, tool,
   methodology, schema, check, and scoring-model versions.
3. Provide a data dictionary, an anonymization note, a SHA-256 manifest, and
   the exact analysis command used for each output.
4. Clearly label synthetic fixtures and separately retain raw authorized data
   under the applicable consent and storage controls.
5. Do not publish claims that cannot be traced from a table or figure to the
   corresponding authorized raw observations.
