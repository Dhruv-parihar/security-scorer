# Database Schema Reference
**Schema version:** 1
**Last updated:** 2026-09-18

## Entity-Relationship Summary

```
target (1) ──────── (N) assessment
                          │
              ┌───────────┤
              │           │
           finding     score_snapshot
              │
           remediation
              │
       (verification_assessment_id → assessment)

taxonomy ──── (N) finding
```

## Key Design Rules

1. `finding.status` is the authoritative observation. Never infer PASS from
   absence of a finding record.

2. `NOT_APPLICABLE` findings must have `severity = NULL`. Enforced by
   application layer (`db/repository.py`) with a `ValueError`.

3. Scores in `score_snapshot` are derived from findings. If findings change
   (e.g. a finding is reclassified), a new score_snapshot must be computed.
   Old snapshots are retained for longitudinal comparison.

4. `PRAGMA foreign_keys = ON` is set on every connection. All FK constraints
   are enforced at the SQLite level.

## Migration Strategy

- Migrations are numbered 0-based and applied in order.
- `schema_migrations` table records which migrations have been applied.
- `db.schema.migrate()` is idempotent — safe to call on an already-current DB.
- Every assessment records `schema_version` at collection time for
  reproducibility.

## Files

| File | Purpose |
|------|---------|
| `db/schema.py` | Schema DDL, migration engine, constants |
| `db/repository.py` | All DB read/write operations |
| `db/__init__.py` | Package exports |
| `tests/test_database.py` | 38-test suite |
| `research.db` | Live research database (gitignored) |
