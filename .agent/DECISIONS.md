# ARCHITECTURAL / RESEARCH DECISIONS

## D-001 — Do not rebuild from scratch
**Date:** 2026-09-18
**Decision:** Preserve existing architecture. Extend, do not replace.
**Rationale:** Working CLI + Flask UI exists. Scores are reproducible.
Destroying baseline breaks research continuity.

## D-002 — Phase 0 audit before any implementation
**Date:** 2026-09-18
**Decision:** Complete full audit and produce PROJECT_AUDIT.md before
touching any module.
**Rationale:** Cannot make safe architectural decisions without
understanding current state. Confirmed: no tests, no DB, no auth,
no taxonomy, no NOT_APPLICABLE handling exist yet.

## D-003 — Branch strategy
**Date:** 2026-09-18
**Decision:** Each phase gets its own branch: phase/N-name.
Main branch remains stable baseline at all times.
**Rationale:** Research reproducibility requires a clean baseline.
