# AGENT PROTOCOL

## Roles
- **Claude** — implementation agent (code, files, git, validation)
- **ChatGPT** — research/architecture agent (design, methodology, analysis)
- **Dhruv** — final authority and communication bridge

## Rules
- Read `.agent/PROJECT_STATE.md` before every task
- Never assume state from conversation memory — always inspect repo
- No fabrication of findings, data, statistics, tests, or results
- Active testing: owned/lab/explicitly-authorized/consented/licensed targets only
- Preserve existing functionality unless approved change requires otherwise
- Separate raw observations from derived scores at all times
- Treat NOT_APPLICABLE, NOT_TESTED, ERROR, UNKNOWN, PASS, FAIL as distinct
- Test every implementation before committing
- Document architectural/research decisions in DECISIONS.md
- Update PROJECT_STATE.md after every completed work block
- Forbidden without human approval: destructive changes, delete research data,
  alter scoring methodology, external active testing, publish data, rewrite history

## Handoff Format (Claude → ChatGPT)
```
STATUS: [COMPLETE / BLOCKED]
BASELINE: [factual summary]
FILES CHANGED: [list]
CURRENT ARCHITECTURE: [brief]
IMPORTANT FINDINGS: [list]
TESTS/VALIDATION: [commands + results]
GIT: [branch + commit hash]
PROJECT STATE: [phase + next task]
BLOCKERS/APPROVALS NEEDED: [list or NONE]
RECOMMENDED NEXT ACTION: [one concrete task]
```
