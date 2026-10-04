# Project Context and Project Brain

## Goal
Share durable project understanding between Codex and workers without copying whole chat histories.

## Levels
- **Global:** reusable development conventions and DevFabric usage.
- **Project:** architecture, ADRs, domain concepts, constraints and retrieval indexes.
- **Task/session:** goals, branch/worktree, acceptance criteria and temporary artifacts.

## Sources of truth
| Information | Source |
|---|---|
| Code | Git repository |
| Schema/migrations | Repository/migration history |
| Architecture decisions | ADR / explicit decision record |
| Current task | Task/session state |
| External docs | Referenced source + retrieval cache |

## Store
Architecture rationale, conventions, constraints, integration quirks, major-work summaries, authoritative file references and unresolved durable issues.

Do not store complete source copies, every chat message, transient speculation or secrets.

## Worker task packet
```text
TASK
SCOPE
RELEVANT CONTEXT
FILES/REFERENCES
ACCEPTANCE CRITERIA
ALLOWED TOOLS
TEST COMMANDS
PERMISSIONS
```

## Worker handoff
```text
STATUS
SUMMARY
CHANGED FILES
TEST RESULTS
DECISIONS
WARNINGS
ARTIFACT REFERENCES
```

Every Project Brain operation carries a project ID. Cross-project retrieval is denied by default.
