# ADR-0004: Other coding agents are workers

**Status:** Accepted

## Decision
Cursor, OpenHands, local coding agents and future agents are bounded workers that Codex may invoke through Dev Hub.

## Consequences
Worker integrations need a common task/handoff contract, isolated workspaces and explicit permissions. They do not independently control the overall project or silently modify main by default.
