# ADR-0001: Codex is the main orchestrator

**Status:** Accepted

## Decision
The developer works primarily in Codex. Dev Hub exposes capabilities to Codex and does not implement a competing top-level coding orchestrator in V1.

## Consequences
Planning and final integration remain with Codex. Dev Hub focuses on tools, routing, context and bounded workers. A separate full development UI/task orchestrator requires a future explicit ADR.
