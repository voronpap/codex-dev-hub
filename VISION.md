# DevFabric vision

## Mission

Build a developer-first AI orchestration fabric connecting coding agents to shared
project context, controlled local/cloud model delegation and auditable resources.
Codex is the first deeply integrated orchestration client. Cursor, Claude and other
coding agents / IDE assistants are planned integrations, not current capabilities.

## Product thesis

The coding agent remains the orchestrator. DevFabric provides reusable context,
privacy, routing and accounting services through an Agent Adapter / Client Adapter
boundary. Provider Adapters connect the other side to model resources.

```text
Developer -> Coding agent -> Client Adapter -> DevFabric shared services
                                             -> Provider Adapter -> AI resource
                          <- compact handoff <-
```

## Principles

- Git-backed project evidence and selective context, not a shared giant prompt.
- Deterministic eligibility/resource policy and explicit privacy boundaries.
- Durable accounting and no automatic retry after ambiguous dispatch.
- Replaceable client and provider adapters; no forced dependency on one vendor.
- Paid execution only through explicit reviewed policy; no automatic paid fallback.
- Benchmark evidence before semantic-quality, savings or Delegation Value claims.

## Scope and maturity

DevFabric is not another coding agent or a replacement for Codex, Cursor or Claude.
Current accepted integrations and the open execution-boundary milestone are listed
in the [README](README.md). Research tools, specialist workers, broader client
support and one-command startup remain future directions unless explicitly marked
implemented. Stage 3G remains open; production readiness is not claimed.

See [naming policy](docs/NAMING.md) for retained technical identifiers.
