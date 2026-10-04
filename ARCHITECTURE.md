# DevFabric architecture

Concrete V1 design: [technical proposal](docs/V1_TECHNICAL_PROPOSAL.md) and
[contracts](docs/V1_CONTRACTS.md). Consult the [README status](README.md#project-status) for implemented scope;
older proposals also contain future capabilities.

## Position

DevFabric is the shared orchestration/control/context layer between coding agents
and AI resources. Codex is the current primary integration and remains its workflow
orchestrator. Cursor, Claude and other clients are planned, not implemented.

```text
Coding agent -> Agent / Client Adapter -> DevFabric shared services
                                         |-- Project Brain / Context Builder
                                         |-- ResourceController / Router
                                         |-- Privacy / Accounting
                                         `-- Provider Adapters -> AI resources
```

The current Codex-facing boundary remains MCP `devhub_delegate`. Public branding
does not change this identity or the contracts bound to it. See [naming](docs/NAMING.md).

## Core
Keep it small: capability registry, routing policy, provider health/quota state, project isolation, context building, handoffs, telemetry and policy checks.

## Providers
Normalize free-cloud, local and paid inference. Track availability, capabilities, privacy class, quota/rate state, latency and recent failures. Never assume a free tier is permanent.

## Tools
High-level capabilities: research/search, extraction/crawl, browser, documents/OCR, RAG, sandbox and Git/GitHub. Avoid exposing hundreds of low-level schemas to Codex.

## Agents
Workers receive a bounded task, relevant context, workspace, permissions, acceptance criteria and tests. They return a compact handoff: status, summary, changed files, tests, decisions, warnings and artifact references. Codex remains orchestrator.

## Project Brain
Shared storage, not shared prompt state. Layers: global conventions, project architecture/decisions, repository retrieval and task/session state. Project boundaries are explicit.

## Context Builder
Assemble the minimum useful task package from the request, relevant repo sources, decisions, conventions and related prior work. More context is not automatically better.

## Routing
Current delegation filters configured profiles deterministically by task/privacy
and resource eligibility. No universal provider ordering or quality ranking is
claimed. Private context stays local; cloud needs explicit approved export.
Benchmark-driven policy changes require later review.

## Codex-facing interface
Primary: MCP. Proposed V1 tools: `devhub_status`, `devhub_delegate`,
`devhub_research`, `devhub_context`, `devhub_remember`, `devhub_sandbox`.
See versioned inputs/lifecycle in [contracts](docs/V1_CONTRACTS.md). Validate actual
Codex interoperability in Stage 1; document/browser/external-worker adapters can follow V1.

## Deployment
V1 favors simple local/self-hosted deployment, likely Docker Compose plus a small MCP service. Optional capabilities are enabled independently.

## Observability
For delegated operations record route reason, provider/tool/agent, latency, quota/cost, success/failure and whether Codex had to redo the work. These measurements decide whether DevFabric is actually useful.
