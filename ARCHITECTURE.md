# Architecture

## Position
Codex is the control plane for development reasoning. Dev Hub is a capability plane exposed primarily through MCP.

```text
Developer -> Codex -> MCP/API -> CODEX DEV HUB
                               |-- Core
                               |-- Providers
                               |-- Tools
                               |-- Agents
                               '-- Project Brain
```

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
After Codex decides to delegate:

```text
FREE CLOUD -> LOCAL -> PAID
```

Routing can consider capability, privacy, complexity, context size, quota, measured quality, latency and cost.

## Codex-facing interface
Primary: MCP. Candidate high-level tools:
- `devhub_status`
- `free_model_task`
- `research`
- `web_extract`
- `project_context`
- `project_decision_write`
- `document_analyze`
- `sandbox_run`
- `delegate_agent`

Validate the surface experimentally.

## Deployment
V1 favors simple local/self-hosted deployment, likely Docker Compose plus a small MCP service. Optional capabilities are enabled independently.

## Observability
For delegated operations record route reason, provider/tool/agent, latency, quota/cost, success/failure and whether Codex had to redo the work. These measurements decide whether Dev Hub is actually useful.
