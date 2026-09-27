# Codex Integration

## Objective
Dev Hub should feel like a native Codex toolbox, not a second application the developer must operate.

## Primary integration
Use MCP with a small high-value surface.

Candidate V1 tools:
- `devhub_status`: capabilities/provider state.
- `free_model_task`: bounded task via free/local routing.
- `research`: bounded source-aware web research.
- `project_context`: relevant architecture, decisions and repo knowledge.
- `project_decision_write`: persist an explicit durable decision.

Later: document analysis, sandbox and worker delegation.

## Discipline
Tool responses should prefer result + evidence/references + caveats + artifact/diff reference over verbose agent transcripts.

Codex asks Dev Hub for volatile state (quota, provider health, worker availability) rather than trusting static docs.

## Resilience
Codex must remain useful if Dev Hub is down. Dev Hub is an accelerator, not a prerequisite for basic coding.

## Failure path
On free-provider failure: retry only when sensible -> another eligible free provider -> local -> paid only under project policy. Never report success when delegation failed.
