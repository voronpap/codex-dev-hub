# Codex Integration

## Objective
Dev Hub should feel like a native Codex toolbox, not a second application the developer must operate.

## Primary integration
Use MCP with a small high-value surface.

Proposed V1 tools:
- `devhub_status`: capabilities/provider/job state.
- `devhub_delegate`: bounded model worker via policy-controlled routing.
- `devhub_research`: bounded source-aware web research.
- `devhub_context`: relevant architecture, decisions and repo knowledge.
- `devhub_remember`: explicit durable decision or evaluated task outcome.
- `devhub_sandbox`: isolated command-profile execution.

See [contracts](V1_CONTRACTS.md) for schemas, lifecycle, artifacts and errors, and
[research](V1_RESEARCH.md) for official Codex MCP evidence. Stdio is first;
actual interoperability remains a Stage 1 check. Document analysis and dedicated
Cursor/OpenHands adapters follow later. Sandbox is required within V1.

## Discipline
Tool responses should prefer result + evidence/references + caveats + artifact/diff reference over verbose agent transcripts.

Codex asks Dev Hub for volatile state (quota, provider health, worker availability) rather than trusting static docs.

## Resilience
Codex must remain useful if Dev Hub is down. Dev Hub is an accelerator, not a prerequisite for basic coding.

## Failure path
On free-provider failure: retry only when sensible -> another eligible free provider -> local -> paid only under project policy. Never report success when delegation failed.
