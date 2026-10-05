# Roadmap

Build the smallest system that proves DevFabric improves real Codex development.
Codex remains orchestrator; free-first applies only after choosing to delegate.

## Phase 0 вЂ” Technical design

- [x] Vision, principles and Accepted ADR-0001вЂ“0004.
- [x] Audit all repository documentation and preserve the ideas catalog.
- [x] Recheck official technology/provider documentation.
- [x] Propose stack, contracts, security, baseline and ADR-0005вЂ“0010.
- [x] Owner accepted ADR-0005–0010 and the offline-only Stage 1 scope in PR #1 review.
- [ ] Verify actual Codex MCP interoperability during Stage 1.

Public documentation verification is complete; account/hardware probes and
benchmark execution are not. See [audit](docs/V1_AUDIT.md),
[proposal](docs/V1_TECHNICAL_PROPOSAL.md) and [ADR index](docs/adr/README.md).

## V1 вЂ” Small, independently verified stages

1. Offline skeleton, MCP status, locked contracts and baseline fixtures.
2. ResourceController, Capability Registry, deterministic Router and telemetry.
3. Project Brain, Context Builder and Groq/Gemini/Ollama delegation.
4. Bounded research and optional OpenRouter free adapter.
5. Isolated sandbox/executor, worker handoffs and deployment packaging.
6. Recovery tests, controlled paid path and paired V1 acceptance benchmark.

Project Brain, context, resource control and sandbox are within V1, not postponed
to a later product version. Model workers provide bounded delegation; dedicated
Cursor/OpenHands integrations can follow. Each stage has small PR boundaries,
acceptance evidence and rollback in the [implementation plan](docs/V1_IMPLEMENTATION_PLAN.md).

## After V1 evidence

Pilot existing repositories without rewrites; add one external worker adapter
when useful; evaluate smarter routing against the [baseline](docs/V1_BENCHMARK.md).
Add AST/vector/graph retrieval, multimodal, browser, workflows or larger hosting
only when measured needs justify them. All ideas remain in [catalog](docs/catalog/README.md).

`ai-platform` remains a separate application-runtime project. No V1 dependency
or shared deployment is planned. PLAIK/DealHunter changes are outside this stage.

## Planned shared client layer

```text
Agent Adapter / Client Adapter
  -> DevFabric shared services
  -> Brain / Context / Policy / Routing / Provider Adapters
```

Codex is the existing primary integration. Future adapter work includes evolving
that integration and adding Cursor, Claude and other coding-agent/IDE clients.
No Cursor/Claude adapter or shared multi-client execution is implemented by this
branding change. These integrations must reuse the same privacy/accounting core.
Technical identifiers remain governed by [naming policy](docs/NAMING.md).
