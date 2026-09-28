# Staged V1 implementation plan

Status: proposed; this change is documentation only. Each row is a small review
boundary; stages can contain several focused PRs. Do not combine them into one
implementation commit. New ADRs remain Proposed until the design is adopted.

## Stage 1 coding readiness

The design package is ready for review: all 17 requested design topics are covered
by the technical proposal, contracts, research and benchmark. Start Stage 1 only
when the owner adopts ADR-0005–0010 and the following checklist is recorded:

- [x] Repository audit, gap analysis and current primary-source research written.
- [x] Responsibilities, MVP scope and external-project boundaries explicit.
- [x] MCP/provider contracts, quota concurrency/crash rules and privacy defaults defined.
- [x] Baseline protocol, measurement gaps and V1 acceptance targets specified.
- [x] Small stages and pass/fail acceptance criteria defined below.
- [ ] Design disposition recorded (Accepted or explicit revisions to proposed ADRs).
- [ ] Stage 1 target confirmed: local Python 3.12 + Codex stdio; Linux CI and Windows/WSL smoke coverage.

The last target is a proposed default, not a requirement for cloud credentials.
Exact SDK patch/lockfiles and runnable fixture manifests are Stage 1 deliverables,
not reasons to start the entire runtime now. Live provider accounts, model/hardware
selection and search data policy block their own later stages, not offline Stage 1.
Repository license is unresolved; choose it before public package distribution.

## Stages and exit evidence

| Stage | Small implementation slices | Acceptance / exit evidence | Rollback |
|---|---|---|---|
| 0 — Design (this change) | Audit, source ledger, proposal, schemas, ADRs, benchmark and roadmap | Links/examples/whitespace checked; catalog intact; no runtime changes | Revert docs change |
| 1 — Offline skeleton and baseline | First PR: package/config/DTOs + status over stdio, fake adapter; second: fixture manifest and A recording procedure | Locked dependencies + license inventory; schema tests; real SDK client initializes/lists/calls; manual Codex status call; invalid config fails closed; fixture oracles frozen | Remove local MCP registration; no other repo changes |
| 2 — Resource and policy core | Ledger migrations/reservations; deterministic router and registry; error/telemetry skeleton | Parallel last-slot test admits once; shared account pools enforced; crash-before/after-send cases; budget/approval/unknown-price tests; deterministic decision trace | Restore pre-migration backup; adapters remain disabled |
| 3 — Context plus first usable delegation | Brain/FTS + Context Builder; Groq adapter; Gemini adapter; Ollama adapter in separate PRs | Provenance and stale-index tests; local-only cannot egress; bounded valid handoff; verified live model per adapter; full accounting on invalid output/429/timeout; initial B vs A report | Disable failing adapter; Codex continues directly |
| 4 — Research and third cloud option | Tavily search + safe extraction; optional OpenRouter free adapter | Citation-backed fixture output; SSRF redirect/IPv6/DNS tests; search credit exhaustion; verified free-only route cannot select paid | Disable search/OpenRouter independently |
| 5 — Sandbox and worker validation | Separate executor; command profiles; patch/test handoff; Compose packaging | Prove network denial, resource/deadline limits, no secret/socket/root mount, path-safe artifacts; disposable worktree; no main writes; WSL path mapping smoke | Stop executor and clean only its registered job dirs |
| 6 — V1 acceptance | Optional disabled-by-default paid adapter; restart/restore drills; complete paired benchmark; operating guide | Cost caps and trusted approval tested with mocks; live paid only if separately enabled; all required core paths tested; positive/inconclusive/negative value published by class; V1 exit gates below | Keep only demonstrated valuable task classes enabled |

Dependencies: Stage 2 follows Stage 1; Stage 3 follows Stage 2; research and sandbox
require working policy/context. The final benchmark waits for all required paths.
Any paid adapter must pass accounting tests before real paid access is possible.

## V1 exit gate

1. Codex discovers six tools and reliably uses the implemented paths; unavailable
   optional adapters report unavailable rather than simulated success.
2. Free/local fallback, project isolation and context freshness work end-to-end.
3. ResourceController prevents tested quota/cost overcommit, survives restart and
   preserves uncertain liabilities. No hidden paid transition exists.
4. Research sources and sandbox artifacts have trustworthy provenance and bounded
   permissions. Test evidence distinguishes executed from merely suggested tests.
5. A/B reports satisfy [benchmark thresholds](V1_BENCHMARK.md) for selected classes;
   unavailable total-token data is disclosed and does not support total savings.
6. Backup/restore, pinned update procedure and adapter disablement are documented.

Only then propose a separate read-only/import pilot for PLAIK/DealHunter or another
existing repo. Do not change them during this design stage. Graphiti, Mem0, Cognee,
ComfyUI, voice, UI-TARS, n8n, Hatchet, Supabase, Coolify, fine-tuning and additional
providers remain catalog candidates. Their adoption needs measured demand.

## Open verification ledger

| Question | Owner / when resolved | Safe default |
|---|---|---|
| Account quotas, region and data use for exact models | Operator + adapter implementer, Stage 3/4 | All providers disabled; public docs do not prove account entitlement |
| Local RAM/VRAM and chosen model license/digest | Operator + local adapter implementer, Stage 3 | No download; local route unavailable |
| SDK/client patch compatibility | Implementer, Stage 1 | Lock tested versions; no claim of completed MCP smoke |
| Codex per-task token visibility | Benchmark implementer, Stage 1 | Null + documented proxy; no quota-saving claims |
| Repository distribution license | Repository owner, before release | No license invented in this docs change |
| Rootless executor availability on host | Implementer/operator, Stage 5 | Sandbox unavailable; never execute on host as fallback |
| Design adoption | Repository owner, before Stage 1 | ADRs Proposed; coding not started |
