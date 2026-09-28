# Staged V1 implementation plan

Status: **Stage 2 CLOSED** after owner acceptance and sequential merge of PR #4–#9.
Stage 1 was closed after PR #2/#3. Each row is a small review
boundary; stages can contain several focused PRs. Do not combine them into one
implementation commit. ADR-0005–0010 are Accepted; later stages remain gated by their acceptance evidence.

## Stage 1 coding readiness

The design package is ready for review: all 17 requested design topics are covered
by the technical proposal, contracts, research and benchmark. Start Stage 1 only
when the owner adopts ADR-0005–0010 and the following checklist is recorded:

- [x] Repository audit, gap analysis and current primary-source research written.
- [x] Responsibilities, MVP scope and external-project boundaries explicit.
- [x] MCP/provider contracts, quota concurrency/crash rules and privacy defaults defined.
- [x] Baseline protocol, measurement gaps and V1 acceptance targets specified.
- [x] Small stages and pass/fail acceptance criteria defined below.
- [x] Design adopted: ADR-0005–0010 Accepted following owner review of PR #1.
- [x] Stage 1 target confirmed: local Python 3.12 + Codex stdio; Linux CI and Windows/WSL smoke coverage.

The target is confirmed and requires no cloud credentials.
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
| 3 — Context plus first usable delegation | Brain/FTS + Context Builder; Ollama before Groq and Gemini; real delegation path; first B-arm benchmark, each in separate PRs | Provenance and stale-index tests; local-only cannot egress; bounded valid handoff; verified live model per adapter; full accounting on invalid output/429/timeout; initial B vs A report | Disable failing adapter; Codex continues directly |
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
| Design adoption | Repository owner, PR #1 and Stage 1/2 reviews | Accepted; Stages 1–2 CLOSED; Stage 3 follows the local-first sequence below |

## Conditions recorded with design acceptance

- Stage 1 scope: offline skeleton, MCP status, DTO/config/schema, fake adapter and
  baseline fixtures only. No cloud-provider implementation or live paid calls.
- Updated at Stage 2 acceptance: Ollama then Groq then Gemini is implementation
  order, not a fixed routing order.
  Future routing uses eligibility and benchmark evidence under ADR-0002.
- Tavily is the initial search implementation; ToolAdapter must remain replaceable
  so Jina/SearXNG can be added without changing the MCP contract.
- Context/summary caps of 8,000/1,500 tokens are configurable initial policy defaults.
- Paid adapter work remains Stage 6.

## Stage 1 delivery

The offline skeleton and status integration are implemented in the first review
slice; [runbook](STAGE1.md) and [verification](STAGE1_VERIFICATION.md) record the
executable proof. The second slice provides [12 frozen baseline seed fixtures](../benchmarks/README.md),
reviewer oracles and isolated packet preparation. The seed summary is deliberately
smaller than the future ten-page benchmark and is labeled accordingly.
No cloud adapter or full A/B benchmark is included in Stage 1.

## Stage 2 closure

The owner accepted the Stage 1 diffs and requested the sequence merge #2, update
#3 from main, repeat CI, then merge #3. All steps completed. Stage 2 was delivered as
six dependent PRs: ledger, reservations, registry, router, events and recovery.
[Stage 2 scope and evidence](STAGE2.md) records the implementation boundaries.
The owner accepted all six slices. Each successor was updated onto main and
passed fresh Linux/Windows CI before merge. Stage 2 is CLOSED. The resource
core operates on synthetic resources only; no real provider has been implemented.

## Stage 3 local-first sequence

Stage 3A is **CLOSED**, accepted and merged: [scope, API and retrieval evidence](STAGE3A.md).
It does not expose a new MCP tool or implement Context Builder/provider execution.

Stage 3B is **CLOSED**, accepted and merged: [selection, budget and validation contract](STAGE3B.md).
Its token accounting remains an explicitly labeled offline proxy until model-specific
validation is introduced with Ollama.

Stage 3C is **CLOSED + Local E2E Gate PASSED**: [local execution and smoke evidence](STAGE3C.md).
Execution/accounting gate passed; semantic quality not yet established.
[Stage 3D Groq](STAGE3D.md) is **CLOSED** after owner acceptance of PR #17 and
UTF-8 documentation cleanup. Its bounded probe consumed one durable authorization;
unknown provider quota dimensions remain unknown. [Stage 3E Gemini](STAGE3E.md)
is implemented for review, with shared export/accounting and separate provider
data-use/token/quota gates. Stage 3E remains open until owner acceptance.

The owner revised adapter implementation order at Stage 2 acceptance. Keep these
as separate review slices; this sequence does not prescribe routing priority.

| Slice | Scope | Acceptance evidence |
|---|---|---|
| 3A | Project Brain + SQLite FTS5 | Project isolation, provenance, stale/deleted source handling and deterministic retrieval |
| 3B | Context Builder | Bounded selected context, configurable caps, source references and privacy classification |
| 3C | Ollama adapter | Explicitly configured local model; one transport attempt; accurate usage/unknown handling; minimal real Codex-to-handoff smoke through context, router and controller before any cloud adapter |
| 3D | Groq adapter | Verified account/model limits; opt-in egress; no hidden retries; provider-specific usage and reconciliation evidence |
| 3E | Gemini adapter | Separate account/model capability evidence; shared-pool enforcement; provider-specific quota and reconciliation tests |
| 3F | Real delegation path | Integrated MCP submission/handoff, validation, cancellation and recovery across enabled adapters |
| 3G | First B-arm benchmark | Frozen fixture/oracle integrity, matched A/B conditions and measured quality/latency/usage; unavailable metrics remain null or labeled proxy |

3C must prove the real local path before 3D starts:
Codex → MCP → Context → Router → ResourceController → Ollama → accounting → handoff.
3F completes the common delegation surface after the individual adapter slices.
Local execution still records measured tokens and unknown usage; it does not
pretend that unavailable hardware/energy costs were measured as zero.

The conservative unknown-liability rule remains the Stage 2 default. Cloud adapter
reconciliation must be supported by provider-specific evidence before relaxing it.
Paid adapter implementation remains Stage 6. No live provider, model download or
benchmark run is performed by this closure update.
