# V1 repository audit and gap analysis

Date: 2026-09-28. Audited baseline: `bccb913f85846fbc53268c60f6bf8774a0eab158`.

## Scope and evidence

Read all 24 tracked files: README, VISION, ARCHITECTURE, ROADMAP; docs/V1_CORE,
PRINCIPLES, CODEX_INTEGRATION, PROJECT_CONTEXT, FREE_FIRST_ROUTING, PROVIDERS,
TOOLS, AGENTS, SECURITY; ADR-0001 through ADR-0004; all seven catalog documents
(README, MODELS_AND_AGENTS, WEB_AND_TOOLS, CONTEXT_AND_QUALITY, MULTIMODAL,
INFRA_AND_FREE_CLOUD, FUTURE_PLATFORM).

The baseline contains documentation only: no application, dependency manifest,
lockfile, tests, CI, deployment files or root license. No runtime test results can
be claimed. `docs/AGENTS.md` describes worker behavior, not a requirement to spawn
agents during this audit. The four existing ADRs are Accepted and remain intact.

## Gaps and disposition

| Evidence | Gap / consequence | Resolution in this proposal |
|---|---|---|
| ROADMAP phases 2–4 vs V1_CORE required components | Brain, context and sandbox appear post-V1 | V1 stages include minimal versions; external coding-agent product integrations remain later |
| ARCHITECTURE, CODEX_INTEGRATION, V1_CORE | Three candidate MCP naming conventions; no wire contracts | Six stable `devhub_*` tools and versioned envelopes in V1_CONTRACTS |
| PROVIDERS, catalog/MODELS_AND_AGENTS | Different free classifications; no expiry evidence | Separate service class, replenishment and verification; current research ledger |
| V1_CORE ResourceController | No atomic admission or crash accounting | Persistent reservations across account pools, task/project/global budgets |
| FREE_FIRST_ROUTING | Order exists but missing rejection/quality rules | Eligibility first, deterministic ranking, bounded attempts, explicit abstention |
| PROJECT_CONTEXT, ADR-0003 | Storage, invalidation and decision conflicts unspecified | Git references + per-project SQLite/FTS5, content hashes, revisioned decisions |
| SECURITY | No concrete SSRF, executor or artifact boundary | Explicit threat controls and negative tests |
| V1_CORE benchmark | No fixtures, baseline procedure or definition of value | Paired A/B protocol with quality gates and measurement provenance |
| catalog/INFRA_AND_FREE_CLOUD | PostgreSQL described as relational default | SQLite is the V1 selection; PostgreSQL remains a later catalog candidate |
| VISION and catalog/FUTURE_PLATFORM | Potential application-runtime direction could blur product boundary | V1 proposal explicitly separates ai-platform; no dependency or shared service |
| Repository | No lockfiles or license decision | Stage 1 freezes dependency versions; owner chooses repository license before distribution |

## Boundaries preserved

Codex decides whether to delegate and integrates results. Dev Hub is a toolbox.
No existing product repository (including PLAIK, DealHunter or ai-platform) was
changed. Catalog files are unchanged in Git; omission from V1 is not
rejection. No credentials, inference calls, provider subscriptions, service
installations or benchmark runs are part of this design stage.

## Reading order

1. [Current research](V1_RESEARCH.md): evidence, uncertainty and alternatives.
2. [Technical proposal](V1_TECHNICAL_PROPOSAL.md): architecture and policies.
3. [Contracts](V1_CONTRACTS.md): fields, lifecycle and validation rules.
4. [Benchmark](V1_BENCHMARK.md): baseline before adaptive routing.
5. [Implementation plan](V1_IMPLEMENTATION_PLAN.md): gates and small changes.
6. [ADR index](adr/README.md): proposed decisions supplement ADR-0001–0004.

Documentation verification covers relative links, code-fence balance, example
JSON/TOML parsing, whitespace, scope and catalog preservation. It does not prove
MCP interoperability, provider account access, hardware capacity or sandbox safety.
