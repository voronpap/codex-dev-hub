# V1 technology research

Checked: **2026-09-28**. Primary documentation was opened during this review.
This is a public-documentation assessment, not an authenticated account test or
performance benchmark. Provider availability, region, accepted terms, quotas and
model IDs must be checked again when enabling an adapter. All selections below
are engineering recommendations, not upstream guarantees.

## Evidence ledger: providers

Classes describe an offer, not an entire company. `CORE_FREE` means a verified,
renewing allowance that passes our workload tests; it does not mean permanent or
unlimited. `DEV_FREE` is useful development capacity, `EVAL_FREE` evaluation-only,
`TINY_FREE` a small allowance, `FREE_CREDITS` a credit allocation with explicit
renewal/expiry, `TRIAL_CREDIT` a time-limited or one-off trial, `VERIFY` unresolved,
and `PAID` billable. None is currently proven CORE_FREE for this project.

| Offer | Public evidence and provisional class | V1 disposition / remaining check |
|---|---|---|
| Gemini Developer API free | Selected models have free input/output; free-tier content can improve products. **DEV_FREE**. [Pricing](https://ai.google.dev/gemini-api/docs/pricing) | Primary candidate for public/redacted synthesis; private code blocked by default. Confirm exact model, account limits, region and applicable data terms. |
| Groq Free | RPM, RPD, TPM and TPD are independent limits; response request headers refer to RPD and token headers to TPM. **DEV_FREE**. [Limits](https://console.groq.com/docs/rate-limits) | First cloud text adapter; bind account/model quota pools, not API key alone. Inspect console and retention settings before private use. |
| NVIDIA hosted NIM developer endpoints | Developer access is for prototyping; downloadable NIM access and enterprise trials are different offers. **EVAL_FREE**, quota **VERIFY**. [Run anywhere](https://docs.api.nvidia.com/nim/docs/run-anywhere), [FAQ](https://docs.api.nvidia.com/nim/docs/product) | Keep as an evaluation alternative, not dependable core capacity. No claim of unlimited free inference or fixed credits. |
| OpenRouter free variants | Free requests have account-dependent limits; key endpoint exposes daily counters. **DEV_FREE**, exact entitlement **VERIFY**. [Limits](https://openrouter.ai/docs/api_reference/limits) | Third cloud adapter, opt-in after two direct adapters. Explicit model/upstream allowlist; prohibit paid substitution. Retrieved public table lacked numeric cells, so no stale 50/1000-RPD claim is copied. |
| Cloudflare Workers AI Free | 10,000 neurons/day; some models require a paid billing method. **DEV_FREE** for eligible models. [Pricing](https://developers.cloudflare.com/workers-ai/platform/pricing/) | Reserve alternative. Requires non-token quota units; paid-plan overage must be disabled or bounded. Not an initial dependency. |
| Hugging Face routed inference | Free users receive $0.10 monthly credits, subject to change. **TINY_FREE**, credit renewal monthly. [Pricing](https://huggingface.co/docs/inference-providers/pricing) | Smoke/evaluation capacity, not a primary pool. Paid subscription allowances are not free-account capacity. |
| Mistral Free mode | Included monthly usage and limits are account/plan-dependent. **DEV_FREE**, model entitlement **VERIFY**. [Usage and limits](https://docs.mistral.ai/admin/billing-usage/usage-limits) | Reserve alternative; account probe and data policy review required. |
| Tavily free search credits | 1,000 API credits monthly; request types have different credit costs. **FREE_CREDITS**, renewing monthly. [Credits](https://docs.tavily.com/documentation/api-credits) | One initial search adapter; basic bounded search, paid disabled. Account billing/retention check before enablement. |
| Other catalog services | Not selected or revalidated exhaustively: Cerebras, SambaNova, Z.AI, ModelScope, Jina, aggregators, etc. **VERIFY** | Retain catalog; no operational eligibility until evidence exists. |

Trial-credit offers require `expires_at` and cannot satisfy a recurring free
capacity assumption. The NVIDIA enterprise trial is not interchangeable with
hosted developer access. Local electricity/hardware costs remain benchmark costs
even when token billing is zero.

For each enabled offer store source URL, observed_at, expires_at/recheck_after,
account pool, model ID, plan, region, billing mode, data-use class and evidence
quality. Public docs seed candidate metadata; an account probe establishes actual
eligibility. Failure to observe a limit means unknown, never unlimited. Recheck
on startup if stale, after 401/403/404/429, and before any billable dispatch.

## Gateway comparison

| Dimension | LiteLLM | Bifrost | Minimal in-process adapters (selected) |
|---|---|---|---|
| Maintenance | Broad integration surface maintained upstream; upgrade and regression burden | Upstream gateway plus plugin/config surface | Small initial surface, but all provider normalization is our responsibility |
| License | MIT outside enterprise directory; enterprise separately licensed | Apache-2.0 root; verify enterprise feature terms | Project license not yet selected; dependency license inventory in Stage 1 |
| Hosting / complexity | Self-hosted gateway or library; proxy introduces another policy owner | Self-hosted gateway; separate service and configuration | One Python process; no general-purpose public gateway API |
| Performance | Upstream claims require reproduction | Upstream throughput claims require reproduction | No extra network hop; actual overhead still unmeasured |
| API stability | Normalizes many APIs; provider edge cases and upgrades remain | Common gateway API; provider/plugin semantics need contract tests | Our v1 contract stays stable; upstream differences live in adapters |
| OpenAI compatibility | Broad normalization | Common API support | Only the tested chat subset where supported; native Gemini and Ollama APIs allowed |
| MCP | MCP bridge/gateway features | MCP integrations; enterprise boundaries need checking | Official MCP SDK exposes only six domain tools |
| Observability | Existing logging/cost integrations | Built-in gateway observability/governance | Explicit Dev Hub events; optional OTel export later |
| Replacement | Hide behind ProviderAdapter; disable nested routing/retries | Same boundary; prohibit policy bypass | Add a GatewayAdapter without changing Codex tools |

Evidence: [LiteLLM repository](https://github.com/BerriAI/litellm),
[license](https://raw.githubusercontent.com/BerriAI/litellm/main/LICENSE),
[Bifrost repository](https://github.com/maximhq/bifrost),
[license](https://raw.githubusercontent.com/maximhq/bifrost/main/LICENSE).
Gateway feature summaries do not establish equivalence for our workloads.
No published speed multiplier is used as a measured advantage here.

Recommendation: avoid a second routing/budget authority for three cloud adapters.
Reconsider gateways at more than five active providers, material adapter upkeep,
or demonstrated throughput pressure. Compare equal retry settings and payloads
before a swap. ResourceController remains authoritative even behind a gateway.

## Other component decisions

| Choice and alternative | Reason / limitation / replacement boundary |
|---|---|
| Python 3.12 + official MCP Python SDK + Pydantic + httpx; TS/Go alternatives | Python suits adapters, retrieval and evaluation in one runtime. Less CPU throughput than a Go design is acceptable as a hypothesis at V1 concurrency; measure it. SDK currently documents stable v2 and supported transports. Pin a tested patch in Stage 1; do not copy v1 FastMCP examples uncritically. Domain DTOs must not depend on SDK types. [SDK](https://github.com/modelcontextprotocol/python-sdk) |
| MCP stdio first; Streamable HTTP later | Codex documents both transports and shared host configuration. Stdio avoids listening/auth infrastructure for the first local slice. Test actual client version in Stage 1. Dev Hub is the server consumed by Codex; running Codex as a server reverses the intended relationship. [Codex MCP](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) |
| Ollama native local adapter; llama.cpp alternative | Runtime adapter keeps local queue/health/context observable; OpenAI compatibility alone does not configure local context size. Explicit installed-model allowlist, local endpoints and cloud-disabled configuration are required. Model license and hardware fit are separate from runtime choice. [Compatibility](https://docs.ollama.com/api/openai-compatibility) |
| SQLite + FTS5 + Git/ripgrep; PostgreSQL/Qdrant/tree-sitter alternatives | Minimal single-host storage and lexical retrieval; FTS5 supports full-text queries and ranking. It is not semantic or AST retrieval. Store rebuildable excerpts only, with provenance. Storage/retriever interfaces allow replacement. [FTS5](https://sqlite.org/fts5.html) |
| Structured SQLite events + JSONL export; OTel/Langfuse alternatives | First measure domain value without another database service. OpenTelemetry offers a portable Python instrumentation path; Langfuse is a richer evaluation/trace product but adds operations. Export boundary preserves evolution. [OTel](https://opentelemetry.io/docs/languages/python/), [Langfuse](https://github.com/langfuse/langfuse) |
| Tavily basic search; SearXNG alternative | One hosted search adapter reduces operations; quota and query privacy constrain it. SearXNG can expose JSON search but public instances may disable formats and self-hosting still sends queries upstream. ToolAdapter makes switching independent of MCP. [Search API](https://docs.searxng.org/dev/search_api.html) |
| Rootless Docker worker sandbox; bare worktree / VM alternatives | Worktree alone is not execution isolation. Containers provide bounded disposable environments; shared-kernel isolation is insufficient for hostile multi-tenant code. Rootless reduces daemon privilege but does not replace seccomp, network or mount policy. VM isolation is the escalation path. [Rootless Docker](https://docs.docker.com/engine/security/rootless/) |

Maintenance/operations ratings above are design judgments, not vendor facts.
Direct license checks: [Pydantic MIT](https://raw.githubusercontent.com/pydantic/pydantic/main/LICENSE),
[httpx BSD-3-Clause terms](https://raw.githubusercontent.com/encode/httpx/master/LICENSE.md),
[Ollama MIT](https://raw.githubusercontent.com/ollama/ollama/main/LICENSE),
[SQLite public-domain dedication](https://www.sqlite.org/copyright.html), and
[ripgrep Unlicense option](https://raw.githubusercontent.com/BurntSushi/ripgrep/master/UNLICENSE).
The official MCP SDK repository identifies MIT. These runtime licenses do not
grant rights to every downloaded model or hosted service; provider/model terms
must be checked separately. No claim about all transitive dependencies is made.

Exact dependency versions, transitive licenses, model licenses and image digests
belong in the Stage 1/adapter-stage lock manifests. No dependency is installed by
this proposal. No existing provider key was read or used.
