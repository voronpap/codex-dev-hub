# Context, Memory, RAG and Quality

## Future research record (2026-10-04)

These are operator-supplied research directions and future requirements, not
independently verified claims about current external releases. Exact project
identity/version, licensing and security remain adoption gates. No dependencies,
MCP servers, memory migration, compression benchmark or runtime integration are
authorized by this catalog. Stage 3G-C remains the priority: Stage 3G-C/3G OPEN,
execution_ready=false. The accepted production-router requirements are unchanged.

| Idea | Decision | Boundary |
| --- | --- | --- |
| Headroom | REFERENCE / BENCHMARK FIRST | Optional replaceable compression, not Context Builder replacement |
| Claude-Mem | REFERENCE | Retrieval/lifecycle ideas, not Project Brain replacement or database adoption |
| Task Observer | TAKE CONCEPT | Session Observer proposals, no automatic policy mutation |
| Progressive retrieval | TAKE CONCEPT | Budgeted evidence selection |
| Reversible compression | BENCHMARK FIRST | Preserve original provenance and recovery |
| Session Observer proposals | TAKE CONCEPT | Validation and human review before explicit apply |
| Automatic skill rewriting | REJECT | No silent prompt/skill/policy mutation |
| OmniRoute | OPTIONAL ADAPTER / REFERENCE | AI Platform long-tail backend; not Dev Hub core |
| Fail-open routing | REJECT | Never widen eligibility to obtain an answer |
| Random exploration as production default | REJECT | Explicit, separately accounted experiments only |

TAKE means take a concept, not install its originating project. Evaluate overlap
with existing capabilities before adding anything. Do not duplicate functionality
already served better by our Brain, Context Builder or ResourceController.

### Optional reversible compression

Headroom-style ideas worth evaluating: tool-output, log, RAG-chunk, file and history
compression; content-aware compressors; reversible retrieval; shared context;
learn/session-improvement loops. None is assumed implemented or suitable here.

The future sequence remains:

```text
Project Brain -> retrieval -> Context Builder -> optional compression
             -> provenance revalidation -> model
```

Compression is a transport representation. Original source remains truth. Retain
original source ID/hash, compressor algorithm/version, compressed hash and
mapping/recovery metadata. Recovery must permit original-source hash revalidation.
Shared context must retain project/privacy isolation. Lossy representations must
not impersonate original evidence or erase citation provenance.

Before adoption, use a separately reviewed experiment over our frozen fixtures:
tokens before/after (with estimator identity), semantic acceptance, citation and
provenance retention, latency, measured CPU cost and recovery success. Freeze an
acceptable quality-degradation threshold before results. External claims such as
60–95% token reduction are not our evidence. Do not run this experiment in Stage 3G.

### Progressive Project Brain retrieval

Claude-Mem-style references include progressive disclosure, layered retrieval,
session observations, timeline retrieval, observation IDs, deduplication and memory
lifecycle. Project Brain remains the durable project context system over Git.

Future API concept, not an implemented API:

```text
brain_search() -> compact matches
brain_timeline() -> related decisions/events/context
brain_get(ids) -> full selected evidence
```

Never inject all session history automatically. Select relevant evidence using
context budget, task relevance, source priority, freshness, provenance and
deduplication. FTS scores from different queries are not globally comparable:
retain within-query rank plus source priority.

### Session Observer and reviewed improvement

```text
development session -> structured observations -> recurring patterns
 -> improvement proposal -> offline validation/benchmark -> human review
 -> explicit, versioned skill/policy change
```

Candidate observations: repeated user corrections, tool misuse, repeated debugging
sequences/manual workflows, provider failures, context omissions, citation errors,
unnecessary token usage, common task templates and poor routing outcomes. Do not
copy secrets or raw sensitive context into global memory. Define project scope,
redaction, retention and deletion before collection.

A future proposal may contain pattern, evidence references, affected workflow,
suggested skill, expected benefit, risk, benchmark plan and confidence. Confidence
does not authorize application. Routing/security/privacy policy, provider
permissions and paid execution must never mutate autonomously. Observers propose;
reviewed explicit apply changes policy. No automatic skill creation now.

Session Report may summarize existing telemetry: provider calls/tokens/latency,
context size, retrieval sources, delegations, failures, retries, human corrections
and measured or explicitly estimated local/cloud cost. Unknown metrics stay null;
estimated cost stays labelled. No savings claims without benchmark evidence.

The future Dev Hub flow is:

```text
Codex -> Project Brain -> progressive retrieval -> Context Builder
 -> optional reversible compression -> devhub_delegate -> AI resource
 -> Session Observer -> improvement proposal
```

### Optional tools and skill research

Prioritize Context7 for fresh documentation retrieval, Playwright for browser/UI
testing, and Firecrawl for structured web extraction. GitHub is already used.
n8n, Supabase, Figma, Notion, Vercel, Telegram, Stripe and Zapier remain
project-specific optional integrations; do not include every integration in core.

Skill research candidates: Superpowers, Ralph Loop, Context7, Frontend Design,
Playwright, GStack, Productivity, Document Skills, Session Report, Skill Creator,
Code Review, Security Review and DataViz. For each, record the problem solved,
overlap with Dev Hub, security impact, token impact and benchmark value before
copying or installing anything.

### Adoption and portability gates

Before any external integration verify license/commercial use, maintenance,
release cadence, security posture, dependency chain, telemetry, network access,
data retention, secret handling and supply-chain risk. Popularity is not a
security proof. Contracts must permit replacing the compressor, memory backend
and observer implementation without rewriting core. AI Platform's independent
aggregator/facade requirements are recorded in its own provider-routing catalog.

The older inventory below remains candidates only, not an activation decision.

## Project Brain / memory candidates
- **Graphiti** — temporal knowledge graph; strong candidate for evolving project facts.
- **Mem0** — long-term agent memory.
- **Cognee** — knowledge/memory/RAG.
- **Letta** — stateful agent/memory architecture.
- **LangMem**, **Supermemory**, **Memobase**, **MemOS**, **OpenMemory** — additional candidates.

Do not deploy all. Project Brain may combine explicit ADR/files + repo index + vector retrieval + optional temporal graph + task summaries. Git remains source of truth.

## Vector / RAG
- **Qdrant** — primary self-hosted vector DB candidate.
- **Upstash Vector** — cloud free-tier candidate for small/zero-ops use.
- **Hugging Face TEI** — self-hosted embeddings/rerank serving.
- **Jina AI** — cloud free embeddings/rerank plus Reader/Search.
- Model families: BGE, Jina, GTE and benchmarked multilingual/code embeddings.
- Framework candidates: **LlamaIndex**, **RAGFlow**, or lightweight custom pipeline.

Retrieval should combine code/lexical search, metadata, vectors where useful, explicit decisions and provenance.

## Context optimization
- Headroom compression candidate.
- Selective Context Builder.
- Progressive tool-schema disclosure.
- Structured handoffs instead of raw transcripts.
- Semantic caching only with correct project/version keys.

## Evaluation
- **Promptfoo** — model/prompt/RAG/agent evaluation and red-team.
- **DSPy** — programmatic prompt/pipeline optimization.
- **GEPA** — feedback/evolution optimization direction.

Routing should eventually rely on benchmarks from our real tasks, not model reputation.

## Metrics
Track correctness/tests, human corrections, latency, Codex quota/context, external tokens/cost, retries and whether Codex had to redo delegated work. Cheap work that must be redone is not efficient.

## Observability
- **Langfuse** — LLM tracing/evaluation candidate.
- **Prometheus + Grafana** — system metrics.
- Structured Dev Hub telemetry: route reason, task class, provider/model/tool, quota state, tokens, latency, cost, errors/retries and rework.
