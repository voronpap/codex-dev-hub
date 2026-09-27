# Context, Memory, RAG and Quality

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
