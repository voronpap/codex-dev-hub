# Infrastructure and Free Cloud Catalog

These services may support Dev Hub or future projects. Free quotas change and must be revalidated.

## Separate free pools
The architecture can pool zero-cost resources by capability, not just LLM:
- LLM/VLM;
- embeddings/rerank;
- search;
- extraction;
- STT;
- OCR/vision;
- database;
- vector DB;
- queue;
- KV/cache;
- serverless compute.

## Free cloud data/services researched
- **Jina** — embeddings, rerank, Reader, Search free allowances.
- **Groq** — LLM plus Whisper free plan.
- **Cloudflare** — Workers AI plus Workers/D1/KV and related free allowances.
- **Supabase free** — PostgreSQL/Auth/API/Realtime/Storage for future projects.
- **Neon free** — serverless PostgreSQL/branching.
- **Cloudflare D1** — small edge SQL.
- **Cloudflare KV** — KV/config/cache.
- **Upstash Vector** — free vector operations.
- **Upstash QStash** — free message allowance.
- **Upstash Search** — free search allowance.
- **Neo4j Aura Free** — small graph experiments.
- Search allowances: Brave, Exa, Tavily, Firecrawl, SerpAPI and others as currently offered.

## Core/self-hosted data
- PostgreSQL — durable relational default.
- Qdrant — vectors/RAG.
- Redis-compatible cache where needed.
- Graphiti/graph store as selected.

## Object storage
- **RustFS** — S3-compatible self-hosted candidate.
- **MinIO** — alternative; re-evaluate current licensing/product direction.
- Cloud R2/Supabase/etc. — future free-tier artifact options.

## Secrets / identity
- **Infisical** — secrets management candidate.
- Agent Vault/credential-proxy direction — keep raw credentials away from prompts/workers.
- **ZITADEL** — advanced SSO/multi-user future option.
- Supabase Auth — simpler application auth option.

## Workflow / queues
- **Hatchet** — durable background/workflow engine.
- **Trigger.dev** — long-running TS/AI task engine; free allowance/self-host options.
- **n8n** — visual automation/integration; self-hosted AI starter kit is a useful reference.
- QStash — small cloud queue option.

## Deployment
- Docker Compose — preferred simple V1 deployment.
- **Coolify** — self-hosted PaaS/deployment candidate.
- Kubernetes — only if future scale justifies complexity.

## Security principle
Free is not automatically acceptable. Track provider privacy/data-use class. Sensitive tasks can force local execution.
