# Future Platform Ideas

These ideas were discussed/researched but are secondary to the current goal: **Dev Hub as a Codex development module**.

## Project generator
Possible future CLI:
```text
aihub project create <name>
aihub project import <existing>
```
Templates might include minimal, webapp, aggregator, research, coding and agent projects.

## Application stacks
Possible generated-project choices:
- FastAPI + PostgreSQL;
- Next.js;
- Supabase backend;
- Neon/Supabase/Cloudflare free-cloud variants;
- optional RAG/web/vision capabilities.

Applications should consume stable Dev Hub APIs rather than embedding every Dev Hub service.

## Existing projects
PLAIK/DealHunter and other existing repos should be importable gradually; no rewrite merely to fit Dev Hub.

## Feature flags / experiments
- **Unleash**;
- **GrowthBook**.
Potentially compare router/model strategies safely.

## Fine-tuning / LoRA
Candidates:
- **Axolotl**;
- **Unsloth**;
- **LLaMA-Factory**.
Only after enough clean successful task data exists. RAG/routing come first.

## Production AI service
Later, selected Dev Hub capabilities may be offered to applications via a stable API. This is not V1.

## Full platform direction previously explored
Potential modules: auth, DB, storage, queues, workflows, deployment, monitoring, project templates, multimodal services and agents. Keep these modular and do not let them turn the Codex toolbox into an unnecessary monolith.

## Monorepo direction
Dev Hub itself remains one repository with logical areas such as core/providers/tools/agents/mcp/memory/config/tests/docs. Product repositories remain separate.

## Efficiency objective
The end goal is not maximum component count. The catalog exists so options are not forgotten. Later selection must minimize complexity while maximizing quality, free-resource utilization and Codex effectiveness.
