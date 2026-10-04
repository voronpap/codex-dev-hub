# Future Platform Ideas

These ideas were discussed/researched but are secondary to the current goal: **Dev Hub as a Codex development module**.

## Startup / Control UX — TAKE (future core feature)

Recorded 2026-10-04. Roadmap only: no startup CLI, service, observer, provider or
backend is implemented/activated by this note. Stage 3G-C router/origin proof is
unchanged; Stage 3G-C/3G OPEN, execution_ready=false.

Users should manage one stack, without manually starting Brain, Context Builder,
Router, ResourceController, delegate MCP, adapters, telemetry or optional services.
In-process components need not become separate daemons merely to provide this UX.

| Proposed command | Required behavior |
| --- | --- |
| `devhub init` | Create a local config template; check state directories; create no secrets, pull no models, enable no paid execution |
| `devhub up` | Validate trusted config and state/ledger; check configured Ollama/providers; start required local services and `devhub_delegate`; fail with a clear reason if a mandatory security/runtime dependency is unavailable |
| `devhub status` | Report component readiness, health and policy without keys, credential fingerprints or sensitive account data |
| `devhub doctor` | Safe local/metadata-only checks; never automatic inference |
| `devhub down` | Stop managed runtime services only; retain ledger, Brain, project memory, evidence and configuration |
| `devhub restart` | Controlled stop/start preserving durable state and accounting liabilities |
| `devhub logs` | Redacted structured logs; no keys, credentials, full secrets, private source payloads by default or sensitive provider responses |

Status should distinguish Dev Hub ONLINE, Brain/Context/Router READY, ledger
HEALTHY, and provider HEALTHY/AVAILABLE/VERIFY/UNKNOWN. Ollama, Groq, Gemini and
future OpenRouter are examples, not current activation instructions. Credential
presence is not proof of availability, free eligibility or remaining quota. Show
effective routing/privacy/paid policy (for example FREE-FIRST, PRIVATE LOCAL ONLY,
PAID DISABLED), not an unconditional promise or benchmark-based provider ranking.

Doctor covers configuration, SQLite schema/integrity, Brain index, MCP availability,
Ollama endpoint/model, credential presence through the approved boundary, safe
provider metadata access and observable quota metadata, Docker/runtime, filesystem
permissions, state-root separation and secret handling. If health verification
requires a paid or request-consuming call, report UNKNOWN / requires explicit
probe. Unknown limits are not unlimited. Startup performs no cloud inference,
automatic model pull or automatic paid activation.

One trusted configuration layer controls provider enablement, routing, privacy and
profiles; credentials remain in approved secret/environment boundaries. Conceptual
options include free_first=true, local_fallback=true, paid_enabled=false and
private_cloud_allowed=false. These are future policy settings, not a bypass of
eligibility, operator authorization, accounting or post-dispatch no-fallback rules.

Profiles are convenience selections over the same execution core:

- minimal: Ollama + Dev Hub;
- normal: minimal + AI Platform and reviewed Groq/Gemini/OpenRouter configuration;
- full: normal + explicitly enabled long-tail providers, browser/search,
  compression, observers and additional MCP/tools.

A profile is not authorization to install or activate catalog candidates, consume
quota or weaken privacy. Mandatory dependency failure must fail closed. A private
task with no eligible local model is DENIED, never silently exported to cloud.
Startup must preserve the approved MCP identity, origin/schema and tool ceiling;
orchestration cannot substitute a same-name unreviewed process.

Future launch options: `start-devhub.ps1` or Windows service/task, Linux systemd,
and `docker compose up -d`. These are implementation alternatives, not three
execution cores. The desired daily flow is PC boot -> managed stack starts ->
open repository -> Codex starts -> approved delegate already available. Users
should not need to choose a physical provider for every task.

Once implemented and reviewed, AI Platform may serve as a shared runtime and be
started alongside Dev Hub. The products and repositories remain separate.
One-command setup aims for `devhub init`, `devhub up`, `devhub status`.

Classification: Startup/Control UX = TAKE; up/status/doctor = future core feature;
Compose/systemd/PowerShell = implementation options; single execution core =
mandatory; automatic unsafe fallback = REJECT. No Stage 3G-C scope expansion.

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
