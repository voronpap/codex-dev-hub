# V1 Core Specification

## Goal

V1 must prove that Codex Dev Hub makes **real Codex development more efficient** without replacing Codex.

Codex remains the main orchestrator. Dev Hub exposes a small MCP toolbox and routes bounded delegated work to free cloud resources first, then local resources, then paid resources only under policy.

## Required V1 components

```text
                         CODEX
                           |
                          MCP
                           |
                  +--------v--------+
                  |    DEV HUB V1   |
                  +--------+--------+
                           |
          +----------------+----------------+
          |                                 |
   Context Builder                         Router
          |                                 |
   Project Brain                    ResourceController
                                            |
                                   Capability Registry
                                            |
                                    Provider Manager
                                            |
                            +---------------+---------------+
                            |               |               |
                       FREE CLOUD         LOCAL           PAID*
                                            |
                                      Tool Manager
                                            |
                               Research / Sandbox / etc.
                                            |
                                      Telemetry
```

`* paid is optional and policy-controlled.`

---

## 1. ResourceController

ResourceController answers: **what can we afford/use right now?**

Responsibilities:

- estimate input/context/output tokens before dispatch where possible;
- track provider RPM/TPM/RPD and other rate limits;
- track daily/monthly/rolling quotas and reset times;
- classify free tiers and credits;
- maintain free-quota reserve;
- track paid budgets by task/project/global scope;
- enforce paid-approval thresholds;
- track local availability/queue/resource pressure;
- maintain provider health/error history;
- enforce context and output budgets.

Suggested modules:

```text
core/resource_controller/
├── token_estimator
├── context_budget
├── quota_tracker
├── rate_limiter
├── cost_controller
├── free_reserve
├── provider_health
├── usage_history
└── policy_engine
```

Example decision data:

```text
Gemini FREE    eligible, quota 71%
NVIDIA FREE    eligible, slower
Groq FREE      blocked: TPM
Local Qwen     context insufficient
OpenAI PAID    eligible, estimated cost ...
```

ResourceController does **not** decide which eligible option is best. Router does.

---

## 2. Capability Registry

Capability Registry answers: **what can each currently available resource actually do?**

Example:

```text
Gemini
  text: yes
  vision: yes
  tools: yes
  structured_output: yes

Groq
  text: yes
  stt: yes

Jina
  embeddings: yes
  rerank: yes
  search: yes
  reader: yes

Cursor
  coding_agent: yes
```

Store dynamic metadata such as:

- modality/capability;
- context/output limits;
- tool/JSON support;
- privacy class;
- free/paid class;
- health;
- current model/provider availability.

Codex asks Dev Hub for a **capability**, not for implementation-specific provider wiring.

---

## 3. Router

Router answers: **which eligible resource should execute this delegated task?**

Inputs:

- task type;
- required capabilities;
- complexity estimate;
- privacy policy;
- context size;
- ResourceController eligibility/quota;
- Capability Registry;
- observed historical quality;
- latency;
- cost.

Default delegated preference:

```text
FREE CLOUD -> LOCAL -> PAID
```

This is not absolute. Privacy, capability or measured quality may override it.

Important: a separate decision exists before routing — **should Codex delegate at all?** Small/tightly coupled work may be more efficient for Codex to perform directly.

---

## 4. Context Builder

Context Builder answers: **what is the minimum context the delegated task actually needs?**

Potential inputs:

- current task;
- relevant repository files;
- architecture/ADR records;
- project conventions;
- related prior task summaries;
- retrieved external documentation.

Example:

```text
raw possible context: 142k
  repo: 73k
  docs: 41k
  history: 26k
  task: 2k

selected package:
  repo retrieval: 18k
  docs rerank: 8k
  history summary: 3k
  task: 2k
  total: 31k
```

Context reduction is a first-class optimization. Saving model price while sending unnecessary context is not sufficient.

---

## 5. Project Brain

V1 Project Brain should be intentionally simple.

Required sources:

- Git/repository search/index;
- VISION/ARCHITECTURE/ADR/docs;
- explicit project decisions;
- compact completed-task summaries;
- lightweight retrieval index.

Do **not** require Graphiti, Mem0, Cognee or a large memory stack in V1. They remain cataloged future candidates.

Git is source of truth for code.

Project-specific data is isolated by project ID.

---

## 6. Provider Manager

All model providers implement a normalized adapter contract.

Conceptual interface:

```text
provider.execute(task)
provider.health()
provider.quota()
provider.capabilities()
```

Initial target set should stay small:

- Gemini free;
- Groq free;
- one of NVIDIA NIM / OpenRouter free;
- Ollama local.

Paid provider support may exist behind a disabled/approval policy.

Provider adapters must be replaceable because free tiers and model catalogs change.

---

## 7. Tool Manager / MCP surface

Codex should see a **small curated tool set**, not every underlying integration.

Candidate V1 tools:

```text
devhub.status
devhub.delegate
devhub.research
devhub.context
devhub.remember
devhub.sandbox
```

Exact names/contracts are subject to an MCP integration spike.

Internally, a high-level tool can choose among Jina/SearXNG/Crawl4AI/etc. Codex should not need to know every implementation.

---

## 8. Telemetry and Evaluator

V1 must measure whether delegation was beneficial.

Record at minimum:

- project/task ID;
- task class;
- route/provider/model/tool;
- input tokens;
- output tokens;
- context tokens;
- free quota consumed;
- paid cost;
- latency;
- success/failure/retries;
- tests/result validation;
- whether Codex had to redo the delegated work.

### Key metric: Delegation Value

Example:

```text
Without delegation:
estimated Codex context: 48k

With Dev Hub:
Codex context returned: 7k
free provider work: 31k
paid cost: $0
result accepted: yes

=> delegation beneficial
```

If a free model produces work that Codex repeatedly has to redo, routing should learn not to use that route for the task class.

---

# Initial V1 deployment

Keep it small:

```text
Codex
  |
 MCP
  |
Dev Hub Core
  |-- Gemini FREE
  |-- Groq FREE
  |-- NVIDIA or OpenRouter FREE
  |-- Ollama LOCAL
  |-- Research tool
  |-- Project Brain
  |-- Sandbox
  '-- Telemetry
```

Do not block V1 on Graphiti, ComfyUI, voice, UI-TARS, n8n, Hatchet, Supabase, Coolify, fine-tuning or every free provider in the catalog.

Those ideas remain preserved in `docs/catalog/`.

# V1 exit criteria

V1 is ready to expand only after it works on real repositories and demonstrates:

1. Codex can discover/use Dev Hub reliably through MCP.
2. Free/local delegation works with fallback.
3. Project context is shared without giant prompt histories.
4. ResourceController prevents accidental quota/cost waste.
5. Telemetry can compare direct Codex vs delegated work.
6. At least some task classes show measurable positive Delegation Value.
