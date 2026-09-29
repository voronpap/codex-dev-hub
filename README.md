# Codex Dev Hub

> A Codex-first development toolbox that extends Codex with free-first cloud models, local models, shared project context, research tools, and optional worker agents.

## Status

**Stage 2 CLOSED.** Stages 1 and 2 are accepted, merged and verified. MCP exposes status,
strict configuration and synthetic test resources. Internal offline resource APIs
add SQLite accounting, reservations, capabilities, deterministic routing and recovery.
The default server has no inference or paid execution. See the
[Stage 1 runbook](docs/STAGE1.md) and [Stage 2 scope and evidence](docs/STAGE2.md).

[Stage 3A Project Brain + FTS5](docs/STAGE3A.md) is **CLOSED**, accepted and merged as an
internal, project-scoped retrieval API. [Stage 3B Context Builder](docs/STAGE3B.md)
is **CLOSED**, accepted and merged with immutable, budgeted and revalidated packages;
its private packages require explicit export approval before any cloud use.

[Stage 3C Ollama](docs/STAGE3C.md) is **CLOSED + Local E2E Gate PASSED** through an
explicit local-only MCP entry point, with model-specific token admission and real
Codex smoke evidence. Execution/accounting gate passed; semantic quality not yet
established. The default status server remains offline. [Stage 3D Groq](docs/STAGE3D.md)
adds an opt-in, one-shot Free probe through the same accounting boundary and explicit
public/redacted export. **Stage 3D CLOSED** after owner acceptance of PR #17 and
UTF-8 documentation cleanup. [Stage 3E Gemini gates](docs/STAGE3E.md) preserve the
same boundary and require separate data-use, quota and token-accounting verification;
the opt-in Gemini partial implementation was accepted and merged in PR #18.
**PR #19: Gemini execution/accounting gate PASSED; Stage 3E CLOSED.** Its approved one-shot follow-up settled 81 input + 11 output tokens
before returning `invalid_output`; semantic acceptance remains null. See the
[follow-up evidence](docs/STAGE3E_FOLLOWUP.md). At the PR #18 merge, Stage 3E was
OPEN and the live gate NOT_PASSED. The first count
returned HTTP 404 and blocked inference. Merge accepts the implementation and
fail-closed evidence; it does not verify Gemini execution.

## Core idea

Codex remains the **main development orchestrator** and the primary place where the developer works. Codex Dev Hub does not try to replace Codex or build another coding-agent UI.

Instead, Dev Hub gives Codex a reusable toolbox:

- free cloud LLM/VLM capacity;
- local models when useful;
- paid providers only as a controlled fallback;
- web search, crawling, scraping and browser tools;
- project memory and retrieval;
- document and vision capabilities;
- sandboxed execution;
- optional worker agents such as Cursor or OpenHands;
- quota, cost and capability awareness.

The intended flow is:

```text
Developer
    |
    v
  Codex                 <- main orchestrator
    |
    v
Codex Dev Hub
    |
    +-- Free cloud providers
    +-- Local models
    +-- Paid fallback
    +-- Search / Web / Browser
    +-- Project Brain
    +-- Documents / Vision
    +-- Sandbox
    +-- Worker agents
```

## Primary rule

```text
Use Codex directly when that is the most efficient path.

For delegated work:
FREE CLOUD -> LOCAL -> PAID
```

Free-first is a routing preference, not a reason to create unnecessary delegation. A trivial task should not travel through several models just to avoid a few Codex tokens.

## What Dev Hub is

Dev Hub is a **module/tool layer for Codex**. Its responsibilities are to:

1. expose useful capabilities to Codex through stable interfaces, primarily MCP;
2. pool and route free cloud resources;
3. expose local inference without coupling projects to Ollama or another runtime;
4. maintain reusable project context;
5. provide compact handoffs between Codex and worker agents;
6. measure whether delegation actually saves time, tokens, and money;
7. make capabilities replaceable without changing every project.

## What Dev Hub is not

V1 is **not**:

- a replacement for Codex;
- another full coding-agent UI;
- a mandatory runtime dependency for applications developed with it;
- a reason to rewrite existing projects;
- a monolithic bundle where every discovered AI project runs all the time;
- an autonomous system allowed to modify production without explicit policy.

## Context model

Agents do not share one enormous prompt. They share a **Project Brain**.

```text
                    PROJECT BRAIN
                         |
          +--------------+--------------+
          |              |              |
     Architecture     Decisions      Knowledge/RAG
          |              |              |
          +--------------+--------------+
                         |
                   Context Builder
                         |
          +--------------+--------------+
          v              v              v
        Codex          Cursor       Free/Local model
```

Each consumer receives only the context relevant to its task.

Git remains the source of truth for code. Project Brain stores architecture, decisions, conventions, task history, useful summaries and retrieval indexes—not stale copies of the whole repository.

## Planned capability groups

### Model resources

- Google Gemini free tier
- Groq
- NVIDIA NIM
- OpenRouter free models
- Cloudflare Workers AI
- Mistral / Hugging Face / other eligible free tiers
- Ollama / llama.cpp / other local runtimes
- paid OpenAI, Anthropic, DeepSeek and others as optional fallback

Free-tier availability and limits change. Providers must therefore be adapters with quota/health tracking, not hard-coded assumptions.

### Development tools

- web search and research
- web extraction/crawling
- browser automation
- RAG and project retrieval
- document parsing
- vision/OCR
- sandboxed command execution
- Git/GitHub integration
- worker-agent delegation

### Worker agents

Codex may delegate independent subtasks to workers such as:

- Cursor Agent
- OpenHands
- local coding agents
- other compatible agents added later

Workers are not peers competing to control the project. Codex remains the coordinating agent.

## Repository direction

The implementation is intended to remain a single monorepo:

```text
codex-dev-hub/
├── core/          # routing, quotas, context, policies
├── providers/     # cloud/local model adapters
├── tools/         # search, web, RAG, browser, documents...
├── agents/        # worker-agent adapters
├── mcp/           # Codex-facing MCP interface
├── memory/        # Project Brain
├── config/
├── tests/
└── docs/
```

The exact implementation structure may change after V1 spikes. Architecture documents describe contracts and responsibilities rather than prematurely fixing a framework.

## Documentation

- [V1 technical proposal](docs/V1_TECHNICAL_PROPOSAL.md) — proposed stack and architecture, design only.
- [Repository audit and gaps](docs/V1_AUDIT.md)
- [Current technology research](docs/V1_RESEARCH.md)
- [V1 contracts and schemas](docs/V1_CONTRACTS.md)
- [Baseline and Delegation Value](docs/V1_BENCHMARK.md)
- [Staged implementation and Stage 1 gate](docs/V1_IMPLEMENTATION_PLAN.md)
- [Mandatory V1 core](docs/V1_CORE.md)
- [Vision](VISION.md)
- [Architecture](ARCHITECTURE.md)
- [Roadmap](ROADMAP.md)
- [Principles](docs/PRINCIPLES.md)
- [Codex integration](docs/CODEX_INTEGRATION.md)
- [Project context](docs/PROJECT_CONTEXT.md)
- [Free-first routing](docs/FREE_FIRST_ROUTING.md)
- [Providers](docs/PROVIDERS.md)
- [Tools](docs/TOOLS.md)
- [Agents](docs/AGENTS.md)
- [Security](docs/SECURITY.md)
- [Architecture decisions](docs/adr/)

## V1 success criterion

V1 succeeds if Codex can use Dev Hub during real development work and we can demonstrate that selected delegated tasks:

- consume fewer scarce/paid resources;
- preserve or improve result quality;
- do not add excessive latency or orchestration complexity;
- share useful project context safely;
- remain observable and reversible.

The objective is not “delegate as much as possible.” The objective is **make Codex development more efficient**.

Normal delegation entry point: [Stage 3F contract and configuration](docs/STAGE3F.md),
`python -m devhub.delegate_server --config <trusted-local-json>`.
