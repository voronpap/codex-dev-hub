# DevFabric

A developer-first AI orchestration fabric for coding agents, local models,
cloud providers, shared project context, deterministic routing, and auditable execution.

- Shared project context, designed for reuse across coding-agent integrations.
- Controlled delegation to local and cloud models.
- Deterministic privacy and resource policy.
- Durable accounting and provenance.
- Evidence-driven execution and benchmarking.

DevFabric is the public project name. Some internal identifiers retain the
historical `devhub` naming for compatibility and evidence stability.
The repository remains `codex-dev-hub`; see the [naming policy](docs/NAMING.md).

**Active development. Execution-boundary qualification is in progress.**
The paired benchmark has not run; semantic quality, savings and Delegation Value
are not yet established. This is not a production-ready release.

## Try DevFabric

Run one bounded repository explanation through **Codex → MCP → Ollama**.
Requires Python 3.12, uv, Codex and an already installed reviewed Ollama model.

```sh
git clone https://github.com/voronpap/codex-dev-hub.git
cd codex-dev-hub
uv sync --locked
```

Follow the [local demo guide](docs/DEMO1.md): verify Ollama/model identity,
copy the [local config](config/devfabric-local.example.json), connect Codex,
and ask why the output validator rejects fabricated citations. The guide includes
an exact MCP config, task and route/accounting fields to inspect.

Initialize the reviewed ledger identity once before starting the server:

```sh
uv run --locked python -m devhub.delegate_server \
  --config .devhub/local.json --initialize-ledger
```

Canonical stdio server command, from the repository root:

```sh
uv run --locked python -m devhub.delegate_server --config .devhub/local.json
```

Codex normally starts this child process itself; it is not an HTTP service.
The demo uses local Ollama only. No cloud generation, paid execution or automatic
model pull is enabled. Docker/OCI is used for benchmark/isolation work, **not**
one-command DevFabric deployment. Docker Compose startup remains future work.

## Why this exists

As coding workflows add model clients and tools, context can be duplicated,
local/cloud choices can become implicit, and retries can obscure what actually ran.
A successful model call also says little about whether delegation helped the developer.

DevFabric keeps the coding agent as the orchestrator (currently Codex), with delegation
behind explicit context,
privacy, capability and resource rules. It combines Project Brain, Context Builder,
Capability Registry, deterministic Router, ResourceController and provider adapters.
A frozen paired benchmark is the next step toward measuring usefulness.

DevFabric is not a replacement for Codex, Cursor or Claude, just a model proxy,
just an Ollama frontend, an MCP collection, or a generic autonomous multi-agent
framework. It is the shared orchestration, control and context layer around those
tools, rather than a separate coding agent.

## Agent integrations

| Agent / client | Status |
| --- | --- |
| Codex | Current primary integration вЂ” first and deepest integration |
| Cursor | Planned; not implemented |
| Claude | Planned; not implemented |
| Other coding agents / IDE assistants | Future candidates |

Each client should connect through an Agent Adapter / Client Adapter boundary.
The shared Brain, Context Builder, routing, privacy, accounting and provider
infrastructure are designed to be reused rather than reimplemented per agent.
Cross-client operation is a design direction, not an already validated capability.

## Project status

вЂњCompleteвЂќ below means the accepted implementation and its scoped gate are complete;
it does not establish general task quality or full production qualification.

| Area | Status |
| --- | --- |
| Core architecture and offline runtime | Complete |
| Project Brain and Context Builder | Complete |
| ResourceController and durable accounting | Complete |
| Ollama local execution/delegation | Complete |
| Groq and Gemini adapters | Complete вЂ” scoped execution/accounting gates |
| Unified `devhub_delegate` | Complete вЂ” local unified delegation gate passed |
| Frozen benchmark harness | Complete вЂ” offline harness accepted |
| Execution boundary and isolated runtime qualification | In progress |
| Real paired delegation benchmark | Not run |

See [accepted milestones](docs/STAGES.md), [unified delegation](docs/STAGE3F.md)
and the [offline benchmark harness](docs/STAGE3G-A.md) for scope and evidence.

## Architecture

```text
DevFabric
|-- Agent / Client adapters
|   |-- Codex (current primary integration)
|   |-- Cursor (planned)
|   `-- Claude / other coding agents (planned)
|-- Project Brain + Context Builder
|-- ResourceController + Router / Policy
|-- Privacy + durable accounting
`-- Provider adapters
    |-- Ollama
    |-- Groq
    `-- Gemini / future providers
```

Current Codex delegation path:

```text
Codex вЂ” orchestrator
  |
  v
MCP: devhub_delegate
  |
  +--> Project Brain --> Context Builder --> source revalidation
  |
  +--> privacy / explicit public-redacted export when cloud is eligible
  |
  +--> Capability Registry + deterministic Router + ResourceController
  |       select provider --> reserve --> revalidate --> durable dispatch
  v
Provider adapter
  +--> Ollama (local)
  +--> Groq (approved Free configuration)
  +--> Gemini (qualified Free configuration)
  |
  v
usage settlement / unknown_usage + transactional outbox
  |
structured output + citation validation --> compact handoff --> Codex
```

- **Git:** source of truth; revision and content hashes bind retrieved evidence.
- **SQLite / FTS5:** project retrieval, durable reservations, accounting and events.
- **MCP:** the Codex-facing delegation contract.
- **Linux Docker/OCI:** the chosen benchmark isolation boundary, still being qualified.

Context is prepared before inference. Provider selection precedes reservation;
a dispatch marker is durable before the provider send. Complete usage is settled
even when output validation fails. See [architecture](ARCHITECTURE.md) and
[contracts](docs/V1_CONTRACTS.md).

## What works today

**Project Brain** provides project-scoped FTS5 retrieval with provenance,
Git revision/hash binding, snapshot invalidation and source revalidation.
[Brain scope](docs/STAGE3A.md)

**Context Builder** ranks and deduplicates selected evidence, applies a bounded
budget, preserves provenance through permitted compaction, and creates immutable
packages. Its deterministic byte proxy is distinct from actual model tokens.
[Context scope](docs/STAGE3B.md)

**ResourceController** supports durable reservation, dispatch and settlement,
shared quota pools, budgets, eligibility, recovery and transactional events.
Uncertain post-dispatch usage remains a liability; it is not recorded as zero.
[Resource core](docs/STAGE2.md)

**Provider adapters** implement accepted Ollama, Groq and Gemini execution paths.
Cloud probes use explicit permits and public/redacted payloads. Accepted probe
history is not reusable account authorization or unlimited available quota.
[Ollama](docs/STAGE3C.md) В· [Groq](docs/STAGE3D.md) В· [Gemini](docs/STAGE3E_FOLLOWUP.md)

**Unified delegation** exposes `devhub_delegate` for bounded summarize, explain
and extract tasks, with trusted provider configuration, privacy checks, structured
output, supplied-source citation checks and compact handoff. A real local
Codex-to-Ollama unified execution/accounting proof has passed. Citation identity
validation does not prove that a claim is semantically supported.
[Delegation contract](docs/STAGE3F.md)

**Benchmark infrastructure** preserves 12 frozen fixtures and reviewer oracles,
independent A/B packets, artifact hashes, null unknown metrics and a blind review
protocol. The launcher/evaluator isolation design uses separate Linux OCI guests;
its final runtime qualification is unfinished. Real sessions and evaluation have
not started. [Harness](docs/STAGE3G-A.md) В· [Protocol and launcher](docs/STAGE3G-B.md)

## What makes it different

These are differences in scope, not claims about every gateway implementation.

| Typical AI gateway focus | DevFabric focus |
| --- | --- |
| Routes prompts to models | Agent в†’ context в†’ policy в†’ provider delegation |
| Stateless request handling | Shared Project Brain |
| Provider switching | Deterministic eligibility and resource control |
| Retry/fallback handling | Explicit post-dispatch rules |
| Provider-centric abstraction | Agent + context + policy + provider architecture |
| Per-client context | Reusable project context |
| Quality assumptions | Frozen benchmark and evidence approach |
| One frontend | Designed for multiple coding-agent clients |

## Security and accounting principles

- `local_only` and `project_private` tasks cannot route to cloud. Cloud use needs
  explicit eligibility and a separately approved public/redacted export.
- Unknown capability or eligibility fails closed. Catalog evidence is not runtime
  authorization or a measurement of remaining quota.
- Paid execution is disabled by default; this path has no automatic paid fallback.
- Ambiguous execution retains `unknown_usage`; no automatic cross-provider retry
  follows dispatch. Request replay protection uses durable state.
- A SQLite path is a storage location, not accounting authority. Normal startup
  requires the exact immutable [ledger identity](docs/LEDGER_IDENTITY.md).
- Source provenance is preserved and revalidated. Secrets stay outside request
  DTOs, repository config and evidence.
- Tool exposure is minimized. Exact tool origin, schema and retained runtime
  authority are currently being qualified for the benchmark executor.
- The isolation design keeps accounting state, reviewer oracles and other arms'
  outputs outside guest execution. Final intended-host qualification is pending.

See [security design](docs/SECURITY.md) and [runtime qualification](docs/STAGE3G-C.md).

## Current milestone

Validate the real Codex в†” DevFabric execution boundary before the paired benchmark:

- Arm A exposes no delegated tools.
- Arm B exposes only the reviewed `devhub_delegate` capability.
- Tool identity, origin and schema remain bound to the exact admitted runtime.
- Benchmark execution is isolated in Linux/OCI with a qualified host and preflight.

**`execution_ready = false`**. Stage 3G remains open. No real paired benchmark
has run, and passing integration tests does not establish quality or savings.

## Development quick start

Requires **Python 3.12** and **uv**. From the repository root:

```sh
uv sync --locked
uv run --locked devhub validate-config --config config/offline.toml
uv run --locked pytest -q
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy
uv run --locked python scripts/check_evidence.py
```

The default MCP server is offline/status-only and performs no inference:

```sh
uv run --locked devhub serve --transport stdio --config config/offline.toml
```

A configured MCP client consumes its stdio protocol. This is not the delegation
server. For the separate, opt-in `devhub_delegate` server and trusted project,
state-root and provider configuration, follow the [delegation runbook](docs/STAGE3F.md).
Do not reset existing accounting state or reuse consumed cloud permits.

One-command production startup is not implemented. Model installation, live
provider probes and benchmark execution are not part of this quick start.
Normal CI runs Linux full plus Windows smoke; full Windows remains a stage-close
and platform-change gate. See [CI policy](docs/CI.md).

## Next steps

1. Bind the qualified production host executable into the exact runtime image.
2. Qualify the intended Linux execution host and fixed same-environment receipts.
3. Complete an all-green, reviewed qualification manifest.
4. Run one separately approved paired rehearsal.
5. Run the 24 frozen A/B sessions under the reviewed protocol.
6. Review raw quality, latency, resource use and correction requirements.
7. Publish Delegation Value conclusions only where the evidence supports them.

Future research includes Agent Adapters for Cursor and Claude, additional providers,
optional integration with the
separate AI Platform project, improved retrieval, reversible context compression,
and reviewed observer/strategy proposals. These are research directions, not
installed components. See the [research catalog](docs/catalog/README.md).

## Repository map

| Path | Purpose |
| --- | --- |
| `src/devhub/` | MCP contracts, context, resource core, adapters and benchmark tooling |
| `benchmarks/` | Frozen fixtures, separate reviewer oracles and experiment configuration |
| `config/`, `schemas/` | Offline configuration and exported contracts |
| `docs/` | Architecture, stage runbooks, security and research decisions |
| `docs/evidence/` | Machine-readable qualification receipts and historical evidence |
| `scripts/` | Validation, synthetic probes and pinned-source proof tooling |
| `tests/` | Offline and platform-specific regression tests |

## Evidence and contributions

This project separates **implementation**, **qualification evidence** and
**benchmark claims**. Detailed engineering records belong in [docs](docs/) and
[evidence](docs/evidence/); frozen inputs live in [benchmarks](benchmarks/).
Unknown measurements remain null. A successful transport/accounting integration
is not automatically a successful task or a quality benchmark.

The project is under active development, currently focused on Stage 3G runtime
qualification. Changes should preserve frozen fixture/oracle bytes, evidence
history, privacy rules and accounting semantics. Discuss major architectural
changes before implementation. Keep this overview current using the
[README maintenance policy](docs/CI.md#readme-maintenance).

### Optional task usage footer

Trusted delegation config supports `telemetry_footer: off | compact | verbose`
(default `off`). It reports observed task usage without changing routing or accounting:
`DF task: Codex unknown | delegated 724 | saving unknown | 16.3s | API $0.00`.
This illustrative demo rendering is not a savings or semantic-quality claim.
See [usage scope, evidence and configuration](docs/USAGE_FOOTER.md).
