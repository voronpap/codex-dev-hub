# Codex Dev Hub

Codex-first AI development hub for controlled delegation across local and cloud
models, with shared project context, deterministic resource policy, and auditable execution.

- **Codex stays in control:** delegate bounded tasks through one MCP contract.
- **Local-first, free-first intent:** approved providers, explicit eligibility, no paid fallback.
- **Shared project context:** Git-backed retrieval and selective context packages.
- **Durable accounting:** reserve before dispatch; preserve uncertainty after ambiguous sends.
- **Explicit boundaries:** project isolation, reviewed cloud export, and minimal tool exposure.

**Active development. Execution-boundary qualification is in progress.**
The paired benchmark has not run; semantic quality, savings and Delegation Value
are not yet established. This is not a production-ready release.

## Why this exists

As coding workflows add model clients and tools, context can be duplicated,
local/cloud choices can become implicit, and retries can obscure what actually ran.
A successful model call also says little about whether delegation helped the developer.

Dev Hub keeps Codex as the orchestrator and puts delegation behind explicit context,
privacy, capability and resource rules. It combines Project Brain, Context Builder,
Capability Registry, deterministic Router, ResourceController and provider adapters.
A frozen paired benchmark is the next step toward measuring usefulness.

The scope extends beyond a provider proxy or model frontend: Dev Hub manages the
project evidence and execution/accounting boundary around a delegated task.
It does not replace Codex or require a separate coding-agent UI.

## Project status

“Complete” below means the accepted implementation and its scoped gate are complete;
it does not establish general task quality or full production qualification.

| Area | Status |
| --- | --- |
| Core architecture and offline runtime | Complete |
| Project Brain and Context Builder | Complete |
| ResourceController and durable accounting | Complete |
| Ollama local execution/delegation | Complete |
| Groq and Gemini adapters | Complete — scoped execution/accounting gates |
| Unified `devhub_delegate` | Complete — local unified delegation gate passed |
| Frozen benchmark harness | Complete — offline harness accepted |
| Execution boundary and isolated runtime qualification | In progress |
| Real paired delegation benchmark | Not run |

See [accepted milestones](docs/STAGES.md), [unified delegation](docs/STAGE3F.md)
and the [offline benchmark harness](docs/STAGE3G-A.md) for scope and evidence.

## Architecture

```text
Codex — orchestrator
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
[Ollama](docs/STAGE3C.md) · [Groq](docs/STAGE3D.md) · [Gemini](docs/STAGE3E_FOLLOWUP.md)

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
not started. [Harness](docs/STAGE3G-A.md) · [Protocol and launcher](docs/STAGE3G-B.md)

## What makes it different

These are differences in scope, not claims about every gateway implementation.

| Gateway-oriented concern | Dev Hub focus |
| --- | --- |
| Provider request forwarding | Codex-controlled task delegation |
| Prompt routing | Shared Brain and selective Context Builder |
| Fallback configuration | Deterministic eligibility and resource admission |
| Retry handling | No automatic retry after ambiguous dispatch |
| Provider abstraction | Provider, privacy, quota and budget authority |
| Model availability | Frozen paired experiments before quality claims |
| Tool configuration | Explicit admission/origin boundary under qualification |

## Security and accounting principles

- `local_only` and `project_private` tasks cannot route to cloud. Cloud use needs
  explicit eligibility and a separately approved public/redacted export.
- Unknown capability or eligibility fails closed. Catalog evidence is not runtime
  authorization or a measurement of remaining quota.
- Paid execution is disabled by default; this path has no automatic paid fallback.
- Ambiguous execution retains `unknown_usage`; no automatic cross-provider retry
  follows dispatch. Request replay protection uses durable state.
- Source provenance is preserved and revalidated. Secrets stay outside request
  DTOs, repository config and evidence.
- Tool exposure is minimized. Exact tool origin, schema and retained runtime
  authority are currently being qualified for the benchmark executor.
- The isolation design keeps accounting state, reviewer oracles and other arms'
  outputs outside guest execution. Final intended-host qualification is pending.

See [security design](docs/SECURITY.md) and [runtime qualification](docs/STAGE3G-C.md).

## Current milestone

Validate the real Codex ↔ Dev Hub execution boundary before the paired benchmark:

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

1. Finish execution/admission proof.
2. Qualify the intended Linux execution host.
3. Complete an all-green, reviewed preflight.
4. Run one separately approved paired rehearsal.
5. Run the 24 frozen A/B sessions under the reviewed protocol.
6. Review raw quality, latency, resource use and correction requirements.
7. Publish Delegation Value conclusions only where the evidence supports them.

Future research includes additional providers, optional integration with the
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
