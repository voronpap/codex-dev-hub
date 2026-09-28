# Stage 1 verification record

Date: 2026-09-28. Scope: offline skeleton. No cloud adapter or paid API call.

| Check | Observed result |
|---|---|
| Windows Python 3.12.10 | 19 skeleton tests pass (config, schema, fake, MCP); Ruff and mypy pass |
| WSL Ubuntu 24.04, Python 3.12.3 | Same 19 skeleton tests pass using an independent Linux environment |
| Actual Codex CLI 0.155.0-alpha.9.2 | One successful devhub_status call; offline_stage1; fake resource non-routable |
| SDK client against subprocess | Initialize/discover/call succeeds with MCP 2.2.0 |
| Invalid config/request | Unknown config keys/types fail startup; extra MCP arguments rejected with -32602 |
| Project boundary | Unregistered project denied; status does not disclose filesystem roots |
| Dependencies | uv.lock frozen; direct versions and GitHub Action revisions pinned |
| Published schemas | Generated JSON matches domain models; schema examples validate |

The Windows/WSL full working-tree runs also included three baseline-packet tests
from the separate fixture review slice (22 total). Those tests validate data
integrity/preparation, not model quality. Linux/Windows hosted CI is defined in
the PR; its status is tracked by the PR checks, not inferred from these local runs.

[Sanitized Codex smoke evidence](evidence/stage1-codex-smoke.json) contains only the
tool name, arguments and relevant observed fields, excluding host paths and
session identifiers. The test used per-invocation configuration with normal Codex
authentication. It did not change persistent MCP settings or use a Dev Hub API key.

The CLI emitted turn usage for this smoke test, but that does not establish
Desktop-wide measurement or a paired baseline. No A/B benchmark was run, no
Delegation Value calculated, and no savings inferred. All future benchmark
measurements without evidence remain null/proxy.

Scope limitations: only status is exposed, fake output is synthetic, capability
ports are a Stage 1 subset, single local-user stdio only. Resource admission,
routers, real inference, research and sandbox are later gated stages.
