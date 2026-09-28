# Stage 1: offline executable proof

Scope: local skeleton, MCP status, DTO/config/schema and an explicitly synthetic
fake adapter. Cloud providers, routing, resource accounting, Project Brain,
research, sandbox and paid execution are not implemented by this stage.

## Run

Requires Python 3.12 and uv 0.12.10. Install the exact dependency resolution:

```sh
uv sync --locked
uv run --locked --offline devhub validate-config --config config/offline.toml
uv run --locked --offline devhub serve --transport stdio --config config/offline.toml
```

The server waits for MCP input; it is not an interactive shell. Only
`devhub_status` is discoverable. Example arguments: `{"schema_version":1,
"project_id":"devhub"}`. Omit project_id for the locally registered project list.
Unknown project IDs are denied. No repository files are retrieved or indexed.

The default fake resource is test-only and non-routable. It reports no measured
model tokens or cost. Disable it with `[fake] enabled = false` for an empty resource
list. Configurable context/summary policy defaults remain 8,000/1,500; no model call
exists to consume these budgets yet. Provider configuration, paid mode, unknown
keys, coercible wrong types and unsupported transports fail closed.

This is a strict Stage 1 subset of [V1 contracts](V1_CONTRACTS.md), not a claim that
all future DTOs or six tools are implemented. DTOs never import MCP types. The
ProviderAdapter test port deliberately lacks admission tickets until Stage 2;
the ToolAdapter capability port has no Tavily-specific request/response types.
Runtime startup reads trusted TOML, validates root directories, and starts stdio.
No SQLite DB, secret lookup, package download or local model loading occurs.

## Codex connection

Use an absolute path to the installed `devhub` executable and config. For Windows,
the executable is `.venv/Scripts/devhub.exe`; Linux/WSL uses `.venv/bin/devhub`.
Do not share the same virtual environment between Windows and WSL.

```toml
[mcp_servers.devhub]
command = "/absolute/path/to/.venv/bin/devhub"
args = ["serve", "--config", "/absolute/path/to/config/offline.toml"]
```

Host configuration is not modified by the repository or tests. A temporary
single-run CLI override can perform a Codex smoke test; it uses Codex's normal
authentication, not any Dev Hub provider credential. Connection configuration:
[official Codex MCP documentation](https://learn.chatgpt.com/docs/extend/mcp?surface=cli).

## Verification

```sh
uv run --locked --offline ruff check .
uv run --locked --offline ruff format --check .
uv run --locked --offline mypy
uv run --locked --offline pytest -q
uv run --locked --offline python scripts/export_schemas.py
git diff --exit-code -- schemas/stage1.json
```

Tests cover strict config, safe startup failure, secret canaries, canonical project
root resolution, project access, schema publication, real subprocess stdio
discovery/call, unavailable tools and network-denied fake/status paths. SDK v2
function argument handling ignores extra fields by default; a narrow middleware
validates the raw StatusRequest and publishes that exact strict schema.

The CI workflow runs on Linux and Windows after locked installation with no
provider secrets. Exact action revisions and uv version are pinned. WSL smoke
is a separate local environment check, not equivalent to every Linux host.

## Dependencies and license evidence

[STAGE1_DEPENDENCIES.json](STAGE1_DEPENDENCIES.json) records installed Windows
runtime/test transitive package versions and declared license metadata. Generate
with `uv run python scripts/dependency_inventory.py`; Linux omits Windows-only
packages. `uv.lock` is the reproducible multi-platform resolution with hashes.
Build backend hatchling is pinned separately in pyproject.toml. Python, uv and
GitHub Actions are external tooling, not included in that environment inventory.
Missing SPDX expressions remain null; classifiers/installed notices are evidence,
not an invented license. The repository's distribution license remains undecided;
no package publication is part of Stage 1.

## Evidence and remaining work

See [Stage 1 verification record](STAGE1_VERIFICATION.md) for actual checks and
limitations. Baseline packet fixtures are a separate review slice. No A/B quality,
token savings, routing benefit or Delegation Value is claimed from fake responses.
Stage 2 resource implementation is outside this change.
