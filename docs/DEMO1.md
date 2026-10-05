# Local demo: Codex в†’ DevFabric в†’ Ollama

This is a product demo, not a Stage 3G rehearsal or benchmark. Current transport
is Python MCP stdio. There is no DevFabric HTTP daemon, localhost:4000 service,
web UI, Docker Compose deployment or production installer.

## 1. Prepare dependencies and model

Install Python 3.12, uv, Ollama and an authenticated Codex client. Clone this repo
and run `uv sync --locked` from its root. Start your existing Ollama app/service
(or `ollama serve` if no daemon is running); do not start a second daemon.

```sh
ollama --version
ollama list
```

The example pins `qwen2.5:14b-instruct` with manifest digest
`7cdf5a0187d5c58cc5d369b255592f7841d1c4696d45a8c8a9489440385b22f6`.
Reviewed versions are **0.34.2** (historical) and **0.35.0** (local compatibility).
The configured version must match exactly; the default example uses 0.35.0.
The tokenizer must also match the supported Qwen2 metadata/template contract.
A different model or digest requires review, not silently copying the observed
value into the allowlist. No automatic download, pull or update is performed.
If this model is absent, stop and arrange installation separately.

## 2. Copy and review local configuration

These commands work in PowerShell and POSIX shells with the same Python/uv setup:

```sh
uv run --locked python -c "from pathlib import Path; p=Path('.devhub'); p.mkdir(exist_ok=True); (p/'local.json').open('x').write(Path('config/devfabric-local.example.json').read_text())"
uv run --locked python -c "from pathlib import Path; from devhub.delegate import DelegationConfig; DelegationConfig.model_validate_json(Path('.devhub/local.json').read_text()); print('Config valid')"
uv run --locked python -c "from pathlib import Path; from devhub.delegate import DelegationConfig; from devhub.ollama import OllamaAdapter; c=DelegationConfig.model_validate_json(Path('.devhub/local.json').read_text()); e,_=OllamaAdapter(c.profiles[0].config.ollama).inspect(); print(e.model_dump_json(indent=2))"
```

Review the copied `ledger_identity`. For a new durable authority, replace the demo
`instance_id` with a freshly generated 32-character lowercase hexadecimal value,
then initialize it exactly once:

```sh
uv run --locked python -c "import secrets; print(secrets.token_hex(16))"
uv run --locked python -m devhub.delegate_server --config .devhub/local.json --initialize-ledger
```

Normal server startup will not create a replacement database when `state_root`
changes. A pre-identity historical ledger is rejected pending a separately reviewed
adoption operation; do not delete it or treat another path as a reset.

The last command performs local metadata checks (`version`, `tags`, `show`),
including exact digest/version and tokenizer checks; **no inference**. Copy refuses
to overwrite existing config. There is no variable or tilde expansion in JSON.
All relative paths resolve from the MCP process **working directory**, not the
config file directory. Run from the repository root.

The example exposes only `src/devhub/output.py` to Brain and uses a sibling
`../devfabric-state` for durable state. The root must be a Git checkout, and approved
files must be tracked. For another project, set an explicit root, project ID and
reviewed file allowlist. Reuse its established state/ledger; never reset state,
change request keys to retry ambiguous work, or create a replacement ledger to
bypass a hold. State must remain outside the project; never commit it.

Only Ollama is configured. Cloud is disabled and no paid adapter is available.
Groq/Gemini support exists separately; this example does not check their credentials
or claim current availability. Generation requires separate authorization.

## 3. Start stdio / connect Codex

Canonical server command from the repository root:

```sh
uv run --locked python -m devhub.delegate_server --config .devhub/local.json
```

This waits for MCP input; it is not a shell prompt or HTTP listener. Stop a manual
test with Ctrl+C. Normally **Codex launches this process itself**; do not separately
leave another server running. One configured server serves one project/state scope.

Copy the following into your Codex `config.toml`, substituting your checkout's
absolute path for `REPO_ROOT`. On Windows use forward slashes in the TOML path.
`uv` must be on the Codex process PATH (otherwise use its absolute executable path).

```toml
[mcp_servers.devhub_delegate]
command = "uv"
args = ["run", "--locked", "python", "-m", "devhub.delegate_server", "--config", ".devhub/local.json"]
cwd = "REPO_ROOT"
enabled_tools = ["devhub_delegate"]
startup_timeout_sec = 30
tool_timeout_sec = 150
```

This is a stdio configuration, with no URL or credentials. It uses the existing
`devhub_delegate` server key and tool. See the [official Codex MCP configuration](https://developers.openai.com/codex/mcp).
Restart the Codex session, open this checkout, and inspect `/mcp` / the client tools
panel. Approve this reviewed local tool if your client asks. Do not globally disable
approval. Client tool-exposure behavior depends on version/configuration; a registered
server is not proof the tool is usable. If absent, stop and report the client version
and MCP diagnostic; do not alter Stage 3G router/protocol settings to work around it.

The separate `devhub_status` tool belongs to the offline/status server. It is not
an aggregated live health check for this delegation server. Metadata inspection
above plus the returned handoff are the current demo status surfaces.

## 4. Ask one bounded task

Use [the exact task JSON](../config/devfabric-demo-task.json), or ask Codex:

> Use devhub_delegate once with config/devfabric-demo-task.json as its arguments.
> Explain why valid JSON containing a fabricated citation is rejected by
> src/devhub/output.py. Identify the function, a concise caller fix plan and
> supplied-source citations. Do not edit code. Report the returned execution,
> output/citation validation, route selection, tokens, latency and accounting
> reference. Do not retry a failed or ambiguous delegation or use cloud providers.

This is `task_class=explain`, `privacy=local_only`, `allow_cloud=false`. The tool
supports summarize/explain/extract, not code editing. The task key is deliberately
stable: repeating it is denied by the ledger. A genuinely new task needs a new key.
Do not change it merely to obtain a better demo result.

## 5. Inspect the handoff and accounting

The MCP result includes `provider`, `model`, `selection` (candidate eligibility
trace, not a quality ranking), `reason`, `actual_input_tokens`,
`actual_output_tokens`, `latency_ms`, `accounting_reference`, `accounting`,
`output_validation`, `citations_validation`, `retries` and `fallback`.
Privacy comes from the request; count delegate calls in the Codex tool trace.
No combined status daemon is implied.

The ledger persists reservations and transactional outbox events at
`../devfabric-state/ledger.db`; packages with source provenance are under the same
state root's `packages/`. Inspect a reservation with a SQLite viewer opened read-only:

```sql
SELECT state FROM reservations WHERE id = '<accounting_reference>';
SELECT payload FROM events WHERE reservation = '<accounting_reference>' ORDER BY sequence;
```

Never modify or acknowledge these rows just to inspect them. A successful flow has
`reserved в†’ dispatched в†’ settled`. Schema/citation failure can still be settled;
`unknown_usage` must remain unresolved liability, not be relabeled success or zero.
The package maps `s1` etc. to source provenance. Citation validation checks identity,
not whether a claim is actually correct.

Illustrative shape, **not guaranteed model output or token counts**:

```text
Developer: Explain the fabricated-citation rejection and cite the supplied source.
Codex: delegates one bounded explanation
DevFabric: provider=ollama model=qwen2.5:14b-instruct privacy=local_only
           delegate_calls=1 retries=0 fallback=false
Result: completed/validated; output_validation=passed; citations_validation=passed
Accounting: reserved в†’ dispatched в†’ settled
Tokens/latency: actual values in the handoff (vary by run)
Semantic quality: not automatically established
```

Failures are evidence too: preserve the returned status. Do not retry, reset state,
weaken version/digest checks, pull a model or fall back to cloud automatically.
Demo evidence is separate from the frozen benchmark and makes no savings/value claim.

## Recorded local smoke

On 2026-10-04, Codex CLI `0.158.0-alpha.2.1` used the normal stdio server with
Ollama `0.35.0` and the pinned model digest. [Demo evidence](evidence/devfabric-demo1.json)
records one call: 647 input / 77 output tokens, 16,264 ms provider latency,
validated output/citation `s1`, and reserved → dispatched → settled.
These are one-run observations, not guarantees. The returned explanation omitted
the requested caller fix plan; semantic quality remains null. No rerun/tuning,
cloud generation or model pull was performed. The existing local ledger was reused.
The smoke supplied explicit approval for this single reviewed tool; ordinary
interactive users can approve it in the Codex UI. No global approval bypass.
