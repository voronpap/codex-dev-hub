# Stage 3G-C: observed ToolMode; full router build blocked

PR #30 merged as UNKNOWN feasibility/design evidence. This investigation is
limited to service-default ToolMode and actual pinned ToolRouter/origin behavior.
No production host, protocol v3, rehearsal or benchmark was created.

## Observation and exact derivation

The historical filtered metadata did not retain tool_mode, so one newly authorized
metadata-only GET was performed on 2026-10-01 at 17:29:19 UTC:
`https://chatgpt.com/backend-api/codex/models?client_version=0.155.0`.
HTTP 200, retries 0. Only selected tool-relevant fields and the selection candidates
were retained; no full response, account identity or auth material was saved.
This is one new request (two models-metadata requests including prior history).
No request is repeated by the committed scripts or CI.

Pinned stable priority/default selection again chooses `gpt-6-astra`:

| Field | Observed |
| --- | --- |
| priority / visibility | 2 / list |
| tool_mode | `code_mode_only`, explicitly present |
| apply_patch_tool_type | freeform |
| shell_type | shell_command |
| supports_search_tool | true |
| use_responses_lite | true |

Pinned ModelInfo uses the exact field `tool_mode: Option<ToolMode>`. Serde defaults
an omitted field to None; null also yields None. The custom selector maps unknown
string variants to None. Known enum values are snake_case `direct`, `code_mode`,
`code_mode_only`. This observation is a known, present value, so no omission or
feature-based inference is necessary.

`requested_tool_mode()` first uses model_info.tool_mode; only None falls back to
CodeModeOnly/CodeMode feature flags, then Direct. `effective_tool_mode()` falls
back to Direct only for requested **CodeMode**, unavailable code-mode runtime
and enabled in-process fallback. It does not downgrade CodeModeOnly.
Thus the observed model resolves exactly to **CodeModeOnly**, regardless of those
feature fallback flags. [Pinned source evidence](evidence/stage3g-full-router/source-bindings.json)
binds the schema, selection and derivation methods by full-file hash and excerpt.
This is source-derived mode evidence, not execution of a real model or full router.

## Actual-code test attempt

`scripts/build_full_router_proof.py` downloads the exact source archive for
`4607249e430dac1c961df4dc615beae88e33cec8`, verifies archive SHA-256, and extracts
it into a new disposable build directory. It appends only a unit test to the
upstream test module and adds its filtered metadata fixture. No Codex production
source, dependency manifest, lockfile or release binary is patched.

The test uses upstream synthetic TurnContext/MCP helpers and actual
ToolRegistry / ToolRouter::from_registry / finalize_tool_router. It sets the
observed model fields and frozen feature controls, with dummy ChatGPT auth.
The frozen requested unified_exec=false resolves true under accepted managed
normalization; shell_tool remains false. No tool-mode forcing or wrapper
allowlisting is added. The planned binary runs in an isolated network namespace
and drops back to runner UID before tests; compilation may fetch locked build
dependencies, not model requests.

The test covers A empty ceiling/no MCP; B exact
`ToolName::namespaced("mcp__devhub_delegate", "devhub_delegate")`; excluded late
builtin/extension/dynamic/wrong-namespace candidates; an adversarial hosted web
spec; and wrong-origin-first canonical collision. These are **unexecuted test
cases**, not passing evidence. The upstream production code has not been compiled
successfully by this attempt.

## Build blocker and honest nulls

Both build attempts stopped at dependency resolution with exit 101:

```text
cannot update the lock file .../codex-rs/Cargo.lock
because --locked was passed to prevent this
```

The source-pinned toolchain 1.95.0 was installed by rustup. The lockfile exists
upstream (409390 bytes, SHA-256
`7bb060a9b67a22503f9d15030c22122fea38623be9077d44cbadb919896a4146`).
Why resolution requires a lock change has not been established. We did not remove
`--locked`, regenerate dependencies, change compiler/source pin or substitute a
method-slice proof. The second attempt used corrected synthetic ChatGPT auth in
the test; it stopped at the same earlier build gate.

[Build failure](evidence/stage3g-full-router/build-failure.json) and
[result](evidence/stage3g-full-router/result.json) retain that distinction:

| Required observation | Result |
| --- | --- |
| A registered/visible/code-mode/hosted sets | null |
| B registered/visible/code-mode sets | null |
| Exact visible B surface | null |
| Origin verified / collision result | null / null |
| Actual pinned router successfully executed | null; test executions 0 |
| Method-slice substituted | false |
| Classification | **UNKNOWN** |

Pinned visibility source suggests a CodeModeOnly nested delegate will be hidden
without exec/wait, but this is not promoted to ROUTER_BLOCKED_TOOL_MODE without
the requested actual full-router proof. The name-only registration/collision
source likewise motivates origin binding, not a claimed successful provenance
test. A future candidate must bind server key, raw tool name, canonical name and
accepted MCP process/config before task exposure; first-registrant identity alone
is insufficient. No production origin guard is implemented in this PR.

## Preserved boundaries and review

The existing absence gate remains unchanged and failing. No effects policy is
accepted. No Direct override, exec/wait expansion, app-server injection search,
wrapper implementation, speculative hashes or v3. Protocol/config, fixture/oracle
bytes and historical evidence remain unchanged. Docker/WSL, Ollama endpoint and
ledger were not changed; intended host remains unqualified.

Stage 3G-C OPEN; Stage 3G OPEN; execution_ready=false. inference_requests=0,
real_codex_executions=0, provider_sends=0. Semantic acceptance, quality, savings,
Delegation Value and internal Codex retries remain null. STOP for review of the
build blocker; the full-router requirement is unmet.
