# Stage 3G-C Router Fix investigation

PR #31 was merged as actual pinned router blocker proof, merge commit
`dd348d9e166ee999942534e0b37ff10976a0f0ec`. Its accepted result remains
`ROUTER_BLOCKED_BOTH`; failed builds, stale-lock diagnosis, original/derived lock
hashes, actual output and cancelled non-proof runs remain historical evidence.

This investigation does not change the production Codex binary, benchmark
executor, v1/v2 protocols, fixtures/oracles, plan hashes or session IDs. There is no
v3 or production host wrapper. execution_ready=false regardless of the design
proof outcome. Stage 3G-C and Stage 3G remain OPEN.

## Exact cause and supported visibility mechanism

Source remains `4607249e430dac1c961df4dc615beae88e33cec8`, CLI
`0.155.0-alpha.9.2`. Existing observed service-default metadata remains
`gpt-6-astra`, `tool_mode=code_mode_only`. No metadata refresh or model request.

The exact path is:

1. MCP metadata preserves the trusted connection/server key and raw tool name;
   separate callable namespace/name fields form canonical ToolName. Sanitization
   and collision disambiguation do not authenticate an origin.
2. McpHandler constructs its schema and runtime from ToolInfo. Dispatch prepares
   the call using `tool_info.server_name` and `tool_info.tool.name`, not a parsed
   display name. ToolRegistry's AllowedTools predicate only matches canonical name.
3. finalize_tool_router first filters hosted specs, then applies configured
   `code_mode.direct_only_tool_namespaces` overrides, then computes effective mode.
4. register_code_mode_executors maps runtimes whose exposure is available in code
   mode and tries to prepend `exec`/`wait`. The frozen AllowedTools ceiling excludes
   both host entry points. A nonempty nested map alone gives no model-visible API.
5. build_model_visible_specs applies is_hidden_by_code_mode_only: CodeModeOnly +
   exposure available in code mode + nested name hides the tool. Hence #31's mapped
   MCP delegate was intentionally hidden, not absent from the registry.
6. **DirectModelOnly** is a supported per-tool exposure, distinct from global
   ToolMode::Direct. The namespace override sets this exposure before mapping.
   It remains model-visible under CodeModeOnly and is excluded from the nested map.
   The existing upstream dynamic-namespace test independently documents this path.

Exact file hashes and numbered excerpts covering all these boundaries are in
`docs/evidence/stage3g-router-fix/source-bindings.json`. The code-mode-host process
is an execution backend for code-mode sessions; making it available does not
bypass the visible-spec predicate or the AllowedTools exclusion of exec/wait.

## Candidate comparison

| Candidate | Model-visible surface | Origin guarantee | Security/protocol impact | Production work / comparability |
| --- | --- | --- | --- | --- |
| A: standard code-mode host bridge | exec/wait abstraction over nested delegate | Still needs trusted MCP binding | Violates current no-exec/no-wait ceiling; a general code entry point is broader than one operation | Not selected; host provisioning and new protocol needed, larger comparability change |
| **B: explicit single-tool exposure** | Exactly the namespaced devhub_delegate function via DirectModelOnly; global mode stays CodeModeOnly | Typed trusted-channel ingress, raw/canonical/server match, exact runtime seal, fatal collisions | Existing namespace config plus exact allowlist; no additional API, nested map empty | **Selected for synthetic proof**. Visibility needs no upstream patch. Shipping origin-hook integration and AllowedTools host API still require review; no production integration claimed |
| C: narrow host-owned delegate wrapper | One new delegate operation, explicitly DirectModelOnly | Host owns closure and fixed MCP binding; still must exclude competing registrations | Can fit ceiling, but introduces a second schema/dispatch layer and wrapper identity | Not implemented; requires wrapper/parity and protocol review, changes task-facing API more than B |
| D: global Direct override (control only) | Direct tool specs after allowlist filtering | Does not itself solve origin | Alters global mode/other surface behavior; current metadata takes precedence over feature flags | Not activated; may need model-info override, greatest comparability concern |

A custom code-mode bridge with only one operation becomes Candidate C rather than
the standard exec/wait code-mode host. No additional shell, exec, wait, web, apps,
diagnostic MCP, hosted or dynamic extension capability is permitted.

## Candidate B origin boundary

The test-local prototype is deliberately explicit; it is not an existing upstream
origin-aware AllowedTools feature or a production security claim.

`devhub_fix_admit` receives a trusted connection key separately from ToolInfo.
It requires Arm B, channel `devhub_delegate`, matching server key, exact raw
operation `devhub_delegate`, and exact canonical namespace/name. It constructs a
concrete pinned McpHandler itself; it never accepts a caller-provided executable.
It retains the accepted Arc as the approved runtime identity.

Before finalization, `devhub_fix_origin_seal` requires either an empty A registry
or exactly that approved B runtime object, matching canonical name and server,
and no collision. A same-name object that merely reports the expected server is
insufficient. The existing `tool_registry.error_on_tool_collisions=true` makes
finalization fail on a bypassed wrong-first/approved-second duplicate, rather than
just logging it. This flag alone is insufficient for wrong-origin-only input; the
ingress/seal is required.

The trust assumption is that only reviewed host code supplies the connection key
and builds ToolInfo from the approved MCP connection/config. A forged host or a
compromised approved server is outside this unit proof. `server_origin` metadata is
not treated as cryptographic provenance. Future production integration must bind
the actual MCP process/config and schema identity, enforce this boundary on every
router rebuild/refresh and retain the approved dispatch binding. It must not let
arbitrary extension code supply approved runtimes or swap the connection after
validation. Those integration and runtime/TOCTOU gates remain unproven here.

Private CoreToolRuntime/registry plumbing is accessible to this appended unit
test. The public production-host integration point for the seal is not established
by that access; it may require a narrowly reviewed core hook. No upstream
production file is patched in this investigation.

## Actual-code proof plan

`scripts/router_fix_test.rs` is appended only to the pinned unit-test module in a
disposable source tree. The accepted LOCK_B transformer changes only the 152
manifest-required local package versions; no broad regeneration. Compilation keeps
`--locked`. Test execution uses a separate network namespace, dummy auth and no MCP
process, inference or model task.

The test exercises actual pinned core source planning, ToolRegistry, McpHandler,
finalize_tool_router, exposure overrides, visible schema generation and code-mode
mapping. Test-local origin admission/seal logic is identified separately.

Required assertions:

- A: empty registered/visible/nested-map/hosted surfaces even with the namespace override.
- B: one namespace with one devhub_delegate function, exact runtime identity,
  DirectModelOnly exposure, effective CodeModeOnly, empty nested map/hosted specs.
- Wrong-origin first is rejected before admission; approved second can register.
- Spoofed server metadata on a wrong trusted channel, different raw tool name and
  namespace alias are rejected.
- If a wrong-first registration bypasses ingress, the seal rejects it; adding an
  approved duplicate makes actual finalization fail.
- A separate forged runtime claiming the correct server cannot satisfy the seal.
- Core runtimes, extra same-namespace MCP diagnostic tool, deferred extension,
  dynamic tool and adversarial hosted web spec cannot widen the ceiling.

Until actual compilation and assertions succeed the outcome is UNKNOWN, not
ROUTER_FIX_FEASIBLE. A successful proof would establish feasibility of this narrow
composition only; it would not qualify an executor or close Stage 3G-C.

## Build budget and validation

The expensive workflow uses relevant **push** paths rather than PR-wide paths:
GitHub PR path filtering includes the entire PR diff and previously reran proof
on later docs-only commits. Push paths select the candidate test, proof builder,
derived-lock transformer, exact metadata input and proof workflow. One branch
concurrency group cancels superseded runs. Docs/evidence-only follow-ups do not
start another Rust build. Manual dispatch remains available when explicitly needed.

Normal validation is Linux full + Windows smoke, Ruff, formatting, strict mypy and
secret/history/evidence scans. Full Windows is not required for this open-stage
investigation. The old runtime qualification gate remains unchanged and failing.
No cross-host qualification or benchmark results are assembled from this proof.

All real_codex_executions and provider_sends remain zero. Semantic acceptance,
quality benchmark, Delegation Value, savings and Codex internal retries stay null.
STOP for review after recording the actual result, even if feasible.
