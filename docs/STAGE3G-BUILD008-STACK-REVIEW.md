# Stage 3G-C: build-008 production-stack review

This review refines the interpretation of build-008 without editing its raw or
historical assessment. It uses only Codex source commit
`4607249e430dac1c961df4dc615beae88e33cec8`. Build-009 is not authorized or run.

## Pinned production stack budget

The pinned source defines `codex_async_utils::THREAD_STACK_SIZE_BYTES` as
`16 * 1024 * 1024`, or **16,777,216 bytes**. `arg0_dispatch_or_else` starts the
regular async entrypoint on an OS thread named `codex-main` with that stack size.
The same module constructs the multi-thread Tokio runtime with
`thread_stack_size(THREAD_STACK_SIZE_BYTES)`.

| Pinned source | Lines | SHA-256 | Finding |
| --- | ---: | --- | --- |
| `codex-rs/async-utils/src/lib.rs` | 5 | `5582ec7e69b8ab0493e62721620099ff0cefe391b58e58165534f8d227ea74f4` | 16 MiB constant |
| `codex-rs/arg0/src/lib.rs` | 233–246 | `476895d5adc6c8c897e53c8ec7a5d49556f9798d1d9a2918168c85f14c1ae5d7` | `codex-main` OS thread uses the constant |
| `codex-rs/arg0/src/lib.rs` | 293–297 | same | Tokio workers use the constant |

No current-upstream source is used for these conclusions.

## Intended Stage 3G CLI mapping

The frozen launcher constructs `codex exec --ephemeral ...`. The locked runtime
image installs the verified release executable as `/usr/local/bin/codex` and uses
`codex` as its entrypoint. In the pinned source, package `codex-cli` declares the
`codex` binary at `cli/src/main.rs`. Its `main()` directly calls
`arg0_dispatch_or_else`, and the `Exec` branch calls `codex_exec::run_main`.

The intended host path is therefore:

```text
Stage 3G launcher
  -> codex exec
  -> codex-cli/src/main.rs::main
  -> arg0_dispatch_or_else
       -> codex-main, 16 MiB
       -> Tokio workers, 16 MiB
  -> codex_exec::run_main
  -> InProcessAppServerClient::start
  -> thread/start
```

Conclusion: **YES**, 16 MiB is representative of the intended Stage 3G Codex CLI
host. This statement is limited to the `codex` CLI entrypoint and its `exec` path;
it does not claim that every auxiliary executable in the workspace uses this path.

Exact binding hashes and line references are in
`evidence/stage3g-approved-call/build-008-production-stack-review.json`.

## Refined build-008 classification

Both observations remain true:

- the ordinary libtest thread stack produced SIGABRT before
  `preparation_closure_entered`, with an initialized empty synthetic receipt;
- the exact same binary and handler filter passed with
  `RUST_MIN_STACK=16777216`, traversed the full handler, produced the exact
  endpoint/raw-tool/schema/payload receipt, and returned successfully.

The pinned production CLI uses the latter stack budget. The review layer records:

```text
diagnostic_stack_sensitivity = STACK_DEPTH_OR_FRAME_SIZE_SENSITIVE
exact_overflow_root_cause = UNKNOWN
libtest_default_stack_representative_of_pinned_production = false
production_stack_budget_bytes = 16777216
handler_dispatch_libtest_default_stack = false
handler_dispatch_production_stack_equivalent = true
same_binary_production_stack_equivalent_handler_dispatch = true
candidate_b_production_defect_from_overflow = NOT_ESTABLISHED
```

This does not identify recursion, a particular frame, or another exact overflow
cause. It does not turn a test executable into process evidence. Build-007 and the
build-008 normal-stack failure remain unchanged.

The reviewed router/security matrix is now PASS except exact process-host
qualification. Handler execution at the pinned production-equivalent stack and
catalog refresh after preparation are PASS. `process_proof` remains null, so
`production_classification` remains UNKNOWN.

## Exact process-proof design

The intended `codex exec` path uses an in-process app-server. The pinned
`InProcessStartArgs` has no field for host-owned `AllowedTools` or
`ApprovedDelegatePolicy`; `thread/start` constructs its own `ExtensionDataInit`
and currently inserts selected capability roots only. Candidate B cannot be
process-qualified by setting another undocumented TOML value or by reconstructing
a router in a test helper.

The next proof should use one actual `codex` executable compiled from the pinned
source plus the unchanged Candidate B patch and one separately reviewed, opt-in
host integration/proof hook:

1. Bind source commit, proof-only lock, Candidate B patch, real schema, synthetic
   server and exact A/B startup configuration before compilation.
2. Add the narrow host-owned admission input at the real `codex exec` ->
   in-process app-server -> `thread/start` boundary. When absent, behavior must be
   byte-for-byte/semantically unchanged. Caller/model input cannot populate it.
3. Start Arm A with no MCP and an empty ceiling. Start Arm B with only the reviewed
   `devhub_delegate` server, exact `AllowedTools`, exact schema, per-tool `Approve`,
   global CodeModeOnly and direct-only namespace `mcp__devhub_delegate`.
4. Before any turn/model request, use a narrow proof-only observation hook on the
   actual finalized host registry. Record tool mode, visible specs, nested map,
   hosted/dynamic surfaces and the admitted origin/schema/generation identity.
5. If the production host can invoke the retained `McpHandler` without a model
   turn, submit one host-originated synthetic `ToolInvocation`. Require the exact
   synthetic MCP receipt and successful completion. Do not invoke a provider.
6. If that invocation cannot be reached without a model request, stop and report
   the missing host observation API. Do not fabricate a model response or replace
   the production host with a wrapper/router helper.

### Required arm results

Arm A must report zero visible tools, zero nested code-mode entries, zero hosted or
dynamic widening, and zero MCP dispatches.

Arm B must report global CodeModeOnly, exactly one visible
`mcp__devhub_delegate.devhub_delegate`, an empty nested code-mode map, no other
MCP/dynamic/hosted tools, the approved schema hash and the exact retained binding.
The host-originated dispatch, if supported, must reach only the synthetic endpoint.

### Required artifacts

- actual `codex` executable and SHA-256;
- source commit/archive, Candidate B patch and build-lock hashes;
- Rust/Cargo versions, target, compile command and duration;
- exact A/B config and config hash;
- schema, payload and synthetic MCP script hashes;
- observation-hook source/hash and default-absent regression evidence;
- A/B process stdout/stderr, exit status, timing and visibility records;
- dispatch receipt path/hash/count and exact parsed record;
- explicit zero model requests, real Codex task executions and provider sends.

One additional meaningful Rust compilation is required because build-008 retained
`codex_core` and `codex_mcp` test executables, not the production `codex` CLI.
That future compilation is not authorized by this review.

### Stop conditions

Stop before execution if the intended CLI no longer maps to the confirmed 16 MiB
path; Candidate B or schema hashes drift; exact executable/config/source binding is
not possible; the proof needs model inference, protocol v3, a wider tool ceiling or
a wrapper that bypasses production host construction.

No production stack setting is changed and no `RUST_MIN_STACK` launch workaround is
proposed. Stage 3G-C and Stage 3G remain OPEN; execution_ready=false;
production_classification=UNKNOWN; process_proof=null; real Codex executions=0;
provider sends=0; build_009_run=false.
