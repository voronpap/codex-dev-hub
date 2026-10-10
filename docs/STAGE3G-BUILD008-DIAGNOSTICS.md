# Build-008 diagnostic execution

The operator authorized one diagnostic compilation after the accepted acd0dd3 plan.
Build-007 remains historical: stack overflow; root cause UNKNOWN. The Candidate B
production patch is frozen at
`d2e27068ca8020f014c7cd3bea2cc73181b1b892d8e6869814680d2076eb3e36`.

Only disposable instrumentation, harness, artifact retention and runner changed.
Inner preparation checkpoints narrow the handler boundary without logging runtime
objects or private payloads. Instrumentation changes stack layout: a passing
instrumented test cannot retroactively explain build-007.

Both compiled test executables are copied and hashed before enumeration or tests.
The artifact includes the runner, synthetic server, schema/payload, toolchain and
library requirements. Relocated artifacts require rebinding manifest paths and
restoring executable permissions; they are not shipping binaries.

The runner enumerates fully qualified names and invokes exactly one test at a time:
baseline first, handler with normal stack and RUST_BACKTRACE=full, then independent
catalog proof. Baseline failure stops the suite. Only an observed normal-stack
overflow permits the same binary/filter/assets with RUST_MIN_STACK=16777216.
Rust 1.95.0 libtest source confirms that its test-thread Builder does not override
stack size. This diagnostic setting is never a production fix.

Every run initializes a persistent receipt outside TempDir cleanup before execution.
The synthetic server appends and flushes before responding. Missing receipt is null;
initialized empty receipt establishes zero observed receipts. Receipt proves synthetic
endpoint arrival only, not handler completion or model/provider execution.

Pre-build source/schema/approval checks are recorded in build-008-prebuild.json.
Linux full and Windows smoke CI passed before the one manual compilation.
Workflow remains manual-only. No build-009 is authorized.

Stage 3G-C and Stage 3G remain OPEN; execution_ready=false; process_proof=null.
Real Codex executions=0; provider sends=0. No v3, rehearsal, benchmark or role runtime.

Remote preparation through 84b64c4 was reconciled without rewriting its history.
The unified runner retains exact filters and fsynced receipts. Transport markers
are unconditional only inside the disposable tree: codex-mcp is a dependency
of the core test binary and its cfg(test) markers would otherwise be absent.
No production patch or historical evidence changed during reconciliation.

## Actual result

Implementation: `21e2892b4f0251de15f6ac84cdeeb27c11d4bca2`.
[Run and retained artifacts](https://github.com/voronpap/codex-dev-hub/actions/runs/37235328411).
One Rust compilation passed in **582.335862486 s**. Workflow failure reflects the
normal-stack test failure, not a compile failure. Both binaries were retained before
any test; downloaded binaries/assets/receipts were independently hash-verified.

| Independent exact test | Stack | Result | Duration | Receipts |
| --- | --- | --- | ---: | ---: |
| baseline | normal | PASS | 0.315224546 s | 5 |
| adversarial handler | normal | SIGABRT (signal 6 / exit -6), stack overflow | 0.465498811 s | 0 |
| same adversarial binary/filter | RUST_MIN_STACK=16777216 | PASS | 0.265097671 s | 1 |
| catalog | normal | PASS | 0.064415 s | 1 |

No timeout occurred. RUST_BACKTRACE=full produced no backtrace on the normal-stack
abort. The initialized normal handler receipt exists, is zero bytes and has SHA-256
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

The larger-stack handler receipt is 527 bytes, SHA-256
`9c41be818a8bc51a6984c8b13e26aca41704c088c3d23a41cfa5c40cf376cbb7`.
Its sole record matches approved-adversarial-endpoint, raw devhub_delegate, exact
approved real schema and exact synthetic payload. Handler returned successfully.
This is diagnostic evidence only; no production stack size was changed.

**Diagnostic classification: STACK_DEPTH_OR_FRAME_SIZE_SENSITIVE.**
Exact root cause: UNKNOWN. Normal stack fails after prepared_execution_entered and
before preparation_closure_entered. The evidence does not identify a recursive
function, particular future/frame, or production Candidate B defect. Build-007
remains unchanged with root cause UNKNOWN. Instrumentation changes stack layout.

Catalog independently rejected the stale prepared call with:
`tool call rejected because the catalog changed after devhub_delegate/devhub_delegate was prepared`.
Receipt bytes remained unchanged after the rejected call. Existing run_with_snapshot
provided this protection; no second catalog authority was introduced.

## Exact checkpoints

Normal handler (after origin/collision/ceiling assertion checkpoints):

```text
handler_entry
prepared_approved_call_selected
notify_tool_start_completed
originating_call_completed
approval_decision_path
handle_approved_mcp_tool_call_entered
prepared_execution_entered
```

Same-binary larger-stack additional checkpoints:

```text
preparation_closure_entered
approval_application_enter
approval_application_exit
memory_pollution_enter
memory_pollution_exit
rewrite_args_enter
rewrite_args_exit
request_meta_build_enter
request_meta_build_exit
request_ids_enter
request_ids_exit
sandbox_meta_enter
sandbox_meta_exit
trace_enter
trace_exit
add_request_meta_enter
add_request_meta_exit
trusted_access_context_enter
trusted_access_context_exit
transport_call_enter
transport_call_return
prepared_execution_returned
handler_return
synthetic_receipt_seen
handler_dispatch_passed
```

All checkpoints, fully qualified filters, commands/environment, stdout/stderr and
receipt records are preserved in `docs/evidence/stage3g-approved-call/build-008-*`.

## Identity and binary retention

- pinned_source_commit: `4607249e430dac1c961df4dc615beae88e33cec8`
- proof_lock_sha256: `a5369b7f5d713d21c9f2481afdc27b7577e45d4b713fc84a4ab03c2833c4d48d`
- diagnostic_harness_sha256: `c79c25fd07965c412c1be41786da76f562c4ecb7bc4b98a7b17c2d533c70bd1b`
- `codex_mcp`: `binaries/codex_mcp-5c9fd2f54b4378c9`; SHA-256 `54ac6436715469c2f3eeee63be6ae8cf998c2aab50f074f30a3348d26a736dd8`.
- `codex_core`: `binaries/codex_core-53e740d1c6e5e203`; SHA-256 `91ec5c2ea3da2be38a628f0eb5909f051e045f79d799da18dbf67e44a1d30e61`.

Rust/Cargo 1.95.0, x86_64-unknown-linux-gnu, Ubuntu runner glibc 2.39.
The raw runner manifest records dynamic libraries, source/patch/lock identities,
fixture assets and runtime requirements. These are disposable proof binaries, not
production runtime replacements.

## Gate interpretation

A empty / B exact delegate, schema/Apps/lifecycle, origin/collision and scoped forged
binding checks retain their actual evidence. Extra MCP and dynamic/hosted ceiling
checks passed before the normal-stack handler abort and in the larger-stack run.

- handler_dispatch=false for the normal-stack gate.
- diagnostic_large_stack_handler_dispatch=true, conditional diagnostic scope only.
- catalog_refresh_after_preparation=true.
- process_proof=null.
- production_classification=UNKNOWN.

No production change is proposed from an unidentified frame-level cause. Review the
retained-binary stack/frame diagnostic evidence before authorizing further changes.
No build-009 ran. Stage 3G-C/3G OPEN, execution_ready=false, real_codex_executions=0,
provider_sends=0. Synthetic MCP receipts are not provider inference.

CI: Linux full 403 passed / 1 skipped; Windows smoke 14 passed; Windows full
403 passed / 1 skipped. Ruff, format, strict mypy and secret/history/evidence scans
passed. The evidence-only follow-up does not trigger another Rust proof.
