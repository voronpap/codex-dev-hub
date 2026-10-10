# Build-007 diagnosis: source audit only

Historical build-007 is unchanged: compile PASS (382.178388101 s), baseline
PASS, adversarial SIGABRT/stack overflow after prepared_execution_entered.
Build-006 timeout history is unchanged. Production classification UNKNOWN.

The downloaded Actions artifact contains logs, result JSON, lock provenance and
binary SHA-256, but no executable. The workflow uploads production-proof only;
compiled executables were in the disposable source target tree. Consequently no
same-binary RUST_BACKTRACE=full or larger-libtest-thread-stack comparison is possible
from these artifacts. Neither experiment was performed. No Rust rebuild.

## Pinned-source findings

Source identities are bound in build-007-diagnosis.json. The additional handler
closure applies approval, marks memory pollution, rewrites file inputs, builds
request metadata/IDs, augments sandbox state, starts tracing and adds trace metadata.
PreparedMcpCall runs this closure under run_with_snapshot, then adds trusted access
context and calls the captured managed client's transport. The direct-call proof
uses a small preparation closure; the handler path includes larger nested async
futures. Stack-frame depth/size sensitivity is a hypothesis, not a measured cause.

- maybe_mark_thread_memory_mode_polluted has configuration and server early exits,
  then a state-DB call. No direct self recursion in this helper.
- rewrite_mcp_tool_arguments_for_openai_files returns unchanged arguments when no
  file metadata exists; otherwise iterates declared fields and uploads selected
  files. No self recursion in the inspected entry/helper iteration.
- augment_mcp_tool_request_meta_with_sandbox_state checks a server capability,
  then serializes a concrete SandboxState and inserts it in an owned JSON map.
- start_mcp_call_trace has a disabled no-op path; enabled creates an ID and appends
  an event. add_request_meta inserts a string into an owned JSON map.
- ManagedClient retains the RmcpClient; call_with_preparation uses the captured
  catalog snapshot. RmcpClient.call_tool validates object arguments and sends a
  tools/call request (or modern tool-input path) through its service.

No confirmed recursion, cyclic serialization or callback re-entry was established
by this source inspection. Owned JSON does not by itself establish a cyclic graph.
Downstream async call graph/stack layout has not been runtime-localized. The last
marker precedes closure polling: it does not prove any particular inner step ran.

## Proposed disposable diagnostic revision (not compiled)

Keep Candidate B bytes frozen. Add short static enter/exit markers at approval
application, memory_pollution, rewrite_args, request_meta_build/IDs, sandbox_meta,
trace, add_request_meta, trusted-access-context and transport_call boundaries.
Preserve existing generation and catalog guards. Export the synthetic receipt file
outside temporary cleanup and print synthetic_receipt_seen after append. Missing
receipt artifact remains null, never zero. Do not replace actual handler dispatch
with the already-passing direct call.

For a separately reviewed future build, retain the exact test binaries as artifacts
so RUST_BACKTRACE=full and a supported libtest RUST_MIN_STACK comparison can reuse
one compilation. Larger stack is diagnostic only, not a production fix. Separate
catalog-filter execution may be reviewed independently; current result stays null.

STOP for review: no build-008, production patch change, process proof, v3,
rehearsal or benchmark. Stage 3G-C/3G OPEN, execution_ready=false; no model/provider
calls. This diagnosis does not alter Issue #38 observability work.

## Reviewed next diagnostic plan after PR #40 merge

PR #40 merged as accepted design only at
`da935f6cf9612b5ce8eea3b0ad6bc5694b51f96f`. Role runtime is deferred until after the
current Stage 3G; it is unrelated to this diagnostic. Branding, PR #37 demo and
Issue #38 footer are merged. Current delegation, task-scoped usage, protocol and
fixture/oracle behavior remain unchanged. No new runtime evidence is available.

This section is a plan, not implemented instrumentation or build authorization.
Do not change production Candidate B bytes:
`d2e27068ca8020f014c7cd3bea2cc73181b1b892d8e6869814680d2076eb3e36`.

### Disposable checkpoints

Retain actual router-selected McpHandler → ToolInvocation → retained approved call.
In a future separately approved disposable proof tree add only static markers:

1. preparation closure entry; approval application enter/exit;
2. memory_pollution_enter / memory_pollution_exit;
3. rewrite_args_enter / rewrite_args_exit;
4. request_meta_build_enter / request_meta_build_exit;
5. request_ids_enter / request_ids_exit;
6. sandbox_meta_enter / sandbox_meta_exit;
7. trace_enter / trace_exit;
8. add_request_meta_enter / add_request_meta_exit;
9. trusted_access_context_enter / trusted_access_context_exit;
10. transport_call_enter / transport_call_return;
11. synthetic_receipt_seen (server-side after receipt append/flush), handler_return.

Keep catalog snapshot, generation leases and all security logic intact. A marker
before constructing/polling an async closure does not establish that its first
statement ran; distinguish closure entry from the existing prepared_execution_entered.
No runtime object formatting, credentials, raw pointers or private context in markers.

### Persistent receipt and binary artifacts

Plan an explicit per-scenario artifact directory outside TempDir cleanup. Initialize
and identify the receipt path before startup; synthetic server appends/flushes each
exact endpoint/raw-tool/schema/payload receipt before responding. The runner preserves
it on success, timeout and SIGABRT with content hash and scenario/binary identity.
A missing file means null, not zero. A verified initialized empty receipt can establish
zero observed receipts, not necessarily that no bytes were sent. A receipt proves
arrival at the synthetic endpoint, not handler completion or a provider/model request.

Retain both compiled codex_core/codex_mcp test executables before test execution, with
SHA-256, pinned source, patch/diagnostic hashes, proof-only lock identity, toolchain,
platform/dynamic-library requirements and required synthetic assets. Keep these
proof artifacts separate from shipping images/binaries; never replace the production
Codex runtime. Artifact upload must survive test failure. No secrets/auth in artifacts.

### Independent filters, one future compilation

The existing source already contains three named tests:
- `devhub_production_admission_path` (baseline);
- `devhub_production_admission_path_adversarial` (handler/adversarial);
- `devhub_production_admission_path_catalog` (catalog refresh).

Future runner should enumerate fully-qualified names from each compiled binary and
use exact filters, separately captured outputs/status/deadlines, and separate synthetic
receipt paths. Catalog execution must not be silently suppressed by a handler abort.
Do not call a substring-filtered broad run an independent test. Independent catalog
success cannot establish handler success. Compile once only after explicit approval;
changing test filters later must reuse recorded binaries where feasible.

First same-binary diagnostic would preserve network isolation, exact synthetic host
approval and all guards, adding RUST_BACKTRACE=full. Record absent backtrace honestly.
A supported libtest RUST_MIN_STACK comparison, if separately approved, is diagnostic
only: record exact environment and binary hash, never change production stack size.
No binary is available from build-007's existing artifacts, so none of these reruns
has been performed. Checkpoint instrumentation itself can affect stack layout; any
future pass must state that limitation and cannot retroactively explain build-007.

### Stop / classification

Current production_classification=UNKNOWN, root_cause=UNKNOWN, handler proof incomplete,
catalog_refresh_after_preparation=null, process_proof=null. Preserve build-006 and
build-007 evidence unchanged. Build-008 NOT RUN. Stage 3G-C/3G OPEN;
execution_ready=false; new model/provider calls=0, rehearsal=0, benchmark=0.
Stop for review of this diagnostic plan. No v3, role runtime, production patch change
or expensive workflow dispatch follows this documentation update.
