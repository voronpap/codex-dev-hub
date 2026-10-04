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
