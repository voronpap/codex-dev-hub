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
Rust compilation remains pending Linux full and Windows smoke CI. Workflow remains
manual-only. No build-009 is authorized.

Stage 3G-C and Stage 3G remain OPEN; execution_ready=false; process_proof=null.
Real Codex executions=0; provider sends=0. No v3, rehearsal, benchmark or role runtime.

Remote preparation through 84b64c4 was reconciled without rewriting its history.
The unified runner retains exact filters and fsynced receipts. Transport markers
are unconditional only inside the disposable tree: codex-mcp is a dependency
of the core test binary and its cfg(test) markers would otherwise be absent.
No production patch or historical evidence changed during reconciliation.
