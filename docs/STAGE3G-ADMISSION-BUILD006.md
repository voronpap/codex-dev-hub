# Build-006 adversarial proof plan

This run extends tests only. The accepted production candidate.patch remains
SHA-256 d2e27068ca8020f014c7cd3bea2cc73181b1b892d8e6869814680d2076eb3e36.
No shipping runtime, protocol, model, provider or evidence-history mutation.

One manual compilation command targets codex-core and codex-mcp together using
accepted disposable LOCK_B. The two test binaries run serially in an empty network
namespace. Failure stops remaining execution; no retry or build-007 is authorized.

## Source audit and test boundaries

- Wrong origin uses a real second synthetic MCP binding with the same canonical
  identity/schema but an unreviewed launch configuration/endpoint. Admission rejects it.
- Wrong-first registers the metadata runtime first; production policy rejects the
  nonempty registry. Approved-first rejects duplicate registration and fatal router
  finalization. Both exercise actual registry/policy functions.
- Forgery covers the public empty binding constructor and metadata-only handler.
  Neither can manufacture the private runtime generation/client/catalog authority.
- Extra MCP captures both configured servers, then tests cardinality admission;
  it does not remove the extra tool after capture.
- Dynamic/extension/web candidates go through append_source_tools and production
  finalization with the exact ceiling. Actual build_tool_router is also used to
  select the sole handler for execution.
- Handler execution uses ToolInvocation. Session has no ordinary delegate runtime,
  so success must use retained approved authority; receipt bytes must match payload.
- Catalog test is appended inside disposable codex-mcp binding.rs. Private access
  injects an explicit refresh on the retained client's catalog; production admission,
  PreparedMcpCall and run_with_snapshot enforce rejection without a second send.
  This test-only access is not a new production API or shipping patch.
- Synthetic subprocess code only handles initialize/list/call/ping, records receipts,
  and cannot launch a provider. It has no subprocess/network imports. Real stdio
  dispatch is observable, but comprehensive process-tree verification remains null.
  Do not conflate this with exact CLI startup/config qualification.

The source compatibility audit checks existing helper/signature visibility, config
registration and permission publication, error conversion, and ToolInvocation fields.
Existing lifecycle lock-order and Apps exclusion audit is unchanged. All new tests
use the approved real schema and schema-valid synthetic payload.

Before dispatch: pinned anchors/patch application, pinned rustfmt 1.95, Python tests,
Linux full, Windows smoke, Ruff/format/mypy, secret/evidence/history scans must pass.
Result fields stay unknown until compiled execution produces evidence.

Stage 3G-C and Stage 3G remain OPEN; execution_ready=false. Real Codex executions
and provider sends remain zero. No quality, savings or Delegation Value claim.

## Actual build-006 outcome — stop for review

Run 37222526797 compiled both crates successfully in 807.291987807 seconds.
Core tests: one passed, one failed; test invocation took 20.542964699 seconds.
The unchanged A/B/lifecycle proof passed again. Adversarial checkpoints prove
wrong-origin-only, wrong-first, approved-first, metadata/empty-binding forgery,
extra MCP and dynamic/hosted ceiling checks passed.

The actual router-selected handler invocation hit its 20-second timeout:
`Error: deadline has elapsed`. Completion/endpoint receipt assertions were not
reached. This is HANDLER_DISPATCH_TIMEOUT with root cause unknown, not evidence
of origin bypass or confirmed exploit. Catalog test compiled but was not run
because the runner stops after failure. Process proof remains null.

Machine-readable assessment and raw receipt/stdout/stderr are in
[build-006-assessment.json](evidence/stage3g-approved-call/build-006-assessment.json).
Production classification UNKNOWN; no build-007. Stage and execution readiness
remain unchanged. No runtime fix was applied after this result.
