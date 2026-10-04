# Build-007: exact synthetic invocation approval

Build-006 remains historical: compile PASS, 807.291987807 seconds; one test passed,
one failed at handler dispatch after 20 seconds. Root cause is not retroactively
runtime-proven. The leading source-derived hypothesis is an unhandled approval wait.

Pinned PreparedMcpCall delegates approval selection to McpServerMetadata:
per-tool mode → server default → default Auto. The build-006 synthetic server
supplies neither policy nor annotations. The actual pinned helper maps Auto with
no annotations to required=true; Approve maps to false. Strict auto review and
other approval policy can still affect the full decision path. Source hashes,
config schema validation and unchanged patch identity are recorded in
[evidence](evidence/stage3g-approved-call/build-007-source-approval.json).

The only synthetic host configuration correction is:

```json
{"enabled_tools":["devhub_delegate"],
 "tools":{"devhub_delegate":{"approval_mode":"approve"}}}
```

No server-wide default, global approval bypass or model-controlled policy. Exact
origin/config/schema/generation admission, AllowedTools, direct-only namespace,
CodeModeOnly and fatal collisions remain intact. Wrong-origin config still fails.
Host invocation consent is distinct from DevFabric privacy/resource/quota/dispatch
authorization; this synthetic server does not execute any DevFabric/provider logic.

The test captures a legacy binding without invoking it and observes actual Auto,
absent annotations and the pinned helper's true result. It then observes Approve
on the corrected retained call. A cfg(test) accessor delegates to the original
helper; it does not reimplement its semantics. Diagnostic println checkpoints are
applied only to the disposable pinned source tree, after the unchanged Candidate B
patch. Their separate source hashes are recorded. No shipping binary/API is changed.

Markers cover handler entry, retained prepared selection, tool-start notification,
originating call, actual approval decision/strict-auto-review, approved-call handler,
prepared execution, handler return and receipt observation. Completion still requires
exact endpoint/raw tool/arguments/real schema hash. Catalog refresh runs only after
core tests pass. Process proof remains null; no exact CLI/config process gate here.

Future intended unattended B-arm host needs explicit reviewed invocation permission
for this tool only. This is a future protocol/config review requirement, not v3.

One manual build-007 is permitted after cheap gates. No automatic build-008.
Production classification remains UNKNOWN until actual evidence supports the matrix.
Stage 3G-C/3G OPEN, execution_ready=false; no Codex/provider/model requests.
