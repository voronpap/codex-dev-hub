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

## Actual build-007 result: STOP for review

[Manual run](https://github.com/voronpap/codex-dev-hub/actions/runs/37225858504)
compiled both crates successfully in 382.178388101 seconds. The baseline test
completed successfully. The adversarial test process aborted with stack overflow
(SIGABRT, exit -6), not a timeout; there is no final test-suite summary.

Actual pinned runtime observations confirm legacy Auto + absent annotations +
required=true. Corrected config reports Approve, all three hints null,
global policy OnRequest, permission profile present, strict_auto_review=false,
required_by_mode=false. The handler passed retained-call selection, tool-start
notification, originating-call and approval-decision checkpoints and entered
approved-call handling and prepared execution. No handler-return or receipt
observation marker followed. The exact stack-overflow cause remains unknown.
This does not retroactively prove build-006's timeout root cause.

A/B visibility, lifecycle/schema/Apps subset and adversarial origin/collision/
forgery/extra-MCP/dynamic-hosted checkpoints passed. Handler dispatch did not
complete; its receipt count remains unknown. Catalog refresh was compiled but
not executed after the abort. Process proof remains null. Production classification
is UNKNOWN. No production patch fix or build-008 was attempted.

Raw receipt and byte-preserved test outputs accompany the
[assessment](evidence/stage3g-approved-call/build-007-assessment.json), including
artifact hashes and cumulative compilation costs. Build-006 and earlier evidence
remain unchanged. Linux full (377 passed, 1 skipped), Windows smoke (14 passed),
Ruff, formatting, strict mypy and evidence/secret scans passed before this run.

Stage 3G-C and Stage 3G remain OPEN; execution_ready=false. Real Codex executions
and provider sends remain zero. No protocol revision, rehearsal or benchmark.
