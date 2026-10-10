# Build-003: proof constructor correction only

Replace exactly five ExtensionData::default() calls with the pinned supported
ExtensionData::new("devhub-proof"). Production patch bytes remain identical to
build-002 (d2e27068ca8020f014c7cd3bea2cc73181b1b892d8e6869814680d2076eb3e36).
No upstream Default implementation, unsafe constructor or production change.

The source preflight independently hashes pinned extension-api/src/state.rs,
checks new(level_id) delegates to empty ExtensionDataInit::default(), rejects the
unsupported harness constructor, and records the new test hash. A normal offline
regression test also prevents reintroduction. These checks are API compatibility
checks, not runtime proof. All original source anchors/patch bytes, schema and
synthetic payload pass the same preflight. Pinned Rust 1.95.0 rustfmt passes for
all eight patched files and the harness.

The source lifecycle/lock audit in STAGE3G-ADMISSION-BUILD002.md applies unchanged:
production files are byte-identical, including synchronous reconnect, serialized
publication/shutdown, same-snapshot shutdown and generation/catalog read leases.
Apps publication remains observed and excluded by exact configured server binding.
No new lock acquisition was introduced. No new source-level inversion identified;
actual races remain unproven until a compiled test runs.

Historical build-001, redundant-build-001, build-002 and their assessments remain
unchanged. Build-003 is manually dispatched once only after Linux full and Windows
smoke plus normal lint/type/evidence checks pass. No build-004. Compile or test
failure is preserved, followed by STOP for review. Even a passing subset leaves
unexercised matrix/process fields null and production classification UNKNOWN.

Stage 3G-C/3G OPEN; execution_ready=false; real_codex_executions=0;
provider_sends=0. No v3, benchmark, rehearsal or model/provider request.

## Actual result — STOP for review

[Build-003 run](https://github.com/voronpap/codex-dev-hub/actions/runs/37212782847)
at c2582eb5e15986921630191f8e417f3c917a9e1e compiled successfully (exit 0),
574.4356849850001 seconds. The single compiled test failed (exit 101),
0.23056369100004304 seconds, with `approved binding must contain exactly one tool`.
A PATH-alias permission warning is also preserved; its causal relevance is unknown.
No assertions were weakened and no follow-up code fix or build-004 was attempted.

The error originates in the approve_call cardinality guard, not the prior
constructor API mismatch. Multiple B call sites can reach it. Neither actual
binding size nor exact lifecycle call site is logged, so root cause remains
unknown. No completed DEVHUB_ROUTER_PROOF record was emitted. Synthetic receipt
count is null: the temporary receipt was not exported. This must not be converted
to zero. No model/provider execution path is used.

Arm A's ordinary empty visible ceiling and approved A empty registered/visible/
nested surfaces with CodeModeOnly are established by assertions preceding all
B approve_call sites in the executed sequential loop. This is control-flow-bound
partial evidence, not a separately emitted successful arm receipt. Embedded real
schema compiled. All B runtime matrix fields and process proof remain null.

Raw result, stdout/stderr, errors and assessment are preserved under
build-003*. Production classification UNKNOWN; Stage 3G-C/3G OPEN;
execution_ready=false; real_codex_executions=0; provider_sends=0.
Pre-build CI: Linux 375 passed / 1 skipped; Windows smoke 14 passed; Ruff,
format, strict mypy, secret/evidence/history scans green. Final evidence commit
runs only normal CI. Historical receipts remain unchanged.
