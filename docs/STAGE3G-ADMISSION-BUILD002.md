# Corrected Candidate B build-002

Implementation remains opt-in and proof-only. Stage 3G-C/3G OPEN;
execution_ready=false, real_codex_executions=0, provider_sends=0. No wrapper,
protocol revision, runtime activation or model request. Production classification
is UNKNOWN until actual evidence; the full matrix/process proof is incomplete.

## Narrow correction from build-001

- Restore original sync reconnect marker and leave core/session/handlers.rs
  untouched. Setting reconnect_pending schedules work; it does not replace
  approved authority. The old call is allowed until actual replacement.
- publish holds admission_publication, captures current runtime, invalidates
  that generation (waiting for approved read leases), builds connections and
  publishes a fresh generation. Existing reconnect/replace_fresh entry points
  still reach this path. No Apps lifecycle changes.
- shutdown holds the same publication mutex, loads one current snapshot,
  invalidates its generation, then shuts down its connections. It never resolves
  latest_connections after invalidation. Later trusted fresh publication is
  allowed; it cannot reactivate an old generation and needs fresh host admission.
- Keep ApprovedMcpCall/PreparedMcpCall, schema/config checks, exact server/raw/
  canonical identity, global CodeModeOnly, one DirectModelOnly namespace,
  AllowedTools and fatal collisions unchanged. Template formatting is cosmetic.

Scope: eight upstream production files; the ninth build-001 file
core/src/session/handlers.rs is no longer patched. No Cargo.lock committed.

## Replacement and Apps audit

All executable binding replacement relevant to approved devhub_delegate uses
the reviewed McpRuntime path. This is not a blanket statement about all clients.
CodexAppsStartupReconnect has an independent current_client publication. Its
factory is created only for CODEX_APPS_MCP_SERVER_NAME="codex_apps". Candidate B
requires configured reviewed server key devhub_delegate, raw devhub_delegate,
canonical mcp__devhub_delegate/devhub_delegate and exact config/schema plus
executable generation. Canonical names alone cannot make Apps eligible.

Cached bindings belong to a captured PublishedMcpRuntime and catalog revision;
the generation is copied from that same snapshot. New publication has a new
cache and generation. A retained cached G0 binding may survive as an object but
cannot execute after G0 invalidation. Catalog changes retain the lower existing
run_with_snapshot guard; no parallel catalog execution mechanism is added.

## Source lock-order audit

Inspected pinned runtime.rs, binding.rs, client_tool_catalog.rs,
connection_manager.rs, rmcp_client.rs, core/mcp_tool_call.rs,
core/mcp_openai_file.rs and session/mod.rs. Exact patched-file hashes are in
candidate.sources.json; preflight reproduces them against the pinned source.

| Operation | Acquisition/order and release |
| --- | --- |
| Approved call | generation read -> catalog snapshot read -> preparation/send; releases catalog then generation |
| Publish | async publication mutex -> old generation writer; writer released after invalidation -> connection reconciliation -> short event_stream_cancellation sync mutex -> current.store; no await under that sync mutex |
| Shutdown | async publication mutex -> generation writer; writer released -> captured connections shutdown; no second runtime lookup |
| Catalog refresh | refresh serialization -> fetch -> catalog writer -> synchronous publication callback; no admission-publication lock acquired |
| Binding cache | short sync cached-binding mutex; released before capture awaits; generation comes from captured runtime |
| Host policy | short sync admitted mutex; handler construction/registration has no await |
| Event subscription | short sync event_stream_cancellation mutex; no admission lock or await while held |
| Startup/connection shutdown | async connection operations after invalidation; do not acquire admission_publication or generation read leases |

No lock cycle was found in the inspected paths. Preparation can persist tool
approval and reload config; inspected reload_user_config_layer ultimately marks
MCP dirty and schedules prewarm rather than awaiting MCP publication while
holding the call lease. Memory marking and optional file rewriting do not acquire
admission_publication. This is a source audit, not a universal deadlock proof for
arbitrary future callbacks/extensions. Preparation must not synchronously await
replacement of its own leased runtime. Ordinary None-policy calls do not acquire
a generation read lease. The added lifecycle mutex is internal serialization.

Writer waiting for an active approved call is intentional security serialization,
not a throughput improvement. It covers connection construction/current.store or
shutdown, not unrelated discovery or post-publication Apps refresh. No permanent
closed state and no global lock are introduced.

## Pre-build gates and proof scope

`scripts/audit_approved_lifecycle.py` checks source hashes, applies the generated
patch exclusively to a disposable tree, checks the exact sync marker, one-snapshot
shutdown, Apps exclusion, generation transfer, real schema and JSON payload.
rustfmt from pinned Rust 1.95.0 formats/checks all eight patched files and the
standalone test. Official tool archives are checksum-verified; no cargo build is
used as a redundant precheck.

Schema SHA-256 remains
`0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be`.
Synthetic payload is validated against the real DelegationRequest wire contract.
The synthetic process only appends receipt records; it has no Dev Hub/provider
execution. Appending every send avoids hiding a repeat behind exclusive-write
failure. No real provider calls are counted as synthetic traffic.

The corrected compiled test is intended to cover actual router A/B construction,
the ordinary no-policy empty ceiling, configured schema checks, sync marker
semantics, call-first publication/shutdown, writer-first rejection, fresh host
admission after replacement and republish. It polls a real call until its
preparation closure signals entry (generation/catalog leases already held), then
polls real publish/shutdown for Pending before releasing the call. No timing
sleep is used as the race oracle. Late-call errors must be generation rejection
and receipt bytes must remain unchanged.

Dispatch in this subset uses retained PreparedMcpCall directly, not a full
model-facing McpHandler invocation. Process proof, complete wrong-origin/collision
matrix, forged runtime, explicit catalog-refresh-after-preparation and dynamic/
hosted adversarial tests remain null unless independently proven. Scenario
generation labels are not production runtime IDs. No PASSED claim from a subset.

## Build history and authorization

Build-001: E0728, 642.18142584 seconds. Redundant-build-001: same patch/test and
E0728, 513.23940692 seconds. Both preserved, total failed compilation time
1155.42083276 seconds. Neither is renamed. Corrected build-002 is the single
next authorized meaningful build, manually dispatched only after all cheap gates
and normal Linux/Windows-smoke CI pass. No automatic build-003. Record actual
result and STOP for review even if this subset passes.

## Actual corrected build-002 outcome — STOP for review

Manual run [37204375041](https://github.com/voronpap/codex-dev-hub/actions/runs/37204375041)
at implementation `8e5b159b1c4fdc3b824b57c02a9d76fa955ac641` failed compilation
(exit 101, no timeout) after 727.519144516 seconds. Five E0599 errors in the
proof harness call `ExtensionData::default()`, absent from this pinned API.
Diagnostics identify `ExtensionData::new` and `new_with_init` as constructors.
This is an IMPLEMENTATION_ERROR (pinned API mismatch), not an architecture
blocker. E0728 is absent from this run, but that does not establish a passing
production build or runtime proof. No test binary executed.

Raw receipt is `build-002.json`; all five compiler diagnostics are preserved in
`build-002-errors.json`; assessment and artifact hashes are in
`build-002-assessment.json`. Historical build-001, redundant-build-001 and the
original result snapshot are unchanged. Three compilation attempts total
1882.939977276 seconds, including the historical redundant run.

Cheap validation before dispatch passed: pinned patch/anchor/hash checks,
rustfmt, source lifecycle and lock-order audit, real schema and synthetic wire
payload, Ruff/format/strict mypy and evidence scans. Normal CI 37204281003 passed
374 Linux tests (one skipped) and 14 Windows smoke tests. These checks do not
substitute for the failed Rust proof. All compiled production matrix results
and process proof remain null.

Production classification remains UNKNOWN; Stage 3G-C and Stage 3G OPEN;
execution_ready=false; real_codex_executions=0; provider_sends=0. No correction
to the newly discovered test API mismatch and no build-003 were attempted.
Further implementation requires review. No protocol v3, rehearsal or benchmark.
