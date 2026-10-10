# Candidate B pre-build-002 lifecycle audit

Status: STOP FOR REVIEW before build-002. Production classification UNKNOWN.
Stage 3G-C and Stage 3G remain OPEN; execution_ready=false. No model tasks,
provider sends, rehearsal, protocol revision or shipping runtime changes.

Build-001 is preserved byte-for-byte. Its E0728 is an IMPLEMENTATION_ERROR
(compile_failure / async API mismatch), not an architecture blocker.

## Reviewed correction, not yet applied

Restore upstream synchronous `reconnect_on_next_refresh()` and synchronous
`refresh_mcp_servers()`. The marker only sets reconnect_pending; it publishes no
new client or binding. Old admission may remain usable until actual replacement.
Keep the asynchronous generation read lease through preparation/send and writer
invalidation at replacement. Do not propagate async through the marker call graph.

The audit stop was reached before modifying the patch or test lifecycle. The
build-001 patch therefore still contains the compile error. No claim of a fixed
or validated implementation is made.

## Source paths inspected

Pinned source: 4607249e430dac1c961df4dc615beae88e33cec8. Exact source hashes and
excerpts are in `evidence/stage3g-approved-call/prebuild-002-audit.json`.

| Path | Source-level finding |
| --- | --- |
| Startup | McpRuntime::new uses empty then replace; Session constructs a shared runtime and installs initial state |
| replace | Consumes reconnect_pending; calls publish with old connections or None |
| replace_fresh | Calls publish with None, then refreshes Apps catalog |
| publish | Sole production `self.current.store` in runtime.rs; candidate serializes publications, invalidates old generation before connection construction and stores a fresh generation |
| Refresh request | Synchronous flag only; does not publish authority |
| Session refresh | refresh_mcp_servers_now acquires the session refresh semaphore and calls publish_mcp_runtime |
| Cached binding rebuild | Captures exact ready client and catalog snapshot from captured PublishedMcpRuntime; candidate stamps its generation; cache is scoped to that runtime and catalog revisions |
| Catalog refresh | ClientToolCatalog::refresh publishes under its writer lock; PreparedMcpCall::run_with_snapshot retains the reader through preparation/send and rejects explicit stale snapshots |
| Apps startup recovery | Additional client publication outside McpRuntime::publish; detailed below |
| Shutdown | Candidate invalidates one loaded generation then separately obtains latest connections; publication synchronization needs review |
| Whole runtime object | Session retains Arc<McpRuntime>; inspection of session startup/refresh found no assignment replacing that field after construction. This is source evidence, not a compiled lifecycle proof |

## Additional client publication path: stop condition

`CodexAppsStartupReconnect::reconnect_in_background` runs the startup factory and
assigns `state.current_client = Some(client)` under its own mutex. The current
client is subsequently used by AsyncManagedClient::client and binding capture.
This does not pass through McpRuntime::publish or the candidate generation writer.

The reconnect object is created only when server_name equals
CODEX_APPS_MCP_SERVER_NAME. Candidate B requires exact server key devhub_delegate;
therefore this source path is excluded for the approved delegate. This is **not**
a confirmed delegate bypass or exploit. It does disprove a blanket claim that
all executable client publication uses publish. Per the requested audit stop
condition, record and review the exclusion before spending build-002.

## Shutdown/publication synchronization question

The candidate publication mutex currently covers publish only. Its shutdown:

1. loads current generation G0 and awaits invalidation;
2. independently calls latest_connections().shutdown().

At runtime API level, a concurrent publish could install G1 between those steps.
Shutdown would then operate on G1 connections without invalidating G1 admission.
The session refresh semaphore is not itself proof that shutdown cannot interleave.
Host-level reachability and an actual synthetic execution of this interleaving
remain unproven. Do not classify a confirmed exploit or compiled blocker.

Proposed review direction: serialize shutdown with the same per-runtime
publication boundary and capture the generation/connections as one snapshot;
define whether publication after shutdown is disallowed or requires a fresh
lifecycle. Do not implement a broader lifecycle policy without review. No global
lock or AtomicBool replacement is proposed.

## Cheap validation and outstanding proof

The real schema was independently derived from DelegationRequest and equals
the stored reviewed schema. Canonical SHA-256:
`0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be`.

The audit records a minimal synthetic JSON payload validated via
DelegationRequest.model_validate_json, matching the MCP wire format. It was not
sent to any process/provider. The old Rust test's empty payload is not claimed
fixed; replacing it belongs to the resumed implementation.

No build-002, cargo check, rustfmt or patch reassembly was run: no source patch
changed, and the audit requires review first. Required actual race, A/B, origin,
collision, schema-drift, handler dispatch and process tests remain unproven/null.
The initial audit counted only build-001 (642.1814258400001 seconds). A subsequent
Actions inventory found an unintended second compilation on documentation-only
commit d83472b: run 37192943484, 513.23940692 seconds, the same patch/test hashes
and E0728. The old broad patches/** push filter included README.md. Its raw receipt
and diagnostics are preserved as redundant-build-001, not corrected build-002.
**Actual compilation count is two**, total 1155.42083276 seconds. Neither test
binary ran. Corrected candidate build-002 remains NOT_RUN. No third compilation
is launched automatically. The expensive workflow is now workflow_dispatch only,
retaining concurrency cancellation; this enforces the pre-build review boundary
and prevents documentation from spending another build.

Default MCP behavior and Candidate B security requirements are unchanged by this
documentation-only audit. Default-path regression remains required before any
production pass. Future startup/research notes remain documentation only.
