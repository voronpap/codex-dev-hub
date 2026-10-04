# Production router integration: admission-to-dispatch design review

PR #32 merged as `82a6a49fb5ac29ddb75345459726b400da55faac`.
Its compiled unit composition remains `ROUTER_FIX_FEASIBLE`; #31 remains
`ROUTER_BLOCKED_BOTH` for its earlier composition. Neither is a production proof.
Stage 3G-C and Stage 3G remain OPEN, execution_ready=false. No protocol revision,
benchmark/rehearsal, model metadata refresh, provider send or Rust build occurred
in this investigation. Production classification is **UNKNOWN**, not PASSED.

## What the pinned source establishes

Source pin: `4607249e430dac1c961df4dc615beae88e33cec8`, Codex
`0.155.0-alpha.9.2`. Exact file hashes and excerpts are stored in
`evidence/stage3g-production-router/source-bindings.json`.

`McpHandler::handle_call` passes its stored server name and raw tool name to
`Session::prepare_mcp_call`. That method refreshes dirty MCP state, then obtains
the **current** binding and prepares a call. The admitted handler does not retain
that executable binding from registry admission. Consequently #32's pointer seal
on the handler alone does not establish the requested admission-to-dispatch seal.

There is already a useful lower-level safeguard: `PreparedMcpCall` captures its
client, configuration, tool metadata and catalog snapshot. Its execution holds
catalog authority through `run_with_snapshot`, rejecting a stale prepared call.
This is protection **after preparation**, not evidence that preparation selected
the binding originally approved for model exposure. No exploit or failed actual
production test is claimed here.

Public `McpToolContext` deliberately exposes read-only provenance, not the
executable client. `ToolLifecycleContributor::on_tool_start` returns a future
with unit output; it is not a veto/admission contract. `AllowedTools` compares
names. External registry insertion is `pub(crate)`. These inspected interfaces
do not provide the complete seal required here. A generic callback, server key,
or equality of configuration metadata must not be presented as channel identity.

## Proposed narrow Candidate B patch (NOT implemented or approved)

Keep the existing model-facing MCP API and DirectModelOnly namespace mechanism.
Do not add Candidate C or globally switch to Direct. The accompanying config
JSON is a **design representation**, not a loadable production Codex config:
AllowedTools is host startup data, not a demonstrated CLI TOML option.

1. Add an opt-in, host-owned MCP admission policy at registry construction, before
   registration/model exposure. Supply the exact reviewed process launch binding
   (command, ordered arguments, config file hash/path, project, state root, server
   key), canonical and raw names, and real input-schema hash/version. Reject
   duplicate attempts before the first-wins registry can hide a conflict. Keep
   error_on_tool_collisions=true as a second check.
2. Materialize the prepared call from the same frozen binding used by admission.
   Retain an opaque client/generation identity minted by trusted runtime code,
   plus catalog identity and the exact prepared call. Never accept an identity
   supplied by ToolInfo, the MCP response or caller-controlled strings. Runtime
   publication/reconnect invalidates the generation; it cannot reuse approval.
3. Construct the normal MCP handler with that admitted call. Dispatch must use
   the retained call, without a new canonical-name/server-name lookup. Check the
   admitted generation under an execution lease; serialize invalidation against
   irreversible call preparation/send. Preserve the existing catalog snapshot
   guard. A check followed by unlocking and name re-resolution is insufficient.
4. Rebuilds require fresh admission. Changed process binding, schema, generation,
   raw name or runtime identity fail closed; no automatic reapproval. Explicit
   schema review supplies a new approved hash. Default non-benchmark behavior
   remains unchanged when this policy is absent.
5. Add a metadata-only observation entry point using the real host construction
   and finalization path. It must emit visibility and admission outcomes before
   any model request. It must not synthesize a router independently of the host.
   A/B ceilings must be immutable host startup data.

The patch would touch production upstream MCP binding/lifecycle, handler and host
admission plumbing. No such upstream patch is applied in this PR. Review this
specific scope before changing the pinned production source, build provenance or
host entry point. No evidence currently establishes that a wrapper is necessary.

The proof-only LOCK_B authorization does not authorize shipping a modified lock
or production binary. A reviewed production build/lock strategy is still needed
if this design proceeds; keep the stock executor unchanged in the meantime.

## Real schema and required proof

The input schema is exported offline from the actual `DelegationRequest` used by
`delegate_server.boundary` for tools/list, not the zero-property synthetic schema:
`0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be`.
Hashing uses sorted compact UTF-8 JSON with ensure_ascii=false. This is not a
process-observed schema or an approved runtime/channel hash; those remain null.

After patch review, one meaningful compiled integration proof must cover:

- A has no configured MCP and no visible, mapped or hosted tools.
- B exposes exactly the real delegate schema under CodeModeOnly, with empty
  code-mode map and hosted surface.
- Wrong-origin-only, wrong-first and approved-first collisions reject admission;
  forged runtime and extra MCP/dynamic/hosted tools cannot satisfy the ceiling.
- Schema drift and reconnect/refresh/catalog/router replacement fail closed.
- Refresh injected between admission and preparation, and between preparation
  and send, cannot redirect the call. Dispatch records the admitted server/raw
  name and generation against a synthetic MCP process, without provider calls.
- Process proof uses the exact built binary/config, not a unit-only registry;
  observation ends before any task/model request.

Until that proof exists, every production test and A/B visible surface in
`audit.json` is null. The old unit tests are not relabelled as production tests.
Rust builds=0, duration=null; no expensive rebuild is justified for this design
and evidence-only change. Required production proof is **not run**.

## Review boundary

This is an incomplete integration investigation, presented for patch-scope review.
There is no production implementation or runtime qualification. All benchmark
claims and Codex internal retry count remain null. Real Codex task executions=0,
provider sends=0. No v3, new plan/session IDs, protocol changes, ledger operations
or historical evidence edits. Even a later production pass will not close 3G-C;
protocol review and intended-host qualification remain separate gates.
