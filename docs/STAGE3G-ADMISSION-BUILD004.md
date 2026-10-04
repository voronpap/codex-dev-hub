# Build-004: binding diagnostics only

Production patch is byte-identical to build-003. No cardinality/filter/config,
AllowedTools, schema, lifecycle, publication or shutdown semantic changes.
Historical build-003 retains unknown B cardinality and compile PASS/test FAIL.

## Pinned source path

Source commit 4607249e430dac1c961df4dc615beae88e33cec8; exact file hashes recorded
in build-004-source-audit.json, verified against the archive source manifest.

- McpRuntime::current_binding_for_call captures current, checks config and waits
  for named server startup; binding_from_published_runtime captures the complete
  published connection set, not a binding filtered down to that server.
- binding_from_published_runtime may reuse a weak cached binding only at matching
  stable catalog revisions; otherwise it calls capture_binding_with_metadata.
  Candidate patch stamps the captured published generation, unchanged here.
- capture_binding_with_metadata snapshots all servers. Startup/required-server,
  dormant/cache and optional grace behavior can determine catalog availability.
  Ready clients contribute catalog snapshots; missing exact ready clients may
  omit a server. Cached tools can supply visible declarations without a call.
- Per-server enabled/disabled filtering and regular/Apps preparation precede
  metadata attachment and namespace normalization. listed_tools is combined.
- For each normalized ToolInfo, model visibility is determined by ui.visibility
  metadata (absent means visible). Ready tools require successful prepare_call;
  prepared calls retain exact client/config/catalog snapshot. Calls include
  permitted app-only metadata; tools includes only model-visible entries.
- McpBinding::new stores tools/calls unchanged. tools() returns that frozen vector;
  tool_info reads calls including app-only metadata; prepare_call also checks
  model visibility. has_servers is connection-set presence, not tool count.
- effective_mcp_servers reads configured_mcp_servers, which reads materialized
  mcp_server_catalog.configured_servers(), applies auth/plugin metadata and removes
  Apps when disabled. It does not synthesize missing servers. The test's legacy
  turn.config.mcp_servers assignment is intent; mcp_config_for_test converts via
  to_mcp_config_with_loaded_plugins. No runtime equivalence is inferred.

## Diagnostic boundary

Before runtime.replace: sorted legacy configured, materialized catalog and
actual effective keys, Apps/plugin/other presence. No credential/config values.
After initial binding and before build_tool_router's implicit approve_call:
flushed DEVHUB_BINDING_DIAGNOSTIC captures sorted identities, visibility,
tools.len, has_servers, target tool_info and prepare_call presence.
DEVHUB_STAGE distinguishes initial router admission from direct approve_call,
later schema/Apps probes, publication, fresh admission, shutdown and republish.
stdout/stderr survive test failure through the existing driver artifact.
No production logging. Querying prepare_call clones a handle and does not send.

## Cheap gates and scope

Synthetic process offline test verifies exactly one tools/list entry and exact
name/schema; hash recorded. This is not proof of captured runtime cardinality.
Pinned source/patch anchors, schema/payload, constructor regression and lifecycle
source audit are unchanged and rerun. Lock ordering unchanged (no production
edit); prior scoped audit applies. Pinned 1.95 rustfmt checks patched files and
harness. Linux full/Windows smoke and lint/type/evidence checks must pass before
one manual build-004. No full Windows, build-005, v3, rehearsal or benchmark.

Production classification UNKNOWN; Stage 3G-C/3G OPEN; execution_ready=false;
real_codex_executions=0; provider_sends=0. Any failed scenario is preserved without
fix-forward. Missing matrix observations remain null.
