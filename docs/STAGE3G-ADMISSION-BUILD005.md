# Build-005: production-equivalent permission materialization in harness

Candidate production patch is unchanged (d2e27068ca8020f014c7cd3bea2cc73181b1b892d8e6869814680d2076eb3e36).
Only synthetic harness config materialization, diagnostic assertions/markers,
offline regression and build ID change. No guard/configured-server/AllowedTools,
visibility, schema, lifecycle, generation or capture modifications.

Pinned core/src/session/mcp_runtime.rs derives effective servers and invokes
set_server_permission_profiles with each desired turn environment's environment_id
and permission_profile_with_workspace_roots before Arc<McpConfig>/runtime input.
The harness now invokes the identical method with its actual turn environments.
No handcrafted permission profile, direct map insertion, threadless override or
permissive profile is introduced.

Pinned config/mcp_types.rs defaults an unspecified server environment_id to local;
is_local_environment compares that exact default. Materialization handles enabled
registered servers: host Apps runtime profile, then exact environment profile,
then local/selected-plugin runtime profile, otherwise no authority. Our configured
synthetic server must be Config, enabled, local. Before replace we emit profile
presence before/after, environment id, local flag, source and selected branch;
assert required authority exists. If the turn exposes a matching environment,
its real derived profile is used; otherwise the existing runtime profile applies
through the production local branch. Actual branch is not predeclared.

Binding diagnostics and every previous assertion remain. Additional stale-call
markers isolate post-publication/shutdown failures. No synthetic provider/model
execution. Optional raw catalog observation not added: public binding diagnostic
is sufficient to test the hypothesis without expanding production APIs.

Exact source hashes are in build-005-source-audit.json. All pinned patch/schema/
payload/constructor checks rerun. Production lock ordering remains byte-identical
to prior audited patch. Rustfmt 1.95, Linux full, Windows smoke, lint/type/scans
must pass before one manual build-005. No build-006 or fix-forward after failure.
Earlier receipts/assessments immutable. Stage 3G-C/3G OPEN, production UNKNOWN,
execution_ready=false, real_codex_executions=0, provider_sends=0.

## Actual result: PERMISSION_FIX_RESOLVES_ZERO

[Build-005](https://github.com/voronpap/codex-dev-hub/actions/runs/37219997165)
at 1ec0c325486ae9a96467c4dfb1b43dd32328c1c5: compile exit 0,
817.697410516 seconds; one test exit 0, 0.40475303300001997 seconds.
Last marker all_subset_assertions_completed. Five synthetic MCP receipts.

Actual authority source is turn_environment_profile: exact environment local,
Config source, enabled=true, explicit_environment_match=true. Permission absent
before materialization and present before replace. No permissive profile invented.
Binding tools_len=1, exact server/raw devhub_delegate and canonical namespace
mcp__devhub_delegate/name devhub_delegate. tool_info/prepare_call both present.
Configured/materialized/effective keys remain delegate-only, no Apps/plugins/extras.

Actual subset proves A empty surfaces, B one visible delegate under CodeModeOnly
with empty nested map, compiled/retained real schema, ordinary empty no-policy
ceiling, sync marker preserving calls, publication and shutdown waiting on active
call leases, stale calls denied afterward, fresh binding requiring fresh host
admission, republish not reviving old calls, schema mismatch and absent Apps key
rejection. Retained PreparedMcpCall path reaches the synthetic endpoint with five
validated receipts. This does not prove full McpHandler dispatch or process host.

Wrong-origin-only, both collision orders, forged runtime, catalog refresh after
preparation, extra MCP ceiling, dynamic/hosted adversarial, handler dispatch and
process proof remain null. Raw probe registered-name display concatenates namespace
and name; canonical identity is separately established by binding diagnostics and
visible namespace/tool schema, not that display string alone.

PATH-alias permission warning is retained; test passed despite it. Earlier receipts
and UNKNOWN assessments are unchanged. Production classification UNKNOWN;
Stage 3G-C/3G OPEN; execution_ready=false; real_codex_executions=0; provider_sends=0.
No build-006, protocol v3, rehearsal or benchmark. STOP for review.
