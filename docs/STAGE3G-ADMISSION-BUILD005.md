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
