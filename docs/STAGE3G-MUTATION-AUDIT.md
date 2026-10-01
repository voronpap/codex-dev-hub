# Stage 3G-C mutation surface investigation: Case B

PR #26 merged as partial capability-gate revision (5dd76c2). Stage 3G-C and
Stage 3G remain OPEN. execution_ready=false. No benchmark/rehearsal/inference.
Accepted qualification policy remains e3aa6f28641e7b9c8e73b36f5943dd4af946a4641fecc061dae8ecf122d0a8ec.
No runtime/gate, protocol, model selection, endpoint, ledger, Docker or WSL changes.

## Metadata observation and stop decision

Exactly one GET to the built-in ChatGPT Codex models endpoint with
client_version=0.155.0 returned HTTP 200 on 2026-10-01. Pinned source strips the
alpha suffix for this metadata query. Existing local auth was used in memory;
no key, account ID, fingerprint or full response body is published. No fixture
or task content was sent. No redirects, retries, proxy discovery or token refresh.

For ChatGPT auth the pinned manager sorts by priority then marks the first
picker-visible model default. The observed catalog selects gpt-6-astra and its
apply_patch_tool_type is freeform. This is a derived catalog snapshot, not a
pinned model override or observation of a running task. The protocol still has
codex_model=null. Future metadata can change; this snapshot is not authorization.

Pinned spec_plan.rs:1213-1216 registers ApplyPatchHandler when an execution
environment exists and model_info.apply_patch_tool_type.is_some(). ShellTool is
not checked here. The planned ordinary exec environment satisfies the environment
side; no extra AllowedTools exclusion is configured. This is metadata-bound,
source-derived registration evidence, not an actual runtime tool-list observation.
Therefore apply_patch_absent=false for this snapshot/context: CASE B, STOP.
No attempt was made to prove filesystem writes or invoke any tool/model task.
Read-only sandbox restrictions apply during handling and do not remove registration.

## Canonical inventory

Machine-readable inventory, source file hashes and exact excerpts are in
`evidence/stage3g-mutation-audit/`. All references pin source commit
4607249e430dac1c961df4dc615beae88e33cec8; no current-main claims.

| Surface | Mutation | Frozen-bound observation |
| --- | --- | --- |
| exec_command, write_stdin | process execution/stdin | absent via effective shell_tool=false |
| apply_patch | create/update/delete/move files | registration condition met; absent=false |
| notes.write_file, notes.append_to_file | server-side notes | canonical names proven; effective extension absence unobserved |
| memories.add_ad_hoc_note | local append-only memory note | blocked by memories=false |
| image_gen.imagegen | image generation and local artifact write | separate feature/model/auth guard; absence unknown |
| create_goal, update_goal | persisted goal database state | blocked by goals=false |
| exec, wait | code-mode execution/resume, nested tool authority | wrappers, not shell aliases; complete nested absence unproven |
| multi_agent_v1.spawn_agent/send_input/resume_agent; spawn_agent/followup_task | indirect agent execution | multi_agent=false; v2 namespace can be configured |
| request_plugin_install | installation request and choice persistence | separate client-mediated surface, not declared harmless |

There is no invented top-level write_file alias: the audited builtin mapping is
notes.write_file. Internal filesystem write_file methods are not automatically
model tools. Arbitrary external MCP/dynamic plugin names are open-ended; the
frozen MCP allowlist is separately A=none, B=devhub_delegate, whose accepted
local execution/accounting writes are explicitly authorized. Read/list/search,
clock, plan notifications and synchronization helpers were distinguished from
agent-requested file/process mutation; incidental transcript/cache writes are
not claims of exposed mutation tools. This is not a blanket absence proof for
all extension or indirect surfaces. other_mutation_tools_absent remains null.

## Reproduce offline validation

`uv run --locked python scripts/check_mutation_audit.py`
validates recorded metadata selection, inventory and source bindings without network.
`uv run --locked python scripts/check_mutation_audit.py --verify-upstream`
fetches only pinned public source files and checks complete hashes plus excerpts;
it does not repeat the model metadata request. CI uses this source check followed
by existing isolation/evaluator regression. No live metadata or inference in CI.

The app-server model/list path exposes picker ModelPreset objects; conversion
omits apply_patch_tool_type. Direct model catalog metadata was therefore used,
matching the pinned endpoint/version semantics. No model generation was required.

## Review boundary

Do not flip the capability gate green. A supported patch-disable mechanism,
a different mode, or a model/protocol revision needs a separate reviewed direction.
The Linux host still lacks unified qualification; no environment repair was made.
Real Codex task executions=0; provider sends=0; metadata requests=1; inference=0.
Semantic acceptance, quality, savings and Delegation Value remain null.
