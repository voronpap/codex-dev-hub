# V1 contracts and schemas

Status: Proposed. These are design contracts, not implemented APIs. Every object
has `schema_version: 1`; timestamps are UTC RFC3339, durations milliseconds, token
counts nonnegative integers and money integer micro-USD. Unknown measurements are
null with a reason, never zero. All string/array sizes are bounded. Reject unknown
request fields and invalid enum values. Generated JSON Schema is a Stage 1 task.

## MCP surface

All tools require `project_id` except a host-only status call; host status returns
only accessible project IDs and redacted aggregate health. Project identity is
checked before any resource lookup. Expose six names throughout V1:

| Tool | Input beyond common envelope | Output / effect |
|---|---|---|
| `devhub_status` | optional project_id, optional job_id | capabilities, health freshness, eligibility reasons, job status, approximate quotas; no credential values |
| `devhub_delegate` | action submit/poll/cancel; submit TaskRequest; poll/cancel job_id | bounded model worker job / compact handoff |
| `devhub_research` | action submit/poll/cancel; query <=2,000 chars, approved seed URLs, max_sources <=5, privacy, deadline, budget | sources with URL/title/retrieved_at/evidence, synthesis, uncertainty |
| `devhub_context` | query <=2,000 chars, revision, allowed_paths, token_cap <= project cap | package_id, compact excerpts/provenance, missing_context |
| `devhub_remember` | kind decision/task_outcome; idempotency_key; expected_revision; record | stored revision or conflict; no inferred global writes |
| `devhub_sandbox` | action submit/poll/cancel; snapshot_ref, profile_id, validated argv, timeout | job state, exit code, capped logs and artifact references |

Submit creates a durable job and returns promptly. Poll takes at most 1 second;
job lifetime obeys the overall deadline. No reliance on experimental MCP tasks.
Cancel is idempotent; after provider dispatch it does not imply zero usage.
Mutating submit/remember calls require an idempotency key; same key + different
payload returns `idempotency_conflict`. Keys remain for 90 days with job metadata.
Poll/cancel is authorized against job ownership, not just project input.

Common response: `schema_version, request_id, trace_id, project_id, status,
job_id?, summary, result?, evidence[], artifacts[], usage?, warnings[], error?`.
Status: `queued|running|succeeded|failed|cancelled|needs_approval`.
MCP returns `structuredContent` plus a compact text summary for compatibility;
execution errors set `isError`, protocol validation errors use the SDK protocol
error mechanism. Total response <=64 KiB, default summary <=1,500 estimated tokens;
larger content uses project-scoped opaque artifact IDs, not arbitrary host paths.
Artifacts are retrieved as authorized MCP resources with byte/range limits.

Error: `code, safe_message, retryable, retry_after_ms?, details_ref?`.
Codes include `policy_denied`, `invalid_request`, `stale_context`,
`context_insufficient`, `quota_exhausted`, `budget_exhausted`,
`no_eligible_resource`, `provider_unavailable`, `unknown_usage`,
`deadline_exceeded`, `capability_unverified`, `revision_conflict`.
An approval-needed response is not an approval grant; no MCP argument can
authorize itself. A trusted local operator policy record is checked on resubmit.

### TaskRequest example

```json
{
  "schema_version": 1,
  "project_id": "fixture-project",
  "idempotency_key": "review-parser-001",
  "action": "submit",
  "task": {
    "task_id": "review-parser",
    "task_type": "code_review",
    "instructions": "Identify boundary errors in the selected parser and cite lines.",
    "revision": "registered-snapshot-id",
    "scope": ["src/parser.py"],
    "context_package_id": "ctx-001",
    "required_capabilities": ["text", "json_schema"],
    "acceptance_criteria": ["Cite source lines for each finding"],
    "privacy": "local_only",
    "max_output_tokens": 1500,
    "max_attempts": 3,
    "deadline_ms": 120000,
    "max_cost_microusd": 0
  }
}
```

Task types initially: `summarize|extract|code_review|test_draft|research_synthesis`.
Coding drafts are patches, not direct repository mutations. `scope` must be within
registered allowed paths. Runtime resolves snapshot/package IDs; this example's
IDs are placeholders. Task limits cannot expand project limits.

### Worker handoff

`status, summary, changed_files[], patch_artifact_id?, tests[{profile_id, status,
exit_code?, evidence_ref}], decisions[], warnings[], artifact_ids[],
source_revision, result_hash`. Tests suggested but not run use `not_run`.
Only a sandbox result can supply executed test evidence. Workers have no authority
to mark decisions accepted or alter permissions. Cursor/OpenHands later implement
the same handoff with their own adapter-level lifecycle.

## ProviderAdapter and ToolAdapter

Conceptual async protocol (domain types, not SDK classes):

```text
capabilities(account_ref) -> CapabilitySnapshot[]
health(account_ref) -> HealthSnapshot
quota(account_ref) -> QuotaSnapshot | unknown
estimate(ModelRequest) -> UsageEstimate
execute(ModelRequest, AdmissionTicket, Cancellation) -> ModelResult
```

`ModelRequest`: request/attempt/task/project IDs, exact model+endpoint ID,
messages built from approved context, optional response schema, max output,
timeout, context hash and privacy classification. No arbitrary URL or unvalidated
provider arguments from Codex. Extension fields are adapter-owned allowlists.

`AdmissionTicket`: reservation IDs, resource ID, request hash, max charge,
expires_at, policy version; internal only, validated before send. A ticket is
single-attempt and cannot be reused by another provider or context package.

`ModelResult`: normalized content, finish_reason, schema_valid, usage, upstream
request ID, rate headers normalized with window meaning, model actually used,
safe error if any. Usage includes input/output/reasoning/cached tokens and whether
reasoning is already included in output; never add it twice. Preserve observed
versus estimated provenance. Raw responses remain ephemeral by default.

Adapters perform one network attempt, no automatic SDK retry/fallback. Errors
normalize to auth, entitlement, rate_limit, context_limit, timeout, transient,
invalid_response or permanent. Mark `sent` and `usage_known` independently.
ProviderManager manages adapter registry/lifecycle and circuit state, not routing.

`ToolAdapter.describe/estimate/execute` has the same admission envelope with
provider units (search credits, requests, CPU seconds). Research orchestration
accounts for every subcall. `WorkerAdapter.submit/status/cancel` is reserved for
external coding agents; V1 uses bounded model workers through ProviderAdapter.

## Capability Registry schema

| Field | Type / invariant |
|---|---|
| resource_id, adapter_id, endpoint_id, model_id, model_revision | stable strings; explicit revision/digest when available |
| resource_kind | cloud_model/local_model/tool/worker |
| account_pool_id, plan, region | account-scoped references; no secrets |
| offer_class | CORE_FREE/DEV_FREE/EVAL_FREE/TINY_FREE/FREE_CREDITS/TRIAL_CREDIT/VERIFY/PAID; null for local |
| replenishment | none/daily/monthly/rolling/unknown; independent of offer_class |
| capabilities | map from text/vision/json_schema/tool_calls/search/etc. to supported/unsupported/unknown |
| context_window, max_input, max_output | positive integer or unknown; effective deployment limits override theoretical model limit |
| privacy | local_only/public_only/approved_private/unknown; approved_private requires a project policy binding |
| price | input/output/cached/request/unit prices, currency, source, valid_until; null means unknown |
| verification | docs_url, observed_at, checked_at, valid_until, probe_id, status candidate/verified/quarantined |
| task_quality | task_class -> benchmark_run, accepted_count, total_count, p95_latency_ms; no fabricated prior |

TTL defaults: capability/offer verification 24 hours, health 60 seconds, quota
snapshot 60 seconds; reset headers and runtime errors can invalidate earlier.
Essential unknown/expired fields trigger refresh or rejection. Status reports age.
Metadata fetch is not sufficient to prove JSON conformance or model quality.

## Resource ledger schema

| Entity | Keys and fields |
|---|---|
| quota_pools | pool_id; provider/account/model-family scope; shared membership |
| quota_windows | pool_id + dimension + window_id; unit requests/tokens/credits/etc.; fixed/rolling; limit; used; reserved; reserve_floor; reset_at nullable; observed_remaining; snapshot_watermark; source; observed_at |
| reservations | reservation_id; project/task/attempt; request_hash; state; created_at; lease_until; dispatched_at; reconciled_at; uncertainty_reason |
| reservation_items | reservation_id + quota_window/budget ID; reserved_amount; settled_amount nullable |
| budgets | scope task/project/global; period boundaries; ceiling_microusd; spent; reserved; policy version |
| approvals | approval_id; trusted issuer; project/task; route set; ceiling; expiry; used_at; policy hash |
| health | resource_id; state closed/open/half_open; failure count; cooldown_until; last_success; local queue/RAM/VRAM observations |

Reservation admission updates all dimensions in one transaction or none. Global
ledger writes must not leak project prompts to other projects. If project event
write fails after dispatch, the ledger retains usage; reconciliation links it
later by attempt ID. No cross-database atomicity is assumed. A transactional
outbox in the ledger records pending accounting events until project storage
acknowledges them; duplicates are deduplicated by event_id.

Window rollover moves subsequent admissions to the new window; unsettled old
charges remain assigned to their dispatch/billing period until reconciled.
Sliding windows require timestamped attempt usage, not an invented fixed reset.
External usage may invalidate local estimates; a dedicated key/account is advised.

## RouterDecision

`decision_id, task_id, policy_version, context_package_hash, evaluated_at,
candidates[{resource_id, eligible, rejection_codes[], tier, benchmark_ref,
estimated_latency_ms, headroom, estimated_cost_microusd}], selected_resource_id?,
override_reason?, reservation_id?, terminal_reason?`.

Example: private task excludes every cloud resource before ranking; local model
has insufficient context; paid cloud cannot bypass privacy; outcome is
`no_eligible_resource`, returned to Codex. Another example: free model A is TPM
blocked, B passes all checks, so choose B without contacting A.

## ContextPackage and Brain schema

`ContextPackage`: package_id, project_id, task_id, repo_identity, revision,
dirty_manifest_hash, created_at, expires_at, policy_version, task/acceptance,
privacy, items[{source_id, path_or_url, start_line, end_line, content_hash,
trust_class, selected_text, estimated_tokens, selection_reason}], total_input_estimate,
excluded_sources/reasons, missing_context, package_hash. Default lifetime 15 minutes;
hash validation is still required on use. Content package artifacts are private.

| Table | Primary key / important columns |
|---|---|
| projects | project_id; canonical roots, repo identity, policy revision |
| source_refs | project + source_id; path/URL, revision/hash, trust, sensitivity, fetched_at |
| chunks + FTS | project + source + revision + range; bounded excerpt, index_version; derived/rebuildable |
| decisions | project + decision_id + revision; text, source refs, author, proposed/accepted/superseded, supersedes_id |
| task_summaries | project + task_id; compact text, evidence, completion time, expiry |
| context_packages | project + package_id; hashes, artifact ID, expiry |
| jobs | project + job_id; idempotency hash, lifecycle, deadline, result ref |
| artifacts | project + artifact_id; relative storage key, MIME, byte length, digest, expiry, producer |
| evaluation_outcomes | project + task + evaluation revision; accepted, tests, corrections, redo, evaluator |

Per-project DB separation is not sufficient alone: all DAO methods still require
ProjectScope. The caller never chooses a DB file. Global conventions are explicitly
approved local records, not cross-project search results. Decisions referencing
Git ADRs store links; writing `remember` does not modify Git. Optimistic revision
checking rejects concurrent changes; authority is explicit, not last-write-wins.

## Telemetry schema

Every event: `event_id, schema_version, timestamp, trace_id, project_id, task_id,
job_id?, attempt_id?, event_type, policy_version, config_hash`.

Attempt fields: `task_class, route_decision_id, adapter/provider/model/endpoint,
context_hash, context_tokens, input_tokens, output_tokens, reasoning_tokens,
cached_tokens, token_measurement_source, quota_consumed[{pool,unit,amount,source}],
cost_estimated_microusd, cost_actual_microusd?, cost_source, queue_ms, provider_ms,
end_to_end_ms, retry_index, status, error_code, validation_result, artifact_ids`.

Outcome fields: `benchmark_pair_id?, codex_model/version?, codex_input_tokens?,
codex_output_tokens?, codex_context_peak?, measurement_source, missing_reason?,
accepted?, tests_passed?, tests_total?, quality_score?, human_corrections?,
human_minutes?, codex_redo?, codex_redo_minutes?, evaluation_revision`.
Outcome is separate because Codex acceptance happens after provider success.
Unreported redo is unknown, not false. Counters join by IDs rather than summing
duplicated trace events. Prompt/code content and credential IDs are not log labels.

## Illustrative configuration

This configuration is intentionally offline until accounts/models are verified.
Numeric limits are Hub policy defaults, not provider quota facts.

```toml
schema_version = 1

[server]
transport = "stdio"
state_dir = "/var/lib/devhub"
single_instance = true

[policy]
allowed_offer_classes = ["CORE_FREE", "DEV_FREE", "FREE_CREDITS"]
max_attempts = 3
deadline_ms = 120000
context_token_cap = 8000
summary_token_cap = 1500
free_reserve_fraction = 0.10
paid_mode = "disabled"
global_monthly_budget_microusd = 0

[projects.fixture]
roots = ["/repos/fixture"]
privacy = "local_only"
daily_budget_microusd = 0
allowed_paths = ["src", "tests", "docs", "README.md"]
denied_paths = [".env", ".git", "secrets"]

[providers.groq]
enabled = false
adapter = "groq"
secret_env = "DEVHUB_GROQ_KEY"
account_pool_id = "groq-account-1"
model_allowlist = []

[providers.gemini]
enabled = false
adapter = "gemini"
secret_env = "DEVHUB_GEMINI_KEY"
account_pool_id = "gemini-project-1"
model_allowlist = []

[providers.openrouter]
enabled = false
adapter = "openrouter_free"
secret_env = "DEVHUB_OPENROUTER_KEY"
model_allowlist = []
allow_paid_substitution = false

[providers.ollama]
enabled = false
adapter = "ollama_local"
endpoint = "http://127.0.0.1:11434"
model_allowlist = []
allow_cloud = false
max_concurrency = 1

[providers.paid]
enabled = false
adapter = "openai_compatible_paid"
model_allowlist = []

[tools.search]
enabled = false
adapter = "tavily"
secret_env = "DEVHUB_TAVILY_KEY"
max_sources = 5
paid_overage = false

[sandbox]
enabled = false
executor_socket = "/run/devhub-executor/control.sock"
network = "none"
cpu_limit = 2
memory_mib = 2048
pids_limit = 128
image_allowlist = []

[telemetry]
payloads = false
metadata_retention_days = 90
artifact_retention_days = 7
```

Enablement requires exact models, price/quota evidence and credential validation;
an empty allowlist never means all models. Paid endpoint/secret must be supplied
through trusted operator configuration before paid_mode can change. Loopback
Ollama address is for native service; Compose must use an explicit reachable host
address and restrict it to the local inference service, not the research fetcher.

Codex-side shape, to test during Stage 1 (future executable name):

```toml
[mcp_servers.devhub]
command = "devhub"
args = ["serve", "--transport", "stdio", "--config", "/absolute/path/devhub.toml"]
```

This does not configure the user's current Codex installation. Provider secrets
stay in the Hub environment/secret store, not in checked-in TOML or prompts.
