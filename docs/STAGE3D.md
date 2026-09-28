# Stage 3D: bounded Groq execution

Status: implementation awaiting review. Stage 3C remains CLOSED with its local
execution/accounting gate passed; semantic quality remains unestablished. Gemini,
general cloud routing and the B-arm benchmark are not enabled by this slice.

## Shared execution boundary

The explicit `python -m devhub.cloud_server --config <local-config.json>` stdio
entry point exposes `devhub_cloud_probe`. The default server stays offline.
The strict MCP task schema accepts no credentials, endpoints, export approvals,
provider options or quota policy. Trusted operator configuration supplies non-secret
policies. No key is present in CloudConfig or any DTO.

The path is Brain -> Context Builder -> approved export -> account/model probe ->
full-request estimate -> Capability Registry -> Router -> ResourceController ->
reservation -> source/export revalidation -> dispatch commit -> one HTTPS send ->
settlement / unknown usage -> outbox -> compact handoff. Both Ollama and Groq use
`execution.py` for reservation, revalidation/dispatch and settlement. There is no
cloud bypass. Capability records retain the exact model ID.

Credentials come only from `HKCU\Environment\GROQ_API_KEY` (Windows user environment),
inside the HTTP boundary. Process overrides, machine environment, .env and repo
configuration are ignored. Keys are never stored on the adapter or emitted in errors.
Transport exceptions become stable codes; raw response bodies remain ephemeral.
Credential echoes are rejected. Only TLS-verified `api.groq.com` and GET
`/openai/v1/models` / POST `/openai/v1/chat/completions` are available. The client has
no SDK retries, redirects, proxy discovery or fallback; responses are capped at 1 MiB.

## Public/redacted export

Brain stays project_private; ContextPackage stays local_only. A separate operator
ExportPolicy binds project/worktree identity, full task hash, source hashes,
selected excerpt hashes and outgoing text hashes. Public grants release exactly
reviewed text. Redacted grants select explicit whole LF-lines and verify the
outgoing hash. Every provenance reference on a deduplicated excerpt needs approval;
conflicting releases fail closed. Changed CRLF/LF bytes require new hash approval.

Outgoing content contains only approved instructions, criteria, citation IDs and
released text. Paths, root identities, revision metadata, original private content
and original provenance do not go to Groq. Local receipts map citations back to
original source hashes/lines, per-source release classification/line selections,
package hash, task hash and approval hash. No AI redactor or probabilistic secret
scanner authorizes release. Operators must review the exact text they approve.

The adapter accepts only a process-local integrity-sealed ReleasedPayload, never a
raw ContextPackage or MCP dictionary. Recomputing a hash cannot authorize altered
text. This application boundary is not a sandbox against malicious Python code in
the process. Sources and export are revalidated after reservation, before dispatch.
Canary tests prove both denial of an unapproved changed source before adapter
preparation, and removal through explicit redaction before adapter input. Task and
cross-project content cannot borrow a source approval.

## Model and admission semantics

The initial configuration selects `qwen/qwen3.8-27b`, reasoning_effort=none. The ID,
profile documentation, reasoning mode and limits are configuration, not architecture
constants. This is a preview model. Its active ID and context/output limits must
match /models before reservation. Text/JSON capability comes from operator-qualified
model documentation; catalog presence alone does not prove inference entitlement
or quality. No substitute model is selected when the configured one is unavailable.

/models exposes no serving tokenizer/chat template. The
`utf8_request_bytes_plus_wrapper_v1` estimate counts the complete serialized request,
including system prompt, messages and response options, plus a wrapper allowance
(default 1024). Reserved output and safety margin (default 256) must also fit both
the live context and the operator's probe cap (at most 4096). This conservative
estimate is neither an actual model tokenizer count nor a mathematically verified
upper bound. There are no tools or additional runtime-generated messages.

Handoffs preserve offline_context_proxy, provider_input_estimate and actual provider
input/output tokens separately. model_input_tokens_preflight remains null because
no exact tokenizer ran. An estimate/output overshoot is fully settled and reported
failed; the consumed one-shot permit prevents another inference. General cloud
execution with a calibrated tokenizer is not claimed by this slice.

## Quota bootstrap

Free is an operator declaration, not a fact inferred from /models. The account
field is a stable operator-assigned organization alias, not server attestation.
All projects using that account must share its protected ledger and alias. Creating
another ledger is not a recovery procedure or permission for another request.

Only actually observed quota headers are recorded. Unknown RPD/TPM/RPM/TPD remain
null; published free-tier tables are not imported as account availability. There
is a deliberate distinction between provider quota and the explicitly authorized
one-request smoke. The regular controller still rejects unknown bucket capacity.
This opt-in entry point installs separate operator ceilings: one request, at most
4096 estimated input+output, an expiry, and a durable single-probe account policy.
Those ceilings are not provider quotas. allow_free_probe defaults false; general
live free execution and live paid execution remain unsupported.

Migration 4 persists observations. Request headers mean RPD; token headers mean
TPM, not RPM/TPD or separate input/output limits. Partial, duplicate or malformed
headers fail closed. Known insufficient remaining quota, stale observations,
elapsed reset windows and active retry-after deny admission. Header-less probes
cannot erase observed restrictions. Checks run transactionally at reservation and
again at dispatch. The single-probe account check and one-live-inference guard
share BEGIN IMMEDIATE with the hold; another key, task or model cannot reset the
permit. Post-inference headers are persisted with timestamp/source and included
in the handoff; they do not create a new grant. No automatic unknown-usage expiry.

## Failure and accounting behavior

- Dispatch and its event commit before inference HTTP send.
- Timeout, transport ambiguity, invalid/incomplete usage, wrong model identity or
  unparseable envelopes retain unknown_usage and held resources; actuals stay null.
- 401 is auth, 403 entitlement, 429 rate_limit, 5xx transient, 408 timeout; other
  errors are permanent. Categories never manufacture zero usage or trigger retry.
- Exact-model, complete prompt/completion/total usage settles before validation of
  generated JSON/schema, truncation or overshoot, even when the attempt fails.
- Nothing releases an ambiguous dispatch commit. Expired reserved leases recover
  as released; dispatched leases recover as unknown; request replay is denied.
- A probe permit stays consumed even after pre-send release. Another live request
  requires explicit operator review, not automatic policy renewal.

## Verification

Offline tests cover canary denial/redaction, task/project binding, payload integrity,
stale context, full-request admission, model identity, quota dimensions/constraints,
strict MCP arguments, HTTP failures, no retry/redirect, honest unknown usage,
settlement on invalid output, concurrent last permit and crash/restart recovery.
Windows and WSL use separate environments. Offline tests never use real credentials.

[Live stdio MCP evidence](evidence/stage3d-groq-smoke.json) records exactly one
inference on implementation commit `346cd00`: HTTP 200, 250 ms HTTP latency,
97 actual input tokens and 12 output tokens, with reserved/dispatched/settled
outbox events. Offline byte proxy was 867; full-request estimate was 1648; exact
preflight tokenizer count remains null. The returned summary was "The synthetic
lighthouse is blue." No follow-up inference or prompt tuning was performed.

The discovery response had no rate-limit headers. The inference response reported
RPD limit 1000 / remaining 999 / reset 1m26.4s and TPM limit 8000 / remaining 7807 /
reset 1.447s. RPM/TPD remain null. Header-counter deltas are not usage receipts;
settlement uses the explicit provider usage, not a subtraction of remaining quota.
The account plan is still operator-declared. The one-shot permit is now consumed.

A synthetic smoke cannot
establish semantic quality, Delegation Value, savings or benchmark quality; these
remain null. Stage 3E/Gemini waits for review of this PR.

## Upstream contracts

- [Model catalog](https://console.groq.com/docs/models)
- [Initial Qwen preview profile](https://console.groq.com/docs/model/qwen/qwen3.8-27b)
- [RPD/TPM header semantics](https://console.groq.com/docs/rate-limits)
- [Request and usage fields](https://console.groq.com/docs/api-reference)
- [Error categories](https://console.groq.com/docs/errors)
