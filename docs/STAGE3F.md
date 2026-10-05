# Stage 3F: unified delegation

Status: Stage 3F CLOSED; Local unified delegation gate PASSED. PR #21 accepted
and merged after full Linux, Windows smoke and full Windows CI on 2b8c5d8
(Actions run 36476939766). Accepted 3C/3D/3E execution gates remain closed;
semantic quality and provider comparisons remain unestablished.

## Normal MCP contract

Run `python -m devhub.delegate_server --config <trusted-local-json>` and use
`devhub_delegate`. The offline status server and diagnostic `devhub_local_task` /
`devhub_cloud_probe` remain available for regression evidence. A server is bound to
one project/worktree and one shared ledger. Provider profile tuple order is explicit
operator policy, not an inferred quality ranking. Only installed/verified Ollama,
Groq Free and qualified Gemini Free config contracts can be configured; no catalogs
are loaded and no paid adapter or fallback is enabled.

The trusted config now includes one exact `ledger_identity` shared by all profiles.
Provision it once with `--initialize-ledger`; ordinary server startup never creates
missing accounting authority. See [Ledger identity](LEDGER_IDENTITY.md).

`DelegationRequest` v1 reuses LocalTask and adds project, explicit task_class
(`summarize`, `explain`, `extract`), privacy, allow_cloud and require_citations.
Classification is explicit/deterministic, not an LLM guess. Cloud requires both
caller allow_cloud and trusted cloud_enabled plus public/redacted privacy.
local_only/project_private always exclude cloud before runtime construction.
Caller intent never releases private context: every cloud task/source/output must
still match the separately reviewed ExportPolicy and sealed ReleasedPayload.
Extra fields (credentials, endpoints, model IDs, quotas, billing overrides) fail
strict MCP validation without echoing their values.

The trusted config has profiles [{id, config, task_classes}] and cloud_enabled
(default false). Each config is an existing LocalConfig, CloudConfig or
GeminiCloudConfig. All profiles must share project, root and state_root. State must
remain outside the project. Model IDs/endpoints come only from these configs.
The operator must reuse existing accounting state; this entry point never resets
permits or issues new cloud authorization. The consumed 3D/3E permits remain
consumed. Further live cloud delegation needs a separate reviewed proposal; this
stage does not expand one-shot account grants into general cloud quota.

## Shared execution

Policy filters task class/privacy, then tries eligible profiles in configured order.
The selected runtime indexes Brain, builds/deduplicates/budgets/revalidates context,
verifies model/token admission, and uses the existing Capability Registry, Router,
ResourceController and execution helpers. No second quota or accounting engine exists.
Provider-specific metadata/count semantics remain in accepted adapters. The Router
and Controller make final resource admission using the selected prepared request;
no inference reservation precedes provider selection or Gemini counting.

An ineligible candidate can advance only while no reservation exists for this
project/request key. Any reservation (including one released on revalidation)
terminates selection conservatively. After dispatch there is no cross-provider
fallback, retry, or second send. Shared-ledger request replay and single-live-slot
checks survive restart. Unknown usage remains liability, never zero.

## Structured output and compact handoff

A trusted optional OutputPolicy enables the new provider output contract without
changing the historical diagnostic request bodies. All selected modes request:

```json
{"schema_version": 1, "summary": "Brief answer", "citations": ["s1"]}
```

Version is mandatory, summary <=800 characters, extra fields forbidden, citations
unique and limited to IDs actually supplied in this invocation. Local source IDs
bind ordered ContextPackage items; cloud IDs come from the exact ExportReceipt.
IDs are package-local, not globally reusable references. Missing required or invented
citations fail validation; optional citations still cannot be fabricated. This does
not test whether a source actually supports a claim: semantic acceptance remains null.
The provider never rereads the repository. Provenance remains in the package/export
receipt locally, with package/export hashes in the compact handoff.

The full Ollama prompt including the new schema instructions and source IDs is counted
by the model tokenizer before reservation. The deterministic offline byte proxy stays
separate. Gemini counts the full changed request; old request-hash permits cannot
implicitly authorize it. Groq retains its explicitly named conservative estimator.

Result v1 separates status/reason, execution, accounting, output_validation,
citations_validation, provider/model, summary/citations, package/export hash,
input preflight, actual usage, latency and accounting reference. It never returns
ContextPackage or credentials. Complete usage settles before schema/citation failure.
HTTP 200 and settled accounting do not imply task acceptance. semantic_acceptance,
quality_benchmark, delegation_value and savings remain null.

## Verification and scope

Offline tests exercise private/cloud eligibility, cross-project denial, stale package,
fabricated/missing/duplicate citations, deterministic selection before reservation,
pre-reservation candidate advance, dispatch-before-send, post-dispatch stop, replay,
unknown usage, invalid-output settlement, secret/extra-field rejection and real MCP
stdio with a Unicode/spaced config path. Existing provider tests remain regression
coverage for model, count, quota, privacy, timeout and credential contracts.

First live proof is real Codex -> devhub_delegate -> shared pipeline -> already
installed allowlisted Ollama -> validated structured handoff. No auto-pull, new cloud
inference, prompt tuning of the old smoke, adaptive routing, benchmark, DeepSeek,
paid provider, embeddings or AI Platform facade. Final closure requires Linux full
and Windows full CI; ordinary Windows smoke cannot replace the stage-close gate.

## Real local proof

[Machine-readable evidence](evidence/stage3f-local-delegation.json) records a real
Codex CLI 0.155.0-alpha.9.2 call over MCP stdio on implementation `5b59bd5`.
The existing numeric-loopback endpoint and installed qwen2.5:14b-instruct manifest
allowlist were reverified; the Stage 3C ledger was reused, not reset. The task used
local_only context from docs/STAGES.md through the normal devhub_delegate entry point.
Its single inference returned completed/validated with citation s1. Offline byte
proxy was 2184, model preflight and actual input both 767, output 119 (886 total),
inference latency 20311 ms. Output schema and citation membership both passed.
Outbox: reserved -> dispatched -> settled; the observer checked committed dispatch
at the HTTP send boundary. Retry/fallback: zero. No Groq/Gemini call or model pull.

The first Codex invocation was blocked by host approval configuration before the
runtime ran: zero reservations and zero sends. Its transcript hash and failure
remain recorded. The subsequent invocation used the documented per-tool
`mcp_servers.devhub_delegate.tools.devhub_delegate.approval_mode="approve"` only for
this already operator-authorized, exact, local one-shot proof. The shell sandbox
stayed read-only; no global config or tool annotations were weakened. Request,
model and prompt were unchanged. The observer enforced one exact request and at
most one send. This was host setup recovery, not a provider retry.

For normal Codex setup, review the configured providers and approve the tool at the
host boundary explicitly. See the [Codex configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference).
Do not copy a broad approval into a cloud-enabled configuration without reviewing
its export and account permissions. This proof's configuration had cloud disabled
and only the verified local profile. Raw context/provenance stays local; the handoff
is compact and untrusted. Semantic acceptance/value/savings/quality stay null.

## Optional observability

The trusted delegation config may enable `telemetry_footer` (`off` by default).
A derived summary is attached after execution; the structured handoff and accounting
remain authoritative and unchanged. See [task usage](USAGE_FOOTER.md) for scope,
unknown values, baseline provenance and API-cost limitations.
