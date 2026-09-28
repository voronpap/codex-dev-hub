# Stage 3E: Gemini acceptance gates

Status: partial implementation accepted and merged in PR #18 on 2026-09-28.
At the PR #18 merge: **Stage 3E OPEN; live gate NOT_PASSED**.
The separately approved PR #19 follow-up now demonstrates **execution/accounting
gate PASSED; Stage 3E CLOSED**. Output validation
returned `invalid_output` after complete usage settlement; semantic acceptance is null.
Merge accepts the adapter, fail-closed behavior, offline contract investigation and
provider catalogs; it does not establish successful Gemini execution.
Stage 3D is accepted and CLOSED.
The default MCP status server remains offline. Gemini is an explicit one-shot
Free Developer API probe through `devhub.cloud_server`, using `GeminiCloudConfig`.
No general routing, paid execution, Stage 3F or benchmark is enabled.

## Approved follow-up

[Follow-up review and live result](STAGE3E_FOLLOWUP.md) records the approved one-shot
3.5 Flash-Lite run and its consumed permit. The frozen proposal remains an inactive
historical artifact. No further count/inference is authorized.

[Offline 404 investigation](STAGE3E_INVESTIGATION.md): root cause remains unknown.
The documented wire contract matches; current Gemini 2.5 eligibility restrictions
are a plausible account-level explanation. No new permit or live call was made.
New 404 diagnostics say `not_found`; the historical failure remains unchanged.

## Implemented boundary

`CloudRuntime` now composes either configured provider through the same Brain,
Context Builder, export, Capability Registry, Router, ResourceController and
execution functions. Provider-specific count, usage and quota logic stays separate.
`cloud_types` contains credential-free request/envelope types shared with Groq.
Groq's existing configuration and request behavior remain supported.

The configured Gemini profile is single-candidate JSON text with thinking budget
zero, no tools, grounding, files, explicit cache, streaming or model fallback.
The model ID is configuration, not a runtime constant. Metadata must prove both
`generateContent` and `countTokens` support and sufficient input/output limits.
The existing whole-line release approval and process-local payload seal protect
both remote counting and generation. A fresh package validation precedes counting;
another precedes inference dispatch.

`FreeQualification` is a **trusted local operator/reviewer record**, not an API
attestation or model-supplied claim. It records an authenticated AI Studio check
of the exact project, billing disabled, Free tier, country, reviewed pricing and
unpaid data use. Unknown/paid/enabled/expired qualification fails closed. Its maximum
lifetime is one hour; recheck AI Studio immediately before a live probe. This limited
slice does not continuously monitor external billing changes. Do not edit timestamps
to make old evidence fresh. The credential's project association must be independently
verified; `models.list` cannot establish it. The transport pins the Windows User key
identity from metadata through counting and generation, without persisting the key
or its fingerprint in configuration, DTOs or evidence.

Migration 5 adds `gemini_preflights`. Before the content-bearing count call, a short
transaction permanently claims the project-scoped count permit, including the
qualification and exact generation-request hash. One count attempt is allowed even
across threads/restarts; a crash or timeout cannot automatically repeat it. The
full `generateContentRequest`, including system instructions and generation settings,
is passed to `countTokens`. Successful counting records its positive count durably;
only then may the shared Controller reserve inference. A failed count leaves no
inference reservation and the count permit remains consumed. The count method's
provider quota consumption remains unknown; its local one-shot ceiling is separate.

The Controller checks the stored Free qualification at reservation and dispatch,
requires the counted input amount, and applies Gemini **input** TPM semantics. The
one-inference permit is project-scoped, so another key/model does not grant another
attempt in this ledger. UI limits are recorded separately from remaining capacity:
historical peaks, including zero, never become remaining quota. Daily reset is
midnight America/Los_Angeles; no rollover/replenishment is implemented for this
one-shot permit. Gemini does not borrow Groq's rate-limit header names. Only numeric
Retry-After and sanitized structured RetryInfo/QuotaFailure evidence are retained;
there is no retry. Unknown remaining quotas stay null.

The count, offline byte proxy and actual usage remain separate. Usage requires an
exact response model ID and complete prompt/candidate/total counts with conservation.
Thought tokens contribute to generated output; cached tokens are already included
in prompt count. Absent optional dimensions remain null. A missing candidate count,
including on a blocked response, is not invented as zero. Complete usage settles
before output validation, including invalid JSON, safety or truncation. Incomplete
usage, transport ambiguity and post-dispatch failures retain `unknown_usage`.

Credentials are loaded only from Windows User `GEMINI_API_KEY`, never process env,
files or MCP arguments. HTTPS uses a fixed Google hostname and exact model paths,
with no redirects, proxies, retries or fallback; provider messages are not logged.

## Validation

Offline tests cover the full shared MCP path, pre-send dispatch commit, canary
rejection before remote counting, explicit redaction, stale source after count,
immutable counted body, exact request counting, Free/billing/terms expiry gates,
count permit concurrency/restart, inference crash/recovery, provider errors,
thought/cache conservation, missing usage and malformed output. Existing Groq,
Ollama, Controller and Brain tests remain regression coverage.

## Historical first preflight: gate NOT PASSED

[Recorded public synthetic probe](evidence/stage3e-gemini-preflight.json), 2026-09-28,
implementation `de32099`. Authenticated AI Studio showed project `836602474597`
(`gen-lang-client-0241797686`) as Free tier with Set up billing. The official
[billing guide](https://ai.google.dev/gemini-api/docs/billing#verify-billing-status)
identifies that action as no linked billing account. The displayed key was matched
by SHA-256 with Windows User environment without exposing or publishing its value
or fingerprint. Country Ukraine is operator-declared. No billing setting changed.
The selected exact model `gemini-2.5-flash-lite` has free Standard text input/output
pricing. AI Studio showed 10 RPM / 250,000 input TPM / 20 RPD; remaining capacity
is unknown. Those limits are evidence for this account/model, not runtime defaults.

`models.list` and the exact model metadata request succeeded. The model advertised
both required operations. **The one full-request countTokens call returned HTTP 404**,
normalized to `count_model_unavailable`. No inference reservation, dispatch marker,
generateContent send or settlement occurred. The project count permit remains
consumed with tokens NULL. No retry, second model or fallback was attempted.
Discovery alone therefore did not prove this model's counting endpoint usable.
The failure's root cause is not established by the sanitized status alone.

The original handoff/evidence is retained unchanged, including null metrics. A later
change improves preflight error diagnostics (HTTP status, latency, response hash and
package/export binding), tested offline only. No second live call was made to obtain
better evidence. At that point Stage 3E stayed OPEN and required a separately reviewed follow-up.
The new follow-up above preserves this historical failure and consumed claim. Do not reset this ledger, edit the
permit or switch models merely to obtain a green smoke. No semantic, quality,
savings or Delegation Value claim is made.

## Reuse the accepted boundary

Gemini must use the same explicit public/redacted export, local provenance,
Capability Registry, Router, ResourceController and shared execution boundary as
Ollama/Groq. A private ContextPackage cannot become adapter input. Keep canary,
task/project binding, sealed-payload integrity and source revalidation tests.
Export approval must precede **every** outbound content-bearing call, including
remote token counting, not just inference. Revalidate again before dispatch.

Use an exact configured model ID and verified supported operations/context/output
limits. Discovery is not evidence of billing tier, remaining quota or quality.
Keep secrets in an explicitly selected local secret boundary, outside DTOs,
configuration, URLs, logs and evidence. Pin credential identity across discovery,
counting and execution. No SDK retry, redirect, model fallback or implicit billing.

## Free-tier data-use qualification

Checked 2026-09-28 against [Gemini API terms](https://ai.google.dev/gemini-api/terms),
effective 2026-03-23. The general Unpaid Services terms allow Google to use submitted
content and generated responses for product improvement, including human review,
and prohibit submitting sensitive, confidential or personal information. Regional
exceptions apply in the EEA, Switzerland and UK. API clients made available to users
in those regions have a separate Paid Services requirement. Do not infer the relevant
account/usage region from a timezone or assume one global privacy rule.

Gemini API Paid Services treatment depends on the Cloud project's active billing
association. A free allowance, AI Studio UI access, or a model listing is not
sufficient evidence of the API project's terms. Record project/tier/region and
the applicable terms version before live use. Do not enable billing as a privacy
workaround in this stage. Default scope remains public synthetic or explicitly
reviewed redacted content, with no confidential/personal data left in the release.

## Provider-specific quota and token semantics

[Gemini limits](https://ai.google.dev/gemini-api/docs/rate-limits) are scoped to
the project, not the API key. Documented dimensions include RPM, **input** TPM and
RPD; daily request quotas reset at midnight Pacific time. Actual limits depend on
model/tier and are visible in AI Studio. Bind shared pools to the actual project
and verified dimensions/windows; key rotation must not create extra capacity.
Do not reuse Groq's RPD/combined-TPM header parser, infer limits from model discovery,
or fill unknown values with unlimited. Verify the quota impact of discovery and
countTokens separately. An operator probe ceiling is not provider quota evidence.

Use [countTokens](https://ai.google.dev/api/tokens) with the full supported request
representation, including system instructions and any schema/tool overhead.
Preserve its provenance, exact model/request binding, the independent offline
byte proxy, reserved output and safety margin. Count failure or an unsupported
request shape must fail closed before inference admission.

[GenerateContent usage metadata](https://ai.google.dev/api/generate-content#UsageMetadata)
has prompt, candidate, thought, cached-content and tool-use fields. Preserve raw
numeric dimensions with provider provenance and verify their relationships before
normalizing into Controller units; cached tokens are not blindly added twice and
thought tokens are not discarded. Missing fields must follow verified API omission
semantics or remain unknown, not a generic zero default. Do not copy Groq's usage
envelope or assume visible candidate tokens are all generated tokens. Keep the
initial slice text-only, single candidate, without tools/grounding or explicit cache.

## Acceptance evidence

- Durable reservation and dispatch commit before inference send; one live inference
  by default, no automatic retries or model switches.
- Timeout/ambiguous send/incomplete usage retains liability as unknown_usage.
- Complete verified usage settles even for blocked, truncated or invalid output;
  safety-blocked content is not automatically evidence of zero usage.
- Provider-specific auth, entitlement, quota, transient and context errors, including
  observed structured quota/retry details, have explicit tests and safe messages.
- Crash/restart, last shared slot, request replay and credential rotation tests
  preserve the accepted Controller behavior.
- A separately authorized minimal public synthetic smoke records model/version,
  counting result, actual usage dimensions, observed quota evidence, accounting
  events and latency. Unknowns remain null; no quality, savings or Delegation Value
  claim follows from one request.

Live prerequisites: operator-selected project/alias, billing/tier and applicable
region, secret environment reference, exact available model and applicable quota
evidence. These are not inherited from the Groq account. Implement and review this
slice separately before Stage 3F or any general cloud routing expansion.
