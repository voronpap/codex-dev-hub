# Stage 3E: Gemini acceptance gates

Status: not implemented. Stage 3D is accepted and CLOSED. This document records
the next provider's requirements; it does not authorize paid execution or claim
a Gemini account, model, quota or live result has been verified.

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
