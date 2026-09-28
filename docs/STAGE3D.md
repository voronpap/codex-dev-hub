# Stage 3D: Groq acceptance gates

Status: not implemented. Stage 3C's execution/accounting gate is accepted; semantic
quality remains unestablished. Preserve the existing citation misses for Stage 3G.
Do not optimize prompts against the individual smoke cases.

## Required execution boundary

Groq must reuse Brain/Context, model-specific admission, Capability Registry,
Router, ResourceController, revalidation, durable dispatch, usage normalization,
settlement/outbox and compact handoff. No cloud-specific execution shortcut.

1. API keys come only from a secret/environment boundary, never DTOs, logs or evidence.
2. Bind an exact approved model ID and account/plan metadata; never infer the plan
   from a published free-tier table or silently choose another model.
3. Verified account limits and response rate-limit headers constrain ResourceController.
4. Document provider input-estimation/tokenizer semantics before admission; preserve
   the independent offline context proxy and actual provider usage measurements.
5. Commit the dispatch marker before network send. Disable SDK retries, or use a
   transport that sends exactly once and never follows redirects with credentials.
6. Normalize 429, 401, 403 and 5xx according to the agreed failure policy; a status
   code alone must not fabricate complete zero usage after dispatch.
7. Timeout after send retains `unknown_usage`; settle only complete trusted usage.
8. Invalid generated output still accounts for valid provider usage.
9. Cloud privacy defaults to explicitly approved **public/redacted** content only.
   Existing `project_private` Brain evidence is not implicitly relabeled for cloud.
   Private-source terms require separate confirmation before enabling that path.
10. No automatic model fallback. Keep live smoke to one short request within verified
    free quota, using public synthetic text; do not claim quality or savings.
11. Apply the same contracts to Gemini only after the Groq slice is reviewed.

## Verified upstream distinctions

Groq's documented `x-ratelimit-*-requests` headers describe **requests per day**;
the `x-ratelimit-*-tokens` headers describe **tokens per minute**. They do not by
themselves establish RPM or every account limit. `retry-after` is documented on
429 responses. Header names cannot be mapped to arbitrary quota windows.
Account-specific limits must be established separately, with provenance and expiry.
See [Groq rate limits](https://console.groq.com/docs/rate-limits).

HTTP error categories describe authentication, permission, throttling and server
failures; they do not constitute token-usage receipts. See
[Groq errors](https://console.groq.com/docs/errors). Model availability and context
limits must be checked against the exact configured model and live account;
see [supported models](https://console.groq.com/docs/models).

## Inputs needed for a live proof

The operator supplies the account/plan, exact allowed model ID, key environment
variable or secret reference, and verified quota metadata. The key value must not
be pasted into review artifacts. Without those inputs, only offline contract/tests
can be qualified; no live Groq gate or free-plan eligibility can be claimed.
