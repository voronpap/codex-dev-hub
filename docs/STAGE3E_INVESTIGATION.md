# Stage 3E: offline investigation of the first countTokens 404

Date: 2026-09-28. Outcome: `root_cause = unknown`; live follow-up NOT AUTHORIZED
by this investigation. Stage 3E remains OPEN. PR #18 was subsequently accepted and
merged as partial implementation; its live gate remains NOT_PASSED. No new account
metadata, countTokens or generateContent call was made during this investigation.
Only public documentation/discovery schemas were fetched without credentials.

## Findings and uncertainty

The first probe used the documented method, hostname, API version, model path and
full-request wrapper. No wire-contract implementation bug explaining its 404 was
found. The original sanitized handoff lost the upstream error type/message; its
`count_model_unavailable` label was a local mapping of HTTP 404, not a provider
root-cause diagnosis. HTTP 404 can represent either a missing resource or model,
according to Google's [error reference](https://ai.google.dev/gemini-api/docs/api-errors).
New responses therefore normalize HTTP 404 to `not_found` (`count_not_found` for
counting). This is a diagnostic correction, **not a fix for the upstream 404**.
The historical label and evidence file are unchanged.

The [exact model page](https://ai.google.dev/gemini-api/docs/models/gemini-2.5-flash-lite)
now documents restricted Gemini 2.5 access for prior active users and directs new
projects to 3.5 Flash-Lite or 3.8 Flash. This is a material eligibility constraint
missing from the initial model selection. Prior authenticated UI evidence showed
our project was created on the probe date. An account/project eligibility restriction
is therefore a plausible explanation, but neither that creation date nor the
preserved status proves the backend's reason. The 2.5 models are not described as
deprecated. Do not relabel this as confirmed model retirement or a proven account ban.

| Candidate cause | Assessment |
|---|---|
| Wrong version / endpoint / model resource spelling | No mismatch found against both official discovery documents |
| Wrong request envelope or unsupported JSON fields | No mismatch found in the used schema; model supports budget zero and JSON output |
| Account/project restriction | Plausible from current model eligibility notice; not established as the cause of this response |
| Catalog/capability inconsistency | Observed successful advertised capability followed by failed counting; this does not establish a catalog bug |
| Exact model unsupported for counting globally | Not proven; no official blanket prohibition found |
| Unknown upstream behavior | Still possible; `root_cause = unknown` is retained |

## Exact REST contract

Sources: [countTokens](https://ai.google.dev/api/tokens),
[generateContent](https://ai.google.dev/api/generate-content),
[models](https://ai.google.dev/api/models),
[API versions](https://ai.google.dev/gemini-api/docs/api-versions), and Google's
[v1beta discovery](https://generativelanguage.googleapis.com/$discovery/rest?version=v1beta)
/ [v1 discovery](https://generativelanguage.googleapis.com/$discovery/rest?version=v1).
Both discovery documents returned revision `20260927`. Their SHA-256 values and
relevant field/method names are frozen in
[discovery-contract.json](../tests/fixtures/gemini/discovery-contract.json).

| Check | Verified contract and current implementation |
|---|---|
| API version | `v1beta`; documented and present in discovery |
| Count URL | `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-lite:countTokens` |
| Exact resource | `models/gemini-2.5-flash-lite` |
| Method | POST, JSON; key only in x-goog-api-key header |
| Envelope | Only `generateContentRequest` at the top level; no parallel top-level contents/model |
| Nested model | Required `GenerateContentRequest.model`, exact same model resource |
| System instruction | Supported text `systemInstruction.parts[].text` |
| Generation config | Included inside the full GenerateContentRequest |
| Thinking | `thinkingConfig.thinkingBudget = 0`; supported for 2.5 Flash-Lite by the model thinking guide |
| JSON output | `responseMimeType = application/json`; JSON mode, with local Summary validation, not a supplied schema guarantee |
| Count support | Saved catalog advertises countTokens; generic API supports this model-name form. Account execution remains unproven |
| Metadata guarantee | Models/get/list describe capabilities; neither response establishes billing, quota remaining or account eligibility |
| Version differences | Both discovery schemas include this count method and all used fields. No evidence that switching to v1 fixes this failure |
| Other endpoint forms | Vertex, OpenAI-compatible, Interactions and v1alpha are not substitute paths for this reviewed request; none were probed |

The count response schema does not echo a model ID. Exact-model binding comes from
the pinned credential, successful exact model metadata and configured request path /
nested model; a positive totalTokens alone cannot establish a different identity.
The entire serialized generation input is counted, with output capacity and margin
checked separately. This does not turn the offline byte proxy into provider tokens.

## Exact request fixture, not another send

[preflight-1-request.json](../tests/fixtures/gemini/preflight-1-request.json) contains
the exact canonical UTF-8 generation body and its wrapped counting body, paths and
hashes, with public synthetic content only. Offline reconstruction of the generation
body matched the first probe's durable `gemini_preflights.request_hash`:

`abefe2e812d50a67a8900f2fd16706d93216cf0a597e7828a067a454872015db`

This proves reconstruction consistency with the stored request, not a captured HTTP
transcript or a successful upstream parse. No API key/header value or credential
fingerprint is present. The request retains the original system prompt, task, public
lighthouse source, JSON mode, temperature 0, candidateCount 1, output cap 96 and
thinking budget 0. No prompt tuning occurred.

If a future reviewed permit authorized this model/profile, this fixture describes
the request shape; **nothing is scheduled or authorized to send it now**. Generation
would use the identical nested body minus its path-bound model field at
`POST /v1beta/models/gemini-2.5-flash-lite:generateContent`, only after successful count.

## Free/privacy/usage review

The [pricing table](https://ai.google.dev/gemini-api/docs/pricing) lists free Standard
text input/output for 2.5 Flash-Lite and 3.5 Flash-Lite. Published pricing does not
prove this account's access. The [billing guide](https://ai.google.dev/gemini-api/docs/billing)
explains the prior observed Set up billing state as no linked billing account.
This investigation did not renew the time-bound account qualification.
The [Unpaid Services terms](https://ai.google.dev/gemini-api/terms) permit product
improvement and human review; sensitive, confidential and personal data must not be
submitted. Ukraine remains operator-declared. Whole-line public/redacted release,
task/source/output binding, local provenance and both package validations remain.

The [rate-limit guide](https://ai.google.dev/gemini-api/docs/rate-limits) scopes quotas
to the project, including input TPM and RPD resetting at Pacific midnight. Historical
UI limits are not current remaining quota. No Groq headers/reset parser is reused.
RetryInfo and QuotaFailure remain sanitized evidence, never authorization to retry.

[UsageMetadata](https://ai.google.dev/api/generate-content#UsageMetadata) describes
prompt tokens including cached content, candidate tokens, thought tokens and total
prompt + thought + candidate tokens. Cache is not added twice; generated usage
includes thoughts. Optional absent dimensions remain null. Tool-use prompt counts
are separate; this profile has no tools and rejects unsupported positive tool-use
accounting. Missing required counts, inconsistent totals, malformed envelopes and
wrong model versions remain unknown_usage after dispatch. Complete usage settles
before safety/truncation/JSON validation. These semantics are unchanged.

[Token counting](https://ai.google.dev/gemini-api/docs/tokens),
[JSON output](https://ai.google.dev/gemini-api/docs/generate-content/structured-output)
and [thinking configuration](https://ai.google.dev/gemini-api/docs/generate-content/thinking)
were checked separately. Request-schema acceptance and model feature support do not
prove this project's entitlement or successful remote counting.

## Candidate for separate review; no fallback

`gemini-3.5-flash-lite` is the concrete Free text candidate recommended by the
[2.5 model notice](https://ai.google.dev/gemini-api/docs/models/gemini-2.5-flash-lite).
Its [model documentation](https://ai.google.dev/gemini-api/docs/models/gemini-3.5-flash-lite)
and pricing were checked. The previously saved models.list (no fresh API call) lists
version `3.5-flash-lite-07-2026`, 1,048,576 input / 65,536 output limit and both counting
and generation methods. This is stale discovery evidence, not current eligibility.
Its thinking profile needs separate review; do not carry over the 2.5 budget-zero
configuration blindly. No configuration/model change or candidate invocation occurred.

## Permit and validation decision

The later [provider catalogs](PROVIDER_CATALOG.md) preserve user-reported Gemini
account limits and documented Groq Free-plan limits without authorizing execution.
Positive Gemini 2.5 Flash Lite quotas do not prove endpoint eligibility or establish
the 404 cause; they also do not prove an account restriction. No new live probe was
performed to reconcile these observations. Root cause remains unknown.

No new permit was created: no unambiguous causal implementation fix was established.
The old project count claim remains consumed, tokens NULL, reservations/events zero.
The historical evidence file is unchanged and guarded by a fixture hash test.
The current one-claim-per-project implementation cannot authorize a second attempt.
A future reviewed grant must coexist with the old claim, bind project/account/model
and exact request hash, expire promptly, and atomically consume at most one count
and one successful-count-dependent inference attempt across crash/restart. Creating
a new state directory, changing a key or deleting the old row is not that grant.

Tests add independent exact wire fixtures (URL/method/version/nested model/canonical
JSON), documented field checks, no redirect, immutable historical evidence, broader
missing/malformed/wrong-model usage cases and non-causal 404 classification. Existing
privacy, count concurrency/restart, rotation, Free expiry, dispatch ordering and
settlement tests remain. CI results belong to the latest PR check run, not this
historical probe. No new live count or inference was executed; Stage 3F/3G unchanged.
