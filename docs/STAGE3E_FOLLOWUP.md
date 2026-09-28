# Stage 3E follow-up: candidate and one-shot grant review

Status: operator-approved follow-up executed once on accepted implementation
`a1037e2`. **Live execution/accounting gate PASSED; Stage 3E CLOSED.** PR #19 accepted and merged. Runtime output validation failed
(`invalid_output`); complete actual usage was settled before returning failure.
This gate establishes execution/accounting only, not semantic acceptance or quality.
The original 2.5 Flash Lite HTTP 404 and consumed claim remain unchanged;
root cause remains unknown. The approved 3.5 request was not an automatic fallback.

## Approved live result

[Machine-readable evidence](evidence/stage3e-followup-live.json) records the single
2026-09-28 follow-up through the real MCP stdio server. Fresh authenticated AI Studio
qualification matched the Windows User key to project `836602474597`, Free tier,
Set up billing and No billing account. Official Standard Free pricing and unpaid
public-data terms were reviewed. The exact model account UI showed 15 RPM / 250K
input TPM / 500 RPD; remaining capacity stays null. Catalogs do not authorize runtime.

Permit `gemini-followup-836602474597-02` was issued in the existing ledger, bound to
the approved request hash and review digest, with a ten-minute lifetime. It is now
consumed. Migration preserved the original failed claim; no historical reset occurred.
Two exact-model metadata GETs occurred (before issuance and within the runtime).
Exactly one count returned HTTP 200 / 81 tokens in 203 ms, before any reservation.
Exactly one generation returned HTTP 200 in 3328 ms. The HTTP boundary asserted
frozen request bytes, successful durable count and a committed dispatch marker.
Outbox order was `reserved -> dispatched -> settled`; actual usage was 81 prompt,
11 candidate/output and 92 total tokens. Absent thought/cache/tool dimensions remain
null. Offline byte proxy remains 867, distinct from the provider count and usage.

The runtime returned `failed / invalid_output` after settlement. Sanitized evidence
does not distinguish the precise JSON/shape failure; raw output was not retained.
No retry, fallback, prompt tuning or extra inference was performed to diagnose it.
Semantic acceptance, Delegation Value, savings and quality benchmark remain null.
The approved request and inactive proposal below are retained as historical review
artifacts; they must not be reactivated or replayed. No further live call is authorized.

## Candidate review (pre-execution record)

Propose **gemini-3.5-flash-lite**, with `gemini-3.1-flash-lite` recorded only as a
reviewed alternative, not an executable fallback. Both exact IDs come from official
model documentation, not UI display-name conversion:

- [3.5 Flash-Lite](https://ai.google.dev/gemini-api/docs/models/gemini-3.5-flash-lite)
- [3.1 Flash-Lite](https://ai.google.dev/gemini-api/docs/models/gemini-3.1-flash-lite)

Both document 1,048,576 input / 65,536 output tokens, text output and structured
output support. The [pricing table](https://ai.google.dev/gemini-api/docs/pricing)
lists Standard Free input/output for both. Published prices do not qualify our
account or remaining quota. The newer stable 3.5 candidate fits the same reviewed
smoke capabilities; no measured quality or savings advantage is claimed.

During preparation, exactly two authenticated, metadata-only model GETs returned 200 with the exact
names, limits and advertised countTokens/generateContent methods. See
[sanitized metadata evidence](evidence/stage3e-followup-metadata.json).
No counting, generation, retry or fallback happened during that preparation. Credentials were read only
from Windows User environment. GET does not return project/billing identity or
prove execution entitlement. Our earlier exact-project association and user-supplied
15 RPM / 250K TPM / 500 RPD observations are historical evidence, not fresh qualification.
Account execution eligibility and remaining capacity remain unknown.

The [thinking guide](https://ai.google.dev/gemini-api/docs/generate-content/thinking)
supports `thinkingLevel=minimal` for both Flash-Lite models. Minimal is not a guarantee
of zero thoughts; `thinkingBudget=0` is not reused. A new explicit profile emits
minimal and retains thought/cache-aware complete-usage checks. No prompt tuning:
same public synthetic task/source/system instructions, JSON mode, temperature zero,
one candidate, 96 output cap, 8192 context policy, 256 margin and 4096 probe cap.
The configured cap stays small despite the advertised million-token context.

The [count contract](https://ai.google.dev/api/tokens) remains full
generateContentRequest with matching nested model. Full request bytes for both
count and generation, paths and SHA-256 are in the
[inactive proposal](evidence/stage3e-followup-proposal.json). The new generation hash
is `def8d8e4c9f4fe498a84fa1437662fab15532c85e9fbed5f22115f1bddb0d22f`.
This is the hash the new grant must bind; the model/account bind separately.
Provider modelVersion must satisfy the existing exact identity check; unexpected
identity remains unknown_usage, never relaxed to force a successful smoke.

[Unpaid-service terms](https://ai.google.dev/gemini-api/terms) allow product improvement
and human review. Public synthetic content only; no confidential/personal/private
data. Existing public/redacted whole-line export and canary gates remain mandatory.
No grounding, cache creation, tools, files, batch or paid service is requested.

## Durable operator grant

Migration 6 adds `gemini_followup_permits` beside `gemini_preflights`. It never
updates/deletes the old claim and never creates a grant during migration. The trusted
operator-only `issue_permit` function requires a failed legacy count in the same ledger,
a reviewed approval digest, explicit approval, exact project/account/model/qualification,
task/key/request hash and at most fifteen minutes inside fresh qualification validity.
One UNIQUE project constraint allows only one follow-up, not a series of new grants.
The issuer is not exposed as an MCP tool or invoked by config/catalog loading.

Claiming is a short BEGIN IMMEDIATE transaction committed before count HTTP send.
Wrong project, account, model, qualification, request hash, task/key or expiry denies.
Crash/timeout consumes the count claim permanently. Only a successful verified count
sets tokens. ResourceController checks the grant before reservation and dispatch;
the accepted shared Router, durable reservation/outbox, revalidation and settlement
pipeline remain in use. The account-wide one-inference restriction is unchanged.
New bucket windows start at fresh qualification time and cannot overlap prior account
windows; the old ledger must be reused, not replaced to evade a consumed claim.

The checked-in proposal is deliberately not a `FollowupPermit`: operator_approved
is false; issue/expiry/review fields are null. At preparation time no real grant had been issued and no historical ledger migrated.
The approved live run above subsequently issued and consumed the separate grant.
Tests issue synthetic grants only in temporary ledgers with mocked provider I/O.

## Approval and execution checklist (fulfilled live sequence)

After this exact proposal and code receive explicit approval:

1. Reverify the exact project/key, Free tier and disabled billing in authenticated
   account metadata. If free execution cannot be established, stop without count.
2. Hash the approved review record; issue the scoped grant in the existing ledger
   with fresh qualification and a short expiry. Preserve the old claim and evidence.
3. Use only the proposed model/profile/hash and existing public export policy.
   Reverify exact model metadata and capabilities with the same credential boundary.
4. Atomically consume one count claim, send exactly one countTokens.
5. On count failure: record new sanitized evidence, zero inference, no retry/fallback;
   leave Stage 3E OPEN. Do not issue a third-model grant.
6. On success: reserve through ResourceController; revalidate; commit dispatch before
   exactly one generateContent; settle complete usage and record outbox transitions.
   Ambiguous send/usage retains unknown_usage. No repeated request or prompt tuning.
7. Commit machine-readable evidence and obtain Linux/Windows CI before proposing
   closure. This preparation alone does not close Stage 3E.

Offline tests cover exact serialized minimal request, proposal inactivity, unchanged
historical bytes, migration, one-winner concurrent claims, restart, binding/expiry,
count crash/404, dispatch-before-send, settlement and ambiguous-send liability.
Gemini/Groq catalogs remain non-authorizing and unchanged. No Groq, DeepSeek, facade,
Stage 3F/3G or benchmark work is included.

Even after successful execution: semantic_acceptance, delegation_value, savings and
quality_benchmark remain null until their separately authorized benchmark stage.
