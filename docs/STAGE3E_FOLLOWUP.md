# Stage 3E follow-up: candidate and one-shot grant review

Status: prepared for operator review; no live count/inference authorized or performed.
PR #18 was merged as partial implementation. Stage 3E remains OPEN and the Gemini
execution/accounting gate NOT_PASSED. The original 2.5 Flash Lite HTTP 404, null
usage, zero reservations/dispatch/inference and consumed claim remain unchanged;
root cause remains unknown. This is an explicitly proposed new model, not fallback.

## Candidate review

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

Exactly two authenticated, metadata-only model GETs returned 200 with the exact
names, limits and advertised countTokens/generateContent methods. See
[sanitized metadata evidence](evidence/stage3e-followup-metadata.json).
No counting, generation, retry or fallback happened. Credentials were read only
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
is false; issue/expiry/review fields are null. No real grant has been issued, no
historical ledger migrated, and the existing local model configuration is unchanged.
Tests issue synthetic grants only in temporary ledgers with mocked provider I/O.

## Approval and execution checklist

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
