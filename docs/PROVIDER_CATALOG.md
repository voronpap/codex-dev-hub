# Non-authorizing provider catalog evidence

These JSON snapshots are reviewable evidence, not runtime configuration. Neither
the adapters, Registry nor ResourceController loads them. No routing, permit,
account qualification, quota balance or database migration is added by a catalog.
Dimensions retain their own units and windows; null means unknown, not unlimited.

## Gemini: account-specific, user-reported AI Studio observation

[Catalog](evidence/stage3e-gemini-account-catalog.json) and its
[JSON Schema](evidence/stage3e-gemini-account-catalog.schema.json) bind every entry
through the enclosing provider, exact project, Free tier and source observation.
The source is the user's report of authenticated AI Studio Rate Limits, not a new
independent console inspection. `received_at` records ingestion; the source's exact
observation time was not supplied, so `observed_at` and qualification expiry remain
null and qualification is inactive. This does not refresh the expired live grant.

All 36 rows are retained: 13 text, 2 Gemma, 2 embedding, 4 TTS, 1 transcription,
1 robotics, 6 Live, 2 agents, 4 search-grounding groups and 1 unmapped map-grounding
observation. Display names are not guessed API IDs. Only the existing Stage 3E
exact model ID has prior metadata provenance; other ID mappings need verification.

Zero limits deny account availability, including the zero search-grounding group.
Nonzero limits leave endpoint eligibility unknown. In particular the reported
10 RPM / 250,000 TPM / 20 RPD for 2.5 Flash Lite does not establish why counting
returned 404. Remaining capacity and historical peaks are separate null fields;
local authorization and routing remain false for every row.

Live `Unlimited` is retained literally, restricted by schema to Live rows and
marked `LIVE_API_VERIFY`; it does not authorize unbounded REST inference. Session,
concurrency, token, reconnect, audio/video and billing semantics need independent
review. Search and map grounding are separate capabilities. The 500 RPD map figure
has no supplied model mapping and is not assigned to every model.

Future benchmark-driven candidates only: Gemma 4 26B/31B for high-volume work,
3.1/3.5 Flash Lite for general tasks, Flash for scarcer capacity, and a separate
embedding pool. Before using Gemma verify exact IDs, endpoints, token counting,
JSON support, context, API eligibility and commercial/data-use terms; Gemini
semantics do not transfer automatically. FTS5 remains the retrieval baseline.
No embedding, Live, grounding or new model implementation is included.

## Groq: documented Free-plan limits

[Catalog](evidence/groq-free-plan-catalog.json) records all 10 user-specified model
IDs, independently checked against the official
[Free Plan Limits table](https://console.groq.com/docs/rate-limits). This is plan
documentation, not an authenticated account quota observation. Account limits,
remaining and historical peaks remain null. `observed_response` is null and, if
independently observed later, belongs to the existing `devhub.quota.QuotaObservation`
contract. The catalog does not duplicate or replace that runtime contract.

RPM/RPD/TPM/TPD/ASH/ASD are separate dimensions (ASH/ASD are audio seconds per
hour/day). A dash in documentation is null, not zero. Request limit/remaining/reset
headers describe RPD; token headers describe TPM. They do not imply RPM or TPD.
The documented cached-token exemption is `cached_tokens_rate_limited=false`;
this change implements neither prompt caching nor cache-based reservations/savings.

Qwen remains the existing Stage 3D execution candidate. Other entries are catalog
candidates requiring capability, availability, privacy, benchmark, actual account
limits and Router-policy review before activation. There is no Groq/Gemini routing
preference, new inference or Stage 3F/3G work.
