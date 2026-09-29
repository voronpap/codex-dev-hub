# Accepted execution stages

Stage 1 and Stage 2 CLOSED. Stage 3A Project Brain and 3B Context Builder CLOSED.

| Stage | Provider | Status | Execution/accounting gate |
| --- | --- | --- | --- |
| 3C | Ollama | CLOSED | PASSED (local) |
| 3D | Groq | CLOSED | PASSED |
| 3E | Gemini | CLOSED | PASSED |

PR #19 was accepted and merged after Linux and Windows full CI passed on
`8185b1f` (228 tests per platform). The Gemini follow-up counted 81 input tokens,
then reserved, revalidated, committed dispatch, sent once and settled 81 input +
11 output = 92 total tokens. Its `failed / invalid_output` handoff occurred after
complete settlement and does not invalidate the execution/accounting gate.
Historical 2.5 Flash Lite HTTP 404 and both consumed permits remain unchanged.
No diagnostic repeat inference is authorized.

Semantic quality is not established for any provider. `semantic_acceptance`,
`quality_benchmark`, `delegation_value` and `savings` remain null. HTTP 200 and
settlement do not establish semantic success. Stage 3F CLOSED. Local unified delegation gate PASSED; PR #21 accepted and merged.
Linux full, Windows smoke and stage-close Windows full passed on 2b8c5d8
(Actions run 36476939766). The real Codex proof returned validated output and
citation s1, 767 input / 119 output tokens, one send, no retry/fallback, and
reserved -> dispatched -> settled. The initial zero-send host-approval block
remains historical evidence. Semantic quality remains unestablished.

Stage 3G OPEN: the next slice is offline harness only, pending review before any
paired execution. semantic_acceptance, quality_benchmark, delegation_value and
savings remain null.
