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
settlement do not establish semantic success. Stage 3F is next; Stage 3G is not started.

Stage 3F: local unified delegation proof PASSED in PR #21; CLOSED proposed pending
final full-platform CI and review. Stage 3G remains not started.
