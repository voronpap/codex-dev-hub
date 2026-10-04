# Task usage footer (Issue #38)

## Architecture audit

DelegationResult already carries selected provider/model, actual input/output,
latency, accounting reference, execution/accounting states and validation results.
Selection entries include rejected candidates: they are not an executed route.
EventOutbox and the ledger remain authoritative; the footer does not write either.
Stage 3G stores frozen baseline evidence separately and has no real paired result.

Implement a derived immutable UsageSummaryV1 and separate renderers at the MCP
response boundary. Keep the existing structured DelegationResult unchanged. An
opt-in text footer and MCP result metadata carry observability only. Default off
returns the original response without derivation. No provider adapter changes.

Scope is a delegation task, not a complete Codex response. Baselines and Codex
usage can only be supplied through a trusted Python integration, not MCP request
arguments. No estimator or evidence loader is added. A producer must verify source
provenance/comparability before constructing these inputs.

## Configuration and response contract

Set top-level `telemetry_footer` in the trusted delegation JSON config to `off`
(default), `compact`, or `verbose`. The caller cannot override it in MCP arguments.
Enabled responses append one text content block and add `_meta.devfabric_usage`
(versioned UsageSummaryV1). Existing structuredContent, input/output schemas,
provider requests and accounting transitions remain unchanged. The original
DelegationResult.savings remains null; derived metrics live only in observability.
The host may display the footer; this server cannot force a Codex final-answer UI.

The route lists only the observed sent provider/model. Full Codex tool history is
not observed, so route_complete=false. Latency copies DelegationResult latency:
it is provider latency when available, otherwise the runtime's measured attempt
interval. It is not full Codex response wall time. Unknown usage is never replaced
by the context byte proxy or preflight estimate. No-send attempts have no inferred
local API charge. A settled local invocation with complete usage has a known-zero local provider
API charge, not a measured billing observation; hardware and electricity are unmeasured. Cloud cost stays unknown
unless a trusted producer supplies explicit measured/estimated cost provenance.

## Savings contract

Formula: `100 * (1 - actual Codex (input + output) / baseline Codex (input + output))`.
Cached input is a subset of input, not added twice. Delegated tokens never enter
this numerator. Negative savings are preserved. Baseline <= 0, missing counters,
or different task/protocol/token-convention comparison keys yields null savings.
A comparison key must bind the full comparable task/protocol and counter semantics;
matching task class alone is insufficient. This is a raw token reduction metric,
not a quality-adjusted Delegation Value claim or billing/cached-token savings.

Exact baseline requires a real comparable paired run with an evidence reference.
Estimated baseline requires a reviewed estimator version, source data reference
and limitations. This version does not implement an estimator, load benchmark
files, verify arbitrary references, or expose baseline inputs to the model.
Trusted host integrations must verify evidence before constructing the typed inputs.
Exact percentage has no tilde; estimated percentage uses ~ and an Estimated label.
Absent baseline is null; renderer cannot invent one.

## Truthful example

Illustrative rendering using PR #37's accepted local demo measurements (not a new
execution): 647 input + 77 output, 16264 ms. Codex usage, counterfactual baseline
and semantic acceptance remain unknown; requested caller fix plan was omitted.

```text
DF task: Codex unknown | delegated 724 | saving unknown | 16.3s | API $0.00
```

```text
DevFabric task usage
Route: ollama/qwen2.5:14b-instruct (observed provider only; full Codex route unknown)
Codex tokens: unknown
Delegated tokens: 724 measured
Baseline: unknown
Premium token saving: unknown
Delegation result latency: 16.3 s measured
Provider/API cost: $0.00 known-zero local API charge (API only; hardware/energy unmeasured)
Semantic quality: unknown
Output validation: PASS
Citation validation: PASS
```

Syntax/citation checks are not semantic acceptance. Stage 3G remains OPEN and
execution_ready=false. No benchmark or provider call is required for this feature.

Cost kinds distinguish `measured` provider/billing observations, `known_zero`
local API charge, and `estimated` reviewed estimates. Missing cost is null.
The Ollama derivation binds `local-ollama:no-external-api-charge` plus the
accounting reference: the latter establishes actual settled execution, not a
monetary measurement. Known-zero requires microusd=0. Explicit measured/estimated
cost supplied by a trusted producer remains unchanged. No hardware, energy or
total economic cost is inferred from the ledger.
