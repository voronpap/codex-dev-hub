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
