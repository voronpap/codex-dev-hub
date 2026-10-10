# Static repository audit addendum after main integration

Date: **2026-10-05**  
Original audit: [STATIC_REPOSITORY_AUDIT_2026-10-05.md](STATIC_REPOSITORY_AUDIT_2026-10-05.md)  
Original audit commit: `b61af47ecf339474808116f8ece7b593245c3ffa`  
Integrated main: `da935f6cf9612b5ce8eea3b0ad6bc5694b51f96f`  
Merge commit: `3a02b3c6446ad734a43bf7505d16e75f122ef5c4`

This addendum is a focused static review of the 19 main-only commits that were absent
from the original Stage 3G branch snapshot. It does not rewrite or broaden the
historical coverage claim of the original audit.

## Scope

Reviewed areas:

- DevFabric public branding and overview documents;
- the accepted PR #37 local demo and its evidence;
- `UsageSummaryV1`, cost/savings provenance, and footer rendering;
- the MCP response-boundary integration;
- the accepted design-only role orchestration proposal;
- merged changes to `delegate.py`, `delegate_server.py`, and `ollama.py`;
- Stage 3G status statements and frozen Ollama protocol identity.

No application, test, CI, model, provider, benchmark, container, or Rust build was
executed for this addendum.

## Confirmed integration properties

### Public positioning

The public name is DevFabric while compatibility identifiers remain unchanged:

- repository: `codex-dev-hub`;
- Python package and CLI: `devhub`;
- MCP tool: `devhub_delegate`;
- historical protocol and evidence identifiers remain unchanged.

The public documents consistently state that Codex is the current primary integration,
Cursor/Claude and other clients are planned, Stage 3G remains open, the paired benchmark
has not run, and production readiness, semantic quality, savings, and Delegation Value
are not established.

### Local demo

The demo is explicitly classified as a demo rather than Stage 3G evidence. Its recorded
Ollama 0.35.0 execution, usage, latency, validation, and accounting observations are not
promoted into the frozen paired benchmark. The documented omitted caller fix plan remains
a semantic limitation.

### Usage summary and footer

`UsageSummaryV1` is derived from `DelegationResult`; it does not write the ledger, route a
request, choose a provider, or alter settlement. `telemetry_footer` defaults to `off`, and
the off path returns before usage derivation. The response middleware preserves existing
`structuredContent` and places optional derived data in `_meta.devfabric_usage` plus an
additional text content item.

The model keeps:

- task scope `delegation_task`;
- `route_complete=false`;
- Codex usage, baseline, savings, and semantic acceptance nullable;
- measured, known-zero local API charge, estimated, and unknown cost distinct;
- estimated savings visibly marked and absent baseline represented as null/unknown.

This observability layer does **not** repair AUD-003. It reports the handoff supplied to
it; Stage 3G still needs an independent authoritative B-arm success check against the
ledger and exact request/session identity.

### Role architecture

The role proposal is design-only. It preserves direct Codex execution as the default,
keeps role selection separate from provider/resource admission, reuses Project Brain,
Context Builder, ResourceController, and the existing ledger, and explicitly defers role
runtime until after current Stage 3G. No role runtime, Strategy Registry, recursive
delegation, additional provider, or accounting store was added.

### Ollama identity

The global adapter now accepts exact versions `0.34.2` and `0.35.0`; it does not accept a
range. The demo config uses 0.35.0. Both frozen Stage 3G protocol files continue to bind:

- version `0.34.2`;
- model `qwen2.5:14b-instruct`;
- digest `7cdf5a0187d5c58cc5d369b255592f7841d1c4696d45a8c8a9489440385b22f6`.

Therefore global 0.35.0 support does not qualify it for Stage 3G. An observed 0.35.0
runtime must fail the current Stage 3G qualification.

### Stage 3G evidence preservation

The complete Git tree below `docs/evidence/stage3g-approved-call/` is byte-identical to
commit `052e202906ed90baf3ca3a9baf7b4ef50d8ac8b6`. Build-001 through build-008 and
build-009 preflight evidence were not modified. The Candidate B patch remains:

`d2e27068ca8020f014c7cd3bea2cc73181b1b892d8e6869814680d2076eb3e36`.

## Addendum findings

### ADD-001 — Public Markdown contains mojibake

**Priority:** P3  
**Confidence:** high

`README.md`, `ROADMAP.md`, and `docs/DEMO1.md` contain literal mojibake sequences such as
`вЂ”`, `в†’`, and `вЂњ`. These are repository bytes, not only terminal rendering. They
degrade the public front page and instructions but do not change runtime semantics.

Recommended direction: make a separate documentation-only encoding correction after
the current security/qualification design review. Do not rewrite historical evidence.

### ADD-002 — Role proposal embeds a stale current-build sentence

**Priority:** P3  
**Confidence:** high

`docs/ROLE_ORCHESTRATION_PROPOSAL.md` correctly remains design-only, but lines 17–20 and
470–473 say build-008 was not run. The Stage 3G branch now contains immutable build-008
evidence and a blocked build-009 preflight. The architecture decision is still valid;
only the embedded current-status snapshot is stale.

Recommended direction: mark those sentences as the historical status at proposal review
time and link to the current Stage 3G status/evidence instead of continuously rewriting
the design record.

## Result

No new P0/P1/P2 defect was established in the main-only implementation slice. The
original audit findings AUD-001 through AUD-011 remain applicable, with AUD-010 resolved
for the Stage 3G path by retaining its exact 0.34.2 protocol pin. Stage 3G-C and Stage 3G
remain open, `execution_ready=false`, and build-009 remains blocked before compilation.

