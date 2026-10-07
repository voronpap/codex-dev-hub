# Stage 3G B-arm delegation observation

This document defines the AUD-003 mechanical success boundary. It does not close
Stage 3G-C, authorize a rehearsal or benchmark, or establish semantic quality.

## Authority boundary

The MCP bridge records transport facts: the exact validated request identity, call
count, response kind, strict `DelegationResult`, schema hash, and accounting reference.
It is not accounting authority.

`experiment_run` reopens the ledger already bound by the reviewed qualification
manifest. It queries the exact reservation named by the handoff, its allocations,
and every accounting event for that reservation in sequence order. Submitted bridge
event lists and project-wide pending outbox views cannot establish success.

## `BArmDelegationObservationV2`

The observation stores:

- frozen session and validated request identities;
- call count and MCP response classification;
- strict handoff and its schema hash;
- authoritative reservation snapshot and full event sequence;
- expected and observed provider/resource/model/runtime identity;
- nullable semantic acceptance.

The following fields are computed and cannot be supplied by a caller:

- `accounting_complete`;
- `provider_execution_observed`;
- `delegation_success`;
- `failure_reason`.

Mechanical success requires exactly one call; matching project, task, request key,
and session; valid structured content; a completed handoff; its matching accounting
reference; an exact `reserved -> dispatched -> settled` ledger chain; complete
allocation usage; the qualification-bound Ollama identity; passing output and citation
validation; zero retries; and no fallback.

`unknown_usage` remains ambiguous: provider execution is nullable, accounting is
incomplete, and delegation success is false. A settled call with failed output or
citation validation keeps its authoritative usage but is not a successful delegation.

Mechanical `delegation_success` is separate from `semantic_acceptance`. The latter
remains null until the later frozen review.

## Current remediation state

- AUD-001 ledger identity: implemented and merged.
- AUD-002 qualification authority: implemented and merged.
- AUD-009 immutable Python runtime: implemented and merged.
- AUD-003 B-arm observation: implemented by the focused change described here.
- AUD-005 recovery ordering: implemented in the focused execution-boundary change.
- AUD-008 executor capture/cleanup: implemented in the focused execution-boundary change.
- AUD-011 task-exposure boundary: implemented in the focused execution-boundary change.

See [STAGE3G_EXECUTION_BOUNDARY.md](STAGE3G_EXECUTION_BOUNDARY.md). These infrastructure
changes do not qualify Candidate B or make Stage 3G execution-ready.
- Legacy ledger adoption: not implemented.

Stage 3G-C and Stage 3G remain open. `execution_ready` remains false. Build-009 has
not run, and no rehearsal, benchmark, model request, or provider send is authorized
by this change.
