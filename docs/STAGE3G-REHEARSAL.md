# Stage 3G paired rehearsal control

Status: implementation under review; no rehearsal has run.

Stage 3G requires one separately reviewed A/B rehearsal before the frozen 24-session
benchmark. The frozen coordinator cannot serve this purpose: `execute_next()` always
selects a session from the qualified benchmark plan and would expose a frozen task.
The rehearsal therefore has its own strict, self-hashed `Stage3GRehearsalPlanV1` and
uses the same production session-launch function as the benchmark.

## Authority and task boundary

The rehearsal plan binds the exact qualification manifest, context, environment,
implementation commit, protocol hash and qualified frozen-plan hash. It embeds exact
base64 task/input bytes and their SHA-256 hashes, then derives two distinct session IDs
in fixed A then B order. The plan has no oracle, benchmark fixture ID, semantic answer
or caller-controlled retry/resume authority.

Plan creation and execution both compare the rehearsal input and task components with
every frozen fixture. A match is rejected. This check verifies only the seed manifest
and fixture files; it never opens an oracle. The rehearsal packet contains only the
dedicated task, the common frozen instructions and its own session metadata.

`rehearsal_plan_id` is SHA-256 over canonical compact JSON of the payload, excluding
the ID field. The ID becomes the execution-plan hash in guest READY/TASK_ACCEPTED and
attempt provenance. `qualified_frozen_plan_sha256` remains a separate binding and is
never substituted by the rehearsal ID.

## Execution

`scripts/run_stage3g_rehearsal.py` is a thin one-pair operator entrypoint. `plan`
creates the reviewed descriptor from explicit regular input/task files. `execute`
requires `--operator-reviewed`, the exact qualification manifest ID, accepted auth and
ledger locators, and an empty external run root.

Both arms call the same `_execute_reviewed_session()` used by the benchmark. This
preserves the environment guard, immutable Python delegate runtime, host-owned tool
ceilings, ledger authority, READY/task exposure protocol, bounded capture, exact CID
cleanup, secret scanning and post-run environment recheck. Arm B must return the
authoritative `BArmDelegationObservationV2` with `delegation_success=true`.

The coordinator runs A then B once in one call. It has no resume and no automatic
retry. Existing run content is rejected. An exposed or ambiguous failure remains
sealed for manual review. A successful pair writes normal attempt artifacts and a
`pair-summary.json` with exact result/output hashes; semantic acceptance, quality,
savings and Delegation Value remain null.

## Required sequence

1. Merge this implementation after required CI and independent review.
2. Rebuild the immutable DevFabric wheel from that exact commit.
3. Re-collect all ten receipts and create a new same-environment manifest with
   `execution_ready=true`; the prior manifest remains historical.
4. Create and independently review one dedicated non-benchmark rehearsal plan.
5. Execute the pair once. Review its sealed evidence before any frozen benchmark
   session is exposed.

This slice does not change protocol v2, fixtures, oracles, their order, the benchmark
plan algorithm, provider policy or any semantic evaluation rule.
