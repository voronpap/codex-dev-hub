# Stage 2: offline resource core

Stage 1 is closed: PR #2 merged, PR #3 updated from main, Linux/Windows CI rerun
successfully, then PR #3 merged. The real Codex MCP smoke and frozen baseline
remain recorded in the Stage 1 evidence. No benchmark savings are claimed.

Stage 2 review sequence: 2A ledger, 2B reservations, 2C capability registry,
2D deterministic routing, 2E transactional events, 2F recovery/concurrency proof.
These are internal offline APIs; MCP still exposes only Stage 1 status. No cloud
provider or paid adapter is enabled or implemented.

## 2A: ledger

The standard-library SQLite ledger uses independent connections, foreign keys,
FULL synchronous writes and short BEGIN IMMEDIATE transactions. Schema changes
and user_version advance atomically. Newer schemas and existing WAL databases
are refused. Use a local filesystem, not a network share. Prompts, credentials
and model responses do not belong in this database.

Implementation adjustment: rollback journal DELETE replaces the proposed WAL
for this slice. The host's Python 3.12 SQLite is 3.49.1. SQLite documents a
[WAL-reset corruption bug](https://www.sqlite.org/wal.html#walresetbug) in versions
through 3.51.2, fixed in 3.51.3 and backports 3.44.6/3.50.7. This avoids dependence
on a patched native runtime; WAL can be reconsidered with a verified safe version.
[BEGIN IMMEDIATE](https://www.sqlite.org/lang_transaction.html) serializes writers
before reading admission counters. No provider call may occur inside a transaction.

`Ledger.backup(new_path)` takes an online SQLite snapshot and refuses overwrite.
For rollback, stop all users, preserve the current database, and open the snapshot
with the matching runtime. Never restore a snapshot over a live ledger. Backups
are operator-controlled local files and must receive the same protection as the ledger.

## 2B: reservations

Trusted operator code registers immutable resource policies and fixed-window
buckets. Multiple resources reference the same bucket for a shared account quota.
Overlapping aliases for the same pool/dimension/scope are refused. Window rollover
requires a new policy/resource ID and bucket; old liabilities are never reset.
Unknown capacities or reset times deny admission. Rolling-window adapters and
provider-header reconciliation belong to later integration work.

Admission reserves requests, full input and maximum output tokens, and all linked
budgets in one transaction, including reserve floors. Input counts must include
the entire provider payload; the future adapter owns token counting. Idempotency
is project-scoped and binds the resource, payload digest, limits and deadline.
Dispatch is a one-way durable transition before transport. Only pre-dispatch
reservations can be released. Timeout becomes unknown_usage and retains every
hold. Settlement requires complete trusted measurements; missing usage never
means zero. Actual overruns are recorded rather than clamped to reserved values.

Paid simulation is disabled by default and requires a fresh upper price including
fees, an explicit project/task/resource approval, and task/project/global budgets.
It cannot execute paid requests. Trusted configuration, approval and measured
usage are internal Python APIs, not tool arguments available to a model.

## 2C: capability registry

Migration 2 adds persisted capability evidence scoped to resource/provider/model/
endpoint/plan. Records include provenance ID, observation and expiry timestamps,
tri-state features/health, context/output limits and qualified task classes.
Unknown remains unknown. Records are explicitly synthetic; no provider metadata
is fetched. Policy kind must match the registry. Updating evidence changes its
SHA-256 revision. The router will bind admission to that revision and deny stale
or changed evidence before dispatch. Upgrading a v1 database preserves counters.

## 2D: deterministic router

Eligibility checks privacy, fresh verified capabilities/health, qualified task
class and combined input/output context size. Unknown values fail closed. Default
ranking is free/local/paid, then trusted task policy preference, then resource ID.
Kind ordering is configurable; there is no hardcoded provider-name sequence,
learned ranking or fabricated benchmark score. Decisions give stable reason codes
for every registered candidate. Quota failure can select the next eligible resource;
there is no provider retry or transport call. Three persisted reservations per
project/task are the maximum, including released attempts.

Selection binds the capability revision inside the reservation transaction and
rechecks it before dispatch, closing the metadata-update race. The router returns
a ticket and its bound admission request. Dispatch must still succeed before any
future adapter is invoked. Missing registry entries are unavailable. This internal
simulation does not change the non-routable fake adapter exposed by MCP status.

## 2E: accounting events

Migration 3 adds a local transactional outbox. Each lifecycle change writes a
typed event in the same transaction as its counters. Event failure rolls back
the whole change. Idempotent calls emit no duplicate transitions. Records contain
IDs, synthetic provenance, timestamp and reserved/actual allocation snapshots;
unknown actual values stay null. No prompt, response, credential or payload digest
is included. Route rejection reasons are returned directly, not sent externally.

Project-filtered polling provides ordered at-least-once delivery; consumers must
deduplicate by event ID and acknowledge only after committing their own work.
Acknowledgement does not touch accounting, and replay is not a second settlement.
This is an internal single-operator boundary, not an authentication service.
No remote telemetry sink is configured. Older reservations remain authoritative;
migration does not invent historical events for them.

## 2F: recovery and concurrency

`ResourceController.recover(now_ms=...)` is an idempotent operator/startup sweep.
Only expired reserved leases release counters. Expired dispatched leases become
unknown_usage, retaining holds until explicit complete settlement. A durable
dispatch marker is intentionally conservative even if a crash happened before
the physical send: the ledger cannot prove whether the provider received it.
Never replay that attempt. A later quota window cannot hide an unresolved hold
in the same pool. Disabling paid simulation also blocks previously reserved paid
dispatches after restart.

The clock and token/price evidence are trusted runtime inputs. A future live
integration must use a reliable clock, run recovery at startup and periodically,
handle cancellation/timeouts as unknown, and reconcile from provider evidence.
This slice has no live scheduler, provider SDK or automatic reconciliation.

Tests start four independent spawned processes competing for the last shared
slot, and hard-exit child processes before commit, after reserve and after the
dispatch marker. Reopening the database verifies rollback/durability, expiry,
unknown holds, reconciliation, outbox and SQLite integrity. A fake post-send
timeout verifies null actual usage and unchanged liability. These tests establish
offline accounting behavior, not real provider transport correctness.

## Verification and review order

Verified 2026-09-28 on Windows Python 3.12.10 and WSL Ubuntu 24.04 Python 3.12.3:
54 tests pass, including the existing MCP/schema/config/baseline suite. Windows
Ruff lint/format, strict mypy and offline config validation pass. No dependencies
were added. CI runs the full suite on Ubuntu 24.04 and Windows; authoritative
run status is attached to each PR rather than inferred from local results.

| Slice | Review |
|---|---|
| 2A ledger/migrations | [PR #4](https://github.com/voronpap/codex-dev-hub/pull/4) |
| 2B reservations | [PR #5](https://github.com/voronpap/codex-dev-hub/pull/5) |
| 2C registry | [PR #6](https://github.com/voronpap/codex-dev-hub/pull/6) |
| 2D router | [PR #7](https://github.com/voronpap/codex-dev-hub/pull/7) |
| 2E events | [PR #8](https://github.com/voronpap/codex-dev-hub/pull/8) |
| 2F recovery/concurrency | Final slice on top of 2E |

These PRs are stacked: review and merge in order, update each successor onto main
and rerun CI before its merge. Stage 2 is not auto-merged. Stage 3 remains gated
on review; real account limits, token counting, transport cancellation and live
usage reconciliation still require adapter-specific evidence.
