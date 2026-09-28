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
