# Stage 3G execution and recovery boundary

Status: implementation infrastructure only. This does not run the benchmark, qualify
Candidate B, or close Stage 3G-C.

## Accounting recovery

`DelegationRuntime` opens and validates the immutable ledger, completes schema handling,
and runs `ResourceController.recover()` before replay lookup or MCP request service. An
expired reserved lease is released; an expired dispatched lease becomes `unknown_usage`.
Settled and unknown-usage rows remain unchanged. Recovery failure prevents server startup.

Direct `LocalRuntime` and `CloudRuntime` construction retains explicit startup recovery.
The unified runtime passes `recover_on_startup=False` after its single authoritative
reconciliation, so profiles sharing one ledger cannot emit duplicate recovery transitions.

## Bounded process capture

Executor and evaluator processes share one capture implementation. Each stream retains at
most 1 MiB and execution is terminated after more than 8 MiB is observed on either stream.
Readers drain stdout and stderr concurrently. Evidence records retained bytes, exact
observed bytes when the reader completed, truncation, the SHA-256 of retained bytes, and
the limit reason. It never labels a retained-prefix hash as a full-stream hash.

Credential scanning is incremental and retains overlap across read chunks. Detection
terminates execution and withholds the affected stream. Timeout, hard output limit, and
secret detection terminate the complete container through its exact validated ID.

After a valid `docker create`, every path removes that exact ID with `docker rm --force`
and verifies that it no longer exists. Cleanup failure prevents successful evidence.

## Attempt exposure state

The lifecycle is:

```text
CLAIMED -> CONTAINER_CREATED -> GUEST_READY -> TASK_EXPOSED -> COMPLETED
```

Failure records the last achieved state. Exposure is represented as `not_exposed`,
`exposed`, or `unknown`; unknown is never converted to false.

The container initially receives only trusted `session.json` control metadata. Task-bearing
`input.txt`, `task.txt`, and `instructions.txt` are not mounted. `/packet` is an empty tmpfs.
After the guest publishes a strict READY record, the host atomically publishes a bounded,
hash-bound task frame on the private control mount. The guest validates the complete frame,
publishes TASK_ACCEPTED, reconstructs `/packet`, and only then starts Codex and supplies the
task on stdin.

The host writes a durable pending-transfer receipt before frame publication. A failure after
that point but before a durable accepted receipt is `unknown`. After TASK_ACCEPTED is
validated, the host seals `task-exposed.json`; later failure consumes the attempt. The timer
still begins immediately before `docker start`, so guest readiness and Codex startup remain
inside the frozen latency boundary.

No state authorizes automatic retry:

| Exposure | Attempt consumed | Rerun policy |
|---|---:|---|
| `not_exposed` | no | review required, null |
| `unknown` | yes (conservative) | review required, null |
| `exposed` | yes | false |

This PR does not define an operator continuation procedure. It only preserves enough sealed
evidence for a later reviewed decision.
