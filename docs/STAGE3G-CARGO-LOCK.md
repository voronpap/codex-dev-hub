# Stage 3G-C pinned Cargo lock diagnosis

This is an additive follow-up to the historical full-router build failure in
[STAGE3G-FULL-ROUTER.md](STAGE3G-FULL-ROUTER.md). Historical evidence is unchanged.
No model metadata refresh, inference, rehearsal or benchmark is part of diagnosis.

## Proven cause: STALE_UPSTREAM_LOCK

The exact source commit is `4607249e430dac1c961df4dc615beae88e33cec8`.
The original lock SHA-256 is
`7bb060a9b67a22503f9d15030c22122fea38623be9077d44cbadb919896a4146`.
Rust 1.95.0 and Cargo 1.95.0 are recorded in the diagnostic receipt; this matches
the pinned `rust-toolchain.toml`. The native target is x86_64-unknown-linux-gnu.

The original lock records **152 local packages at version 0.0.0**. Their exact
manifests inherit `workspace.package.version = "0.155.0-alpha.9.2"`. Each package
is bound to its manifest and workspace manifest by hash. This is an inconsistency
inside the pinned upstream source, not a guessed compiler or target problem.

The [diagnosis run](https://github.com/voronpap/codex-dev-hub/actions/runs/36967187526)
captured stdout, stderr, exit codes and pre-operation source inventory:

| Disposable source | Command | Exit |
| --- | --- | --- |
| Untouched pinned source | `cargo metadata --locked --format-version=1` | 101, lock update required |
| Untouched pinned source | `cargo test --locked -p codex-core --lib --no-run` | 101, same failure |
| Source + appended test and metadata fixture only | `cargo test --locked -p codex-core --lib devhub_review_full_router --no-run` | 101, same failure |

Original and injected source inventories remained unchanged during these commands.
The test injection is **not the cause**. No test execution occurred in diagnosis.

## Rejected regeneration and minimal proof-only derivation

`cargo generate-lockfile --offline` succeeded in a separate disposable copy after
the locked commands populated dependency metadata. It produced a diagnostic
candidate at `137be678a35b43ca2510f40049b76bce316cc4f268a2735d0b2af33eee2c5ac6`.
It changes external dependencies unnecessarily: 550 version changes (including
local versions), 398 checksum changes, 459 dependency-edge changes, 28 additions
and 53 removals under the documented structural pairing algorithm. It is rejected
and never used for a build. Reasons for individual external upgrades are unknown;
the report does not invent manifest requirements for them.

A separate minimal candidate starts from the original lock and uses
`cargo metadata --format-version=1`, preserving existing dependency selections.
Its structural diff contains exactly:

- 152 local version changes, 0.0.0 to 0.155.0-alpha.9.2;
- zero packages added/removed;
- zero external version, source, Git revision, checksum or dependency-edge changes;
- lock format remains 4, with no top-level metadata change.

The justified **LOCK_B** proof build uses a deterministic byte transformation
bound to each pinned manifest. It is byte-identical to that minimal Cargo result:
`a5369b7f5d713d21c9f2481afdc27b7577e45d4b713fc84a4ab03c2833c4d48d`.
This is a **derived test-build lock**, not the upstream pinned lock. It is generated
only inside a disposable proof tree; generated Cargo.lock files are not committed.
The original bytes are retained as a separate artifact. The production Codex
binary, source pin and benchmark runtime remain unchanged. `--locked` stays on
the proof compilation command.

## Upstream context

The pinned workspace uses resolver 2 with no explicit default-members list.
`.cargo/config.toml` only adds Windows MSVC/GNU flags and has no Linux target
override. `just test` uses nextest; the full upstream CI uses nextest archives with
explicit target/profile controls and supports Bazel as well. Our filtered core
unit-test build is narrower. None of those differences explains away the failure:
the untouched base core invocation and metadata resolution reproduce it.

## Evidence and reproducibility

Machine-readable records are under `docs/evidence/stage3g-cargo-lock/`:
`cargo-lock-diagnosis.json`, original/candidate/derived `.sha256` files,
`cargo-lock-structural-diff.json`, `manifest-bindings.json` and
`upstream-context-hashes.json`. Full raw locks, logs, metadata output, source
inventory and the upstream build-context archive are in the diagnosis run's
`pinned-cargo-lock-diagnosis` artifact, with every file hash recorded locally.

Run diagnosis on Linux with Python 3.12, Cargo/rustup and dependency network access:

```sh
python scripts/diagnose_cargo_lock.py --workspace /tmp/fresh-lock-source --output /tmp/fresh-lock-evidence
```

Both directories must be new. Dependency downloads are permitted; no Codex or
provider session is launched. A regenerated lock is diagnostic, never accepted
automatically. `scripts/record_cargo_diagnosis.py` verifies artifacts against the
full pinned source before publishing a classified report.

Offline validation is `python scripts/check_cargo_diagnosis.py`. The transformer
rejects changed original bytes, unexpected versions/manifests and unexpected
derived hashes. Tests distinguish ordering noise, added/removed packages, version,
Git revision, checksum and dependency-edge drift.

## Gate boundary

Resolving the lock mismatch is not router feasibility. A/B sets, tool-mode
exposure and wrong-origin collision must come from the actual compiled router.
No wrapper, v3, Direct forcing or exec/wait expansion is authorized by this
diagnosis alone. Stage 3G-C and Stage 3G remain OPEN; execution_ready=false.

## Actual full router result: ROUTER_BLOCKED_BOTH

[Proof job 36967419182](https://github.com/voronpap/codex-dev-hub/actions/runs/36967419182)
built the actual pinned core using the derived proof lock and `--locked` (exit 0).
The actual unit test then ran in an isolated network namespace with dummy auth:
**1 passed, 2528 filtered out, 0.30 seconds**, exit 0. This is not a method-slice
test. The proof build implementation commit was
`1dae4d0d8658d770555a53b3426323bb8785c436`.

| Observation | A | B |
| --- | --- | --- |
| Registered tools | empty | exact canonical delegate |
| Visible model specs | empty | **empty** |
| Code-mode map | empty object | delegate mapping present |
| Hosted specs exposed | empty | empty |
| Effective mode | CodeModeOnly | CodeModeOnly |
| Normal-case server origin | none | devhub_delegate |

The raw `ToolName::to_string()` output for B is
`mcp__devhub_delegatedevhub_delegate`. It is retained verbatim, not rewritten as
another identity. The structured identity in AllowedTools and the code-mode map is
`namespace=mcp__devhub_delegate`, `name=devhub_delegate`; the synthetic MCP helper
constructs the raw tool with that name and server key `devhub_delegate`.

The separate actual collision case registers `wrong_origin` under this same
canonical name first, then registers the approved server. The first registration
survives; the duplicate is rejected and the collision recorded. AllowedTools does
not independently bind origin. Normal-case origin observation does not establish
a fail-closed provenance guarantee.

Thus the successful test proves two blockers, not feasibility:

1. **Tool mode:** B is registered but has no model-visible delegate under the
   observed service-default CodeModeOnly mode and the frozen ceiling.
2. **Collision:** name matching alone permits the wrong-origin first registrant.

No candidate host origin guard has been independently proven. Classification is
**ROUTER_BLOCKED_BOTH**. No exec/wait allowance, Direct override, host wrapper,
protocol v3, rehearsal or benchmark follows. Model metadata was not refreshed.

`router-proof.json` binds the actual receipt, raw artifact hashes and classification.
`router-test.stdout` and `.stderr` retain test output bytes. The stderr warning
about inability to create PATH aliases is retained; it did not fail the unit test
and is not promoted to host-wrapper qualification.

After this decisive result, redundant build 36968308134 was cancelled. It was
triggered by log-capture/prerequisite maintenance, with unchanged pinned source,
test, metadata and derived lock. It is not additional proof or a passing check.
Future documentation-only reruns may likewise be cancelled; the linked completed
proof remains bound to its exact implementation and inputs.

Final state: Stage 3G-C OPEN, Stage 3G OPEN, execution_ready=false,
real_codex_executions=0, provider_sends=0. Semantic acceptance, quality benchmark,
Delegation Value, savings and internal Codex retries remain null.
