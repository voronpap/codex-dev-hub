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

## Build-009 full executable lock result

Build-009 run `37976011705` passed source preparation and its cheap gates, then
started the first actual `codex-cli` compilation. Cargo 1.95.0 rejected the build
under `--locked` because the earlier `LOCK_B` covered the 152 stale local package
versions but not the dependency edges added by the separately reviewed shipping
host-integration patch. No executable was produced and process proof remained null.
The classification is `BUILD_009_CARGO_LOCK_INCOMPLETE`; Build-009 is immutable
failed evidence and is not rerun.

The minimal successor lock starts from `LOCK_B` and adds only these reviewed local
manifest edges:

- `codex-app-server-client` → `codex-extension-api`;
- `codex-exec` → `codex-extension-api`, `codex-tools`, `sha2 0.10.9`;
- `codex-tui` → `codex-extension-api`.

It adds or removes no package and changes no external version, source, checksum,
or Git revision. Its proposed SHA-256 is
`9236f6c0b8703eaf337dd219c8fdfb6834c14fa430a0a83b938159016371bb88`.
Before any successor compilation, the fresh patched source must pass Cargo 1.95.0
`metadata --locked` for `x86_64-unknown-linux-gnu`, `fetch --locked` for that
target, and byte-for-byte lock equality after both commands. A successful check
authorizes only a separately identified Build-010; it does not rewrite Build-009.

Build-010 run `38010156389` stopped in cheap preflight before Cargo. The lock
helper incorrectly compared the pinned workspace semver requirement `sha2 =
"0.10"` with the resolved lock-package identity `sha2 0.10.9`. The lock bytes
and five reviewed dependency edges were not rejected; their two different Cargo
representations were conflated. Build-010 is immutable
`PREBUILD_WORKSPACE_REQUIREMENT_REPRESENTATION_FAILURE` evidence with
`rust_compilation_started=false`. Build-011 verifies the exact workspace
requirement `0.10` and separately retains the exact lock edge `sha2 0.10.9`.

Build-011 run `38010540892` passed cheap preflight, Cargo 1.95.0 locked
metadata/fetch, and byte-for-byte lock verification. Its compilation then failed
after 380.350 seconds because the proof observer returned `anyhow::Error` through
a session function whose error type is `CodexErr`; no conversion existed at the
call boundary. No executable or process proof exists. Build-011 is immutable
`BUILD_011_OBSERVER_ERROR_CONVERSION_COMPILE_FAILURE` evidence. Build-012 adds
only the explicit observer-error conversion already used by Candidate B at the
same `CodexErrorDetails::InvalidRequest` boundary; lock identities are unchanged.

Build-012 run `38011524953` passed source preparation and every identity check,
then stopped before Cargo because pinned `cargo +1.95.0 fmt --check` required the
new observer method chain to use rustfmt's multiline indentation. It is immutable
`PREBUILD_RUSTFMT_OBSERVER_CHAIN_FAILURE` evidence with
`rust_compilation_started=false`. Build-013 changes only those patch bytes to the
exact formatter output; the error conversion, authority boundaries, lock,
manifest, schema, and proof behavior are unchanged.

Build-013 run `38012265371` passed cheap preflight and immutable locked
metadata/fetch, then started Cargo and failed after 457.573 seconds. The static
`thread_start_task` incorrectly accessed `self.thread_extension_init`; no
executable or process proof exists. The classification is
`BUILD_013_THREAD_EXTENSION_PROPAGATION_COMPILE_FAILURE`. Build-014 clones the
trusted template before the existing `async move` boundary and passes that owned
value explicitly into the static task. Client request types and authority remain
unchanged.

Build-014 run `38013790722` passed cheap preflight and immutable locked
metadata/fetch, then started Cargo and failed after 411.169 seconds on two exact
pinned API-shape mismatches. The host patch added an in-process-only extension
field to `RemoteAppServerConnectArgs`, and it treated the constrained resolved
MCP map as the map itself. No executable or process proof exists. The immutable
classification is `BUILD_014_PINNED_API_SHAPE_COMPILE_FAILURE`. Build-015 removes
only the remote-client field and reads the already-resolved map through
`config.mcp_servers.get().get(...)`; the reviewed lock remains byte-identical.

Build-015 run `38015223933` stopped before Cargo when pinned rustfmt parsed the
generated host file. Its new-file patch hunk still declared 253 added lines after
the resolved-map correction made the file 254 lines, so the final closing brace
was outside the applied hunk. The immutable classification is
`PREBUILD_HOST_PATCH_HUNK_COUNT_FAILURE` with `rust_compilation_started=false`.
Build-016 corrects only that hunk count; lock contents and dependency edges are
unchanged.

Build-016 run `38015712940` applied the complete host file and passed the source
and lock identity checks, then stopped before Cargo because pinned rustfmt
required the resolved config lookup to use its compact multiline chain. It is
immutable `PREBUILD_RUSTFMT_RESOLVED_CONFIG_CHAIN_FAILURE` evidence with
`rust_compilation_started=false`. Build-017 carries exactly rustfmt's emitted
representation; resolved-config authority, lock bytes, and dependency edges are
unchanged.

Build-017 run `38016240008` passed every cheap and locked dependency gate and
completed the Rust compilation in `529.002760457` seconds. The retained
production executable has SHA-256
`2adc72002a033fefd3ef05d3b4bb6085eb922d1df325a3aa0240cc93d43d06c5`.
Arm A reached the read-only observer, while Arm B stopped during required MCP
initialization because the pinned MCP client clears the child environment and
the reviewed server config had not allowlisted the synthetic receipt locator.
The endpoint therefore closed at its first `tools/list` receipt write; no model,
provider, real task, or MCP tool call occurred. Build-017 is immutable
`BUILD_017_COMPILATION_PASS_MCP_CHILD_ENV_PROPAGATION_PROCESS_FAILURE`
evidence. Build-018 adds only the host-owned non-secret
`DEVHUB_BUILD009_MCP_RECEIPT` name to the synthetic Arm B MCP `env_vars`
allowlist and binds that exact resolved config in a newly hashed strict host
manifest. Production patches, source, lock, schema, stack, and authority remain
byte-identical.
