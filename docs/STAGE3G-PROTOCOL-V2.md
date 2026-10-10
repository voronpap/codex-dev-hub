# Stage 3G protocol v2: minimal retry configuration revision

PR #24 was accepted as partial Stage 3G-C and merged as cb72a0c. Main was
synchronized and the candidate rebased without semantic conflicts. The initial
permissions-blocked attempt remains in stage3g-v2-local-review.json as historical
evidence; it is not the current validation result.

Stage 3G-C OPEN. Stage 3G OPEN. execution_ready=false.
real_codex_executions=0; provider_sends=0. No rehearsal is authorized.

## Exact revision

`benchmarks/real-protocol.json` remains the immutable v1 input. The new
`benchmarks/real-protocol-v2.json` differs only in protocol_id:
`stage3g-seed1-paired-v1` -> `stage3g-seed1-paired-v2`.
The version-aware CLI configuration removes exactly these two entries for v2:

```text
model_providers.openai.request_max_retries=0
model_providers.openai.stream_max_retries=0
```

The production-host qualification correction also adds exactly this fail-closed
v2 launcher setting:

```text
features.tool_registry.error_on_tool_collisions=true
```

The host manifest and retained Build-020 binary already require this setting;
Build-020's accepted Default/A/B process proof used it. The original v2 evidence
predates this launcher correction and remains immutable historical evidence. New
qualification contexts must bind the corrected Codex config hash and freshly
generated plan/session bindings. The corrected Codex config SHA-256 is
`b8fdd8ca11f582b04b217afc4da6f718eb1bb3b443749324faa4eff13f4207fa`;
the protocol payload SHA-256 remains
`fd6d696a20e70aab4eff59343ef8527ee121efca2707ef08b3d748e1b549a2e6`.

The v1 code path retains both entries and its original hashes. No custom provider,
endpoint, auth mode or model is introduced. Apart from the required fatal-collision
setting, all other overrides, policies, timeouts, ordering, CLI version,
model/digest, instructions, reviewer rules and tolerance are unchanged.
Fixture/oracle bytes and all historical evidence remain unchanged.

The new plan records launcher retries=0, benchmark reruns=0, Dev Hub provider
retries=0, Dev Hub fallback after dispatch=0 and codex_internal_retries=null.
CodexUsage.internal_retries already remains null. No undocumented setting is used
to claim zero retries inside Codex. The protocol and Codex config hashes change;
the existing planner regenerates run/plan bindings and UUIDv5 sessions from v2.
Existing qualification receipt validation rejects mismatching v1 protocol/plan hashes.

## Validation and completion commands

Regression tests assert v1 historical hashes, exact two-override removal, unchanged
other policy hashes, unchanged fixture/arm order, 24 unique new session IDs, nullable
internal retries and zero real execution. The exact-image workflow now explicitly
selects v2 and requires the config probe to pass (no continue-on-error). The evaluator,
image lock/build, base digest, binary/archive verification and isolation remain unchanged.

Reproduce offline validation, then run planning from a clean committed checkout:

```sh
uv run --locked ruff check .
uv run --locked ruff format --check .
uv run --locked mypy
uv run --locked pytest -q
uv run --locked pytest -q -m windows_smoke
uv run --locked python scripts/check_evidence.py
uv run --locked python -m devhub.experiment dry-run --protocol benchmarks/real-protocol-v2.json --run-id stage3g-v2-plan-001 --output ../stage3g-v2-plan-001.json
```

The real planner must run from a clean committed checkout; use a new run ID/output
if the example already exists. Run the existing exact-image build/probe/evaluator
workflow with v2; qualify every newly built immutable image ID. No task/inference.
The preflight command in STAGE3G-C.md must then use the v2 protocol and v2 plan plus
proofs from the one intended Linux execution host. Do not combine CI and Windows
receipts. No qualified image/config result is asserted before these checks run.

## Intended execution host investigation

Priority remains existing local Docker Desktop/WSL Linux backend. GitHub, Python
3.12.10, uv 0.12.10 and pydantic 2.12.5 access were restored on 2026-09-30. WSL
Ubuntu 24.04 starts with kernel 6.18.33.2 and Python 3.12.3, but has no running
Docker socket/native dockerd. Docker Desktop Linux mode is configured, yet its
Linux named pipe is absent and the optional Windows service is stopped.

Backend logs identify startup failure while renaming sailor-ingest.sock to .stale.
Both Docker processes were confirmed absent. A reversible rename to a held name
also failed with "The file cannot be accessed by the system"; no socket or system
configuration was changed. This needs operator environment repair before local
qualification. No native Windows/cwd-only fallback is introduced.

A dedicated controlled Linux VM remains the next candidate only if it can satisfy
the frozen numeric loopback Ollama endpoint, exact identity, reviewed auth, scoped
bridge and same persistent accounting history together. Neither an ephemeral CI
host nor a copied reset ledger is a substitute. CI image/config probes and Windows
Ollama/ledger observations are never combined into a qualified environment.

The canonical verifier scripts/verify_protocol_revision.py fails on any change
outside protocol_id and the two approved override removals. The real planner is
used only after green offline validation. Exact-image CLI config and synthetic
evaluator gates run in Linux CI without tasks/inference. Local readiness remains
false regardless of those independent CI checks.

semantic_acceptance=null; quality_benchmark=null; delegation_value=null; savings=null;
codex_internal_retries=null. Stop for review before any rehearsal, even after a future
all-green preflight.

## Historical validated result and later host correction

At implementation a723094, Linux full passed 320 tests (1 skip), Windows smoke 14,
Ruff/format/strict mypy/config/secret scans green. Canonical tooling verified the
minimal semantic diff and produced 24 v2 sessions, unchanged AB/BA order and fixture/
oracle bindings, all session IDs new. See [summary](evidence/stage3g-v2/summary.json)
and its hash-bound plan/semantic diff. Plan is bound to that implementation commit;
subsequent evidence-only commits do not rewrite its identity.

The recorded exact Linux CLI metadata result reported `cli_config=false`; that
receipt remains historical and cannot qualify the current launcher. The retained
Build-020 process proof later established the actual finalized surfaces: Default
ordinary behavior, Arm A empty, and Arm B exactly `devhub_delegate`. Current
qualification must reproduce those surfaces and the corrected fatal-collision
binding on one environment; no metadata observation is substituted for that proof.
No custom provider was added and no config check was weakened.

CI isolation (15/15), synthetic auth/negative egress and evaluator regression passed
on the recorded exact image, but the intended WSL host still has no Docker socket
and its frozen 127.0.0.1:11434 metadata endpoint refuses connection. There is no
all-green qualification receipt. Do not combine those CI and local observations.
Stage 3G-C OPEN; execution_ready=false; all real execution/send counters remain zero.
