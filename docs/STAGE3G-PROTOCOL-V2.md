# Stage 3G protocol v2: minimal retry configuration revision

PR #24 was accepted as partial Stage 3G-C by the operator. Merge and main sync
have not been performed in this session: GitHub network and GitHub CLI config
access are blocked by the current execution environment. This local branch is
based on accepted #24 head `8d05939`; rebase onto main after that merge.

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

The v1 code path retains both entries and its original hashes. No custom provider,
endpoint, auth mode or model is introduced. All other overrides, policies, timeouts,
ordering, CLI version, model/digest, instructions, reviewer rules and tolerance
are unchanged. Fixture/oracle bytes and all historical evidence remain unchanged.

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

After network/runtime access is restored and PR #24 is merged:

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

Priority remains existing local Docker Desktop/WSL Linux backend. Read-only diagnosis
observed com.docker.service stopped (manual start). Docker daemon access could not be
established; Docker config access is denied. WSL enumeration returns E_ACCESSDENIED,
so backend state is unknown in this restricted session. No system configuration,
service start mode, installation, VM, forwarding, auth or endpoint was changed.

Restore access and diagnose the existing Desktop Linux engine first. A dedicated
controlled Linux VM is the next candidate only if it can satisfy the frozen numeric
loopback Ollama endpoint, exact identity, reviewed auth, scoped bridge and the same
persistent accounting history together. Neither an ephemeral CI host nor a copied
reset ledger is a substitute. Native Windows/WSL cwd-only execution remains forbidden.

The workspace venv cannot start its original Python, and its pydantic native DLL
cannot load under current permissions. Bundled Python can perform stdlib syntax,
hash and seed-integrity checks only; those are not pytest, mypy, the actual planner
or exact-image qualification. Current plan hash and config-probe outcome remain null
until executed. No protocol-ready/environment-ready claim is made.

semantic_acceptance=null; quality_benchmark=null; delegation_value=null; savings=null;
codex_internal_retries=null. Stop for review before any rehearsal, even after a future
all-green preflight.
