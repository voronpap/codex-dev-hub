# Stage 3G-C runtime qualification

Stage 3G-B CLOSED (accepted PR #23). Stage 3G-C and Stage 3G remain OPEN.
Real Codex benchmark executions = 0; provider sends = 0; execution_ready = false.
No fixture, paired rehearsal, benchmark evaluation or inference is authorized here.

## Exact image and provenance

The frozen CLI remains `codex-cli 0.155.0-alpha.9.2`, with service-default model
identity null. The installed Windows executable reports that version; its SHA-256
is `bc45017e8239dc150258f69309ced9df6bbcdf5b8e4f346decf780ac0999e226`.
This Windows hash does not establish Linux identity.

The [official CLI documentation](https://learn.chatgpt.com/docs/codex/cli) describes
distribution through standalone binaries/npm. The exact Linux musl release exists
at [OpenAI's release](https://github.com/openai/codex/releases/tag/rust-v0.155.0-alpha.9.2).
`benchmarks/runtime-lock.json` records its archive SHA-256 from release metadata and
the immutable linux/amd64 Python base manifest. No latest/alpha tag installation,
CLI update, model replacement, pull or protocol model change is performed.

`scripts/build_benchmark_runtime.py` verifies the archive before reading its single
binary, builds from a two-file temporary context and checks CLI --version with
network disabled. The image contains Python, CA certificates/base runtime and Codex;
no Dev Hub source, fixtures, oracle, evaluator, git history or credentials. The
bootstrap remains an explicit read-only mount. Output records content-addressed
image ID, base digest, recipe/lock/archive/binary hashes. OCI images remain local;
the workflow does not publish an image registry tag. Builds may have different image
IDs: only the exact built ID and its exact probes qualify, never a recipe alone.

## Qualification boundaries

The enhanced same-recipe C probe checks the nine accepted isolation checks plus
effective/bounding capabilities, no-new-privileges, actual cgroup v2 memory/PID/CPU
limits, no Docker socket, no host HOME and no repository. Namespace isolation is
not a kernel-escape guarantee; host/operator/daemon/image remain trusted.

`qualify_runtime_config.py` runs metadata-only CLI commands in each A/B container:
features list, MCP configuration list and --version. It supplies synthetic auth and
exercises the actual bootstrap tmpfs copy, mode 0600 and scoped Unix CONNECT bridge.
It never issues a task to Codex or connects an MCP inference call. Only A/B packets
containing synthetic text are mounted. The actual CLI service's authentication and
end-to-end transport are not proven by a synthetic auth-copy test.

The proxy permits exact chatgpt.com/api.openai.com TLS CONNECT destinations. Negative
guest tests cover arbitrary internet, private/loopback, Docker host and Groq/Gemini.
Offline tests inject private DNS results, including metadata/link-local/IPv6, into
the actual proxy and prove rejection before connect. No proxy environment is inherited;
guest proxy variables are explicit. These checks do not claim service availability.

Host MCP scope and one-call/replay/accounting remain accepted 3F/3G-B contracts.
Neither benchmark runtime nor evaluator mounts the ledger. Preflight opens the
existing ledger read-only, checks integrity/schema and never creates/resets it.
Ollama qualification invokes the existing metadata-only inspect contract. A mismatch
does not choose a new model, update or pull. The accepted protocol remains unchanged.

## Evaluator sandbox

The evaluator image is separate and contains Python + exact pytest wheels verified
against uv.lock. It has no Codex binary, credentials, model, MCP or ledger. Only
generated test bytes, one reference and the minimal runner are mounted read-only.
Network none; nonroot; capabilities dropped; no-new-privileges; read-only root;
256 MiB RAM, one CPU, 32 PIDs, 32 MiB tmpfs, a 60-second timeout per reference
and a 1 MiB capture limit per output stream (overflow stops the whole container).
The controller stops/removes the entire container, including on failure.

The trusted reviewer first verifies both frozen A/B launch receipts and output hashes
with frozen_pair(). Exact Python test bytes execute against a buggy then corrected
`solution` module. No host import, code execution, markdown stripping or automatic
repair occurs. Unsupported prose/import conventions require an explicit reviewer
decision and cannot silently become passing tests. Raw artifacts remain unchanged.
Machine-readable output binds generated/reference/runner/image hashes, actual
container exit status, timeout, stdout/stderr hashes and tests_pass. Catching the bug
and passing the reference is necessary but does not establish test adequacy or final
semantic acceptance. The oracle/reviewer checks remain mandatory.

`qualify_evaluator.py` uses a synthetic add/subtract example unrelated to any frozen
fixture. tests-01/tests-02 outputs have not been generated or evaluated. Their reviewed
reference preparation/format decision happens only after both future outputs freeze.

## Preflight and fail-closed launcher

The former single receipt plus caller-supplied expected subset is superseded for new
execution by [the acyclic qualification context and final manifest](QUALIFICATION_MANIFEST.md).
New `RuntimeBindings` carries only `qualification_manifest_id`; its path is a locator.
The launcher re-reads the fixed receipt set and derives image, plan, ledger, Codex,
Ollama, evaluator, and immutable Python runtime identities from that one authority.
Historical receipts remain unchanged and inspectable but cannot pass the new gate.

The following command documents the historical metadata collector. Its output alone
is no longer sufficient for new execution authorization:

```sh
python -m devhub.experiment_preflight preflight \
  --protocol benchmarks/real-protocol.json --plan /private/plan.json \
  --build /private/build.json --isolation /private/isolation.json \
  --runtime-checks /private/runtime-checks.json --evaluator /private/evaluator-proof \
  --auth /explicit/existing/auth.json --ledger-root /existing/accepted/state \
  --output /private/new-qualification.json
```

Run from a clean committed checkout. It verifies fixture/oracle/plan/implementation,
image/binary/CLI/bootstrap, exact-image probes, egress/config/auth gates, accepted
Ollama identity, existing ledger, evaluator, disk and secret scans. Absent/failed
checks remain false. Unknown observed identity fields remain null. Only all gates
true can produce execution_ready=true. The receipt and every input artifact hash
are operator-controlled evidence, not cryptographic protection against a malicious
operator. No credentials, fingerprints, account identifiers, serials or hostnames
are written. Capture publication aborts/withholds on a secret match; bytes are not
redacted to continue.

Qualification remains separate from permission to rehearse. Failure preserves
historical evidence; no attempt/permit reset, rerun, resume or fork.

## Current limits and CI

Build-020 preserves the historical Candidate B patch and adds the reviewed shipping
host integration. Independent review accepted the actual same-binary process proof:
ordinary Codex retained `AllowedTools=None`; Arm A used `Some([])` and exposed no
tools; Arm B used `Some([mcp__devhub_delegate.devhub_delegate])` and exposed only
that delegate. The production-host activation/process-visibility sub-gate is
`PRODUCTION_HOST_QUALIFIED`.

The existing benchmark runtime image still contains the official unpatched release,
not the retained Build-020 executable. Its isolation/effects/config receipts therefore
cannot authorize the patched host, and the exact-image configuration gate still
reports `cli_config=false` with unresolved `apply_patch`/`write_file` mapping. A new
acyclic qualification context must bind the Build-020 binary into the exact runtime
image and collect the complete fixed receipt set on one intended environment. Stage
3G-C and Stage 3G remain open and `execution_ready=false`.

Local Docker Desktop Linux daemon remains unavailable after startup attempts; its
named pipe is absent. Therefore no local runtime image/environment can yet be
qualified. The dedicated Linux qualification workflow builds exact images and uses
only synthetic probes. It has no real auth, accepted local ledger or local Ollama:
its successful checks cannot set local execution_ready=true. Normal CI is Linux
full + Windows smoke. Full Windows remains a final Stage 3G closure gate.

Stage 3G-C remains OPEN until all gates pass together on the intended Linux execution
host. Stop for review before any rehearsal, even after readiness. All quality,
semantic acceptance, Delegation Value and savings claims remain null.

The B-arm completion gate is specified in
[B_ARM_DELEGATION_OBSERVATION.md](B_ARM_DELEGATION_OBSERVATION.md). A tool call count
alone is not success: the runner must join the strict handoff to the exact reservation,
full authoritative accounting chain, complete usage, and qualification-bound local
provider identity. This gate does not change the frozen task protocol or close this
stage.

## Frozen configuration blocker: review required

Metadata-only qualification found that the exact CLI rejects the frozen
`model_providers.openai.request_max_retries=0` and
`model_providers.openai.stream_max_retries=0` overrides: built-in `openai` is reserved
and cannot be overridden. This occurs before any task. The initial probe additionally
found that --strict-config is supported for exec, not features/mcp metadata commands;
only the probe invocation was corrected. Actual frozen exec configuration is unchanged.

The config qualification step deliberately reports failure and stores cli_config=false;
CI continues collecting the independent evaluator evidence. A green report workflow
therefore does NOT mean runtime readiness. Linux full/Windows smoke remain required.

Proposed next review: version the Codex configuration hash to remove the two rejected
built-in provider overrides, retaining zero launcher retries/reruns and null unknown
internal Codex retries, or first establish a supported zero-internal-retry mechanism.
No replacement/custom provider, auth mode, model or endpoint is selected here. Neither
proposal has been applied. The existing frozen config remains blocked. Review is
required before any revised protocol, and again before rehearsal. No silent fallback.

Evidence is stored in [the machine-readable summary](evidence/stage3g-c/summary.json).
At implementation f74e665 Linux full passed 318 tests (1 skip), Windows smoke 14;
Ruff/format/mypy/config/secret scans passed. Runtime CI built the exact CLI image,
passed 15 isolation checks, synthetic auth/negative-egress and evaluator proof,
and recorded reserved_builtin_provider_override for both A and B. The image existed
on an ephemeral CI host; this is not a provisioned local benchmark runtime. The
Windows metadata-only preflight confirms accepted Ollama version/model/digest and
read-only ledger availability, while correctly refusing Linux execution readiness.
These separate environments are not combined into a fabricated all-green manifest.
