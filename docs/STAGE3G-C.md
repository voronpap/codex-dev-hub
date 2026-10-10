# Stage 3G-C runtime qualification

Stage 3G-B CLOSED (accepted PR #23). Stage 3G-C is CLOSED for the exact reviewed
manifest below; Stage 3G remains OPEN. Real Codex benchmark executions = 0;
provider sends = 0. No fixture, paired rehearsal or benchmark evaluation has run.

The intended-host qualification manifest is
`d6d3e1f565064846af495b5d9cab6e3f54738616d383c5c6afddf02c666b5441`,
with context `5d0df8d906fe1f204f916ad4e633f1cbb8a27bb91d3f99a4c9812d81761f6168`
and environment `169a6b903825d8c88973dd592c4601d9`. Its fixed ten-receipt set
mechanically derives `execution_ready=true`. This authority does not transfer to a
different image, executable, ledger, evaluator, Python runtime, Ollama instance,
configuration or environment.

## Exact image and provenance

The frozen CLI remains `codex-cli 0.155.0-alpha.9.2`, with service-default model
identity null. The installed Windows executable reports that version; its SHA-256
is `bc45017e8239dc150258f69309ced9df6bbcdf5b8e4f346decf780ac0999e226`.
This Windows hash does not establish Linux identity.

The [official CLI documentation](https://learn.chatgpt.com/docs/codex/cli) describes
distribution through standalone binaries/npm. The exact Linux musl release exists
at [OpenAI's release](https://github.com/openai/codex/releases/tag/rust-v0.155.0-alpha.9.2).
`benchmarks/runtime-lock.json` retains that historical release provenance and now
also records the accepted Build-020 workflow/artifact/ZIP, pinned source archive,
patchset and production executable identities. No latest/alpha tag installation,
CLI update, model replacement, pull or protocol model change is performed.

`scripts/build_benchmark_runtime.py` re-reads the retained Build-020 executable,
checks it against repository evidence and the runtime lock, builds from a two-file
temporary context and checks CLI --version with network disabled. It has no fallback
to the official unpatched release or an ambient executable. The image contains
Python, CA certificates/base runtime and Codex;
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
Ollama qualification invokes the existing metadata-only inspect contract through a
strict AF_UNIX bridge that runs beside Ollama in the reviewed no-route namespace. The
bridge has a compiled-in `127.0.0.1:11434` destination and a private `0600` socket in
an owned `0700` directory; it is not a general proxy. The coordinator and immutable
B-arm runtime revalidate the exact process start identities, namespace, interpreter
and running executable, Ollama LISTEN inode, bridge socket inode and peer credentials
before use. The bridge-bearing Ollama receipt is V2; historical V1 remains read-only
audit evidence and is non-authorizing. The operator still owns creation
of the isolated namespace; bridge code runs unprivileged as the same UID as Ollama.
A mismatch does not choose a new model, update or pull. The accepted protocol remains
unchanged.

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

The exact-image workflow now builds from the retained Build-020 executable. It keeps
the proof-only Build-020 host manifest immutable and separately binds a shipping host
manifest whose resolved MCP config matches the actual launcher (no proof receipt
environment variable). A fresh read-only observer checks Default host authority,
Arm A empty visibility, Arm B exact delegate visibility, exact A/B difference, one
catalog `tools/list`, zero `tools/call`, and zero model/provider executions.

CI is not the intended execution host. The accepted chain was collected on one local
Linux/OCI environment and binds the retained Build-020 executable, exact runtime and
evaluator images, immutable Python runtime, validated ledger identity, auth/egress,
filesystem/isolation/config probes and exact Ollama 0.34.2 identity. Default exposure,
Arm A empty visibility and Arm B delegate-only visibility were observed using the same
retained executable before sampling; MCP tool calls, model requests, provider sends and
real task executions remained zero. Independent review returned `ACCEPT`.

The additive machine-readable evidence is in
[`evidence/stage3g-intended-host-af5d081/`](evidence/stage3g-intended-host-af5d081/).
Credential bytes, the mutable ledger database, logs, executable/model blobs and
temporary files are deliberately excluded. Stage 3G remains OPEN pending a separate
rehearsal and the frozen paired run. All quality, semantic acceptance, Delegation
Value and savings claims remain null.

The separate rehearsal control is documented in
[STAGE3G-REHEARSAL.md](STAGE3G-REHEARSAL.md). It cannot consume a frozen benchmark
fixture and must be rebound to a fresh manifest after its implementation commit.

The B-arm completion gate is specified in
[B_ARM_DELEGATION_OBSERVATION.md](B_ARM_DELEGATION_OBSERVATION.md). A tool call count
alone is not success: the runner must join the strict handoff to the exact reservation,
full authoritative accounting chain, complete usage, and qualification-bound local
provider identity. This gate does not change the frozen task protocol or close this
stage.

## Historical configuration blocker and current binding

Historical metadata-only qualification found that the exact CLI rejected the frozen
`model_providers.openai.request_max_retries=0` and
`model_providers.openai.stream_max_retries=0` overrides: built-in `openai` is reserved
and cannot be overridden. This occurred before any task. The initial probe additionally
found that --strict-config is supported for exec, not features/mcp metadata commands;
only the probe invocation was corrected. Protocol v2 subsequently removed those two
unsupported retry overrides while retaining null internal-retry observability.

The current production-host binding also requires
`features.tool_registry.error_on_tool_collisions=true`, matching the host manifest
and accepted Build-020 Default/A/B proof. This fail-closed launcher correction changes
the Codex config hash and requires fresh plan, context and receipt bindings. It does
not change protocol v2 task semantics, fixtures, prompts, ordering, timing or provider
policy. A green CI mechanics workflow still does not make CI the intended execution
host or set `execution_ready=true`. Linux full/Windows smoke remain required.

No replacement/custom provider, auth mode, model or endpoint is selected. Historical
receipts and plans remain immutable and cannot satisfy the accepted bindings. The
accepted manifest is necessary but does not itself constitute a rehearsal or authorize
substitution of any bound component. No silent fallback.

Evidence is stored in [the machine-readable summary](evidence/stage3g-c/summary.json).
At implementation f74e665 Linux full passed 318 tests (1 skip), Windows smoke 14;
Ruff/format/mypy/config/secret scans passed. Runtime CI built the exact CLI image,
passed 15 isolation checks, synthetic auth/negative-egress and evaluator proof,
and recorded reserved_builtin_provider_override for both A and B. The image existed
on an ephemeral CI host; this is not a provisioned local benchmark runtime. The
Windows metadata-only preflight confirms accepted Ollama version/model/digest and
read-only ledger availability, while correctly refusing Linux execution readiness.
These separate environments are not combined into a fabricated all-green manifest.
