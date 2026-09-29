# Stage 3G-B: protocol and isolated launcher (review required)

Stage 3G-A CLOSED; offline harness accepted in PR #22. Stage 3G remains OPEN.
Real Codex benchmark executions = 0; provider sends = 0. This PR freezes a proposed
real protocol, provides an opt-in one-session coordinator, and demonstrates the
boundary with offline/synthetic tests. It does not run a frozen fixture, a real
single-pair rehearsal, or an evaluation of benchmark outputs.

## Research and chosen boundary

The installed CLI reports `codex-cli 0.155.0-alpha.9.2`; only version/help/features
metadata was read. The official [non-interactive guide](https://learn.chatgpt.com/docs/non-interactive-mode)
documents fresh exec, ephemeral storage, ignoring user config, JSONL events and the
final-message file. The [permissions guide](https://learn.chatgpt.com/docs/agent-approvals-security)
distinguishes sandboxed commands from the surrounding process. Neither cwd nor
read-only mode is proof that the agent cannot read the rest of the host. Ephemeral
means rollout persistence is disabled, not that access is isolated.

Selected boundary: a new **Linux OCI container for every arm**, immutable local image
ID, no pull, no network namespace access, read-only root and packet, nonroot UID,
all capabilities dropped, no-new-privileges, bounded CPU/RAM/PIDs and private tmpfs
HOME. [Docker's container reference](https://docs.docker.com/engine/containers/run/)
describes the namespace/mount boundary and explicit resource controls. No Docker
socket, host HOME, repository, evaluator, full run root, shared accounting state,
opposite packet or previous output is mounted. Each session gets only:

- its four derived packet files (same task/input bytes in A and B);
- its own empty output directory;
- a reviewed infrastructure bootstrap file (no evaluator/answers);
- one explicit existing CLI auth file read-only, copied into fresh tmpfs HOME;
- session-scoped Unix bridge sockets.

The code and Docker daemon, image, host kernel, controller, accepted Dev Hub runtime,
operator, and Codex service are trusted. This is not a defense against a malicious
administrator, kernel/container escape or compromised runtime image. The runtime
bootstrap is visible infrastructure, not evaluator source. CLI authentication is
visible to the trusted CLI/container; shell tools are disabled, but this is not a
claim of credential secrecy from a compromised CLI. No cross-session model-provider
cache isolation or statistical independence of service/hardware load is claimed.

Native Windows `read-only` and WSL cwd selection were considered insufficient as
outer boundaries. Docker CLI is installed locally, but its daemon was unavailable;
WSL had no Codex/bwrap binary. No installation, model pull or live session was used
to hide that limitation. Real launch supports a reviewed Linux Docker host only,
with the accepted Ollama endpoint reachable as numeric loopback and the existing
accepted accounting ledger available. There is no native-host fallback.

## Frozen inputs, order and policies

`benchmarks/real-protocol.json` pins the CLI version, exact accepted 3F Ollama
configuration (including model, manifest digest and timeout), Context Builder and
output policies. The profile is local only; approved Brain sources are exactly
input.txt/task.txt in a fresh trusted Git snapshot for that session. A/B task intent
and requirements come from the same frozen fixtures. No oracle-derived fact enters
an executor. Source/fixture/oracle hashes remain the original seed-1 values.

Manifest order, alternating AB then BA per fixture, gives six A-first and six B-first
pairs. No runtime randomness, seed selection or result-dependent scheduling. UUIDv5
session IDs bind run ID, protocol hash, fixture and arm. No resume/fork/session reuse.
Every subsequent attempt must follow that order; failed/interrupted attempts cannot
be overwritten or silently skipped. Each run ID has immutable plan/bindings and a
durable exclusive attempt claim before container start.

Plan binds implementation commit, baseline/fixture/oracle hashes, protocol hash,
Codex config/mode, router/context/output/instruction hashes and reviewer rules hash.
Model IDs remain configuration. Ollama identity comes from accepted historical 3F
configuration, not a new probe. Its availability/digest/version must be checked
before and after every future arm. Router/core/provider semantics are unchanged.

Codex selected mode is ephemeral text-only exec with no shell/unified exec, apps,
web search, memories, hooks, remote plugins or subagents. The [configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
and [feature documentation](https://learn.chatgpt.com/docs/config-file/config-basic)
are the sources for overrides. No user/project rules or config are inherited. The
exact underlying Codex model is unknown and null; this is not silently labelled as
a particular model. A service default is explicitly recorded. If an explicit model
is later selected, it changes the protocol/config hash before any execution.

A has no MCP server connection. B has only the accepted devhub_delegate server
behind a host bridge; it accepts one correctly scoped local_only request with cloud
false and the frozen citation policy. It reuses the accepted Brain/Context/Router/
Controller/adapter/ledger. No diagnostic tools or cloud profiles are configured.
Delegation is **optional**; do_not_delegate fixtures remain unchanged. A failed or
ambiguous delegate call cannot trigger another provider send via this bridge.

## Network and secret boundary

Container network is none. A loopback TCP proxy forwards only through its scoped
Unix CONNECT bridge to exact public `chatgpt.com:443` or `api.openai.com:443` targets;
private/loopback DNS results and all other targets are denied. This is Codex service
egress, not Dev Hub cloud eligibility. Adding an endpoint needs a reviewed protocol
change, not automatic retry. B's separate MCP bridge invokes trusted local Dev Hub
outside the container; only that boundary can reach numeric-loopback Ollama.

The accepted shared ledger is reused and never mounted into the executor. Brain
scope and replay key are unique per session. Unknown accounting remains liability;
a killed in-flight runtime may leave dispatched state requiring existing recovery
and explicit reconciliation, never a new run with a reset ledger.

Only explicitly supplied existing ChatGPT CLI auth is accepted, not an OpenAI API
key or Groq/Gemini environment. Host environment is not inherited. Auth is not copied
into the run tree or hashed into evidence; the guest copy lives in tmpfs. Final/event
bytes are scanned against known secret/account values and credential patterns before
publication. A hit aborts and withholds artifacts; it does not redact/rewrite output.
Unverified capture lives in a private /dev/shm directory outside the run tree and is
discarded on teardown; only scanned bytes are published. No credential fingerprints
are recorded. The local Unix Docker socket is selected explicitly, not inherited
from Docker context/environment.

## Timing, failure and metrics

900 seconds per session. The timer starts immediately before container start/attach
and ends on final-byte capture: Codex startup, context, tools, inference and validation
are included equally. Packet staging, image/auth/metadata preflight and later review
are excluded. Cleanup after capture is excluded; timeout cleanup belongs to a failed
attempt and is not used for a latency winner. UTC timestamps and monotonic duration
are retained. No result means unknown duration in pre-execution not_run records.

Container creation failure is technical not_run: packet was not exposed to a running
executor. Once the container starts and can read its packet, conservatively treat
crash/timeout/approval failure as failed experiment attempt, even if task receipt by
the remote model is unknown. No automatic rerun. CLI kill alone is insufficient:
the launcher stops the whole container. Interrupted durable claims consume attempts.

Global abort: model/version/config/implementation/environment drift, unavailable
Ollama, failed OS/auth preflight, tampered fixtures/artifacts, unexpected tool/cloud/
network routing, oracle contamination, incomplete attempt or timeout. Preserve the
partial run and ledger. Do not reuse its run ID. Code/model changes require a new
reviewed protocol/run; never combine results across configurations.

Codex metrics use the documented top-level turn.completed JSONL usage event with
exact version, single fresh thread/turn and integer-shape validation. UI text,
agent prose, proxy counts, ambiguous/multiple turns, malformed data and version drift
produce null. Input/output/cached-input are distinct; cached input is not added twice.
Context usage and internal Codex retries remain null. Requested HTTP/SSE retries and
launcher retries are zero, but a setting is not proof of unobservable internal retries.
Missing usage alone does not turn a completed execution into a failure.

For B, the host bridge records whether/count delegation occurred, validated compact
handoff and actual project-scoped outbox events. Provider/model/package hash, input/
output usage, latency, reservation/dispatch/settlement, retries and fallback remain
separate. Complete local settlement can establish provider API cost = 0 even when
output validation fails. No delegation means API cost=null, not a fictitious free
inference. Electricity/hardware costs are unmeasured. Raw final bytes are copied
without decoding/newline/whitespace normalization before hashing and exclusive write.

## Reviewer and comparison protocol (before results)

All twelve fixtures produce text only, including source and test drafts. None needs
executor file edits. Shell/generated-code execution is disabled. direct-01 uses
exact source comparison allowing only CRLF/terminal-newline differences in the
**comparison view**; raw artifact remains unchanged. extract-* uses typed JSON
structural equality, without accepting markdown fences. The remaining requirements
are enumerated from the frozen oracle by reviewer_rules(), including citations/URLs,
required facts/fixes and forbidden claims. No rubric-weighted score or LLM judge.

Review barrier: both arm output artifacts must be frozen/hash-verified before a
separate blinded reviewer receives the oracle. No production evaluator is invoked
in 3G-B. Evidence-backed item decisions must record required facts hit/missing,
incorrect/unsupported claims, acceptance, applicable tests/citations and human repair.
Unknown required checks => acceptance=null; demonstrated failure => false.
Required false expected_delegation must be backed by zero observed delegate calls.

`tests-01` and `tests-02` additionally require isolated execution against buggy and
corrected references. That evaluator is **not implemented or invoked here**. Its
reviewed design must use a different network-none, credential-free container with
only the frozen generated test plus trusted reference, CPU/memory/PID limits and a
60-second timeout. No shared state/socket/auth mounts. No imports/exec on the host.
Until that gate exists their tests_pass and final acceptance cannot be asserted.

Human correction definitions are unchanged: none = all requirements verified/no
edits; minor = presentation-only edits; major = substantive repair of failed criterion;
unusable = no usable artifact or critical failure. Insufficient review => null.

Frozen comparison uses quality first. Compromised execution/isolation/timing or unknown
acceptance => inconclusive. One passing arm beats a failing arm on acceptance. Two
failed arms => inconclusive with raw failures. Two passing arms compare known human
correction (none/minor), then comparable wall time. Tolerance is
`max(5000 ms, 20% of the faster arm)`, an a-priori practical allowance for startup/
service jitter, not an empirical significance threshold. Within tolerance => equivalent
on these primary dimensions; beyond it => faster arm better **on latency only**.
Missing primary timing/correction => inconclusive. Observable tokens/cost/retries
remain separate dimensions, never silently traded against quality/time. Optional
unknown Codex usage leaves resource value unresolved even if a latency classification
is possible. No weighted aggregate, final Delegation Value or savings is computed.

## Reproduce dry-run and review gates

From the clean implementation commit (no model/auth access):

```sh
uv run --locked python -m devhub.experiment dry-run --protocol benchmarks/real-protocol.json --run-id stage3g-b-plan-001 --output ../stage3g-b-plan-001.json
uv run --locked python -m devhub.experiment schemas --protocol benchmarks/real-protocol.json --run-id stage3g-b-plan-001 --output ../stage3g-b-schemas.json
uv run --locked pytest -q tests/test_experiment.py
```

CLI exposes only dry-run/schemas, not execute. Plan deliberately has
execution_ready=false and runtime_bindings=null. It is not fabricated real-environment
proof. RuntimeBindings requires a reviewed immutable Linux image, real environment
manifest (OS/Python/CLI/commit/Ollama/model/digest/CPU/GPU-if-observable/RAM/timestamp),
bootstrap hash, OS probe artifact hash and exact plan hash. No hostname, serial,
account ID or credential identity is required. Unknown Codex model/GPU/RAM stay null.

Linux CI compiles a static synthetic C probe into a FROM-scratch image without a
pull, using the launcher's mount/network recipe. It verifies hidden host/opposite/
oracle canaries, nonroot/read-only packet access, empty HOME and denied direct network.
No Codex/Ollama runs. This validates the recipe, not an unavailable future runtime
image. After review, an operator can run the same **non-benchmark** probe against an
already-built local image using `scripts/probe_oci_boundary.py --image-id sha256:...`
with an exclusive --output path. It must pass for that exact runtime image. The image
must contain pinned Codex/Python only, no baked benchmark data, user configs, skills,
credentials or volumes. Image provisioning and actual Codex auth/tool/config preflight
remain explicit gates; no placeholder image digest can authorize execute_next().

Normal CI: Linux full plus Windows smoke, with the Linux synthetic OCI check.
Full Windows is deferred until Stage 3G closure. Review this PR before any real
session, including a rehearsal. Stage 3G remains OPEN; Router unchanged.
