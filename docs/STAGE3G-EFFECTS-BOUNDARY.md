# Stage 3G-C: effects-boundary review (not applied)

PR #28 was merged as patch-control investigation / Case C. Stage 3G-C and
Stage 3G remain OPEN. The absence-based gate still fails. No further hidden
patch-disable controls are sought. No benchmark, rehearsal, model request or
provider inference is part of this review.

## Decision

An effects-based replacement is **not yet viable**. Local filesystem protection
does not prove absence of server-side persistence. Critical unknowns fail the
proposed decision rule. No executable `stage3g-tool-effects-v2` policy or policy
hash is issued. The existing policy remains unchanged:
`e3aa6f28641e7b9c8e73b36f5943dd4af946a4641fecc061dae8ecf122d0a8ec`.

The comparison is between requiring forbidden tools to be absent and allowing
registered tools only when their effects cannot escape the approved boundary.
Registration, successful invocation and effect capability are separate facts.
The [complete matrix](evidence/stage3g-effects-boundary/review.json) covers every
canonical #27 surface, including wrappers. Nulls are unresolved, not negatives.
`apply_patch` registration is source/metadata-derived; no direct handler or model
invocation has been observed. The synthetic probe tests filesystem operations
available to a process in the outer boundary, not the inner patch sandbox.

## Threat model and protected assets

Treat instructions and model-selected actions as untrusted. Trust the pinned
runtime binary, host launcher, kernel/container engine and scoped bridges.
This is not protection against a compromised binary or kernel vulnerability.
Read access to the current packet is necessary; immutability protects its
integrity. Other sessions and reviewer secrets require both confidentiality and
integrity. A literal ban on reading all protected state would prevent execution.

| Asset | Guest visibility | Required protection |
| --- | --- | --- |
| Current input, fixture/task bytes, instructions, session manifest | `/packet`, readable | Read-only bind; bytes unchanged |
| Opposite arm, previous/future sessions, oracles, reviewer/evaluator artifacts | Not mounted | Neither readable nor writable |
| Host filesystem, repository, host HOME, Docker socket | Not mounted | Neither readable nor writable; no shared host PID namespace |
| Accepted ledger and Ollama endpoint | Not mounted / direct network unavailable | B accesses approved operation only through trusted MCP bridge |
| Persistent credential source | Host HOME not mounted; staged auth is readable | Guest cannot overwrite source; no secrecy claim against trusted process |
| Network | `network=none`, scoped Unix proxy | Only approved bridge destinations; endpoint effects still need audit |
| Dev Hub state | B-only MCP socket | `devhub_delegate` only, host validation/accounting; A has no MCP |

## Writable and readable surfaces

The launcher is unchanged. The inventory below includes Docker-managed mounts,
not only explicit host binds. Raw mountinfo and namespace observations accompany
synthetic evidence. No generic claim that read-only root means no writable paths.

| Mount/path | Access | Purpose/lifetime | Published / cross-session |
| --- | --- | --- | --- |
| `/` image | RO | Pinned runtime / image lifetime | No guest changes |
| `/packet` | RO bind | Current packet / session | Input retained by host; no cross-arm mount |
| `/bootstrap.py` | RO bind | Trusted launcher / session | Code versioned |
| `/auth.json` | RO bind | Staged credential input / session | Never publish; host staging cleanup remains host responsibility |
| `/bridge` | RO directory bind, sockets usable | Scoped proxy; B additionally MCP / session | Socket operations can affect host/service despite RO mount |
| `/capture` | RW host bind, fresh/empty | Final output / session | Intentionally persists for scanned/hash-bound artifact publication; never mounted into another arm |
| `/tmp` | RW tmpfs, noexec/nosuid, 64 MiB | Scratch / container | Not published, not persistent |
| `/home/runner` | RW tmpfs, noexec/nosuid, 64 MiB | Fresh HOME/CODEX_HOME, auth copy / container | Not published, not persistent |
| `/dev` | Docker-managed tmpfs/devices | Minimal device interface / container | No artifact publication; kernel/device interfaces are not ordinary files |
| `/dev/shm` | RW tmpfs | Container IPC / container | Not published, not persistent; additional writable scratch beyond preferred three paths |
| `/dev/pts`, `/dev/mqueue` | Kernel-managed mounts | Terminal/IPC / container | No intentional publication/persistence |
| `/proc` | Mixed procfs, masked/RO submounts | Container processes/kernel interfaces | Some process-local state writable; not a general disk-write exemption |
| `/sys` and cgroup | RO | Kernel/resource metadata | No publication/persistence |
| `/etc/hosts`, `/etc/hostname`, `/etc/resolv.conf` | Docker-managed binds; nonroot writes denied | Container metadata / container | Not benchmark artifacts; inspected rather than assumed RO |

Synthetic `/probe.py` is one additional RO bind used only for proof. The probe
records all mounts including Docker-generated masked paths; they are not changes
to the executor. `/capture` content is untrusted before exclusive freezing and
hashing. Filesystem isolation cannot guarantee a truthful answer or prevent a
tool from corrupting its own output. The current launcher also rejects file-change
events; this review does not remove that check.

## Credential and network limits

Bootstrap copies staged `/auth.json` into fresh CODEX_HOME tmpfs with mode 0600.
Trusted Codex can read both. No host HOME mount or cross-session tmpfs reuse is
allowed. Scanning with actual secret values remains fail-closed before artifact
publication; it is not a mathematical guarantee against encoded exfiltration.
Synthetic proof uses `{}` only, never real auth.

The CONNECT bridge restricts destination hosts/ports, not encrypted HTTP paths.
Thus permitting Codex service TLS can also permit notes or other server-side
effects at the same destination. `network=none` does not make a mounted Unix
bridge inert. B's guest has no direct ledger, repository or Ollama connection;
MCPGate is the approved host authority. A/B use identical container settings
except B's MCP configuration/socket. Synthetic socket markers test mount shape,
not live RPC; existing bridge/config regressions test scope separately.

## Persistent-effect audit

The matrix cites the unchanged pinned #27 source evidence for exact CLI
0.155.0-alpha.9.2, source commit 4607249e430dac1c961df4dc615beae88e33cec8.

* `notes.write_file` and `notes.append_to_file` use remote notes endpoints.
  Effective extension absence remains unproved. If enabled, OCI filesystem
  controls cannot prevent persistence. This is a critical blocker.
* Memory notes are local; accepted `memories=false` disables their tool surface.
  Goal tools are disabled by `goals=false`. Neither fact establishes absence of
  every service-side state mutation.
* Image generation combines remote generation with local artifact writes.
  Complete feature/account/model guards remain unknown; no image call is allowed.
* Plugin-install requests can ask the client to expand capabilities and persist
  choice state. Client mediation is not proof of impossibility. Still unresolved.
* Code-mode `exec`/`wait` can reach nested tools. They inherit unresolved remote
  authority; changing presentation does not remove effects.
* Shell and multi-agent surfaces are absent under accepted feature guards.
  These source-derived negatives do not imply the whole registry is safe.

Unintended remote persistence remains **possible if enabled, actual availability
unknown**. No endpoint is probed by performing a mutation. No all-clear receipt
can be constructed from filesystem success plus these unknowns.

## Proof, scope and protocol implications

`scripts/probe_effects_boundary.py --image-id sha256:... --output NEW.json` runs
synthetic A and B containers using the existing recipe. It attempts overwrite,
append-open, unlink, rename and replacement of protected files, creates forbidden
host-like paths, and tests intentional scratch/output writes. It records proc,
sys/dev mounts, namespace IDs, visible PIDs and Unix sockets. No model starts.
The separate existing 15-check isolation and synthetic evaluator regressions
remain required. No kernel-perfect isolation or intended-host qualification is
inferred from CI.

Protocol/config bytes and their hashes remain frozen because this PR changes
neither runtime behavior nor qualification semantics. A future readiness-only
policy revision would get a distinct policy hash and require new receipts, while
identical executor protocol/config bytes could keep their hashes. Any future
mount/config/bridge behavior change must version the protocol and be reviewed.

No Docker/WSL repair is performed. The intended Linux host remains separately
unqualified. `execution_ready=false`, `real_codex_executions=0`,
`provider_sends=0`; semantic acceptance, quality, savings, Delegation Value and
internal Codex retries remain null. STOP for review; no rehearsal.
