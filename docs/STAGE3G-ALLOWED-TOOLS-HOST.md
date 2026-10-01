# Stage 3G-C: AllowedTools host feasibility

PR #29 is accepted/merged as a threat model and synthetic local-effects proof.
Its effects-based policy is NOT_ACCEPTED. Stage 3G-C and Stage 3G remain OPEN;
execution_ready=false. This is a source/design investigation, not a new host,
launcher, protocol v3, qualification policy, benchmark or rehearsal.

## Decision: UNKNOWN

The pinned core exposes a practical-looking Rust startup injection point, but
required behavioral equivalence is not yet established. Do not label it HOST_A
because isolated methods compile. No evidence establishes that a small external
wrapper preserves the complete exec/app-server composition, or that B's one
registered MCP tool is actually model-visible under every accepted tool mode.
HOST_B/C would also overstate the evidence: the public core API does exist.

Source authority is exact commit `4607249e430dac1c961df4dc615beae88e33cec8`,
Codex `0.155.0-alpha.9.2`, not current upstream main. The
[source bindings](evidence/stage3g-allowed-tools/source-bindings.json) include
full-file hashes, line ranges and verbatim excerpts. Public pinned raw-source
verification sends no task/auth/model request.

## Exact ceiling semantics

`AllowedTools(Vec<ToolName>)` is supplied in `StartThreadOptions.thread_extension_init`
before `ThreadManager::start_thread`. Session startup captures its Arc once.
Later replacement in extension data does not widen that captured value. Every
new/resumed thread needs an explicit ceiling; omission restores ordinary setup.
The proposed benchmark host must reject resume/fork/recover entirely and create
one new process/thread per arm. No reliance on persisted ceiling state.

Matching is exact `name` equality and namespace equality, with only the default
namespace equivalence `None`, empty string and `functions`. There is no wildcard,
prefix matching or code-mode string interpretation. The list can remove tools;
it cannot bypass independent feature/config/permission checks or create a tool.

Registry insertion filters trusted, prepended and external runtime tools before
insertion. Hosted model specs are separately filtered in `finalize_tool_router`.
Generated code-mode `exec` and `wait` go through filtered prepend and need their
own allowlist entries. The pinned upstream router test covers empty registry,
empty visible specs and empty code-mode mapping for an empty ceiling, including
hosted web, dynamic and extension candidates. That upstream test was inspected;
it is not represented as having been executed here.

No unfilterable model-callable tool was found in these paths. This does not mean
the ceiling suppresses non-tool extension lifecycle callbacks, authentication,
telemetry, metadata refresh or all service persistence. Host composition remains
part of the trust boundary. This review replaces open-ended per-tool auditing
with a bounded candidate boundary, not an assertion that names control all IO.

## Exact B identity

For server key `devhub_delegate`, raw MCP tool `devhub_delegate`, standard prefix
enabled and no collisions/non-prefixed override:

```rust
ToolName::namespaced("mcp__devhub_delegate", "devhub_delegate")
```

`McpHandler::tool_name()` returns `ToolInfo::canonical_tool_name()` after
normalization. The default `NonPrefixedMcpToolNames` feature is false. Config
computes prefix policy; normalization adds `mcp__`, sanitizes names and handles
collisions/length limits. The existing connection-manager tests confirm that
ordinary server names become namespaces such as `mcp__server1`.

The code-mode alias is `mcp__devhub_delegate__devhub_delegate`. It is a flattened
presentation name, **not** the identity to put in `AllowedTools`. Plain
`devhub_delegate`, a flattened plain name or namespace `devhub_delegate` do not
match the prefixed identity. A candidate host must verify resolved namespace,
raw server/tool ownership and exactly one approved tool before task exposure;
it must stop on a mismatch, not discover and automatically allow a new spelling.

## Registry proof and its limit

`scripts/check_allowed_tools.py --verify-upstream --compile-proof --output NEW.json`
builds a dependency-free Rust test executable from verbatim pinned production
matching, naming and registry insertion method bodies. It offers synthetic
builtin/extension/dynamic/MCP-like names through trusted, prepend and external
insertion paths. No Codex executable, model, MCP process or network is used by
the test binary.

The scaffold substitutes a BTreeMap for IndexMap, synthetic runtime trait objects
and logging, and omits ToolName serialization derives. It tests membership,
not ordering, async registration, permission dispatch or the full ToolRouter.
These substitutions are explicit; this is an exact-source **method-slice** proof,
not a compiled Codex host or full upstream integration test.

Expected tested membership:

| Case | Ceiling | Method-slice registry |
| --- | --- | --- |
| A | `[]` | Empty |
| B | Exact namespaced delegate | Exactly that one canonical name |
| Wrong namespace/flat alias/unknown | Nonmatching name | Empty |
| Late unrelated registration | Same startup ceiling | No expansion |
| Duplicate external candidate | Same exact name | Existing entry retained, collision recorded |

The full-router B exposure proof remains **null**. In CodeModeOnly, a namespaced
tool can remain registered but hidden while `exec/wait` are correctly filtered
out. Deferred discovery can similarly require an excluded search entry point.
Model `tool_mode` takes priority over feature-derived mode. Silently forcing
Direct mode would be a behavioral change; it is not done in this PR. The next
review must decide how to guarantee direct B exposure and prove it with the
full pinned router, including hosted tools and code-mode generation.

## Fail-closed cases

| Case | Pinned behavior / candidate requirement |
| --- | --- |
| Unknown name / namespace mismatch | Does not match; never automatically widen ceiling |
| Duplicate allowlist entries | No additional authority, but host should reject malformed duplicate config |
| Duplicate external registration | Records collision and refuses replacement; fatal rejection depends on collision policy |
| Duplicate trusted registration | Calls error_or_panic; not a universal production-mode fatal guarantee |
| MCP appears after startup | Each registry construction uses captured ceiling; matching delegate may appear, other names rejected |
| Reconnect | Revalidate server identity/schema; captured ceiling must remain; full reconnect proof pending |
| Resume / fork / recovery | Unsupported by candidate benchmark host; reject before task exposure |
| Dynamic/late extension tools | Same insertion ceiling; lifecycle side effects are outside tool matching |
| New tool with approved name | Name matching alone is not provenance; pin origin/handler and reject collisions |

The security benefit is future **unapproved names** default to denial, including
patch, notes, image generation, plugin install, goal/memory/multi-agent and nested
code-mode tools. This does not protect against a compromised trusted runtime or
an allowed-name handler substitution. The single B endpoint must still use the
accepted MCPGate and local-only ResourceController pipeline.

## Option 1: external pinned Rust core host (design only)

Link the exact source crates with their lockfile. Use public Config loading,
ChatGPT AuthManager, `build_models_manager`, EnvironmentManager and ThreadManager.
Resolve service default with model unset; do not synthesize a provider or pin a
different model. Build StartThreadOptions with InitialHistory::New, ephemeral
config, unchanged environments/instructions/timeout and explicit AllowedTools.
A gets no MCP config; B gets the existing scoped stdio delegate bridge only.
Do not substitute `environments=[]` for the ceiling.

The narrow host would own startup validation, one task submission, event draining,
usage capture, exact final-answer writing, deadline/shutdown and refusal of
resume/fork. Copy auth into fresh tmpfs using the current reviewed boundary.
The proposed latency boundary remains before host invocation through final capture.

However, ThreadManager::new has many injected services. App-server's
`thread_extensions` and dependencies are `pub(crate)`; an external host cannot
simply call that factory. It must reproduce/review extension composition,
instruction providers, stores, attestation and event adapters. No assumption
that dropping extensions is behaviorally equivalent. No wrapper was implemented
or compiled, no binary patched and no upstream fork created.

## Option 2: existing app-server

Public thread/start and InProcessStartArgs have no AllowedTools/ExtensionDataInit
injection field. The private thread processor creates init internally, inserting
selected capability roots. The ordinary exec path uses this app-server path.
Dynamic tools and MCP enabled_tools add/narrow those sources only; they do not
provide a global builtin/extension ceiling. Existing app-server without a source
change therefore has no established injection route. Exposing one would require
a separately reviewed upstream/API change, not an undocumented config option.

## Behavioral-equivalence table

| Property | Frozen exec v2 | AllowedTools host candidate |
| --- | --- | --- |
| Codex version | Locked release binary, alpha.9.2 | Same exact source intended; new build identity, not same binary |
| Model selection | Unset/service default | Same models manager intended; effective model/tool mode must be observed |
| Auth | ChatGPT auth from tmpfs | Same AuthManager possible; integration unproved |
| Session lifecycle | Fresh ephemeral exec | InitialHistory::New + ephemeral; no resume/fork; lifecycle proof pending |
| Common instructions/task/context | Frozen packet and exec assembly | Packet bytes retained; instruction/extension assembly equivalence pending |
| Tool registry | Ordinary registry; absence gate fails | A empty; B exact ceiling; full visible-B proof pending |
| MCP | A none; B scoped delegate | Same config/bridge intended, plus canonical origin checks |
| Output | Last agent message written via std::fs::write | Core events available; selection/finalization adapter needs exact tests, no normalization |
| Usage | exec JSONL from app-server ThreadTokenUsage totals | Core next_event and token_usage_info exposed; parser/event mapping version required |
| Network | OCI network none + reviewed CONNECT bridge | Unchanged boundary intended, not yet host-qualified |
| Filesystem | Reviewed RO OCI + tmpfs + capture | Same intended mounts; new binary/image must be qualified |
| Retry | Launcher/provider zero; Codex internal unknown | Same, internal retries null; no retry overrides |
| Approvals | never + frozen B tool policy | Same intent; core permission/admission parity unproved |
| Sandbox | read-only config + outer OCI | Same intended; no environment-disabling substitute |
| Persistence | Ephemeral + fresh HOME; service caveats | Ceiling blocks unlisted calls, not all non-tool host/service lifecycle state |

Core `token_usage_info()` returns optional full usage info; missing observation
must remain null. Exec currently uses total input/output/cached-input fields.
Final-message capture writes the string bytes directly. A new adapter must prove
ordering, completion/failure semantics and exact UTF-8 capture with synthetic
events; existence of these APIs alone is not metric equivalence.

## Protocol and next review

Switching exec to a custom host is a runtime-mode change. If approved later,
conceptual `stage3g-seed1-paired-v3` needs new protocol/config/plan hashes and
session IDs, new build lock/image qualification, registry/origin/exposure proof,
and event/output equivalence tests. Fixture/oracle bytes and AB/BA order stay
frozen. No v3 file or hashes are created now; v2/history stay untouched.

The unresolved work is bounded host/registry integration proof, not another
per-tool remote denylist audit. UNKNOWN means neither adoption nor rejection of
the core-host design. Review this feasibility result before authorizing such
integration work. Docker/WSL, Ollama endpoint, ledger and network settings are
unchanged; intended Linux host remains separately blocked. No rehearsal.

## Recorded validation

[Synthetic proof](evidence/stage3g-allowed-tools/synthetic-proof.json): seven
Rust method-slice tests passed with rustc 1.98.1; 25 exact upstream file hashes
and excerpts verified. A membership is empty; B membership is the canonical
delegate only. Full core registry, model-visible B and host equivalence are not
established by that executable. It runs no model or MCP process.

[Results](evidence/stage3g-allowed-tools/results.json) bind commit `8b9fbbd` to
offline run 36897709757 (Linux 344 passed/1 skipped, Windows smoke 14 passed;
Ruff/format/mypy/scans passed) and runtime run 36897709717 (source/synthetic
proof, OCI, effects and evaluator passed; unchanged absence gate failed).
The later receipt-binding regression adds one offline test. The initial audit
run failed because new source paths omitted `codex-rs/`; source bytes and hashes
were not changed to repair it. No full Windows run. 133 historical Git-object
files remain unchanged. These are design/synthetic validation records, not
an execution-ready receipt or benchmark result.
