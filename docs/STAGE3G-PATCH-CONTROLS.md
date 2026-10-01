# Stage 3G-C: supported patch-control investigation

PR #27 merged (4830b17), preserving the metadata-bound patch blocker. No closure.
Stage 3G-C OPEN; execution_ready=false; cumulative model metadata requests=1,
new model metadata requests=0, task executions=0, inference/provider sends=0.

## Decision: Case C for the frozen codex exec interface

Pinned source 4607249e430dac1c961df4dc615beae88e33cec8 and exact CLI
0.155.0-alpha.9.2 help/schema do not expose a model-independent builtin-tool
allowlist or patch-disable config for ordinary codex exec. This conclusion is
scoped to the frozen CLI mode, not a claim that the internal engine cannot filter.

AllowedTools DOES remove apply_patch, independently of model, before registry
insertion. It applies to trusted builtin and external tools. An omitted ceiling
keeps ordinary setup; an empty list permits no tools; names include namespaces.
It is supplied once through Rust ExtensionDataInit when starting a thread, and
must be resupplied on resume. Session captures it; registry checks it before
inserting the handler. This also prevents invocation through that registry.
Upstream registration/code-mode tests support that interpretation (inspected,
not compiled here). No normal CLI/config or public thread/start AllowedTools
field was found. Public thread startup only seeds selected capability roots;
ordinary exec sends environments=None. Guardian/reviewer installs an internal
ceiling but switching to a reviewer session would change task semantics.

## Control matrix

| Control | Registration effect | Exposure / reason not applied |
| --- | --- | --- |
| Internal AllowedTools excludes patch | absent | Rust host API; requires reviewed integration/mode change |
| app-server thread/start environments=[] | absent via no environment | supported experimental field; changes environment/context, not frozen CLI |
| model patch metadata null | absent | model-dependent; no alternative model selected |
| model_catalog_json | can alter metadata | startup catalog replacement, not builtin denylist; changes metadata authority |
| shell_tool / unified_exec | patch stays registered | shell guard is separate |
| apply_patch_freeform | no effect | removed feature, ignored by loader |
| streaming/line-ending patch flags | no removal | behavior/event settings only |
| read-only sandbox/container | registered | effects may be rejected later; no absence proof |
| CodeModeOnly / excluded namespaces | registered | presentation/nesting changes, not builtin removal |
| MCP/plugin disabled_tools | patch stays registered | filters MCP/plugin or tool-suggestion catalog, not builtin patch |

Registered, invocable and mutation-possible are separate evidence fields.
Invocable=true means the registration route remains, not successful filesystem
mutation. All mutation-possible observations remain null: no invocation was tried.
Additional AllowedTools control could deny invocation, but it was NOT installed.

## Review directions, not implementation

No minimal CLI-only patch-disable diff is proposed because none was established.
A dedicated host using AllowedTools could supply an A ceiling without tools and
an exact B devhub_delegate ceiling, but would require a reviewed launcher change,
canonical MCP naming, fresh-session/auth/usage/output equivalence and full new
qualification. Experimental no-environment app-server mode also needs review:
it removes more than patch and does not prove the other mutation extensions
absent. Neither direction is applied. A model pin is not required by this audit
and would not by itself establish all forbidden surfaces absent.

If review instead chooses registered-but-effects-impossible, that is a separate
boundary-policy revision. This investigation does not recommend silently treating
read-only as absence. Existing inventory and qualification policy remain unchanged.

Any future mode/config revision needs new protocol/config/qualification hashes,
new derived plan/session IDs, and unchanged fixture/oracle content hashes. Current
hashes remain unchanged; no candidate new protocol or speculative hashes created.

## Evidence and verification

`evidence/stage3g-patch-controls/controls.json` records each mechanism and source
bindings. `schema-search.json` lists exact schema fields and the three
MCP/plugin/tool-suggest disabled_tools definitions. CLI help/version bytes are
hash-bound and came from the verified binary in a network-none, no-auth diagnostic
container, not an accepted runtime-image or intended-host qualification proof.

`uv run --locked python scripts/check_patch_controls.py --verify-upstream`
checks pinned source hashes/excerpts and schema. It only retrieves public source,
never models metadata or inference. Offline tests reject read-only-as-absence,
internal-host-as-CLI and changed-policy claims. Existing isolation/evaluator CI
continues; the accepted runtime gate remains red for unresolved forbidden tools.

The complete #27 canonical inventory is preserved, including notes writes,
image_gen.imagegen, request_plugin_install and code-mode exec/wait. Unknowns
remain null. Docker/WSL/Ollama/ledger were not changed; intended host is still not
qualified. STOP for review. No rehearsal.
