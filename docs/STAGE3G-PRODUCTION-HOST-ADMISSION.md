# Stage 3G-C: production host admission design

This design resolves the distinction between a proof-only observation hook and
the shipping authority needed to activate Candidate B. It is based on pinned
Codex source commit `4607249e430dac1c961df4dc615beae88e33cec8` and does not
modify the frozen Candidate B patch. Build-009 is not authorized or run.

## Decision

The router and handler can enforce an approved delegate after an
`ApprovedDelegatePolicy` and exact `AllowedTools` ceiling reach the session.
The intended `codex exec` host cannot currently supply either value. The
production blocker is therefore:

```text
PRODUCTION_HOST_ADMISSION_INTEGRATION_MISSING
```

This is a missing shipping activation path, not an exploit and not a failure of
the Candidate B router/security mechanism. A test-only injection would not
close it.

## Current host construction path

The exact pinned path is:

```text
codex exec
  -> codex_exec::run_main
  -> InProcessClientStartArgs
  -> InProcessClientStartArgs::into_runtime_start_args
  -> InProcessStartArgs
  -> MessageProcessorArgs
  -> MessageProcessor::new
  -> ThreadRequestProcessor::new
  -> thread/start
  -> ThreadRequestProcessor::thread_start_task
  -> ExtensionDataInit::new()
       + selected_capability_roots only
  -> StartThreadOptions.thread_extension_init
  -> Session::new
       -> capture AllowedTools
       -> ExtensionData::new_with_init
  -> build_tool_router
```

`StartThreadOptions` already accepts an `ExtensionDataInit`, and session
construction already captures `AllowedTools` from it. The missing link is from
the trusted `codex exec` startup state to the `ExtensionDataInit` created inside
`thread/start`.

The public `ThreadStartParams` must not gain admission fields. It is a client
request boundary, while the required authority belongs to the host.

## Existing trusted extension point

`codex_extension_api::ExtensionDataInit` is the narrow reusable carrier. It is
explicitly designed for typed host values supplied before an `ExtensionData`
scope exists. `AllowedTools` is already documented for this path:

- absence preserves ordinary tool setup;
- an empty list permits no tools;
- a populated list only narrows tools;
- the captured value cannot later be widened through extension state.

The recommended production integration adds a host-owned
`thread_extension_init` template to the in-process construction chain:

```text
InProcessClientStartArgs
  -> InProcessStartArgs
  -> MessageProcessorArgs
  -> ThreadRequestProcessor
  -> clone for each fresh thread/start
  -> insert selected capability roots
  -> StartThreadOptions.thread_extension_init
```

The ordinary app-server path supplies an empty/default template. When the new
host input is absent, behavior remains unchanged.

## Recommended host input

The Stage 3G launcher should pass one explicit, reviewed, read-only admission
manifest to `codex exec` through a dedicated startup option. This must not be a
generic model/task argument, MCP field, undocumented TOML key, environment
variable or project file.

The manifest should bind, at minimum:

- schema/version for the host admission document;
- server key `devhub_delegate`;
- raw tool name `devhub_delegate`;
- canonical namespace `mcp__devhub_delegate`;
- canonical name `devhub_delegate`;
- exactly one allowed tool,
  `mcp__devhub_delegate.devhub_delegate`;
- expected canonical `McpServerConfig` hash;
- expected real input schema plus SHA-256
  `0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be`;
- exact direct-only namespace `mcp__devhub_delegate`;
- expected global `CodeModeOnly` and fatal-collision policy.

The manifest should reuse the resolved `McpServerConfig`: the host loads the
normal trusted configuration, canonically hashes the exact reviewed server
entry, compares it with the manifest, and only then constructs
`ApprovedDelegatePolicy`. It should not create a second MCP configuration
model. The expected schema remains host-owned; the connected server's observed
schema is compared against it and cannot nominate its own approval.

The launcher owns the manifest path and exact argv. The file is mounted
read-only outside the executor task packet, and its bytes, path policy and argv
are bound into runtime qualification evidence. Task JSON, model output, MCP
responses, providers and repository content cannot populate or widen it.

For the first implementation, the admission input should be accepted only for a
fresh ephemeral `codex exec` session. Resume, fork and other lifecycle modes
should fail closed until their authority propagation rules are separately
reviewed.

## AllowedTools and schema ownership

The exact `AllowedTools` value is built from the reviewed host manifest before
MCP catalog observation. It is never derived from the catalog or advertised
tool name. Candidate B then requires both the host ceiling and the admitted
binding to match.

The expected schema is likewise read from the reviewed host input and checked
against the approved SHA-256 before policy construction. Candidate B compares
the actual observed server schema with that expected value. Schema drift fails
closed.

The direct-only namespace remains an explicit host expectation and an exact
resolved-config assertion. Global tool mode stays `CodeModeOnly`; global Direct
mode is not enabled.

## Protocol impact

The frozen Stage 3G task protocol does not inherently require v3. Protocol v2
already defines Arm A as having no Dev Hub tool and Arm B as having only the
local `devhub_delegate`. The host admission input realizes that existing
semantic contract without changing fixtures, oracles, task instructions,
ordering, timeout or provider policy.

The current launcher cannot supply the new host input as written. A later
implementation must change launcher/runtime configuration and therefore produce
new implementation, config, plan/session and qualification bindings as required
by canonical tooling. That is a reviewed host-runtime revision, not
automatically a task-protocol v3. A protocol revision becomes necessary only if
the task-visible semantics or frozen comparison rules change.

## Proof-only observation hook

Observation and authority remain separate. A proof observer may be carried by
the trusted host template, but it cannot create `ApprovedDelegatePolicy`, set
`AllowedTools`, mutate the registry or affect routing.

The narrow observation point is immediately after the real `build_tool_router`
result is finalized and before a sampling request is sent. It records only a
sanitized snapshot:

- effective tool mode;
- model-visible specifications;
- nested code-mode map;
- hosted and dynamic surfaces;
- approved canonical/raw/server identity;
- schema hash and opaque generation identity.

The current pinned process has no public pre-sampling inspection-and-stop API.
Consequently, the observer also needs a separately reviewed host-only proof mode
that reaches actual router construction and exits before model sampling. That
mode may observe and stop; it cannot change admission or execution eligibility.

## Host-originated handler invocation

No existing app-server or `codex exec` production API can invoke the finalized
`McpHandler` without a model-produced tool call. `ToolRouter` has dispatch
methods, but they require the private production `Session`, `StepContext`,
tracker, cancellation state and `ToolCall`. The normal path obtains them from
model output in `handle_output_item_done`.

No privileged dispatch API should be added in this design. If later approved,
the smallest valid seam would retain the actual production `Session`,
`StepContext` and finalized `ToolRouter`, then call the existing dispatch path.
It must not reconstruct the registry or synthesize approval. That seam requires
its own security review.

## Candidate B patch impact

The frozen Candidate B patch can remain byte-identical while this design is
reviewed. A shipping implementation necessarily changes the overall production
source set by adding host plumbing and startup validation. If those changes are
folded into `candidate.patch`, its hash will change; if kept as a second reviewed
patch, the combined production patch-set identity will change. This must be
explicitly rebound before a future build.

Candidate B's existing production files do not need a router or handler redesign.
The new data flow supplies the authority they already consume.

## Proposed implementation files

Likely pinned Codex changes, subject to implementation review:

| File | Production purpose |
| --- | --- |
| `codex-rs/exec/src/cli.rs` | dedicated host admission manifest option |
| `codex-rs/exec/src/lib.rs` | validate host input and build typed extension init |
| `codex-rs/exec/src/approved_delegate_host.rs` | small parser/validator for the reviewed host contract |
| `codex-rs/app-server-client/src/lib.rs` | carry host `ExtensionDataInit` into the in-process runtime |
| `codex-rs/app-server/src/in_process.rs` | forward the host template to `MessageProcessor` |
| `codex-rs/app-server/src/message_processor.rs` | forward the template to `ThreadRequestProcessor` |
| `codex-rs/app-server/src/request_processors/thread_processor.rs` | clone the template into fresh `thread/start` options |
| relevant Cargo manifests | only dependencies required by the existing extension types |
| focused tests in the same crates | absence/default, trust boundary and A/B process behavior |

The external app-server construction in `codex-rs/app-server/src/lib.rs` should
pass an empty template unless a separately reviewed trusted host owns admission.
No fields are added to `ThreadStartParams`.

Later DevFabric launcher/qualification changes would be limited to the reviewed
manifest and its bindings in `src/devhub/experiment_launch.py`,
`src/devhub/experiment.py` and their tests. They are not part of this design-only
change.

## Security and regression matrix

The implementation review must require:

| Case | Required result |
| --- | --- |
| Host admission absent | existing Codex behavior unchanged; no approved delegate |
| Arm A | no MCP, zero visible/nested/hosted/dynamic tool surfaces |
| Arm B | global CodeModeOnly; exactly the approved delegate visible |
| Client/task supplies lookalike admission data | ignored or rejected; cannot create authority |
| Catalog advertises the expected name without host admission | rejected |
| Host AllowedTools differs from the one reviewed tool | rejected |
| Resolved server config hash differs | rejected |
| Observed schema differs or approved schema hash drifts | rejected |
| Direct-only namespace/global mode/collision policy differs | rejected |
| Extra MCP, dynamic or hosted tool appears | cannot widen the ceiling |
| Wrong origin or either collision order | existing fail-closed results preserved |
| Fresh thread | receives a clone of the same immutable host template |
| Resume/fork in initial slice | rejected while host admission is enabled |
| Proof observer absent | no behavior change |
| Proof observer present | read-only snapshot only; cannot alter eligibility |

## Build-009 sufficiency

One future meaningful compilation should be sufficient for the missing host
activation and process-visibility gate only if the reviewed production plumbing,
startup validator and pre-sampling observation/stop seam are implemented in one
source snapshot. It can then build the actual `codex` binary and exercise Arm A
and Arm B through the real in-process construction.

It will not prove a host-originated synthetic handler dispatch unless the
separate privileged invocation seam is first reviewed and implemented. The full
handler path is already proven internally at the pinned production-equivalent
stack; this design does not reopen it.

## Current classification

```text
router/security internal matrix             PASS
handler at pinned production-equivalent stack PASS
catalog refresh after preparation           PASS
intended CLI stack qualification             PASS
production host activation path              MISSING
exact process proof                          null
production_classification                    UNKNOWN
Stage 3G-C                                   OPEN
Stage 3G                                     OPEN
execution_ready                              false
real_codex_executions                        0
provider_sends                               0
build_009_run                                false
```

No v3, rehearsal, benchmark, role runtime, provider request or Rust compilation
was performed for this design.

## Build-009 cheap-gate result

Build-009 was authorized after this design review, but Rust compilation did not
start. The source-level preflight found an unresolved Arm A authority gap. The
required Arm A process proof combines all of these conditions:

- no admission manifest;
- no `ApprovedDelegatePolicy`;
- a read-only observer;
- empty visible and nested tool surfaces.

In the pinned runtime, absence of `AllowedTools` preserves ordinary Codex tool
setup. The frozen Stage 3G overrides disable shell, unified exec, web, apps and
related features, but they do not install `AllowedTools([])` and cannot remove
every core tool. The accepted earlier zero-surface proof explicitly used both
`AllowedTools([])` and `ApprovedDelegatePolicy::no_tools()`. The observer cannot
close this gap because it is forbidden from changing authority or routing.

The pre-build classification is therefore:

```text
PRODUCTION_HOST_ARM_A_CEILING_MISSING
```

The proposed Arm B host integration remains uncompiled and is preserved as a
separately hashed patch for review. No Rust build, process proof, model request,
provider request, rehearsal or benchmark was run. Review must choose an explicit
trusted Arm A no-tools ceiling or revise the expected Arm A surface before a
Rust build is safe. Machine-readable evidence is in
`docs/evidence/stage3g-approved-call/build-009-preflight.json`.

## Remediation-integrated source refresh

The first build-009 preflight result above is immutable historical evidence. Its
Arm A ceiling finding is addressed in the refreshed, separately hashed host
integration proposal without changing Candidate B. One versioned host manifest
contains both reviewed arms. The trusted launcher selects the arm at `codex exec`
startup and the host inserts the corresponding `AllowedTools` into the immutable
fresh-thread `ExtensionDataInit` template:

```text
ordinary Codex: AllowedTools absent; ApprovedDelegatePolicy absent
Arm A:          AllowedTools([]); ApprovedDelegatePolicy absent
Arm B:          AllowedTools([mcp__devhub_delegate.devhub_delegate]); exact policy
```

The ceiling is installed before router construction. Existing reviewed
`AllowedTools` source evidence covers registered, external, hosted, dynamic, and
Code Mode generated surfaces. Thus the proposed source has no permitted
`apply_patch`, `write_file`, or other non-delegate surface in either Stage 3G
arm. This is a source/pre-build result only; finalized process visibility remains
unobserved until the single separately authorized build-009 compilation and
same-binary A/B inspection.

The first refreshed receipt (`build-009-preflight-2.json`) was superseded before
any Rust build after CI found a platform-dependent raw-manifest hash and two
synthetic probes still using the old launcher function signature. The corrected
receipt binds the LF-normalized repository bytes required by `.gitattributes` and
passes the host manifest to every synthetic container-construction path. No
historical receipt was rewritten and neither issue reached task exposure.

The host manifest's exact raw hash is carried by `QualificationManifestV2`.
The benchmark launcher revalidates that hash and mounts the reviewed manifest
read-only. All other merged qualification and execution-boundary authorities
remain unchanged. No Rust compilation, process task, provider request, rehearsal,
or benchmark is performed by this refresh.
