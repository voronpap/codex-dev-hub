# Stage 3G audit remediation design

Status: **ACCEPTED DESIGN / HISTORICAL GATE SNAPSHOT; current closure status below**

This document refines AUD-001, AUD-002, AUD-003, and AUD-009 after integrating main.
PR #41 merged AUD-001 into main as merge commit
`2a9428d2689fd05b8edef901b1caf48c3f985292`. This tracking update does not modify the
frozen protocol, Candidate B, provider behavior, accounting, or benchmark execution.

Current implementation status supersedes the original sequencing snapshot without
rewriting its design decisions: AUD-001/002/003/005/008/009/011 are merged.
Build-020 independently qualified the patched production host and its pre-sampling
Default/A/B visibility. The final exact-runtime-image and same-environment manifest
`d6d3e1f565064846af495b5d9cab6e3f54738616d383c5c6afddf02c666b5441`
was independently accepted with `execution_ready=true`. Stage 3G-C is closed for
that exact manifest/environment; Stage 3G remains open and no rehearsal or benchmark
has run.

## 1. Ledger identity — AUD-001 (IMPLEMENTED / MERGED)

The accepted implementation is `LedgerIdentityCoreV1` in `src/devhub/ledger.py`, with
its operational contract in `docs/LEDGER_IDENTITY.md`. The implementation commit is
`f0030cb8b1809b361de9d6d82be731fa5bd444f4` and the main merge commit is
`2a9428d2689fd05b8edef901b1caf48c3f985292`.

Legacy adoption remains **NOT IMPLEMENTED**. AUD-001 does not close AUD-005 recovery
ordering, AUD-002 qualification authority, AUD-009 immutable Python runtime, or AUD-003
B-arm observation.

Separate reopen equality from creation audit metadata.

```text
LedgerIdentityCoreV1
  family = "devfabric_resource_ledger"
  format_version
  instance_id
  authority_scope_kind
  authority_scope_id
  account_binding_hash?  # only when the authority requires an account binding

LedgerIdentityMetadataV1
  created_at
  created_by_runtime
```

Only `LedgerIdentityCoreV1` participates in reopen equality and its canonical SHA-256.
Creation time and creating runtime are immutable audit metadata but are not expected
caller values and cannot make an otherwise correct reopen fail.

`authority_scope_id` is a trusted stable authority identifier. It is never derived only
from a path, session ID, task ID, or model/MCP input. Stage 3G uses one qualification-bound
shared ledger authority across multiple paired sessions.

### Bootstrap order

1. Resolve and validate `state_root`.
2. Reject symlink/reparse substitution for all supported existing path components.
3. Open SQLite and begin the bootstrap transaction.
4. Before domain migration, inspect `PRAGMA application_id`, `PRAGMA user_version`,
   `sqlite_master`, and the presence/value of `ledger_identity`.
5. Classify the database:

| Classification | Required behavior |
|---|---|
| `NEW_EMPTY` | Set fixed application ID, create and commit identity, then run domain migrations |
| `VALID_IDENTIFIED_DEVFABRIC` | Compare exact core identity, then run migrations |
| `LEGACY_UNIDENTIFIED_DEVFABRIC` | Fail normal startup; require explicit adoption |
| `FOREIGN_NONEMPTY` | Fail closed without mutation |
| `IDENTITY_MISMATCH` | Fail closed without mutation |

An existing identified database is never migrated before equality validation. A new file
is not treated as authority merely because its selected path is new.

### Legacy adoption and reset

Legacy adoption is a separate reviewed operation, not normal startup. It requires:

- an exact recognized legacy schema fingerprint;
- a durable backup;
- operator-supplied expected core identity;
- checks for unresolved unknown-usage/accounting inconsistency;
- identity installation in a dedicated transaction;
- an audit receipt containing pre/post schema and identity hashes.

Changing `state_root` is not adoption or reset. Reset is another explicit operation and
must never run implicitly.

## 2. Two-level qualification identity — AUD-002

Status: **IMPLEMENTED / MERGED**. The historical design status was OPEN and planned
for a separate focused PR together with AUD-009.

The qualification identity uses two acyclic levels.

### QualificationContextV1

Define an ID-free canonical payload and an envelope:

```text
QualificationContextPayloadV1
  environment_instance_id
  implementation
  codex
  benchmark
  runtime_expected
  ledger_expected
  evaluator_expected
  ollama_expected
  arms_expected

QualificationContextV1
  qualification_context_id
  payload
```

The exact rule is:

```text
qualification_context_id =
  SHA256(canonical(QualificationContextPayloadV1))
```

The hashed payload does not contain `qualification_context_id`. Every generated
host-sensitive receipt must carry the resulting ID and the same
`environment_instance_id`.

Required payload content:

- implementation: integrated DevFabric commit, immutable wheel SHA-256, Python
  executable/version identity, and dependency lock SHA-256;
- Codex: pinned source commit/archive, expected executable identity when available,
  Candidate B base patch, host integration patch, and combined patchset;
- benchmark: protocol, config, plan, session-binding, and fixture/oracle manifest hashes;
- expected runtime: OCI image identity, bootstrap hash, approved host manifest hash;
- ledger: exact `LedgerIdentityCoreV1`, its hash, and expected schema version;
- evaluator: image/executable and runner identities;
- Ollama: exact version `0.34.2`, model `qwen2.5:14b-instruct`, and reviewed digest;
- Arm A expected zero-tool ceiling and Arm B expected one-tool/policy identity.

### QualificationManifestV2

After all receipts exist, build another ID-free payload and envelope:

```text
QualificationManifestPayloadV2
  qualification_context_id
  environment_instance_id
  receipt_hashes
  observed_artifact_hashes
  gates
  execution_ready

QualificationManifestV2
  qualification_manifest_id
  payload
```

The exact rule is:

```text
qualification_manifest_id =
  SHA256(canonical(QualificationManifestPayloadV2))
```

The hashed payload excludes `qualification_manifest_id`; the envelope stores the ID only
after computation. This avoids a self-hash and avoids requiring a final manifest ID inside
receipts that are themselves inputs to the manifest.

The final payload binds actual observed receipts for isolation, effects boundary,
auth/egress, Ollama metadata, ledger reopen/identity, Codex executable metadata, host
process visibility, evaluator qualification, immutable Python artifact verification,
and required config probes.

Every receipt must contain the expected `qualification_context_id` and
`environment_instance_id`. Mixed-host or mixed-context composition fails closed.

### Runtime data flow

```text
trusted expected inputs
  → canonical QualificationContextV1
  → same-host qualification receipts
  → canonical QualificationManifestV2
  → RuntimeBindings(qualification_manifest_id)
  → reload and verify every receipt/artifact from the manifest
  → verify exact session and arm binding
  → verify immutable ledger identity and executable identities
  → only then create/expose an attempt
```

RuntimeBindings may locate the reviewed manifest but cannot independently override its
image, ledger, evaluator, isolation proof, Python runtime, Codex binary, Ollama identity,
config, or plan. A difference in any one bound component is a pre-execution failure.

`environment_instance_id` is an opaque host-owned qualification identity. It must not be
derived from user/model/project content or expose sensitive machine/account identifiers.

### Planned typed contracts

Add a small `src/devhub/qualification.py` module. It will reuse `Contract`, `Digest`,
`canonical`, `digest`, and the merged `LedgerIdentityCoreV1`; it must not define another
ledger-identity model. The module will own strict, versioned contracts for:

```text
QualificationContextPayloadV1
  schema_version = 1
  environment_instance_id
  implementation
  codex
  benchmark
  runtime_expected
  ledger_expected
  evaluator_expected
  ollama_expected
  arms_expected

QualificationContextV1
  qualification_context_id
  payload

QualificationReceiptHeaderV1
  receipt_kind
  qualification_context_id
  environment_instance_id

QualificationManifestPayloadV2
  schema_version = 2
  qualification_context_id
  environment_instance_id
  receipts             # fixed typed set, not an open bag
  observed_artifacts
  gates
  execution_ready      # derived from verified gates

QualificationManifestV2
  qualification_manifest_id
  payload
```

Both envelopes recompute their IDs during validation. Unknown fields, missing required
receipt kinds, duplicate receipt kinds, a receipt from another context/environment, and
an envelope ID mismatch fail closed. `execution_ready` is derived only after all required
typed receipts and artifact hashes validate; callers cannot set it independently.

`ledger_expected` embeds the exact merged `LedgerIdentityCoreV1`, its canonical identity
SHA-256, and the expected domain schema version. The implementation must compare all
three against the opened authoritative ledger before replay, recovery, or attempt
creation.

The final receipt set is fixed to the reviewed Stage 3G needs: isolation, effects
boundary, auth/egress, actual Ollama metadata, ledger reopen/identity, actual Codex
executable, production host-process visibility, evaluator qualification, immutable
Python runtime verification, and runtime/config probes. Paths are locators only. Every
referenced file is re-read and checked against its manifest hash.

### Planned integration points

- `src/devhub/experiment.py`: replace independently composable qualification fields in
  `RuntimeBindings` with the reviewed `qualification_manifest_id`. A manifest path may be
  passed separately as a locator, but it is not authority.
- `src/devhub/experiment_preflight.py`: build and validate the final manifest; replace
  `require_ready(raw, expected)` with full context, receipt, artifact, environment, and
  ledger-chain verification.
- `src/devhub/experiment_run.py`: load the manifest by locator, verify its exact ID, derive
  runtime values only from it, and refuse independently supplied image/isolation/evaluator/
  Python identities.
- `scripts/probe_oci_boundary.py`, `scripts/probe_effects_boundary.py`,
  `scripts/qualify_runtime_config.py`, and `scripts/qualify_evaluator.py`: accept the
  reviewed context and emit the common receipt header.
- `scripts/build_qualification_context.py`: create the ID-free canonical context payload
  after all expected immutable inputs, including the actual Codex executable SHA, are
  known.
- `scripts/build_qualification_manifest.py`: verify the complete same-context receipt set
  and create the ID-free final payload and envelope.
- `.github/workflows/runtime-qualification.yml`: pass one context through qualification
  jobs and retain the complete manifest inputs as review artifacts. A CI host cannot be
  mixed with receipts from the intended execution host.

No frozen task, fixture, oracle, ordering, timeout, provider policy, or arm instruction
changes are part of this PR. Implementation-dependent plan/session/runtime bindings will
be regenerated and reviewed without creating protocol v3.

## 3. Immutable Python runtime — AUD-009

Status: **IMPLEMENTED / MERGED**. The historical design status was OPEN as part of
the same focused PR as AUD-002.

Build one wheel or equivalent immutable Python artifact from the reviewed integrated
commit. Bind all of the following into `QualificationContextV1`:

- artifact SHA-256;
- Python executable/version identity;
- `uv.lock` or accepted dependency lock SHA-256;
- isolated installation environment identity;
- absolute reviewed entrypoint.

The B arm must execute that artifact from the bound environment. It cannot use an
arbitrary editable checkout, ambient `sys.path`, or unrelated installed `devhub` through
an unqualified `sys.executable -m devhub.delegate_server` resolution.

### Planned artifact and launch flow

1. `scripts/build_devhub_runtime_artifact.py` requires a clean reviewed source commit and
   builds one non-editable wheel using the locked build environment.
2. The builder records the wheel SHA-256, source commit, package metadata, `uv.lock`
   SHA-256, exact Python implementation/version/executable SHA-256, ABI/platform identity,
   and `devhub.delegate_server:main` entrypoint.
3. A dedicated runtime environment is populated only from the DevFabric wheel and a
   lock-derived, hash-verified runtime wheelhouse. Editable installation, ambient
   `PYTHONPATH`, user site packages, and unrelated installed `devhub` are rejected.
4. An ID-free runtime-environment payload binds the interpreter plus every installed
   distribution/version and installed-file/`RECORD` digest. Its canonical SHA-256 is the
   installation environment identity included in `QualificationContextPayloadV1`.
5. After the qualification context exists, a host-sensitive Python-runtime verification
   receipt rechecks the interpreter, lock, wheel, module origin, installed records, and
   entrypoint and binds both `qualification_context_id` and `environment_instance_id`.
6. `experiment_run.py` obtains the server command from the verified manifest and launches
   the exact absolute interpreter with isolated Python semantics and
   `-m devhub.delegate_server`. It no longer uses ambient `sys.executable` for Arm B.

Artifact construction precedes the qualification context because the wheel/environment
hashes are context inputs. Runtime verification follows context creation so its receipt
can bind the context without a hash cycle.

### Planned tests and documentation

Add `tests/test_qualification.py` and `tests/test_runtime_artifact.py`, and update the
existing experiment/preflight tests. Required negative cases include context/manifest ID
tampering, unknown fields, one-component drift, receipt substitution across hosts,
ledger-identity drift, wheel/lock/interpreter drift, module-origin replacement, editable
or ambient import resolution, incomplete receipt sets, and independently supplied runtime
paths. All failures occur before attempt creation or model/provider activity.

Add `docs/QUALIFICATION_MANIFEST.md` and narrowly update `docs/STAGE3G-C.md`. Historical
evidence files remain immutable.

## 4. B-arm success observation — AUD-003

```text
BArmDelegationObservationV2
  session_id
  call_count = 1
  validated_request_identity(project, task_id, request_key, session_id)
  response_kind
  handoff_schema_hash
  handoff
  reservation_id
  authoritative_reservation_snapshot
  authoritative_accounting_events
  expected_provider_resource_model
  observed_provider_resource_model
  accounting_complete
  provider_execution_observed
  delegation_success   # derived, never caller-controlled
  failure_reason
```

The MCP bridge may retain request and response references, but it is not accounting
authority. `experiment_run` reopens the qualification-bound ledger and queries the exact
reservation, its events, allocations, and final settlement by authoritative IDs.

Successful mechanical delegation requires:

- one call and exact session/project/task/request-key identity;
- result response with strict `DelegationResult` structured content;
- completed handoff and matching accounting reference;
- exact matching reservation row;
- exactly one `reserved → dispatched → settled` chain for that reservation;
- no duplicate dispatch, second provider send, or release after dispatch;
- provider/resource/model matching frozen Ollama identity;
- complete actual input/output usage and completed execution;
- output and citation validation passed;
- retries zero and fallback false.

An MCP error, malformed/missing structured content, identity mismatch, missing accounting,
or unknown usage sets `delegation_success=false`. Complete settlement with failed output
or citation validation sets `accounting_complete=true` and `delegation_success=false`.

`delegation_success` does not include semantic acceptance. A mechanically valid result
can later fail semantic review; `semantic_acceptance` remains nullable until that review.

## 5. Arm ceilings

```text
Default Codex
  AllowedTools = None

Stage 3G Arm A
  AllowedTools = Some([])
  ApprovedDelegatePolicy = absent

Stage 3G Arm B
  AllowedTools = Some(["mcp__devhub_delegate.devhub_delegate"])
  ApprovedDelegatePolicy = exact reviewed Candidate B policy
```

Default-absent behavior is not Arm A. The host-owned ceiling/policy cannot be supplied or
widened through `ThreadStartParams`, task JSON, model output, MCP response, project file,
or repository content.

## 6. Dependency graph

```text
main integration
  → AUD-001 ledger identity [MERGED]
      → AUD-005 recovery ordering
      → AUD-002 qualification context/manifest

main integration
  → AUD-009 immutable Python artifact
      → AUD-002 qualification context/manifest

AUD-002
  → build-009 host qualification

AUD-003
  → benchmark readiness

AUD-008 + AUD-011
  → benchmark readiness

Arm A ceiling correction
  → build-009

build-009
  → final Stage 3G-C review
```

## 7. Implementation decomposition (completed prerequisites)

1. PR #34 stays the Candidate B and historical qualification umbrella.
2. PR #41: AUD-001 ledger identity and explicit legacy-adoption design boundary [MERGED].
3. PR #42 merged AUD-002 qualification context/manifest plus AUD-009 immutable
   Python artifact.
4. PR #43 merged AUD-003 fail-closed B-arm observation.
5. PR #44 merged AUD-005 recovery ordering and AUD-008/AUD-011 benchmark executor
   hardening.
6. PR #34 returned to the reviewed Arm A/B ceiling and shipping host integration;
   Build-020 completed the actual production-host process proof.

The separation above remains part of the accepted history; no audit remediation was
folded into the frozen Candidate B patch.

## 8. Historical gate snapshot and current state

The following snapshot recorded the state when this design was accepted and is
superseded by the current block below:

```text
AUD-001 immutable ledger identity = IMPLEMENTED / MERGED
legacy ledger adoption = NOT IMPLEMENTED
AUD-002 qualification context/manifest = OPEN
AUD-003 B-arm successful-handoff/accounting observation = OPEN
AUD-005 startup recovery ordering = OPEN
AUD-009 immutable Python runtime artifact = OPEN
```

```text
build_009_preflight_attempt_1 =
  BLOCKED_PREBUILD / PRODUCTION_HOST_ARM_A_CEILING_MISSING

production_classification = UNKNOWN
production_host_activation = BLOCKED_PREBUILD
process_proof = null
Stage 3G-C = OPEN
Stage 3G = OPEN
execution_ready = false

model_requests = 0
provider_sends = 0
real_codex_executions = 0
build_009_rust_compilation_started = false
build_010_run = false
```

Current state after merged remediation and independently reviewed Build-020:

```text
AUD-001 immutable ledger identity = IMPLEMENTED / MERGED
AUD-002 qualification context/manifest = IMPLEMENTED / MERGED
AUD-003 B-arm successful-handoff/accounting observation = IMPLEMENTED / MERGED
AUD-005 startup recovery ordering = IMPLEMENTED / MERGED
AUD-008 bounded executor capture/container cleanup = IMPLEMENTED / MERGED
AUD-009 immutable Python runtime artifact = IMPLEMENTED / MERGED
AUD-011 irreversible exposure boundary = IMPLEMENTED / MERGED
legacy ledger adoption = NOT IMPLEMENTED

production_classification = PRODUCTION_HOST_QUALIFIED
production_host_activation = PROVEN
process_proof = PASS
Stage 3G-C = CLOSED for exact manifest d6d3e1f565064846af495b5d9cab6e3f54738616d383c5c6afddf02c666b5441
Stage 3G = OPEN
execution_ready = true for exact environment 169a6b903825d8c88973dd592c4601d9

remaining gate = separate rehearsal, then the frozen paired run and review;
  qualification authority cannot be transferred to another runtime composition

model_requests = 0
provider_sends = 0
real_codex_executions = 0
benchmark_run = false
rehearsal_run = false
```

