# Stage 3G audit remediation design

Status: **DESIGN ONLY — no P1 production implementation and no Rust build authorized**

This document refines AUD-001, AUD-002, AUD-003, and AUD-009 after integrating main.
It does not modify the frozen protocol, Candidate B, provider behavior, accounting,
or benchmark execution.

## 1. Ledger identity — AUD-001

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

## 3. Immutable Python runtime — AUD-009

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
  → AUD-001 ledger identity
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

## 7. Proposed PR decomposition

1. PR #34 stays the Candidate B and historical qualification umbrella.
2. Focused PR: AUD-001 ledger identity and explicit legacy-adoption design boundary.
3. Focused PR: AUD-002 qualification context/manifest plus AUD-009 immutable Python artifact.
4. Focused PR: AUD-003 fail-closed B-arm observation.
5. Focused PR or tightly bounded series: AUD-005 recovery ordering and AUD-008/AUD-011
   benchmark executor hardening.
6. Return to PR #34 for the reviewed Arm A/B ceiling, shipping host integration, cheap
   preflight, and the single authorized build-009 compilation.

Do not combine all findings into one Candidate B patch or start build-009 before its
Stage 3G-C prerequisites are reviewed and integrated.

## 8. Current gate state

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

