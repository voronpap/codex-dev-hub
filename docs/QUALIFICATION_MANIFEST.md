# Stage 3G qualification manifest

Stage 3G execution is authorized by one final manifest identity. Individual paths,
receipts, image IDs, or previously accepted subsets cannot be combined into a new
authority. This design implements AUD-002 and AUD-009; it does not qualify the
Candidate B host, close Stage 3G-C, or authorize a rehearsal or benchmark.

## Acyclic identity model

`QualificationContextPayloadV1` contains immutable expected inputs. It does not
contain its own ID. Its envelope is:

```text
qualification_context_id = SHA256(canonical(QualificationContextPayloadV1))
QualificationContextV1 = { qualification_context_id, payload }
```

The context binds one opaque, operator-persisted `environment_instance_id`; the
reviewed DevFabric source and Python runtime artifact; Codex source, executable and
patch identities; protocol/config/plan/session/fixture identities; OCI runtime;
the existing `LedgerIdentityCoreV1`; evaluator; exact Stage 3G Ollama 0.34.2 model;
and expected Arm A/B surfaces. The environment ID is random correlation authority,
not a hostname, username, account, hardware, project, task, or model fingerprint.

Receipts are generated afterward. Every host-sensitive receipt has the strict shared
`QualificationReceiptHeaderV1` with its fixed kind, context ID, and environment ID.
The final payload references a fixed receipt set by relative locator and SHA-256:

- `isolation`
- `effects_boundary`
- `auth_egress`
- `ollama_metadata`
- `ledger_identity`
- `codex_executable`
- `host_process_visibility`
- `evaluator`
- `python_runtime`
- `runtime_config_probe`

The three intended-host-only receipts are strict contracts rather than generic JSON
bags. `auth_egress` proves that an existing non-empty operator auth object can be
staged privately and binds the exact two-host CONNECT allowlist without serializing
auth bytes. `ledger_identity` reopens the exact `LedgerIdentityCoreV1`, verifies the
SQLite application/schema/integrity state, and rejects outstanding reserved,
dispatched, or `unknown_usage` liability. `ollama_metadata` binds the official
`ollama-linux-amd64.tar.zst` v0.34.2 release artifact, the running executable, a
separate no-outbound network namespace, and metadata-only version/tags/show results.
It records zero generate/model/provider requests. A common header plus
`qualification_passed=true` is not sufficient for any of these gates.

The frozen Linux Ollama release provenance was observed on 2026-10-10 from the
official GitHub release tag `v0.34.2`: asset `ollama-linux-amd64.tar.zst`, release
digest `e155b83589986d2c581fdbf1381ea3ebdb16549883679cd5a0627f7cdc05b12b`.
Qualification re-hashes the downloaded archive and streams `bin/ollama` from that
archive to bind the running executable. The digest is reviewed input; the qualifier
does not fetch release metadata or trust a filename.

`QualificationManifestPayloadV2` does not contain its own ID. Its envelope is:

```text
qualification_manifest_id = SHA256(canonical(QualificationManifestPayloadV2))
QualificationManifestV2 = { qualification_manifest_id, payload }
```

This two-level structure has no self-hash or receipt-hash cycle. Canonical bytes use
the repository's sorted, indented UTF-8 JSON convention with one trailing newline.

## Readiness and same-host rule

`execution_ready` is mechanically derived. It is true only when every fixed receipt
exists and every required gate is true; a contradictory caller-supplied value is
rejected. Verification re-reads the context and each receipt, hashes their exact
bytes, recomputes both envelope IDs, verifies context/environment headers, compares
artifact identities with context expectations, and revalidates ledger identity.

Host-sensitive evidence cannot be assembled from different environments. A CI
isolation receipt, another host's ledger, a local Ollama observation, and a third
evaluator do not form one qualification even when each is independently valid.
CI may exercise the mechanics with an explicitly synthetic, incomplete manifest;
that manifest remains `execution_ready=false` and is not intended-host evidence.

`scripts/build_intended_host_qualification_context.py` constructs the real context
from one reviewed plan, runtime artifact, executor/evaluator image evidence, protocol,
environment ID, and the existing ledger identity model. The plan must still be
unbound and unexecuted. `scripts/assemble_intended_host_manifest.py` requires all ten
receipts beneath one root and re-verifies the complete tree; it cannot assemble a
partial manifest or accept caller-controlled readiness.

Paths are locators only. They never establish artifact identity. A referenced file
must remain a regular file beneath the manifest root (for manifest-contained
evidence), be re-read, and match its reviewed SHA-256 before use.

The Codex executable receipt additionally binds the accepted Build-020 workflow run,
artifact ID/name/ZIP hash, pinned source/archive, Candidate B and host-integration
patches, combined patchset, executable bytes/version, and exact runtime image. The
workflow downloads that retained artifact with read-only Actions permission and
verifies the ZIP and executable hashes before building. There is no official-release
or ambient `codex` fallback. GitHub artifact retention remains an operational locator
availability constraint; it does not change the recorded content authority.

## Immutable DevFabric Python runtime

`scripts/build_devhub_runtime_artifact.py` requires a clean checkout and an explicit
reviewed implementation commit, rejects a different current HEAD, archives that exact
commit, builds one wheel, and installs the wheel without editable mode into a dedicated
environment. Pull-request qualification checks out the PR head SHA explicitly rather
than GitHub's synthetic merge ref; workflow dispatch uses its selected exact SHA. The
builder records the reviewed wheel SHA-256 rather than claiming that future builds
reproduce identical wheel bytes.

The runtime identity binds CPython version/platform tag (and observed nullable SOABI
and machine detail), invoked interpreter bytes,
wheel and `uv.lock` hashes, source commit, installed DevFabric version and module
origin, normalized installed distributions, and their installed RECORD inventory.
Verification uses isolated Python (`-I`), rejects ambient `PYTHONPATH`, user-site and
editable installs, and rejects a module origin outside the dedicated environment.

After a final context exists, `qualify_devhub_runtime.py` emits the context-bound
`PythonRuntimeReceiptV1`. A future B arm derives this exact command from the verified
receipt and re-inspected runtime:

```text
<absolute-reviewed-interpreter> -I -m devhub.delegate_server --config <trusted-config>
```

An ambient `sys.executable`, editable checkout, arbitrary `sys.path`, or unrelated
installed `devhub` cannot satisfy the new gate.

## Runtime bindings and historical evidence

New `RuntimeBindings` contains only `qualification_manifest_id`; the manifest path is
a separate locator. Runtime image, isolation, evaluator, ledger, Python environment,
Codex binary, and Ollama identity are derived from the verified context and manifest.
There is no second independently composable authority.

`HistoricalRuntimeBindingsV1` remains a strict read-only parser for old evidence.
Historical files are not rewritten, but the old structure cannot satisfy the new
execution gate.

## Current status

Build-020 produced and independently qualified the patched production Codex host
executable. The exact-image workflow now builds only from that retained binary and
collects a fresh, read-only pre-sampling Default/A/B router receipt against the
shipping host manifest. The historical Build-020 proof manifest remains byte-for-byte
separate because its MCP config included a proof-only receipt environment variable.
The shipping manifest binds the actual launcher config without that variable.

Runtime config and host-process visibility remain separate gates. Host visibility
proves Arm A has no tools, Arm B has exactly the delegate, one `tools/list` occurred,
zero `tools/call` occurred, and no model/provider execution began. Runtime config
still checks frozen CLI configuration, auth tmpfs, feature state, MCP scope and egress.
The intended-host context
`5d0df8d906fe1f204f916ad4e633f1cbb8a27bb91d3f99a4c9812d81761f6168`
and final manifest
`d6d3e1f565064846af495b5d9cab6e3f54738616d383c5c6afddf02c666b5441`
bind the complete fixed receipt set on environment
`169a6b903825d8c88973dd592c4601d9`. Independent review accepted the chain and
the validator derives `execution_ready=true` for that exact composition. Stage 3G-C
is closed for this manifest; Stage 3G remains open. Qualification alone does not
establish semantic quality, savings or Delegation Value, and cannot authorize a
different runtime composition.
