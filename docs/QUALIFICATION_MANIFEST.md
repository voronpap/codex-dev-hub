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

Paths are locators only. They never establish artifact identity. A referenced file
must remain a regular file beneath the manifest root (for manifest-contained
evidence), be re-read, and match its reviewed SHA-256 before use.

## Immutable DevFabric Python runtime

`scripts/build_devhub_runtime_artifact.py` requires a clean checkout, records exact
HEAD, archives that commit, builds one wheel, and installs the wheel without editable
mode into a dedicated environment. It records the reviewed wheel SHA-256 rather than
claiming that future builds reproduce identical wheel bytes.

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
executable and its pre-sampling Default/A/B visibility. The existing benchmark
runtime image still uses the official unpatched release, so it cannot be combined
with that Build-020 receipt. A real final Stage 3G context and the complete fixed
same-environment receipt set do not yet exist, and the exact-image configuration
gate retains its unresolved execution-tool surface failure. Therefore Stage 3G-C
and Stage 3G remain open, `execution_ready=false`, and no rehearsal or benchmark
is authorized by these contracts.
