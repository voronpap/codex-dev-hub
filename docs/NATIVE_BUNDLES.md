# Native Windows and Linux bundle plan

Status: **IN PROGRESS**. This is the current delivery plan for two native
DevFabric applications: Windows without WSL, Docker or a Linux runtime, and
Linux without Docker. It does not change or supersede historical Stage 3G
evidence. Evidence for one executable or execution profile cannot authorize a
different platform or profile.

## Product boundary

Each platform has one ordinary-user launcher for the same compact DevFabric
control surface. Each bundle supplies its reviewed DevFabric runtime and
pinned/patched native Codex executable. Normal use does not require Python, uv,
Rust, Docker, WSL or a separate VM. Windows is delivered first; native Linux
packaging and qualification remain part of this delivery track.

Ollama remains an external service. The initial supported endpoint profile is a
numeric loopback HTTP URL, normally `http://127.0.0.1:11434`. DevFabric does not
install Ollama, pull models, change its server, or infer during a connection test.
LAN/public endpoints require a separate trust profile and qualification.

One shared shell/coordinator logic presents status, projects, allowed paths,
external endpoints, compatible models, limits, actual usage and bounded
diagnostics. Thin platform adapters own process launch, IPC, permissions,
secrets, system paths, isolation and packaging. The shell does not replace the
MCP server, ResourceController, ledger, provider adapters or Codex, and it must
not start a second MCP server for the same active authority scope.

## Immutable authority

- Windows and Linux builds use separate build IDs, executable hashes,
  OS/toolchain/target identities, host manifests, receipts and readiness states.
- Pinned Codex source remains
  `4607249e430dac1c961df4dc615beae88e33cec8` until separately reviewed.
- Candidate B, the reviewed host integration, canonical DelegationRequest schema,
  Default/A/B ceilings and exact delegate identity remain unchanged.
- Default Codex has `AllowedTools=None`; Arm A has `Some([])` and no delegate
  policy; Arm B has exactly `mcp__devhub_delegate.devhub_delegate` and the
  reviewed policy.
- A path is a locator. Exact content hashes and typed identities establish
  executable, runtime, configuration and ledger authority.
- Each qualification manifest may reference only receipts from its own platform,
  execution profile and environment/context. Windows and Linux receipts cannot
  be composed into one readiness result. Historical OCI evidence remains valid
  only for properties it actually proved; native Linux requires a versioned
  execution profile and native isolation receipts.

### Windows embedded-runtime authority

The first internal Windows directory bundle uses the official CPython
`python-3.12.10-embed-amd64.zip` release asset and its adjacent SPDX document.
Their exact reviewed SHA-256 values, the canonical archive-member identity, the
exact DevFabric wheel, `uv.lock`, every selected dependency wheel allowed by that
lock, installed distribution `RECORD` identities and the complete final file
inventory are separate authority inputs. Equal source does not imply equal wheel
bytes; the exact wheel hashes are authoritative.

`python312._pth` contains only the reviewed relative stdlib, bundle and
site-packages paths. It contains no `import site`, and the installed tree contains
no other `.pth`, editable/direct-URL metadata, generated console entrypoints or
bytecode caches. The delegate command is exactly the bundle-relative
`python.exe -I -B -m devhub.delegate_server`; hostile ambient `PYTHONPATH`,
`PYTHONHOME`, user-site and `PATH` values are excluded from runtime authority.

The bundle contains immutable application files only. Config, ledger, projects,
logs, retained evidence, credentials and Ollama remain external. Its canonical
manifest is external too: a future trusted coordinator must rehash and verify the
directory before launching it. The bundled interpreter cannot attest to itself,
so this packaging slice keeps `package_readiness=false` and
`native_executor_isolation_qualified=false` until those separate gates exist.
Public distribution remains blocked by the repository license decision; this
does not block an internal exact-hash directory artifact.

The Windows bundle builder itself runs through
`uv run --locked --group windows-bundle-build`. Before it creates any staging
directory, it verifies the exact locked `pip` version and requires that both the
interpreter and the imported `pip` module come from the same dedicated virtual
environment. Dependency acquisition then uses that same interpreter with
`-I -m pip download`; ambient or system `pip` is not build authority.
After installation, the builder removes only two reviewed classes of uv
installer metadata. The root `site-packages/.lock` must be an exact empty plain
file. A `.dist-info/uv_cache.json` path must be derived from a retained wheel's
exact `RECORD` path, be a small plain file with the reviewed strict JSON schema,
and match its hash and size in the installed `RECORD`. Wheel-owned collisions,
unexpected or nested locations, malformed content, missing or mismatched
`RECORD` entries, links, reparse points and cleanup failures all fail closed.
The generic wheel ownership verifier remains strict and reconstructs each final
`RECORD` from the retained reviewed wheels.

### Windows no-direct-network isolation baseline

The first Windows isolation slice uses the Windows 11
`Experimental_CreateProcessInSandbox` AppContainer API and the reviewed
`SandboxSpec` 0.1.0 wire layout. It is limited to x64 Windows builds at or above
26100 and must be qualified again on the exact supported OS build. The API is
experimental; its presence or a version check alone is not evidence that its
policy was enforced.

The child starts suspended with no inherited handles, no AppContainer
capabilities and no network policy. The host assigns it to a non-breakaway Job
Object before resuming it. Exact read-only, writable and denied roots are bound
to volume/file identities; root, working-directory and launcher reparse chains
are rejected immediately before launch. The launcher bytes are rehashed against
the verified native bundle. Windows still creates the process from a string path,
so privileged filesystem replacement between final validation and process
creation remains a documented TOCTOU limitation.

Each launch must create and own a fresh exact AppContainer profile. A
pre-existing profile name is rejected and never deleted by the launcher. The
child `LOCALAPPDATA` is derived from the created profile SID with
`GetAppContainerFolderPath`; callers cannot supply this authority-bearing path.
All terminal paths close process and job handles before deleting only that
invocation's profile, and any profile cleanup failure blocks evidence
publication.

If the isolated probe exits before it can create success evidence, the host may
retain `<success-output>.failure.json`. This self-hashed, non-success diagnostic
binds the environment, profile, probe, stdlib-only child-bootstrap hash and exact
unsigned process exit code. Before importing the probe, that separately hashed
bootstrap atomically writes a strict, identity-bound `bootstrap_started` frame.
Reserved exit codes distinguish a loader/self-hash failure, inability to write
that frame, bounded allowlisted import boundaries and inability to retain
bounded failure detail. Import classification is encoded only by reserved exit
codes for `_ctypes`, `_socket`, `pydantic_core`, DevFabric or an unknown name;
raw exception text, module paths and host paths are not retained. Both the
bootstrap frame and child detail are independently marked as
validated, invalid or absent; invalid and absent data are never trusted. Success
requires the validated frame. The diagnostic is published only after exhaustive
cleanup succeeds, never grants readiness and leaves the success output absent.
The V2 receipt retains the validated marker ID and an explicit true observation;
the evidence recomputes that ID from the retained profile identities.
Bootstrap-bearing profile, receipt, evidence and failure contracts are V2. The
strict V1 parsers remain unchanged for the earlier retained non-success evidence;
V1 evidence is historical and cannot satisfy the V2 bootstrap gate.

The host probe also requires an explicit trusted expected DevFabric implementation
commit. After strict bundle verification and before platform observation, scratch
creation or native resource acquisition, it compares that authority with the
bundle's immutable implementation commit. A valid but stale bundle therefore
fails before launch; a filesystem locator cannot select a different runtime.
The authoritative bundle is never handed to `SandboxSpec`. The host copies it
to a fresh non-overlapping, reparse-checked disposable directory, verifies that
copy against the same immutable manifest and launches only from the copy. All
terminal paths remove the disposable directory fail-closed, then reverify the
source bytes and owner/group/DACL inventory before publishing either success or
failure evidence.

After creating the fresh owned profile, the launcher grants only that profile's
exact derived package SID (`S-1-15-2-` plus seven canonical 32-bit decimal
subauthorities) read/traverse/execute (`0x001200A9`) on every entry in the closed
disposable runtime inventory. Broad application-package identities and malformed
or non-package SIDs fail before any ACL write. Directory entries retain
`OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE`; existing files receive an exact
non-inheritable ACE. The launcher intentionally grants the closed existing
inventory entry by entry and does not depend on parent propagation; directory
inheritance covers only entries created later. The launcher rejects protected descendant DACLs,
pre-existing entries for that SID, broad application-package SIDs, missing
entries, duplicate entries and any wider/write-capable mask. It reads every DACL
back and hashes the canonical ACL inventory before process creation. The V3
success receipt binds that self-hashed grant, SID, verified entry count,
disposable root identity, native bundle identity and launcher hash while V1/V2
remain parse-compatible historical contracts. The authoritative source bundle is
never ACL-modified. A trusted full bundle verification runs after the recursive
grant immediately before process creation, followed by root/executable identity
checks. Installation retains an identity-bound ownership token containing only
entries successfully modified by that launch. Preflight failures perform no ACL
write or revocation; partial installation rolls back only that exact token.
Every failed launch and normal close validates the complete token, revokes only
its unchanged entries, and then deletes the owned profile. Substitution,
revocation, or later tree cleanup failure remains terminal non-success and
retains the profile when deletion would make exact cleanup authority ambiguous.

`Experimental_CreateProcessInSandbox` can alter runtime filesystem policy while
creating the suspended process. V4 therefore treats the earlier V3 grant as
pre-create evidence only. Before job assignment or `ResumeThread`, the host
revalidates every identity-bound runtime entry, the full immutable bundle, the
launcher hash and the exact package-SID ACL. It records canonical pre-create and
post-create ACL inventory hashes. Missing or narrower exact-SID entries may be
removed and reinstalled with only the reviewed RX mask; broad package trustees,
protected descendants, substituted entries, duplicate/wider permissions or a
failed repair remain terminal. The suspended child never runs before this gate.
A self-hashed post-create failure diagnostic can be published only after clean
process, ACL and profile cleanup; V3 remains parseable historical evidence and
cannot satisfy the V4 post-create gate.

If a V4 child exits after that gate but before success evidence, the forward V4
failure diagnostic retains the exact V2 runtime-access grant, full self-hashed
profile and their bundle/launcher/environment joins. Before importing the full
probe, the stdlib bootstrap imports the fixed ordered `_socket`, `_overlapped`,
`select` and `_ssl` matrix. Each label and observed extension hash is joined to
the immutable bundle inventory by the host. The diagnostic records only reviewed
CPython loader forms as an allowlisted reason and optional bounded Win32 code,
including `initialization_failed`/`1114`, plus bounded hash/readability observations
for manifest-bound native files. Raw loader messages and filesystem paths are never
retained. Reordered, missing, forged-code or hash-substituted observations fail
closed. Historical V1-V3 failure diagnostics remain strictly parseable but cannot
establish this newer diagnostic authority. As with every failure artifact,
publication occurs only after complete process/profile/runtime-ACL cleanup and
source-bundle re-verification, and it does not grant readiness.

Historical Forward V5 bound Windows DLL lookup only to the resolved parent directory of
the exact running packaged interpreter by retaining one `os.add_dll_directory`
handle for the complete bootstrap, probe import and child execution lifetime.
Ambient `PATH`, the working directory, registry entries and caller-supplied
directories are not lookup authority. Bootstrap hashing uses the pinned
interpreter's built-in `_sha2`, and preloaded `_hashlib` or `_ssl` is terminal,
so binding occurs before either OpenSSL-backed module's first import. Binding
failure is terminal before native imports. The ordered matrix adds `_hashlib`
before `_ssl`; V5 diagnostics join
both extensions and the sibling `libcrypto-3.dll`/`libssl-3.dll` files to the
immutable bundle manifest, with fixed exit codes and bounded status only. V1-V4
remain parseable historical diagnostics and cannot establish V5 loader-boundary
evidence. V5 is still failure-only diagnostic evidence and does not grant
readiness.

Forward V6 replaces that active boundary with the reviewed
`_devfabric_native_loader.pyd` helper from the exact packaged interpreter
directory. The V6 profile binds the accepted loader build/binary authority and
a fixed six-entry expected hash projection for `_ctypes`, `_socket`,
`_overlapped`, `select`, `_hashlib` and `_ssl`. Before any of those modules can
be loaded, the stdlib bootstrap rejects a preloaded matrix member, verifies the
helper's exact sibling path and SHA-256, imports only that fixed module name,
calls `activate()` with no arguments, and requires the exact ordered result
`libffi-8.dll`, `libcrypto-3.dll`, `libssl-3.dll`. The child then imports the
fixed six-module order. Its observed paths and hashes must equal the immutable
bundle expectations retained in both the V6 profile and V5 success receipt;
self-hashed substitution fails on parse. Forward V6 failure diagnostics retain
only bounded loader classifications, exact expected/observed hash joins and
fixed exit mappings. V1-V5 evidence remains parseable historical evidence and
cannot establish the V6 helper boundary.

V6 is still a metadata-only, non-readiness qualification step. It keeps
`native_executor_isolation_qualified=false` and `package_readiness=false`; the
metadata-only AppContainer probe cannot promote Windows readiness.

Forward V7 adds a bounded failure-stage diagnostic to that same helper boundary.
The helper can report only the reviewed stage taxonomy (interpreter-sibling
identity, directory validation, dependency pre-open/load, loaded-path query,
loaded-file reopen or file-identity comparison), one of the three fixed dependency
labels where the stage is dependency-specific, and the numeric Win32 error. Raw
paths, loader messages and caller-controlled labels are excluded. The child and
host failure receipts strictly join the stage, dependency and error code to the
failed activation; malformed or unknown values are treated as invalid evidence.
The loader build receipt also binds negative proofs for missing/invalid/wrong-path
and partial-load cleanup plus concurrent activation. V1-V6 receipts remain
parseable historical evidence and cannot establish the V7 diagnostic boundary.
V7 changes diagnostics only: the fixed DLL allowlist, load flags, held handles,
file-identity checks, ACLs, isolation policy and non-readiness classification are
unchanged.

Forward V8 separates the Python bootstrap boundary from the helper's activation
boundary. It retains exactly one bounded bootstrap stage covering the preloaded
module guard, runtime/helper path resolution, sibling/hash/import/origin checks,
helper activation and activation-result validation. Only `helper_activation` may
carry the V7 `NativeLoaderFailureV1` helper stage, dependency and Win32 code;
pre-helper failures must not claim that authority. Every failure binds the
numeric `winerror`/`errno`, when present, to the activation observation. Raw
messages and paths remain excluded. V1-V7 receipts remain parseable historical
evidence and cannot establish the V8 bootstrap boundary. V8 remains a
metadata-only diagnostic step: it does not change the allowlist, load flags,
handles, file-identity or isolation policy, and it does not grant readiness.

Forward V9 replaces child-side filesystem canonicalization of `sys.executable`
with an exact host-bound lexical launcher authority. Profile V4 seals the already
validated, drive-qualified local `python.exe` locator, its lexical SHA-256, its
Windows volume/file identity and its immutable-bundle byte hash. The host passes
that sealed locator and hash; the child rejects relative, UNC, device, slash-mixed
and dot-segment forms, requires normalized equality with `sys.executable`, and
returns only the bounded locator digest. Receipt/evidence V6 join that child
observation to the V4 profile. Failure diagnostic V9 joins the same expected and
observed digest without disclosing the path. Loader and imported-module paths must
remain exact siblings of that launcher. This avoids traversing intentionally
ungranted AppContainer ancestor directories while preserving the module hash,
native helper sibling, open-handle and file-identity checks. No ancestor ACL is
widened. V1-V8 failure receipts and earlier profile/evidence versions remain
parseable historical evidence and cannot establish this V9 launcher boundary. V9
remains metadata-only and does not grant readiness.

Qualification retains the complete canonical profile, exact `SandboxSpec`
bytes/hash and a strictly joined receipt. It tests filesystem/registry scope,
handle inheritance, child-tree termination, breakaway denial and denial of
direct loopback, LAN, DNS and public network operations without running Codex,
MCP, a model or a provider. This proves only the **no-direct-network baseline**.
It deliberately keeps `native_executor_isolation_qualified=false` and
`package_readiness=false`: the complete packaged executor boundary remains a
later gate. An unsupported API, OS build,
path/ACL semantic or cleanup observation fails closed; there is no unrestricted
fallback.

The forward-only Windows Ollama broker slice is metadata-only. Each attempt
copies and verifies the exact source `NativeBundleV1` into a fresh disposable
runtime, derives a fresh exact-path isolation profile from one strictly joined
`WindowsIsolationEvidenceV6` baseline, and removes that runtime only after
AppContainer cleanup, retained-parent identity checks, and source
re-verification. Its authority embeds the baseline profile, proves that the
fresh profile changes only launcher/path identities, and binds one exact
read-only runtime, writable client root, and denied host-control root. It also
binds the baseline receipt/evidence, exact AppContainer package SID, retained
bundled Python/module bytes, and one exact `127.0.0.1:11434` listener process
identity. The final receipt retains the observed `WindowsRuntimeAccessGrantV2`
and joins its SID, runtime root, bundle, launcher, and pre/post ACL inventories
to that fresh profile. A protected message-mode named pipe grants only generic
read/write to that package SID; the host authenticates the client SID and the
client authenticates the exact broker process. The allowlist is limited to
`/api/version`, `/api/tags`, and `/api/show`; `/api/generate` has no protocol
endpoint. The metadata receipt is derived from the observed ordered responses
and records `generation_requests=0`, `model_requests=0`, and
`provider_sends=0`. Bounded overlapped I/O, exact framing, DACL readback, and
cleanup failures all fail closed. Final evidence re-parses the retained response
bodies and recomputes all authority, runtime, server/client, response, metadata,
listener, pipe, model, SID, access-grant and baseline-isolation joins. The code
still does not claim that a live listener or AppContainer run has passed:
Windows readiness remains false until an exact-host receipt and final platform
manifest exist.

### Native Linux Codex build authority

The first Linux-native attempt, `linux-build-001`, is retained as failed evidence: the
`v8_enable_sandbox` feature intentionally has no generic upstream prebuilt archive. The
second attempt, `linux-build-002`, is also retained as failed evidence: the crates.io
`v8-150.4.0` source package omits required ICU source data, so its source build cannot
complete. The forward-only `linux-build-003` consumed the exact sandbox archive and
matching generated binding from OpenAI's reviewed `rusty-v8-v150.4.0` Codex release.
Both assets, the release checksum manifest, the pinned source `MODULE.bazel`, the
`v8_enable_sandbox` feature and post-build rehashes are receipt-bound. It builds the exact sibling
`codex` and `codex-code-mode-host` executables together from the pinned Codex
source, reviewed Candidate B and host-integration patches, complete derived lock,
Rust 1.95.0 and target `x86_64-unknown-linux-gnu`. It reuses the reviewed source
preparation and Default/A/B observer rather than defining a second patch, lock or
tool-surface authority. Run `38129490280` compiled that exact pair and completed
the observed host proof, then failed closed while serializing the build receipt:
the historical V1 proof contract required ordinary `AllowedTools=None` Default
to be empty, while the observer correctly reported the accepted eleven ordinary
tools. Its immutable classification is
`POSTCOMPILATION_DEFAULT_SURFACE_CONTRACT_REPRESENTATION_FAILURE`; it is not an
Arm A/B ceiling failure. Forward-only `linux-build-004` uses the shared ordinary
Default authority already accepted for Windows while retaining Arm A `{}`, Arm B
exactly the delegate, all security negatives and zero execution counters. It also
seals the complete build output and creates a separate inventory-bound evidence
projection that explicitly includes hidden files. V1-V3 receipts remain strict
historical contracts. Run `38159406760` compiled and proved that exact pair, then
failed closed when the artifact inventory encountered a non-regular process-proof
runtime entry. The retained failure did not record the offending pathname;
`CODEX_HOME` was the only unbounded subprocess-mutated tree in the retained
output, and pinned Codex creates Unix arg0 symlinks there. Its immutable classification is
`POSTPROOF_NONPLAIN_RUNTIME_SCRATCH_INVENTORY_FAILURE`. Forward-only
`linux-build-005` keeps each proof `CODEX_HOME` in a fresh sibling runtime-scratch
root outside sealed output, requires exhaustive cleanup, and binds the successful
cleanup into its proof receipt. The strict recursive evidence inventory is unchanged.
Run `38165368199` is retained as a pre-compilation registration failure: source
preparation rejected the previously unregistered `linux-build-005` identifier, so
Rust compilation and process proof did not start. Run `38165606388` is the immutable
PR-head `linux-build-005` attempt. Its receipt remains valid only for that exact
implementation commit; it cannot authorize a normal merge commit. Forward-only
`linux-build-006` preserves the build-005 pair, proof, cleanup and inventory contracts
and is reserved for one explicit `workflow_dispatch` on `refs/heads/main` after the
registration change merges. Ordinary PR validation remains in Offline Core and does
not compile the pair.

Its strict self-hashed receipt binds both executable hashes, ELF class/machine,
program interpreter, `DT_NEEDED`, absence of embedded RPATH/RUNPATH, required
symbol versions, toolchain binaries, workflow and build/proof scripts. The
current pre-sampling proof requires the exact ordinary eleven-tool Default, Arm A `{}`, Arm B exactly
`{mcp__devhub_delegate.devhub_delegate}`, the existing security negatives, no
missing sibling-host warning, clean MCP-child shutdown and zero model, provider,
MCP-tool and real-task counters. A separate stdio EOF check requires the exact
code-mode host to exit cleanly without a request.

This receipt establishes only native Linux executable/build authority. It keeps
`native_bundle_qualified=false`, `native_executor_isolation_qualified=false` and
`execution_ready=false`; Python packaging, Linux isolation, secrets, mutable data,
Ollama/accounting joins and the final platform qualification remain later gates.
Build-020 and all OCI evidence remain immutable historical evidence.

## Delivery order

1. **Windows native Codex identity and host proof.** Historical
   `windows-build-001` retained only `codex.exe`; its valid pre-sampling proof is
   preserved but cannot authorize the operational CodeModeOnly path. The
   first paired attempt, `windows-build-002`, is retained as historical evidence.
   `windows-build-003` is also retained as failed evidence: the crates.io V8
   build script requested an unpublished generic sandbox archive and received
   HTTP 404. `windows-build-004` consumed the exact sandbox
   archive and matching generated binding from OpenAI's reviewed
   `rusty-v8-v150.4.0` Codex release. Both assets, the release checksum manifest,
   the pinned source `MODULE.bazel`, the `v8_enable_sandbox` feature and
   post-build rehashes are receipt-bound. It builds and binds
   `codex.exe` and the sibling `codex-code-mode-host.exe` together for
   `x86_64-pc-windows-msvc`
   from the exact pinned source, reviewed patches and complete locked dependency
   graph. Its self-hashed receipt records both PE identities, exact toolchain and
   committed builder/workflow provenance. Run `38131544194` at commit
   `8f47c02dccfb994fb9513625d08061c19cf51d74` completed compilation and observed
   the same binary pair, then failed closed while serializing its proof: the V2
   receipt incorrectly required the ordinary `AllowedTools=None` Default surface
   to be empty even though the observer reported the accepted eleven ordinary
   tools. Its immutable classification is
   `POSTCOMPILATION_DEFAULT_SURFACE_CONTRACT_REPRESENTATION_FAILURE`; it is not an
   Arm A/B ceiling failure. Forward-only `windows-build-005` corrects that proof
   representation and adds fail-closed artifact inventory/retention controls; it
   does not change the production binary semantics. It requires the exact sorted
   ordinary Default tuple while retaining Arm A `{}`, Arm B exactly the delegate,
   absent Default ceiling, all security negatives and zero execution counters. A
   content-bound inventory seals every file in the staged build output before CI
   splits the uploads, joins a PASS result to the exact binary pair, process proof
   and EOF proof, excludes `binary/**` from failure evidence, and publishes the
   executable pair only on success. Run `38139154084` at commit
   `9deae70ab018bd6fbd1e9c2c1dbca8356b074f0a` completed compilation and the exact
   Default/A/B proof, but the CI artifact projection omitted 252 inventory-bound
   files beneath hidden path components because `upload-artifact` used
   `include-hidden-files: false`. Its immutable classification is
   `POSTPROOF_ARTIFACT_PROJECTION_INCOMPLETE`; the binary and process proof remain
   valid but the retained evidence artifact cannot satisfy its sealed inventory.
   Forward-only `windows-build-006` keeps the V4 proof semantics unchanged and
   creates a bounded evidence projection from every `kind=evidence` inventory
   member plus the inventory itself before uploading hidden members explicitly.
   Historical receipts remain strict and parseable. Default/A/B
   proof must use the exact colocated pair without a missing-host diagnostic; the
   host must also exit cleanly on stdio EOF. No inference or MCP tool execution
   occurs in this slice.
   Run `38148646088` at commit
   `3b70f932480b017c2a21c1a30c65143ae5d5ff0c` completed `windows-build-006`
   and retained its complete exact pair, proof and inventory. That authority is
   valid for its implementation commit, but the bundle verifier correctly rejects
   replaying it into a bundle built from a later implementation commit. Forward-only
   `windows-build-007` preserves the exact build-006 binary/proof/security contract
   while producing a fresh pair bound to the current merged implementation commit;
   historical build-002 through build-006 receipts remain strict and parseable.
   Build-007 is reserved for one explicit `workflow_dispatch` on `refs/heads/main`
   after the registration change merges, so a PR-head compilation cannot become
   stale solely because the normal merge commit changes the implementation identity.
   Ordinary PR validation remains in Offline Core and does not compile the pair.
   Run `38169871650` at commit
   `c886b042eb57d24a1893d16f5752ac03ef24398a` completed
   `windows-build-007`, including the exact native pair,
   ordinary Default/Arm A/Arm B same-binary proof, EOF and security negatives.
   That receipt remains authority for its exact historical implementation commit.
   The subsequently merged Windows broker and packaging changes require a new
   exact-commit pair; forward-only `windows-build-008` preserves all build-007
   proof semantics and keeps build-002 through build-007 receipts parseable.
   Build-008 is likewise reserved for one explicit `workflow_dispatch` on merged
   `main`; PR validation only registers and tests its strict contract.
2. **Self-contained runtime directory.** Freeze one reviewed Windows CPython and
   non-editable DevFabric wheel environment, verify distribution metadata/RECORD,
   dependency lock, module origin and entrypoint, and bundle the accepted
   `codex.exe` plus its exact `codex-code-mode-host.exe` sibling. No ambient
   developer runtime or codex-only forward bundle is accepted.
3. **Native executor isolation.** Qualify a fail-closed Windows process boundary
   covering the complete child tree, filesystem/registry scope, inherited handles,
   resource termination and exact network destinations. A Job Object alone is not
   sufficient. Unsupported OS/security mechanisms stop execution.
4. **Coordinator, settings, secrets and compact UI.** Add one coordinator and
   atomic settings store, user-selected project/allowed paths/data directory,
   loopback Ollama metadata checks, status/block reasons, accounting usage/recent
   results and bounded diagnostics. Store provider credentials in a reviewed
   user-scoped protected Windows store; do not migrate plaintext environment
   values automatically.
5. **Runnable bundle, then installer.** Keep binaries separate from mutable config,
   ledger, logs, projects and evidence. Prove free-space/disk-full handling,
   upgrade/rollback data preservation and uninstall-with-data-retention before a
   simple per-user installer and shortcut are accepted.
6. **Windows qualification and one bounded end-to-end proof.** Only after all
   preceding gates pass, bind one Windows context/manifest and run one already
   supported task through Windows Codex → MCP → DevFabric → the existing qualified
   loopback Ollama → validated result → settled accounting.
7. **Native Linux bundle and qualification.** Reuse the same core, shell logic,
   source preparation, ledger, schemas and artifact verification. Add only Linux
   adapters for process launch, IPC, permissions, protected secret access,
   system paths, native isolation and packaging. Produce a runnable native Linux
   bundle with its own executable/runtime/file-manifest identities and qualify it
   from the ready-to-run package without Docker. Do not infer general
   distribution support from one tested host.
8. **Cross-platform data lifecycle.** Verify each native package preserves its
   configured ledger, settings, logs and retained evidence through supported
   upgrade/rollback. Do not automatically synchronize state or implicitly reset
   ledger authority between platforms.

## Native Linux directory authority

The forward-only `linux-build-007` receipt adds the workflow run and attempt to
the exact merged implementation identity.  It keeps all earlier Linux receipts
strictly parseable and does not alter their hashes.  The manual main-only
`linux-native-bundle.yml` workflow accepts only the successful build-007 pair
from the same implementation commit.

`LinuxNativeBundleV1` seals a closed directory containing the exact Codex pair,
an exact copied CPython 3.12.10 runtime, a wheel built from the reviewed commit,
all registry wheels selected from `uv.lock`, and two relative launchers.  The
builder clears ambient `site-packages`, installs only reviewed wheels, verifies
RECORD ownership, rejects external runtime symlinks, and repeats runtime
inspection after relocating the complete release directory.  `PYTHONPATH`,
`PYTHONHOME`, user-site state and editable installs cannot authorize imports.
The published transport is one exact `tar.gz` plus its bundle manifest and a
self-hashed archive receipt. Unix file and directory modes are part of the
bundle identity. The trusted verifier requires that exact three-file release,
joins the archive bytes to both receipts, extracts into a fresh root, repeats
strict verification, and runs only the metadata-only `devfabric schema` smoke.

The tested bundle is intentionally tied to Linux x86_64 and the exact host
environment recorded by later qualification.  It does not claim support for
every distribution.  Directory assembly alone leaves
`native_executor_isolation_qualified=false` and `package_readiness=false`;
native process/filesystem/network isolation and platform receipts remain
mandatory before Linux readiness.

### Native Linux isolation mechanics baseline

`LinuxNativeIsolationV1` through `LinuxNativeIsolationV4` remain strict historical
contracts. The private-launcher/AppArmor qualification now emits the forward-only
`LinuxNativeIsolationV5` contract; V1-V4 payloads and canonical identities are
not reinterpreted. V5 preserves the V4 mount and V3 Landlock authority: it records the kernel-reported ABI
separately from the reviewed policy ABI. Kernels reporting ABI 7 or newer keep
their exact observation while enforcement is capped at reviewed ABI 6 and its
exact `handled_access_fs` mask. Kernels older than ABI 3 fail closed. The child
independently repeats the kernel query and derives the same cap before creating
the ruleset.
It binds one exact Ubuntu 24.04 x86_64 host and kernel, the reviewed system
`/usr/bin/unshare`, an exact root-owned copy at
`/opt/devfabric/libexec/unshare`, `/usr/bin/mount`, bootstrap-interpreter file
identity, source directory
device/inode identities, and an explicit private-root
mount table, rootless user/mount/PID/network namespaces, a nonzero namespace UID,
`no_new_privs`, zero capability sets, ABI-specific Landlock rules, observed fixed
rlimits, and a fresh AF_UNIX metadata broker. Python is the already-loaded
qualification bootstrap; this mechanics receipt does not claim a complete
post-chroot Python runtime closure. The broker validates the child outer PID,
start time and UID; the child independently validates the translated broker PID,
UID and socket inode. It forwards only
bounded `/api/version`, `/api/tags` and `/api/show` requests to fixed
`127.0.0.1:11434`; generation, streaming, oversized and ambiguous HTTP requests
are denied before forwarding.

V5 also preserves V4's binding of `/usr/bin/mount`'s ordinary permission bits, special bits and
complete `stat.S_IMODE` separately. The exact Ubuntu 24.04 root-owned mount
binary may retain setuid; setgid, sticky, group/world-writable, non-root or
substituted tools fail closed. Both unshare binaries, `apparmor_parser` and the
bootstrap interpreter continue to require zero special bits. The child
independently re-reads the mount binary bytes, size, owner, full mode,
device/inode and version output before its first mount operation.

The real Ubuntu mechanics probe uses a synthetic non-task fixture and a local
metadata stub. It makes no Codex, MCP, model or provider call. Its receipt
therefore proves namespace/mount/Landlock/broker mechanics only. It explicitly
keeps `cgroup_resource_boundary_qualified=false`,
`syscall_filter_qualified=false`, `native_executor_isolation_qualified=false`
and `package_readiness=false`. A final native-Linux package still requires the
exact runnable bundle, delegated cgroup-v2 resource controls or a narrower
reviewed resource claim, a reviewed syscall boundary, secrets/data lifecycle,
real external Ollama identity and one same-environment qualification manifest.
Unsupported user namespaces, mount operations, Landlock, peer credentials or
cleanup fail closed; there is no unrestricted host-process fallback.
Ubuntu's global unprivileged-user-namespace restriction remains enabled. The
only exception is the repo-owned named AppArmor attachment for the private
launcher; the generic `/usr/bin/unshare` receives no exception. Qualification
binds the profile Git blob and installed bytes, root ownership/mode, exact
`apparmor_parser` file/version, the kernel loaded-profile observation, and the
child's actual `/proc/self/attr/current` label. Privileged policy setup never
runs for pull-request code. It is available only through an explicit
`workflow_dispatch` at an exact commit on `main`; the job uses `sudo` only to
install/load and then remove that host policy. The namespace mechanics and
child remain the ordinary runner user. Cleanup evidence separately records
parser unload, loaded-profile absence, installed-profile removal,
private-launcher removal, snapshot removal and owned-parent cleanup. A final V3
qualification is valid only when its self-hashed mechanics evidence and
self-hashed cleanup receipt join to the same implementation, environment,
exact profile ID and mechanics-evidence ID. Completed cleanup first revalidates
the exact loaded `(unconfined)` profile and every recorded file/directory;
disappearance, mode drift or substitution fails before removal. Partial rollback
alone may tolerate a journaled object that was never created. Every cleanup
mutation first persists a self-hashed pending transition, then seals completion;
recovery accepts only the exact pre-action authority or its exact expected
absence and never removes a substituted object. Setup, rollback,
cleanup and finalization failures emit a bounded self-hashed lifecycle failure
record with zero execution counters and cannot coexist with success evidence.
An intended host that cannot install this exact narrow
profile is unsupported and fails closed; disabling the global sysctl is not an
accepted fallback. The workflow verifies the exact main commit and a clean
tree. Paths remain locators; hashes plus native identities are the authority.

Main-only run `38212445127` is retained as an immutable pre-namespace
`host_authority_invalid` failure: the runner reported Landlock ABI 7 to the
older V2 representation, privileged cleanup succeeded, and model, provider,
MCP-tool and real-task counters remained zero. It is not qualification evidence.
Main-only run `38246458005` is separately retained as an immutable
pre-namespace mount-mode representation failure: V3 rejected the exact
root-owned Ubuntu `/usr/bin/mount` mode `04755` before namespace creation.
Privileged cleanup succeeded and all execution counters remained zero. V4 is
the forward-only correction. Main-only run `38252172665` is retained separately
as a pre-namespace synthetic-upstream bind failure: the fixed fixture port
`127.0.0.1:11434` was already occupied, cleanup succeeded and all execution
counters remained zero. V5 selects an ephemeral loopback fixture port, retains
the exact listening socket, and binds its port, inode and owner process identity
through profile, observation, receipt and evidence. The production Ollama
destination and accepted HTTP Host authority remain exactly
`127.0.0.1:11434`. None of these failed runs grants readiness.

## Platform acceptance matrix

`PENDING` means the requirement has no accepted native-package evidence yet.

| Gate | Windows native | Linux native |
| --- | --- | --- |
| Exact native Codex | PARTIAL — accepted `windows-build-007` pair is bound to historical commit `c886b042eb57d24a1893d16f5752ac03ef24398a`; forward-only `windows-build-008` is registered for the current merged implementation | PENDING — `linux-build-004` compiled/proved but retained non-regular runtime scratch; `linux-build-005` is PR-head evidence and exact-current-commit `linux-build-006` is required; OCI binary does not qualify it |
| Same-binary host authority | PARTIAL — `windows-build-007` proved Default/A/B, EOF, security negatives and complete retention; exact-current-commit `windows-build-008` pending | PENDING — historical builds 003/004 proved surfaces but failed receipt/inventory closure; `linux-build-005` is PR-head evidence and exact-current-commit `linux-build-006` is required |
| MCP lifecycle | PARTIAL source coverage; packaged receipt pending | PARTIAL source coverage; packaged receipt pending |
| Self-contained runtime | PENDING clean host without developer tools | PENDING clean host without developer tools |
| Native paths/IPC | PARTIAL spaces/Unicode source coverage | PENDING native-package coverage |
| Native isolation | PARTIAL — no-direct-network AppContainer/Job baseline and fixed-destination metadata broker implemented; exact-host receipt and complete packaged boundary pending | PENDING process/files/permissions/network proof without Docker |
| Ollama boundary | PARTIAL — closed metadata-only broker implemented; exact listener/AppContainer receipt pending | PENDING native Linux receipt; service/model remain external |
| Accounting | Shared core implemented; Windows end-to-end pending | Shared core implemented; native Linux end-to-end pending |
| Secrets | PENDING reviewed Windows protected store | PENDING reviewed Linux user-scoped protected store/integration |
| Data lifecycle | PENDING upgrade/rollback/disk-full proof | PENDING upgrade/rollback/disk-full proof |
| Runnable artifact | PENDING directory/launcher/file manifest | PENDING directory/launcher/file manifest |
| Installer/package | Engineering pending; public release blocked on license | Engineering pending; format depends on tested environment; public release blocked on license |
| CI/review | PASS for historical `windows-build-007`; current `windows-build-008` registration is under review and later package gates remain separate | Native Linux PR-head `linux-build-005` evidence pending completion; merged-main-only `linux-build-006` registration under review |
| Final execution | PENDING one Windows-only context/manifest | PENDING one native-Linux-only context/manifest |

## Stdio and lifecycle invariant

The MCP client owns the server process. EOF is shutdown, never proof success.
Pre-sampling proof requires a nonzero deliberate observer stop plus a validated
observer receipt; plain EOF or exit zero cannot pass. The packaged server must keep
stdout protocol-only and terminate its owned child tree on timeout/cancellation.
Closing the UI does not terminate an independently client-owned MCP process.

## Data and secret layout

Each bundle directory is immutable application content. Mutable data belongs
under an operator-selected data root with distinct config, ledger/brain/packages,
logs, diagnostics and retained evidence directories. Changing a path does not reset
or replace ledger authority. Disk-full must stop before partial authority/settings
writes; automatic cleanup is limited to reproducible cache/temp content.

Provider credentials are resolved only at the transport boundary from a reviewed
user-scoped protected store adapter and are bound to their intended
provider/endpoint. Cloud providers stay disabled without explicit configuration
and authorization; there is no hidden paid fallback. State is not synchronized
automatically between Windows and Linux.

## External product patterns and licenses

Only interaction patterns were reviewed; no external product code is vendored.

- Goose and Cline show client-owned MCP extension lifecycle and visible permission
  controls. Their permissive/auto-approved modes are not adopted. Both are
  Apache-2.0.
- Jan separates endpoint configuration from manually asserted capabilities; an
  endpoint response alone does not prove model capabilities. Jan is Apache-2.0.
- AnythingLLM demonstrates workspace-scoped provider/model/status views. DevFabric
  keeps its stricter project, route and accounting authority. Its root license is MIT.

The repository itself still has no selected distribution license. That does not
block internal feasibility builds, but it blocks a public installer/release until
the owner records a license decision. Dependency and bundled-runtime notices must
be generated from the exact accepted bundle inventory.

## Non-goals

- No IDE, code editor, general chat, provider marketplace or new provider.
- No Docker/WSL fallback and no unrestricted host-process fallback. Docker may
  remain a historical or CI tool, but it is not a runtime dependency of either
  native application.
- No automatic Ollama/model installation or model substitution.
- No weakening of frozen benchmark fixtures, oracle, ceilings or accounting gates.
- No quality, savings or production-readiness claim from build or transport proof.
