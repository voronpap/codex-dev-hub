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

Qualification retains the complete canonical profile, exact `SandboxSpec`
bytes/hash and a strictly joined receipt. It tests filesystem/registry scope,
handle inheritance, child-tree termination, breakaway denial and denial of
direct loopback, LAN, DNS and public network operations without running Codex,
MCP, a model or a provider. This proves only the **no-direct-network baseline**.
It deliberately keeps `native_executor_isolation_qualified=false` and
`package_readiness=false`: the fixed-destination trusted broker and the complete
packaged executor boundary are later gates. An unsupported API, OS build,
path/ACL semantic or cleanup observation fails closed; there is no unrestricted
fallback.

## Delivery order

1. **Windows native Codex identity and host proof.** Build `windows-build-001` for
   `x86_64-pc-windows-msvc` from the exact pinned source and reviewed patches with
   the complete locked dependency graph. Record the new executable identity and
   run same-binary Default/A/B pre-sampling and security-negative proofs. No
   inference occurs in this slice.
2. **Self-contained runtime directory.** Freeze one reviewed Windows CPython and
   non-editable DevFabric wheel environment, verify distribution metadata/RECORD,
   dependency lock, module origin and entrypoint, and bundle the accepted
   `codex.exe`. No ambient developer runtime is accepted.
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

## Platform acceptance matrix

`PENDING` means the requirement has no accepted native-package evidence yet.

| Gate | Windows native | Linux native |
| --- | --- | --- |
| Exact native Codex | PENDING — run `38065330820` stopped before compilation with `PREBUILD_WINDOWS_PATH_LENGTH_FAILURE`; short-root retry pending | PENDING — native profile/build required; OCI binary does not qualify it |
| Same-binary host authority | PENDING Default/A/B and security negatives | PENDING; historical OCI proof is profile-limited |
| MCP lifecycle | PARTIAL source coverage; packaged receipt pending | PARTIAL source coverage; packaged receipt pending |
| Self-contained runtime | PENDING clean host without developer tools | PENDING clean host without developer tools |
| Native paths/IPC | PARTIAL spaces/Unicode source coverage | PENDING native-package coverage |
| Native isolation | PARTIAL — no-direct-network AppContainer/Job baseline implemented; exact-host receipt and fixed-destination broker pending | PENDING process/files/permissions/network proof without Docker |
| Ollama boundary | PENDING Windows receipt | PENDING native Linux receipt; service/model remain external |
| Accounting | Shared core implemented; Windows end-to-end pending | Shared core implemented; native Linux end-to-end pending |
| Secrets | PENDING reviewed Windows protected store | PENDING reviewed Linux user-scoped protected store/integration |
| Data lifecycle | PENDING upgrade/rollback/disk-full proof | PENDING upgrade/rollback/disk-full proof |
| Runnable artifact | PENDING directory/launcher/file manifest | PENDING directory/launcher/file manifest |
| Installer/package | Engineering pending; public release blocked on license | Engineering pending; format depends on tested environment; public release blocked on license |
| CI/review | Windows native workflow plus shared CI pending | Native Linux workflow plus shared CI pending |
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
