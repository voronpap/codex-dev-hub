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
| Native isolation | PENDING child/files/registry/handles/network proof | PENDING process/files/permissions/network proof without Docker |
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
