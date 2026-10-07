# Candidate B implementation worktree

This patch is applied only to a disposable copy of pinned source
`4607249e430dac1c961df4dc615beae88e33cec8` for compilation. It does not replace the
shipping Codex binary or benchmark runtime. LOCK_B remains proof-only. No v3.

The initial implementation adds an opaque retained approved call, a per-runtime
generation lease, invalidation on publication/reconnect/shutdown, and an opt-in
host startup policy consumed by the actual `build_tool_router` path. Ordinary
MCP handlers still use the original lookup path. Approved handlers do not.
An in-flight leased call finishes before publication invalidates its generation;
after invalidation returns, old approvals cannot start preparation. The lease
covers existing `PreparedMcpCall` execution, not a second execution engine.

`ApprovedDelegatePolicy` is Rust host startup data. It is NOT a CLI-loadable TOML
option. DirectModelOnly namespaces remain the existing internal config field.
The policy demands exact AllowedTools and CodeModeOnly, and constructs only the
approved handler. Canonical-name cache lookup is not used for admission.

This is **incomplete, unvalidated implementation**, not a production gate pass.
The first probe is intended to exercise A/B through production router construction,
real-schema comparison, synthetic stdio dispatch and reconnect invalidation.
It intentionally reports UNKNOWN even if this subset succeeds. It does not yet
establish the entire required adversarial matrix or an exact CLI/host metadata
process proof. The synthetic process is not Dev Hub or an inference provider.

Build 001 failed before test execution with E0728: the synchronous
`refresh_mcp_servers` caller contains an `await`. Its receipt and compiler
diagnostics are preserved in `docs/evidence/stage3g-approved-call/`.
Build time was 642.1814258400001 seconds. No compiled A/B, dispatch or security
result was obtained; those fields remain null and classification remains UNKNOWN.
This failure is implementation work remaining, not evidence against the design.

Outstanding gates include complete trusted launch/config-file/project/state-root
attestation and explicit path normalization, both collision orders, forged runtime,
refresh after preparation using the existing catalog guard, process observation
through a reviewed host entry point, and default-path regression validation.
Do not activate this patch while those gates are unproven. No caller-supplied
identity strings alone may satisfy the missing host attestation.

The admitted schema must remain the real reviewed schema whose canonical JSON
SHA-256 is `0f06b9fc3d912389721413789835053eefb2db7cc14781829bd57234c7e371be`.
Source assembly is explicit and refuses unmatched anchors. No generated Cargo.lock
is committed. Historical #31/#32/#33 evidence remains unchanged.

## Post-remediation host integration refresh

After AUD-001/002/003/005/008/009/011 merged, current main was merged into the
Stage 3G branch without rebasing. The historical Candidate B patch remains
byte-identical. The separately versioned shipping host delta now consumes the
strict shared `stage3g-host-manifest-v2.json` through dedicated `codex exec`
startup arguments and installs host-owned `ExtensionDataInit` before
`thread/start` and `build_tool_router`.

The three distinct startup states are intentional:

- ordinary Codex: no host manifest, `AllowedTools = None`, no approved policy;
- Stage 3G Arm A: `AllowedTools = Some([])`, no approved policy;
- Stage 3G Arm B: one canonical delegate in `AllowedTools` plus the exact
  reviewed `ApprovedDelegatePolicy`.

The manifest locator is not authority on its own. `QualificationManifestV2`
binds its exact bytes, along with the immutable Python runtime, ledger, Codex,
Ollama, evaluator, and other host-sensitive evidence. The launcher re-reads and
rehashes the manifest before container exposure. Client request parameters,
task content, MCP metadata, model output, and repository content cannot populate
the Rust host template.

This refresh is still pre-build evidence. It does not replace the required
actual `codex exec` A/B process observation, does not establish process proof,
and does not change `execution_ready`.
