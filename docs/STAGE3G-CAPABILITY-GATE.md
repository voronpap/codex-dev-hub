# Stage 3G-C capability qualification revision

PR #25 merged as v2 protocol + blocked feature-bit evidence (98124c5).
Stage 3G-C and Stage 3G remain OPEN. execution_ready=false. No benchmark,
rehearsal, provider sends, task execution, or system configuration repair.
Historical v1/v2 receipts are immutable; this revision does not replace them.

## Qualification policy v1

Old gate required unified_exec=false. New gate requires source-derived absence
of forbidden execution tools, effective shell_tool=false, unchanged other
feature controls, and exact A/B MCP scope. Requested unified_exec=false and
observed unified_exec=true remain diagnostics. The gate module bytes define a
separate qualification SHA-256 (LF pinned); preflight rejects receipts without
that current hash. Protocol/config/task semantics and their hashes are unchanged.

The pinned release tag resolves to 4607249e430dac1c961df4dc615beae88e33cec8.
Exact source file hashes and metadata-only binary observations are in
`evidence/stage3g-capability/source-investigation.json`. This diagnostic container
is not the accepted runtime image or an intended-host qualification receipt.
Upstream tests were inspected, not run. No metadata-only actual complete tool
registration listing has been established; observations are source_derived.

- [Managed normalization, lines 153-167](https://github.com/openai/codex/blob/4607249e430dac1c961df4dc615beae88e33cec8/codex-rs/core/src/config/managed_features.rs#L153-L167)
  forces UnifiedExec true absent managed requirements.
- [Shell registration, lines 1031-1069](https://github.com/openai/codex/blob/4607249e430dac1c961df4dc615beae88e33cec8/codex-rs/core/src/tools/spec_plan.rs#L1031-L1069)
  returns before exec_command/write_stdin registration when ShellTool is false.
  A false UnifiedExec alone still permits a one-shot execution handler.
- [Patch registration, lines 1213-1216](https://github.com/openai/codex/blob/4607249e430dac1c961df4dc615beae88e33cec8/codex-rs/core/src/tools/spec_plan.rs#L1213-L1216)
  is independent of ShellTool and depends on model metadata and environment.

## New blocker: patch surface not proven absent

The frozen service-default model is unknown. Therefore apply_patch absence is
null, not true. shell/unified-exec shell surface maps to exec_command/write_stdin
in the pinned implementation. No speculative write_file alias is asserted;
its extension/canonical mapping remains unverified. The conjunctive capability
gate fails closed. Read-only sandbox and natural-language instructions do not
prove tools are unregistered. CI must remain red if this cannot be proven;
there is no continue-on-error or ignored forbidden tool.

Apps, multi-agent and remote-plugin feature checks remain required; web_search
remains disabled in unchanged frozen config. This partial proof does not claim
all browser/extension surfaces have been exhaustively enumerated.

Changing model, disabling patch via a new configuration override, or removing
patch from the forbidden set is not part of this revision. Review is required
before choosing any such direction. No model call for discovery is permitted.

## Intended environment: diagnosis proposal only

Docker Desktop Linux engine is available from Windows. Ubuntu-24.04 currently
has no /var/run/docker.sock; prior WSL loopback Ollama probe failed. This PR does
not mutate Docker/WSL settings, networking, endpoint, model or ledger.
Read-only diagnosis sequence: inspect Docker WSL backend/default integration and
Ubuntu integration settings, distro state, socket, and DOCKER_HOST; inspect WSL
network mode and Windows Ollama listener binding. Do not infer that Windows
loopback works in WSL. Propose any setting changes separately for operator review.

Only a single intended Linux environment passing all gates can become ready.
CI image results cannot be combined with Windows ledger/Ollama observations.

## Validation

Offline tests cover forced-true diagnostics, absent shell guards, unknown patch,
wrong CLI identity and null states. Normal Linux full/Windows smoke and
exact-image metadata/isolation/synthetic evaluator run in CI, never benchmark.
