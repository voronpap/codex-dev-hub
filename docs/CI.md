# CI platform policy

Every PR runs the full platform-neutral suite once on Linux, with Ruff, format,
strict mypy, config validation and secret/evidence checks. Branch pushes do not
repeat PR CI; main pushes and release tags remain checked.

Windows smoke selects existing tests with `windows_smoke`: real MCP stdio/process
startup, SQLite migration/reopen/backup/rollback, Git pathspec isolation, symlinks
(where available), Unicode line boundaries and provider transport secret guards.
A native HKCU test redirects only the Environment key access into a disposable
registry subkey, checks REG_SZ and sanitized missing/invalid values, and ensures
process credentials cannot substitute. Real user credentials are never read or
modified by tests. The Linux full suite includes these tests where applicable.

Full Windows remains automatic for PR paths that affect credential access,
stdio/subprocess entry points, filesystem/Brain, SQLite, provider runtimes or
runtime dependencies (see scripts/windows_scope.py). Use the `windows-full` PR
label before a run, or Actions -> Offline core -> Run workflow for reviewer requests.
Every manual dispatch runs full Linux, Windows smoke and full Windows. Release tags
also require full Windows. Stage closure requires a green full Linux and full
Windows run on the stage head; ordinary smoke is not a stage-close substitute.
The stage owner must dispatch and link that run before proposing CLOSED.

WSL full-suite duplication is not required: use WSL for targeted debugging,
integration smoke or Linux-specific local evidence.

Historical full Windows PR #19 job: 12m10s (pytest 676.98s, 228 passed), run
36469413327, job 109087583054. Its push job took 9m21s (pytest 519.29s), run
36469409002. Current local Windows smoke: 11 passed, 1 skipped in 3.76s;
this excludes hosted setup and is not a hosted CI duration. Hosted PR #20 smoke took 52s including setup (12 passed in 10.80s), run
36473605267. Its full Windows job took 9m15s (229 passed). Manual dispatch
36473604341 completed successfully, including full Windows. This change does not alter runtime semantics.

PR #21 closure restores `v*` tag triggering: this policy requires full Windows
for release tags, not arbitrary repository tags. Manual full runs remain available.

Stage 3G-B adds a Linux-only synthetic OCI boundary probe after pytest. It uses a
locally built FROM-scratch static program, no image pull, Codex, provider, or benchmark
fixture execution. This tests isolation infrastructure, not benchmark quality.

## README maintenance

Update the public README when a major stage closes, user-visible architecture or
provider support materially changes, a coding-agent integration becomes real,
benchmark results become available, setup/
start commands change, or the current milestone changes. Verify claims against
accepted code, stage records and evidence; distinguish implementation from runtime
qualification and benchmark findings. Keep PR/build/debug history in docs/evidence
and stage runbooks rather than the project front page. Documentation changes do
not authorize a live probe, benchmark or expensive Rust proof run.
