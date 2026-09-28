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
this excludes hosted setup and is not a hosted CI duration. Hosted smoke timing
will be recorded after its first run. This change does not alter runtime semantics.
