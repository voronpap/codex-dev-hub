# Build-003: proof constructor correction only

Replace exactly five ExtensionData::default() calls with the pinned supported
ExtensionData::new("devhub-proof"). Production patch bytes remain identical to
build-002 (d2e27068ca8020f014c7cd3bea2cc73181b1b892d8e6869814680d2076eb3e36).
No upstream Default implementation, unsafe constructor or production change.

The source preflight independently hashes pinned extension-api/src/state.rs,
checks new(level_id) delegates to empty ExtensionDataInit::default(), rejects the
unsupported harness constructor, and records the new test hash. A normal offline
regression test also prevents reintroduction. These checks are API compatibility
checks, not runtime proof. All original source anchors/patch bytes, schema and
synthetic payload pass the same preflight. Pinned Rust 1.95.0 rustfmt passes for
all eight patched files and the harness.

The source lifecycle/lock audit in STAGE3G-ADMISSION-BUILD002.md applies unchanged:
production files are byte-identical, including synchronous reconnect, serialized
publication/shutdown, same-snapshot shutdown and generation/catalog read leases.
Apps publication remains observed and excluded by exact configured server binding.
No new lock acquisition was introduced. No new source-level inversion identified;
actual races remain unproven until a compiled test runs.

Historical build-001, redundant-build-001, build-002 and their assessments remain
unchanged. Build-003 is manually dispatched once only after Linux full and Windows
smoke plus normal lint/type/evidence checks pass. No build-004. Compile or test
failure is preserved, followed by STOP for review. Even a passing subset leaves
unexercised matrix/process fields null and production classification UNKNOWN.

Stage 3G-C/3G OPEN; execution_ready=false; real_codex_executions=0;
provider_sends=0. No v3, benchmark, rehearsal or model/provider request.
