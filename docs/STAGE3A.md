# Stage 3A: Project Brain + FTS5

Status: implemented for review, after Stage 2 CLOSED. This slice provides internal
Python APIs for approved repository-source indexing and lexical retrieval. MCP
still exposes only status. Context packages/token allocation, durable decision
authoring, summaries, provider adapters and delegation belong to later slices.
No embeddings, Qdrant, Graphiti, downloads or network calls are introduced.

## Scope and bindings

`ProjectBrain(storage_root, projects)` receives trusted registered Git worktree
roots. The storage directory must be outside all project roots, which must not
overlap. Every operation takes a `ProjectScope`; the caller cannot pass a DB path
to indexing or retrieval. DB filenames are derived from project IDs. Each DB also
stores its project/root binding and rejects reuse or copying under another scope.
This is a single-operator service boundary, not multi-user authentication.

Only explicitly approved paths are considered, with a maximum of 128 per snapshot.
Paths must be relative and literal; tracked status does not accept Git wildcards.
Ignored/untracked files, symlinks/junctions, private/generated/vendor paths,
unsupported extensions, binary/non-UTF-8 text, files over 128 KiB and lines over
4,000 characters are excluded with a reason. No repository-wide crawl occurs.
Approval must include a content/privacy review: path exclusions are not a general
secret detector. Even an ADR excerpt remains `repository_untrusted` data, never a
new instruction or an implicitly accepted decision.

Snapshots bind project ID, canonical root/worktree identity, Git common-directory
identity, branch (or detached state), commit, complete approval/source-hash manifest
and index version. Dirty working files are read as bytes and SHA-256 hashed; this
does not claim their contents equal the committed Git blob. Missing/excluded paths
remain provenance metadata with no invented content hash.

Each hit contains scope, snapshot ID, repository identity, revision/branch,
relative source path, full-source SHA-256, inclusive line range, exact excerpt,
excerpt SHA-256, indexing timestamp, trust/sensitivity and retrieval reason.
Line anchors count LF as Git does, preserving CRLF bytes and Unicode separators
inside lines. Chunks are bounded to 40 lines/4,000 characters;
the full index is limited to 8,192 chunks. No token count is claimed here.

## Invalidation and atomicity

Indexing captures Git state and source hashes twice and refuses changes observed
during capture. It replaces source refs/chunks/FTS in one transaction, conditional
on `expected_snapshot`. Competing writers with the same old revision cannot both
publish. A trigger failure rolls back the entire replacement, including FTS rows.

Before search or `validate_hit`, the saved snapshot is compared to current Git
state, tracked/ignored status and source hashes. Any discrepancy invalidates the
whole snapshot, removes its searchable excerpts and returns `stale_index` with no
hits. Restoring a file's old bytes does not resurrect an invalidated index; an
explicit reindex is required. Removing a path from approval removes its indexed
content on the next successful replacement. An empty approval manifest clears
all source content. Metadata may retain hashes of invalidated sources.

Validation is point-in-time, not an OS filesystem snapshot or lock against a
hostile local process. Stage 3B must preserve the binding and validate again at
use/dispatch. Reads fail closed on repository errors; no stale-result fallback.
There is no watcher, background polling, TTL-only freshness claim or provider
dispatch in this slice.

## Storage and retrieval

The Brain DB has its own application ID/schema version and is separate from the
resource ledger. FTS5 availability is checked by actual transactional schema
creation; missing FTS5, foreign schemas and future versions fail closed. Like the
Stage 2 ledger, it uses DELETE journal, FULL synchronous writes and local storage
pending a verified safe WAL runtime. Files request POSIX mode 0600; on Windows the
private storage directory relies on the operator's inherited ACLs.

[SQLite FTS5](https://www.sqlite.org/fts5.html) uses an external-content index with
transactional insert/delete triggers. Query words are literal AND terms, not raw
FTS syntax. Ranking prioritizes an exact path, then path-weighted BM25, with stable
path/range/hash tie-breakers. Results contain one best chunk per source, up to 20
sources. Unicode text is supported. Semantic paraphrase handling is not provided.
FTS data is rebuildable from approved sources; deletion here is logical removal,
not a forensic-erasure or backup-deletion promise.

## Internal API example

```python
from pathlib import Path
from devhub.brain import ProjectBrain
from devhub.brain_models import SearchQuery

root = Path("path/to/project").resolve()  # existing Git worktree with a commit
brain = ProjectBrain(root.parent / "private-brain", {"demo": root})
scope = brain.scope("demo")
previous = brain.current_snapshot(scope)  # metadata only, not a freshness guarantee
snapshot = brain.index(
    scope,
    approved_paths=("README.md",),
    expected_snapshot=previous.snapshot_id if previous else None,
)
result = brain.search(scope, snapshot_id=snapshot.snapshot_id,
                      query=SearchQuery(text="README.md", limit=3))
for hit in result.hits:
    assert brain.validate_hit(scope, hit)  # repeat at actual use in Stage 3B
```

## Retrieval evidence

The [labeled seed](../benchmarks/retrieval/stage3a.json) contains 12 synthetic source
documents, 12 positive queries and two negative queries. Labels and acceptance
floors were specified before the first run. The fixture SHA-256 and per-query
results are in the [reproducible report](evidence/stage3a-retrieval.json).

- Top-1 accuracy: 10/12, **83.3%**.
- Recall@3: **83.3%**; MRR@3: **0.8333**.
- Negative-query hits: **0**.
- Exact path, identifier, competing documents and Ukrainian query cases pass.
- Both natural-language paraphrase cases miss. They remain in the fixture and
  report; improving query formation needs separate evidence, not hidden labels.

This is a small lexical regression seed, not a broad retrieval benchmark, a
Stage 3G B-arm run or evidence of Codex token savings. Usage/savings remain null.

Reproduce from the repository root:

```sh
uv run --locked --offline python scripts/evaluate_brain.py
uv run --locked --offline pytest -q
```

Tests also cover stale/deleted sources, branch/commit/worktree binding, copied-DB
and scope rejection, hash/excerpt tampering, concurrent indexers, failed writes,
line bounds, Git pathspecs, excluded sources and missing FTS5. The symlink test is
skipped on Windows hosts without symlink creation privileges and runs on Linux.

Local verification on 2026-09-28: Windows Python 3.12.10 ran **80 passed, 1 skipped**
(symlink privilege); WSL Ubuntu 24.04 Python 3.12.3 ran **81 passed**. Ruff lint and
format checks and strict mypy pass. The quality test reproduces the checked-in
report including its fixture hash. No dependency changes were needed. Remote
Linux/Windows CI results are recorded on the PR.

Stage 3B Context Builder follows review of this slice. The gate remains Brain →
Context → Ollama → local end-to-end smoke before Groq/Gemini; Stage 3A does not
claim that this integration path already exists.
