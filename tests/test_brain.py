import shutil
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest

from devhub.brain import ProjectBrain
from devhub.brain_models import SearchQuery, sha256
from devhub.brain_store import BrainError


def git(root, *args):
    return (
        subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)
        .stdout.decode()
        .strip()
    )


def repo(path, files=None):
    path.mkdir()
    git(path, "init", "-q", "--initial-branch=main")
    for relative, text in (
        files or {"guide.md": "Atomic reservation protects shared quota.\n"}
    ).items():
        target = path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8", newline="\n")
    git(path, "add", ".")
    git(
        path,
        "-c",
        "user.name=BrainFixture",
        "-c",
        "user.email=fixture@example.invalid",
        "commit",
        "-qm",
        "fixture",
    )
    return path


@pytest.fixture
def brain(tmp_path):
    root = repo(tmp_path / "repo")
    service = ProjectBrain(tmp_path / "state", {"p": root})
    scope = service.scope("p")
    snapshot = service.index(scope, approved_paths=("guide.md",), expected_snapshot=None)
    return service, scope, snapshot, root


def search(service, scope, snapshot, text="quota"):
    return service.search(scope, snapshot_id=snapshot.snapshot_id, query=SearchQuery(text=text))


def test_provenance_roundtrip_and_revalidation(brain, tmp_path):
    service, scope, snapshot, root = brain
    hit = search(service, scope, snapshot).hits[0]
    assert hit.path == "guide.md"
    assert (hit.start_line, hit.end_line) == (1, 1)
    assert hit.source_sha256 == sha256((root / hit.path).read_bytes())
    assert hit.chunk_sha256 == sha256(hit.text.encode())
    assert hit.revision == git(root, "rev-parse", "HEAD")
    assert hit.trust == "repository_untrusted"
    assert hit.sensitivity == "project_private"
    assert service.validate_hit(scope, hit)
    reopened = ProjectBrain(tmp_path / "state", {"p": root})
    assert reopened.current_snapshot(scope) == snapshot
    assert search(reopened, scope, snapshot).hits == (hit,)
    forged = hit.model_copy(
        update={"text": "invented quota", "chunk_sha256": sha256(b"invented quota")}
    )
    assert not service.validate_hit(scope, forged)


@pytest.mark.parametrize("mutation", ["edit", "delete", "branch", "commit", "ignore"])
def test_mutation_invalidates_fts_and_cannot_resurrect_old_snapshot(brain, mutation):
    service, scope, snapshot, root = brain
    old_hit = search(service, scope, snapshot).hits[0]
    original = (root / "guide.md").read_bytes()
    if mutation == "edit":
        (root / "guide.md").write_text("Changed content.\n", encoding="utf-8")
    elif mutation == "delete":
        (root / "guide.md").unlink()
    elif mutation == "branch":
        git(root, "switch", "-qc", "another")
    elif mutation == "commit":
        git(
            root,
            "-c",
            "user.name=BrainFixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--allow-empty",
            "-qm",
            "new revision",
        )
    else:
        (root / ".gitignore").write_text("guide.md\n", encoding="utf-8")
    result = search(service, scope, snapshot)
    assert result.status == "stale_index" and result.hits == ()
    assert not service.validate_hit(scope, old_hit)
    with service._store(scope).transaction() as connection:
        assert connection.execute("SELECT COUNT(*) FROM chunks").fetchone()[0] == 0
        assert (
            connection.execute(
                "SELECT COUNT(*) FROM chunks_fts WHERE chunks_fts MATCH 'quota'"
            ).fetchone()[0]
            == 0
        )
    if mutation == "edit":
        (root / "guide.md").write_bytes(original)
        assert search(service, scope, snapshot).status == "stale_index"


def test_reindex_replaces_terms_and_records_deleted_source(brain):
    service, scope, snapshot, root = brain
    (root / "guide.md").write_text("Ollama local inference.\n", encoding="utf-8")
    updated = service.index(
        scope, approved_paths=("guide.md",), expected_snapshot=snapshot.snapshot_id
    )
    assert updated.snapshot_id != snapshot.snapshot_id
    with pytest.raises(BrainError, match="revision_conflict"):
        search(service, scope, snapshot)
    assert search(service, scope, updated).hits == ()
    assert search(service, scope, updated, "Ollama").hits[0].source_sha256 == sha256(
        (root / "guide.md").read_bytes()
    )
    (root / "guide.md").unlink()
    deleted = service.index(
        scope, approved_paths=("guide.md",), expected_snapshot=updated.snapshot_id
    )
    assert deleted.sources[0].status == "missing"
    assert deleted.sources[0].content_sha256 is None
    assert search(service, scope, deleted, "Ollama").hits == ()


def test_manifest_removal_rebuild_and_empty_query(brain):
    service, scope, snapshot, _ = brain
    assert search(service, scope, snapshot, '" OR * - : ()').hits == ()
    empty = service.index(scope, approved_paths=(), expected_snapshot=snapshot.snapshot_id)
    assert empty.snapshot_id != snapshot.snapshot_id
    assert search(service, scope, empty).hits == ()
    rebuilt = service.index(
        scope, approved_paths=("guide.md",), expected_snapshot=empty.snapshot_id
    )
    assert search(service, scope, rebuilt).hits


def test_project_isolation_root_binding_and_copied_database(tmp_path):
    left = repo(tmp_path / "left", {"guide.md": "Left confidential apples.\n"})
    right = repo(tmp_path / "right", {"guide.md": "Right confidential oranges.\n"})
    service = ProjectBrain(tmp_path / "state", {"left": left, "right": right})
    a, b = service.scope("left"), service.scope("right")
    sa = service.index(a, approved_paths=("guide.md",), expected_snapshot=None)
    sb = service.index(b, approved_paths=("guide.md",), expected_snapshot=None)
    assert search(service, a, sa, "oranges").hits == ()
    assert search(service, b, sb, "apples").hits == ()
    with pytest.raises(BrainError, match="revision_conflict"):
        search(service, b, sa)
    with pytest.raises(BrainError, match="project_scope_mismatch"):
        service.validate_hit(b, search(service, a, sa, "apples").hits[0])
    rebound = ProjectBrain(tmp_path / "state", {"left": right})
    with pytest.raises(BrainError, match="project_scope_mismatch"):
        search(rebound, rebound.scope("left"), sa)
    shutil.copyfile(service._store(a).path, service._store(b).path)
    with pytest.raises(BrainError, match="project_scope_mismatch"):
        search(service, b, sb)


def test_failed_index_transaction_retains_previous_snapshot(brain):
    service, scope, snapshot, root = brain
    original = (root / "guide.md").read_bytes()
    with service._store(scope).transaction() as connection:
        connection.execute("""CREATE TRIGGER fail_index BEFORE INSERT ON chunks
                            BEGIN SELECT RAISE(ABORT, 'test fault'); END""")
    (root / "guide.md").write_text("replacement text", encoding="utf-8")
    with pytest.raises(BrainError, match="brain_storage_failure"):
        service.index(scope, approved_paths=("guide.md",), expected_snapshot=snapshot.snapshot_id)
    (root / "guide.md").write_bytes(original)
    assert search(service, scope, snapshot).hits
    with service._store(scope).transaction() as connection:
        connection.execute("INSERT INTO chunks_fts(chunks_fts) VALUES ('integrity-check')")
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"


def test_concurrent_indexers_use_optimistic_revision(brain, monkeypatch):
    service, scope, snapshot, root = brain
    (root / "guide.md").write_text("new quota documentation", encoding="utf-8")
    barrier = Barrier(2)
    capture = service._capture

    def simultaneous(*args):
        result = capture(*args)
        barrier.wait(timeout=20)
        return result

    monkeypatch.setattr(service, "_capture", simultaneous)

    def index():
        try:
            service.index(
                scope, approved_paths=("guide.md",), expected_snapshot=snapshot.snapshot_id
            )
            return "indexed"
        except BrainError as error:
            return str(error)

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(lambda _: index(), range(2))) == ["indexed", "revision_conflict"]


@pytest.mark.parametrize(
    "path", ["../escape.md", "/abs.md", "C:/escape.md", "a\\b.md", "a/../b.md"]
)
def test_unsafe_relative_paths_rejected_before_ingestion(brain, path):
    service, scope, snapshot, _ = brain
    with pytest.raises(BrainError, match="invalid_source_path"):
        service.index(scope, approved_paths=(path,), expected_snapshot=snapshot.snapshot_id)


def test_unapproved_ignored_private_binary_and_oversized_sources(tmp_path):
    root = repo(
        tmp_path / "repo",
        {
            "guide.md": "public quota",
            "private/key.txt": "NEVER_INDEX",
            "binary.txt": "\0NEVER_INDEX",
            "large.txt": "x" * (128 * 1024 + 1),
            "long.txt": "y" * 4001,
            "ignored.md": "NEVER_INDEX",
            "unapproved.md": "NEVER_INDEX",
        },
    )
    (root / ".gitignore").write_text("ignored.md\n", encoding="utf-8")
    (root / "untracked.md").write_text("NEVER_INDEX", encoding="utf-8")
    service = ProjectBrain(tmp_path / "state", {"p": root})
    scope = service.scope("p")
    paths = (
        "guide.md",
        "private/key.txt",
        "binary.txt",
        "large.txt",
        "long.txt",
        "ignored.md",
        "untracked.md",
    )
    snapshot = service.index(scope, approved_paths=paths, expected_snapshot=None)
    assert {s.path for s in snapshot.sources if s.status == "indexed"} == {"guide.md"}
    assert search(service, scope, snapshot, "NEVER_INDEX").hits == ()


def test_symlink_does_not_read_another_project(tmp_path):
    root = repo(tmp_path / "repo")
    outside = tmp_path / "secret.md"
    outside.write_text("NEVER_INDEX", encoding="utf-8")
    try:
        (root / "alias.md").symlink_to(outside)
    except OSError:
        pytest.skip("host does not grant symlink creation")
    git(root, "add", "alias.md")
    service = ProjectBrain(tmp_path / "state", {"p": root})
    scope = service.scope("p")
    snapshot = service.index(scope, approved_paths=("alias.md",), expected_snapshot=None)
    assert snapshot.sources[0].reason == "unsafe_path"
    assert search(service, scope, snapshot, "NEVER_INDEX").hits == ()


def test_newer_schema_and_storage_inside_project_refused(brain, tmp_path):
    service, scope, snapshot, root = brain
    with pytest.raises(BrainError, match="storage_must_be_outside"):
        ProjectBrain(root / ".brain", {"p": root})
    with sqlite3.connect(service._store(scope).path) as connection:
        connection.execute("PRAGMA user_version=999")
    with pytest.raises(BrainError, match="unsupported_brain_schema"):
        search(service, scope, snapshot)


def test_changed_source_during_capture_does_not_publish_mixed_snapshot(brain, monkeypatch):
    service, scope, snapshot, root = brain
    capture = service._capture_once
    calls = 0

    def mutate(*args):
        nonlocal calls
        result = capture(*args)
        calls += 1
        if calls == 1:
            (root / "guide.md").write_text("changed during capture", encoding="utf-8")
        return result

    monkeypatch.setattr(service, "_capture_once", mutate)
    with pytest.raises(BrainError, match="repository_changed_during_capture"):
        service.index(scope, approved_paths=("guide.md",), expected_snapshot=snapshot.snapshot_id)
    with service._store(scope).transaction() as connection:
        assert (
            connection.execute("SELECT snapshot FROM brain_meta").fetchone()[0]
            == snapshot.model_dump_json()
        )


def test_line_ranges_and_chunk_bounds_reconstruct_exact_source(tmp_path):
    content = "".join(f"line{index} needle data\r\n" for index in range(1, 92))
    root = repo(tmp_path / "repo")
    (root / "long.md").write_bytes(content.encode())
    git(root, "add", "long.md")
    service = ProjectBrain(tmp_path / "state", {"p": root})
    scope = service.scope("p")
    snapshot = service.index(scope, approved_paths=("long.md",), expected_snapshot=None)
    lines = content.splitlines(keepends=True)
    with service._store(scope).transaction() as connection:
        chunks = connection.execute("SELECT * FROM chunks ORDER BY start_line").fetchall()
        assert "".join(chunk["text"] for chunk in chunks) == content
        assert len(chunks) == 3
        for chunk in chunks:
            assert len(chunk["text"]) <= 4000
            assert chunk["text"] == "".join(lines[chunk["start_line"] - 1 : chunk["end_line"]])
    hits = search(service, scope, snapshot, "needle").hits
    assert len(hits) == 1  # one best chunk per source, not three duplicate source hits
    assert service.validate_hit(scope, hits[0])


def test_missing_fts5_fails_atomically(tmp_path, monkeypatch):
    import devhub.brain_store as storage

    root = repo(tmp_path / "repo")
    service = ProjectBrain(tmp_path / "state", {"p": root})
    scope = service.scope("p")
    monkeypatch.setattr(
        storage,
        "SCHEMA",
        tuple(
            statement.replace("USING fts5(", "USING nonexistent_fts(")
            for statement in storage.SCHEMA
        ),
    )
    with pytest.raises(BrainError, match="brain_storage_failure"):
        service.index(scope, approved_paths=("guide.md",), expected_snapshot=None)
    path = tmp_path / "state" / (sha256(b"p") + ".sqlite3")
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert connection.execute("SELECT name FROM sqlite_master").fetchall() == []


def test_untracked_filename_cannot_match_git_pathspec_pattern(tmp_path):
    root = repo(tmp_path / "repo", {"doc1.md": "tracked"})
    (root / "doc[1].md").write_text("NEVER_INDEX", encoding="utf-8")
    service = ProjectBrain(tmp_path / "state", {"p": root})
    scope = service.scope("p")
    snapshot = service.index(scope, approved_paths=("doc[1].md",), expected_snapshot=None)
    assert snapshot.sources[0].reason == "untracked"


def test_worktrees_share_repo_identity_but_not_snapshot_or_results(tmp_path):
    root = repo(tmp_path / "main")
    worktree = tmp_path / "worktree"
    git(root, "worktree", "add", "--detach", str(worktree))
    (worktree / "guide.md").write_text("Different worktree contents", encoding="utf-8")
    service = ProjectBrain(tmp_path / "state", {"main": root, "worktree": worktree})
    left, right = service.scope("main"), service.scope("worktree")
    a = service.index(left, approved_paths=("guide.md",), expected_snapshot=None)
    b = service.index(right, approved_paths=("guide.md",), expected_snapshot=None)
    assert a.repo_identity == b.repo_identity
    assert a.scope.root_identity != b.scope.root_identity
    assert a.snapshot_id != b.snapshot_id
    assert search(service, left, a).hits
    assert search(service, right, b).hits == ()


def test_unicode_paragraph_separator_does_not_change_git_line_numbers(tmp_path):
    root = repo(tmp_path / "repo", {"guide.md": "first\u2028paragraph\nsecond needle\n"})
    service = ProjectBrain(tmp_path / "state", {"p": root})
    scope = service.scope("p")
    snapshot = service.index(scope, approved_paths=("guide.md",), expected_snapshot=None)
    hit = search(service, scope, snapshot, "needle").hits[0]
    assert (hit.start_line, hit.end_line) == (1, 2)
    assert hit.text == "first\u2028paragraph\nsecond needle\n"
