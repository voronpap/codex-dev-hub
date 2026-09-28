"""Bounded lexical Project Brain. No network, model, embeddings or MCP surface."""

import os
import re
import subprocess
import time
from collections.abc import Iterator, Mapping
from pathlib import Path, PurePosixPath
from typing import cast

from devhub.brain_models import (
    BoundExcerpt,
    BrainSnapshot,
    ProjectScope,
    RetrievalHit,
    SearchQuery,
    SearchResult,
    SourceRef,
    sha256,
)
from devhub.brain_store import BrainError, BrainStore

MAX_SOURCE_BYTES = 128 * 1024
MAX_CHUNKS = 8192
TEXT_SUFFIXES = frozenset(
    {
        ".md",
        ".txt",
        ".py",
        ".toml",
        ".json",
        ".yaml",
        ".yml",
        ".sql",
        ".rs",
        ".go",
        ".js",
        ".ts",
        ".tsx",
        ".jsx",
        ".css",
        ".html",
    }
)
PRIVATE_PARTS = frozenset(
    {
        ".git",
        ".ssh",
        ".venv",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "__pycache__",
        "secrets",
        "private",
        "credentials",
    }
)


def _git(root: Path, *arguments: str, allowed: tuple[int, ...] = (0,)) -> tuple[int, str]:
    try:
        result = subprocess.run(
            ["git", "--no-optional-locks", "-C", str(root), *arguments],
            capture_output=True,
            timeout=10,
            env={key: value for key, value in os.environ.items() if not key.startswith("GIT_")},
        )
        if result.returncode not in allowed:
            raise BrainError("repository_unavailable")
        return result.returncode, result.stdout.decode("utf-8").strip()
    except (OSError, UnicodeError, subprocess.TimeoutExpired) as error:
        raise BrainError("repository_unavailable") from error


def _relative(path: str) -> PurePosixPath:
    if (
        not isinstance(path, str)
        or not 1 <= len(path) <= 512
        or ("\\" in path or ":" in path or any(ord(char) < 32 for char in path))
    ):
        raise BrainError("invalid_source_path")
    result = PurePosixPath(path)
    if result.is_absolute() or any(part in {"", ".", ".."} for part in path.split("/")):
        raise BrainError("invalid_source_path")
    return result


def _source_lines(text: str) -> list[str]:
    # Git line anchors count LF, not Unicode paragraph separators inside a line.
    parts = text.split("\n")
    return [part + "\n" for part in parts[:-1]] + ([parts[-1]] if parts[-1] else [])


def _chunks(text: str) -> Iterator[tuple[int, int, str]]:
    lines = _source_lines(text)
    start = 1
    buffer = ""
    for number, line in enumerate(lines, start=1):
        if buffer and (number - start >= 40 or len(buffer) + len(line) > 4000):
            yield start, number - 1, buffer
            start, buffer = number, ""
        buffer += line
    if buffer:
        yield start, len(lines), buffer


class ProjectBrain:
    """Construct from trusted registered roots; every operation requires a scope."""

    def __init__(self, storage_root: Path, projects: Mapping[str, Path]) -> None:
        self._roots = {key: path.resolve(strict=True) for key, path in projects.items()}
        self._scopes = {
            key: ProjectScope(project_id=key, root_identity=sha256(os.fsencode(str(path))))
            for key, path in self._roots.items()
        }
        roots = list(self._roots.values())
        if any(not root.is_dir() for root in roots) or any(
            left.is_relative_to(right) or right.is_relative_to(left)
            for index, left in enumerate(roots)
            for right in roots[index + 1 :]
        ):
            raise BrainError("overlapping_or_invalid_roots")
        self._storage = storage_root.resolve()
        if any(self._storage.is_relative_to(root) for root in roots):
            raise BrainError("storage_must_be_outside_projects")
        self._storage.mkdir(parents=True, exist_ok=True, mode=0o700)

    def scope(self, project_id: str) -> ProjectScope:
        try:
            return self._scopes[project_id]
        except KeyError as error:
            raise BrainError("unknown_project") from error

    def _store(self, scope: ProjectScope) -> BrainStore:
        if self.scope(scope.project_id) != scope:
            raise BrainError("project_scope_mismatch")
        path = self._storage / (sha256(scope.project_id.encode()) + ".sqlite3")
        return BrainStore(path, scope)

    def _repo_state(self, root: Path) -> tuple[str, str, str]:
        top = Path(_git(root, "rev-parse", "--show-toplevel")[1]).resolve()
        if top != root:
            raise BrainError("root_must_be_git_worktree")
        revision = _git(root, "rev-parse", "--verify", "HEAD^{commit}")[1]
        branch = _git(root, "symbolic-ref", "--quiet", "HEAD", allowed=(0, 1))[1] or "DETACHED"
        common = Path(_git(root, "rev-parse", "--git-common-dir")[1])
        common = (root / common).resolve()
        return sha256(os.fsencode(str(common))), branch, revision

    def _source(self, root: Path, path: str) -> tuple[SourceRef, str | None]:
        relative = _relative(path)

        def excluded(reason: str) -> tuple[SourceRef, None]:
            return SourceRef.model_validate(
                {
                    "path": path,
                    "content_sha256": None,
                    "status": "missing" if reason == "missing" else "excluded",
                    "reason": reason,
                }
            ), None

        if relative.suffix.lower() not in TEXT_SUFFIXES or any(
            part.lower() in PRIVATE_PARTS
            or PurePosixPath(part).stem.lower() in PRIVATE_PARTS
            or part.lower().startswith(".env")
            for part in relative.parts
        ):
            return excluded("unsafe_path")
        target = root
        for part in relative.parts:
            target = target / part
            if target.is_symlink() or target.is_junction():
                return excluded("unsafe_path")
        try:
            if not target.resolve().is_relative_to(root):
                return excluded("unsafe_path")
            if not target.exists():
                return excluded("missing")
            if not target.is_file():
                return excluded("unsupported_text")
            if (
                _git(
                    root,
                    "--literal-pathspecs",
                    "ls-files",
                    "--error-unmatch",
                    "--",
                    path,
                    allowed=(0, 1),
                )[0]
                != 0
            ):
                return excluded("untracked")
            if (
                _git(root, "check-ignore", "--no-index", "--quiet", "--", path, allowed=(0, 1))[0]
                == 0
            ):
                return excluded("ignored")
            with target.open("rb") as stream:
                data = stream.read(MAX_SOURCE_BYTES + 1)
            if len(data) > MAX_SOURCE_BYTES:
                return excluded("source_too_large")
            if b"\0" in data:
                return excluded("unsupported_text")
            text = data.decode("utf-8")
            if any(len(line) > 4000 for line in _source_lines(text)):
                return excluded("overlong_line")
            return SourceRef(
                path=path,
                content_sha256=sha256(data),
                status="indexed",
                reason="approved_tracked_text",
            ), text
        except (OSError, UnicodeError):
            return excluded("unsupported_text")

    def _capture_once(
        self, scope: ProjectScope, paths: tuple[str, ...]
    ) -> tuple[BrainSnapshot, dict[str, str]]:
        root = self._roots[scope.project_id]
        repo, branch, revision = self._repo_state(root)
        sources = []
        texts = {}
        for path in paths:
            source, text = self._source(root, path)
            sources.append(source)
            if text is not None:
                texts[path] = text
        if (repo, branch, revision) != self._repo_state(root):
            raise BrainError("repository_changed_during_capture")
        return BrainSnapshot(
            scope=scope,
            repo_identity=repo,
            branch=branch,
            revision=revision,
            sources=tuple(sources),
        ), texts

    def _capture(
        self, scope: ProjectScope, paths: tuple[str, ...]
    ) -> tuple[BrainSnapshot, dict[str, str]]:
        first, _ = self._capture_once(scope, paths)
        second, texts = self._capture_once(scope, paths)
        if first != second:
            raise BrainError("repository_changed_during_capture")
        return second, texts

    def index(
        self,
        scope: ProjectScope,
        *,
        approved_paths: tuple[str, ...],
        expected_snapshot: str | None,
    ) -> BrainSnapshot:
        store = self._store(scope)
        if not isinstance(approved_paths, tuple) or len(approved_paths) > 128:
            raise BrainError("invalid_approval_manifest")
        for path in approved_paths:
            _relative(path)
        if len(set(approved_paths)) != len(approved_paths):
            raise BrainError("invalid_approval_manifest")
        snapshot, texts = self._capture(scope, tuple(sorted(approved_paths)))
        chunks = [
            (path, start, end, text, sha256(text.encode()))
            for path, content in texts.items()
            for start, end, text in _chunks(content)
        ]
        if len(chunks) > MAX_CHUNKS:
            raise BrainError("index_chunk_limit")
        with store.transaction() as connection:
            row = connection.execute("SELECT snapshot FROM brain_meta WHERE singleton=1").fetchone()
            current = BrainSnapshot.model_validate_json(row[0]) if row[0] else None
            if (current.snapshot_id if current else None) != expected_snapshot:
                raise BrainError("revision_conflict")
            connection.execute("DELETE FROM chunks")
            connection.execute("DELETE FROM source_refs")
            connection.executemany(
                "INSERT INTO source_refs VALUES (?, ?)",
                [(source.path, source.model_dump_json()) for source in snapshot.sources],
            )
            connection.executemany(
                "INSERT INTO chunks(path, start_line, end_line, text, digest) "
                "VALUES (?, ?, ?, ?, ?)",
                chunks,
            )
            connection.execute(
                "UPDATE brain_meta SET snapshot=?, state='ready', indexed_at_ms=? "
                "WHERE singleton=1",
                (snapshot.model_dump_json(), time.time_ns() // 1_000_000),
            )
        return snapshot

    def current_snapshot(self, scope: ProjectScope) -> BrainSnapshot | None:
        """Read the saved binding after restart; search/validate still check freshness."""
        with self._store(scope).transaction() as connection:
            row = connection.execute("SELECT snapshot FROM brain_meta WHERE singleton=1").fetchone()
            return BrainSnapshot.model_validate_json(row[0]) if row[0] else None

    def _fresh(
        self, scope: ProjectScope, snapshot_id: str
    ) -> tuple[BrainStore, BrainSnapshot, bool]:
        store = self._store(scope)
        with store.transaction() as connection:
            row = connection.execute("SELECT * FROM brain_meta WHERE singleton=1").fetchone()
            if row["snapshot"] is None:
                raise BrainError("index_missing")
            snapshot = BrainSnapshot.model_validate_json(row["snapshot"])
            if snapshot.snapshot_id != snapshot_id:
                raise BrainError("revision_conflict")
            if row["state"] != "ready":
                return store, snapshot, False
        try:
            observed, _ = self._capture(scope, tuple(source.path for source in snapshot.sources))
            fresh = observed == snapshot
        except BrainError:
            fresh = False
        with store.transaction() as connection:
            row = connection.execute("SELECT snapshot, state FROM brain_meta").fetchone()
            if row["snapshot"] != snapshot.model_dump_json():
                raise BrainError("revision_conflict")
            if not fresh:
                connection.execute("DELETE FROM chunks")
                connection.execute("UPDATE brain_meta SET state='stale' WHERE singleton=1")
            return store, snapshot, fresh and row["state"] == "ready"

    def search(self, scope: ProjectScope, *, snapshot_id: str, query: SearchQuery) -> SearchResult:
        store, snapshot, fresh = self._fresh(scope, snapshot_id)
        if not fresh:
            return SearchResult(snapshot_id=snapshot_id, status="stale_index")
        terms = sorted(set(re.findall(r"[^\W_]+", query.text, flags=re.UNICODE)))
        if len(terms) > 64:
            raise BrainError("query_term_limit")
        if not terms:
            return SearchResult(snapshot_id=snapshot_id, status="ready")
        # User text cannot introduce FTS operators, column selectors or wildcard syntax.
        match = " AND ".join('"' + term + '"' for term in terms)
        hashes = {source.path: source.content_sha256 for source in snapshot.sources}
        hits = []
        seen = set()
        with store.transaction() as connection:
            meta = connection.execute("SELECT * FROM brain_meta WHERE singleton=1").fetchone()
            if meta["snapshot"] != snapshot.model_dump_json() or meta["state"] != "ready":
                raise BrainError("revision_conflict")
            rows = connection.execute(
                """SELECT c.*, bm25(chunks_fts, 8.0, 1.0) AS score
                FROM chunks_fts JOIN chunks c ON c.id=chunks_fts.rowid
                WHERE chunks_fts MATCH ?
                ORDER BY (c.path=?) DESC, score, c.path, c.start_line, c.digest""",
                (match, query.text),
            ).fetchall()
            for row in rows:
                if row["path"] in seen:
                    continue
                seen.add(row["path"])
                hits.append(
                    RetrievalHit(
                        scope=scope,
                        snapshot_id=snapshot_id,
                        repo_identity=snapshot.repo_identity,
                        revision=snapshot.revision,
                        branch=snapshot.branch,
                        path=row["path"],
                        source_sha256=cast(str, hashes[row["path"]]),
                        start_line=row["start_line"],
                        end_line=row["end_line"],
                        text=row["text"],
                        chunk_sha256=row["digest"],
                        indexed_at_ms=meta["indexed_at_ms"],
                        score=row["score"],
                        reason="exact_path" if row["path"] == query.text else "fts5_bm25",
                    )
                )
                if len(hits) == query.limit:
                    break
        return SearchResult(snapshot_id=snapshot_id, status="ready", hits=tuple(hits))

    def validate_snapshot(self, scope: ProjectScope, snapshot_id: str) -> bool:
        return self._fresh(scope, snapshot_id)[2]

    def validate_hits(
        self, scope: ProjectScope, snapshot_id: str, hits: tuple[RetrievalHit, ...]
    ) -> bool:
        """Check one source snapshot, then every hit in the same DB transaction."""
        store, snapshot, fresh = self._fresh(scope, snapshot_id)
        if not fresh:
            return False
        hashes = {source.path: source.content_sha256 for source in snapshot.sources}
        with store.transaction() as connection:
            meta = connection.execute("SELECT snapshot, state FROM brain_meta").fetchone()
            if meta[0] != snapshot.model_dump_json() or meta[1] != "ready":
                return False
            for hit in hits:
                if (
                    (hit.scope, hit.snapshot_id, hit.repo_identity, hit.revision, hit.branch)
                    != (
                        scope,
                        snapshot_id,
                        snapshot.repo_identity,
                        snapshot.revision,
                        snapshot.branch,
                    )
                    or hashes.get(hit.path) != hit.source_sha256
                    or sha256(hit.text.encode()) != hit.chunk_sha256
                ):
                    return False
                if (
                    connection.execute(
                        "SELECT 1 FROM chunks WHERE path=? AND start_line=? AND end_line=? "
                        "AND text=? AND digest=?",
                        (hit.path, hit.start_line, hit.end_line, hit.text, hit.chunk_sha256),
                    ).fetchone()
                    is None
                ):
                    return False
        return True

    def validate_excerpts(
        self, scope: ProjectScope, snapshot_id: str, excerpts: tuple[BoundExcerpt, ...]
    ) -> bool:
        """Validate compacted text against original chunks, never trust supplied provenance."""
        store, snapshot, fresh = self._fresh(scope, snapshot_id)
        if not fresh:
            return False
        hashes = {source.path: source.content_sha256 for source in snapshot.sources}
        with store.transaction() as connection:
            meta = connection.execute("SELECT snapshot, state FROM brain_meta").fetchone()
            if meta[0] != snapshot.model_dump_json() or meta[1] != "ready":
                return False
            for excerpt in excerpts:
                if not excerpt.start_line <= excerpt.end_line <= excerpt.original_end_line or (
                    hashes.get(excerpt.path) != excerpt.source_sha256
                ):
                    return False
                row = connection.execute(
                    "SELECT text FROM chunks WHERE path=? AND start_line=? "
                    "AND end_line=? AND digest=?",
                    (
                        excerpt.path,
                        excerpt.start_line,
                        excerpt.original_end_line,
                        excerpt.chunk_sha256,
                    ),
                ).fetchone()
                if (
                    row is None
                    or "".join(_source_lines(row[0])[: excerpt.end_line - excerpt.start_line + 1])
                    != excerpt.text
                ):
                    return False
        return True

    def validate_hit(self, scope: ProjectScope, hit: RetrievalHit) -> bool:
        """Future Context Builder must revalidate again at use/dispatch time."""
        if hit.scope != scope:
            raise BrainError("project_scope_mismatch")
        store, snapshot, fresh = self._fresh(scope, hit.snapshot_id)
        if (
            not fresh
            or (hit.repo_identity, hit.revision, hit.branch)
            != (snapshot.repo_identity, snapshot.revision, snapshot.branch)
            or not any(
                source.path == hit.path and source.content_sha256 == hit.source_sha256
                for source in snapshot.sources
            )
        ):
            return False
        if sha256(hit.text.encode()) != hit.chunk_sha256:
            return False
        with store.transaction() as connection:
            meta = connection.execute("SELECT snapshot, state FROM brain_meta").fetchone()
            if meta["snapshot"] != snapshot.model_dump_json() or meta["state"] != "ready":
                return False
            return (
                connection.execute(
                    """SELECT 1 FROM chunks WHERE path=? AND start_line=? AND end_line=?
                AND text=? AND digest=?""",
                    (hit.path, hit.start_line, hit.end_line, hit.text, hit.chunk_sha256),
                ).fetchone()
                is not None
            )
