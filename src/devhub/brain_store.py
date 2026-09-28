"""Per-project SQLite/FTS5 storage; not the global resource ledger."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from devhub.brain_models import ProjectScope

APPLICATION_ID = 0x44484252
SCHEMA = (
    """CREATE TABLE brain_meta (
        singleton INTEGER PRIMARY KEY CHECK(singleton=1), scope TEXT NOT NULL,
        snapshot TEXT, state TEXT NOT NULL CHECK(state IN ('empty','ready','stale')),
        indexed_at_ms INTEGER NOT NULL DEFAULT 0)""",
    "CREATE TABLE source_refs (path TEXT PRIMARY KEY, spec TEXT NOT NULL)",
    """CREATE TABLE chunks (
        id INTEGER PRIMARY KEY, path TEXT NOT NULL REFERENCES source_refs(path),
        start_line INTEGER NOT NULL, end_line INTEGER NOT NULL,
        text TEXT NOT NULL, digest TEXT NOT NULL)""",
    """CREATE VIRTUAL TABLE chunks_fts USING fts5(
        path, text, content='chunks', content_rowid='id',
        tokenize='unicode61 remove_diacritics 2')""",
    """CREATE TRIGGER chunks_insert AFTER INSERT ON chunks BEGIN
        INSERT INTO chunks_fts(rowid, path, text) VALUES (new.id, new.path, new.text); END""",
    """CREATE TRIGGER chunks_delete AFTER DELETE ON chunks BEGIN
        INSERT INTO chunks_fts(chunks_fts, rowid, path, text)
        VALUES ('delete', old.id, old.path, old.text); END""",
)


class BrainError(RuntimeError):
    """Safe reason code without source contents or host paths."""


class BrainStore:
    """Private implementation: only ProjectBrain chooses the database filename."""

    def __init__(self, path: Path, scope: ProjectScope) -> None:
        self.path = path
        self.scope = scope
        if not path.exists():
            try:
                descriptor = path.open("xb")
            except FileExistsError:
                pass
            else:
                descriptor.close()
                path.chmod(0o600)
        with self.transaction() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            app_id = connection.execute("PRAGMA application_id").fetchone()[0]
            if version == 0 and app_id == 0:
                if connection.execute("SELECT name FROM sqlite_master").fetchone() is not None:
                    raise BrainError("foreign_database")
                for statement in SCHEMA:
                    connection.execute(statement)
                connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
                connection.execute("PRAGMA user_version=1")
                connection.execute(
                    "INSERT INTO brain_meta(singleton, scope, state) VALUES (1, ?, 'empty')",
                    (scope.model_dump_json(),),
                )
            elif version != 1 or app_id != APPLICATION_ID:
                raise BrainError("unsupported_brain_schema")
            row = connection.execute("SELECT scope FROM brain_meta WHERE singleton=1").fetchone()
            if row is None or row[0] != scope.model_dump_json():
                raise BrainError("project_scope_mismatch")

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        if self.path.is_symlink():
            raise BrainError("unsafe_storage_path")
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA secure_delete=ON")
            if connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                raise BrainError("brain_requires_delete_journal")
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except sqlite3.Error as error:
            connection.rollback()
            raise BrainError("brain_storage_failure") from error
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
