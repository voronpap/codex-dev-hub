"""Local durable accounting. One short write transaction per state transition."""

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

MIGRATIONS: tuple[tuple[str, ...], ...] = (
    (
        """CREATE TABLE buckets (
            id TEXT PRIMARY KEY, spec TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0 CHECK(used >= 0),
            held INTEGER NOT NULL DEFAULT 0 CHECK(held >= 0)
        )""",
        "CREATE TABLE policies (id TEXT PRIMARY KEY, spec TEXT NOT NULL)",
        """CREATE TABLE reservations (
            id TEXT PRIMARY KEY, project TEXT NOT NULL, task TEXT NOT NULL,
            request_key TEXT NOT NULL, fingerprint TEXT NOT NULL,
            resource TEXT NOT NULL REFERENCES policies(id), policy TEXT NOT NULL,
            state TEXT NOT NULL CHECK(state IN
                ('reserved','dispatched','unknown_usage','settled','released')),
            created_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL,
            UNIQUE(project, request_key)
        )""",
        """CREATE TABLE allocations (
            reservation TEXT NOT NULL REFERENCES reservations(id),
            bucket TEXT NOT NULL REFERENCES buckets(id),
            amount INTEGER NOT NULL CHECK(amount >= 0),
            actual INTEGER CHECK(actual >= 0),
            PRIMARY KEY(reservation, bucket)
        )""",
        "CREATE INDEX reservation_expiry ON reservations(state, expires_ms)",
    ),
)


class LedgerError(RuntimeError):
    pass


class Ledger:
    """Requires a local filesystem. Connections are never shared across threads."""

    def __init__(self, path: Path) -> None:
        self.path = path.resolve()
        if not self.path.parent.is_dir():
            raise LedgerError("ledger directory must already exist")
        with self.transaction() as connection:
            version = connection.execute("PRAGMA user_version").fetchone()[0]
            if version > len(MIGRATIONS):
                raise LedgerError("database schema is newer than this runtime")
            for index in range(version, len(MIGRATIONS)):
                for statement in MIGRATIONS[index]:
                    connection.execute(statement)
                connection.execute(f"PRAGMA user_version = {index + 1}")

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = FULL")
            # Do not silently convert an existing WAL database used by another process.
            if connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                raise LedgerError("ledger requires rollback journal mode DELETE")
            return connection
        except BaseException:
            connection.close()
            raise

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def backup(self, destination: Path) -> None:
        """SQLite online snapshot; refuse overwrites, including the live database."""
        with destination.open("xb"):
            pass
        source = self.connect()
        target = sqlite3.connect(destination)
        try:
            source.backup(target)
        finally:
            target.close()
            source.close()
