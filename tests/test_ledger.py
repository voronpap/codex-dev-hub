import sqlite3

import pytest

from devhub import ledger
from devhub.ledger import Ledger, LedgerError


@pytest.mark.windows_smoke
def test_migrate_reopen_backup_and_rollback(tmp_path):
    path = tmp_path / "ledger.db"
    database = Ledger(path)
    with database.transaction() as connection:
        connection.execute("INSERT INTO buckets(id, spec) VALUES ('pool', '{}')")
    with pytest.raises(RuntimeError), database.transaction() as connection:
        connection.execute("UPDATE buckets SET held = 1")
        raise RuntimeError("crash before commit")
    backup = tmp_path / "backup.db"
    database.backup(backup)
    for candidate in (path, backup):
        with Ledger(candidate).transaction() as connection:
            assert connection.execute("SELECT held FROM buckets").fetchone()[0] == 0
            assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    with pytest.raises(FileExistsError):
        database.backup(backup)


def test_future_schema_and_existing_wal_refused(tmp_path):
    path = tmp_path / "future.db"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version = 999")
    with pytest.raises(LedgerError, match="newer"):
        Ledger(path)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA journal_mode = WAL")
    with pytest.raises(LedgerError, match="DELETE"):
        Ledger(path)


def test_failed_migration_is_atomic(tmp_path, monkeypatch):
    path = tmp_path / "atomic.db"
    monkeypatch.setattr(ledger, "MIGRATIONS", (("CREATE TABLE partial (id TEXT)", "INVALID"),))
    with pytest.raises(sqlite3.OperationalError):
        Ledger(path)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert connection.execute("SELECT name FROM sqlite_master").fetchall() == []
