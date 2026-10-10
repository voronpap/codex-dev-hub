import hashlib
import json
import sqlite3
from datetime import UTC, datetime

import pytest
from ledger_support import identity, initialized_ledger

from devhub import ledger
from devhub.ledger import (
    DEVFABRIC_LEDGER_APPLICATION_ID,
    IDENTITY_UPDATE_TRIGGER_SQL,
    Ledger,
    LedgerError,
    LedgerErrorCode,
    LedgerIdentityMetadataV1,
    canonical_ledger_identity,
    ledger_identity_sha256,
)


def database_snapshot(path):
    with sqlite3.connect(path) as connection:
        has_foreign = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='foreign_data'"
        ).fetchone()
        return {
            "application_id": connection.execute("PRAGMA application_id").fetchone()[0],
            "user_version": connection.execute("PRAGMA user_version").fetchone()[0],
            "schema": connection.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
            ).fetchall(),
            "foreign": connection.execute("SELECT value FROM foreign_data").fetchall()
            if has_foreign
            else None,
        }


def legacy_database(path, version=6):
    with sqlite3.connect(path) as connection:
        for index in range(version):
            for statement in ledger.MIGRATIONS[index]:
                connection.execute(statement)
            connection.execute(f"PRAGMA user_version = {index + 1}")


@pytest.mark.windows_smoke
def test_new_identity_reopen_backup_and_rollback(tmp_path):
    path = tmp_path / "ledger.db"
    expected = identity()
    metadata = LedgerIdentityMetadataV1(
        created_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        created_by_runtime="test-runtime/1",
    )
    database = Ledger.initialize(path, expected, metadata=metadata)
    with database.transaction() as connection:
        row = connection.execute("SELECT * FROM ledger_identity").fetchone()
        assert connection.execute("PRAGMA application_id").fetchone()[0] == 0x4446524C
        assert connection.execute("PRAGMA user_version").fetchone()[0] == len(ledger.MIGRATIONS)
        assert row[1:7] == (
            "devfabric_resource_ledger",
            1,
            expected.instance_id,
            "project",
            "p",
            None,
        )
        assert row[7] == ledger_identity_sha256(expected)
        assert row[8:] == ("2026-01-02T03:04:05+00:00", "test-runtime/1")
        connection.execute("INSERT INTO buckets(id, spec) VALUES ('pool', '{}')")
    with pytest.raises(RuntimeError), database.transaction() as connection:
        connection.execute("UPDATE buckets SET held = 1")
        raise RuntimeError("crash before commit")
    backup = tmp_path / "backup.db"
    database.backup(backup)
    for candidate in (path, backup):
        with Ledger(candidate, expected).transaction() as connection:
            assert connection.execute("SELECT held FROM buckets").fetchone()[0] == 0
            assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    with pytest.raises(FileExistsError):
        database.backup(backup)
    # Explicit initialization is idempotent for the same authority and never rewrites metadata.
    Ledger.initialize(path, expected)
    with sqlite3.connect(path) as connection:
        assert connection.execute(
            "SELECT created_at,created_by_runtime FROM ledger_identity"
        ).fetchone() == ("2026-01-02T03:04:05+00:00", "test-runtime/1")


def test_canonical_identity_hash_golden():
    expected = identity(account_binding_hash="a" * 64)
    assert canonical_ledger_identity(expected) == (
        b'{"account_binding_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",'
        b'"authority_scope_id":"p","authority_scope_kind":"project",'
        b'"family":"devfabric_resource_ledger","format_version":1,'
        b'"instance_id":"0123456789abcdef0123456789abcdef"}'
    )
    assert ledger_identity_sha256(expected) == (
        "0091a0fd094519b85736a42fb6dac10218e8a413b04c8c670720fe3dda5073ca"
    )
    assert DEVFABRIC_LEDGER_APPLICATION_ID == 1_145_459_276


def test_normal_open_never_initializes_new_path(tmp_path):
    path = tmp_path / "ledger.db"
    with pytest.raises(LedgerError) as raised:
        Ledger(path, identity())
    assert raised.value.code is LedgerErrorCode.IDENTITY_BOOTSTRAP_FAILURE
    assert not path.exists()


def test_future_domain_schema_and_existing_wal_are_refused(tmp_path):
    path = tmp_path / "ledger.db"
    expected = identity()
    initialized_ledger(path, expected)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version = 999")
    with pytest.raises(LedgerError) as raised:
        Ledger(path, expected)
    assert raised.value.code is LedgerErrorCode.UNSUPPORTED_LEDGER_SCHEMA_VERSION

    with sqlite3.connect(path) as connection:
        connection.execute(f"PRAGMA user_version = {len(ledger.MIGRATIONS)}")
        assert connection.execute("PRAGMA journal_mode = WAL").fetchone()[0] == "wal"
    with pytest.raises(LedgerError, match="DELETE"):
        Ledger(path, expected)


def test_foreign_database_fails_without_logical_mutation(tmp_path):
    path = tmp_path / "foreign.db"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA application_id = 12345")
        connection.execute("PRAGMA user_version = 77")
        connection.execute("CREATE TABLE foreign_data(value TEXT)")
        connection.execute("INSERT INTO foreign_data VALUES ('preserve-me')")
    before = database_snapshot(path)
    with pytest.raises(LedgerError) as raised:
        Ledger(path, identity())
    assert raised.value.code is LedgerErrorCode.FOREIGN_DATABASE
    assert database_snapshot(path) == before


def test_legacy_database_requires_explicit_adoption_without_mutation(tmp_path):
    path = tmp_path / "legacy.db"
    legacy_database(path)
    before = database_snapshot(path)
    with pytest.raises(LedgerError) as raised:
        Ledger(path, identity())
    assert raised.value.code is LedgerErrorCode.LEGACY_IDENTITY_REQUIRED
    assert database_snapshot(path) == before
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name='ledger_identity'"
            ).fetchone()
            is None
        )


@pytest.mark.parametrize(
    "change",
    [
        {"instance_id": "f" * 32},
        {"authority_scope_kind": "qualification", "authority_scope_id": "stage3g"},
        {"authority_scope_id": "other"},
        {"account_binding_hash": "b" * 64},
    ],
)
def test_reopen_identity_mismatch_matrix(tmp_path, change):
    path = tmp_path / "ledger.db"
    expected = identity()
    initialized_ledger(path, expected)
    with pytest.raises(LedgerError) as raised:
        Ledger(path, expected.model_copy(update=change))
    assert raised.value.code is LedgerErrorCode.LEDGER_IDENTITY_MISMATCH


@pytest.mark.parametrize(
    "column,value,error_code",
    [
        ("family", "another_family", LedgerErrorCode.LEDGER_IDENTITY_MISMATCH),
        ("format_version", 2, LedgerErrorCode.UNSUPPORTED_LEDGER_IDENTITY_VERSION),
    ],
)
def test_stored_family_and_version_fail_closed(tmp_path, column, value, error_code):
    path = tmp_path / "ledger.db"
    expected = identity()
    initialized_ledger(path, expected)
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER ledger_identity_no_update")
        connection.execute(f"UPDATE ledger_identity SET {column}=?", (value,))
        connection.execute(IDENTITY_UPDATE_TRIGGER_SQL)
    with pytest.raises(LedgerError) as raised:
        Ledger(path, expected)
    assert raised.value.code is error_code


def test_hash_inconsistency_and_identity_mutation_are_rejected(tmp_path):
    path = tmp_path / "ledger.db"
    expected = identity()
    database = initialized_ledger(path, expected)
    with pytest.raises(sqlite3.IntegrityError), database.transaction() as connection:
        connection.execute("UPDATE ledger_identity SET identity_sha256=?", ("0" * 64,))
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER ledger_identity_no_update")
        connection.execute("UPDATE ledger_identity SET identity_sha256=?", ("0" * 64,))
        connection.execute(IDENTITY_UPDATE_TRIGGER_SQL)
    with pytest.raises(LedgerError) as raised:
        Ledger(path, expected)
    assert raised.value.code is LedgerErrorCode.LEDGER_IDENTITY_MISMATCH


def test_identity_validation_precedes_domain_migration(tmp_path, monkeypatch):
    path = tmp_path / "upgrade.db"
    expected = identity()
    with monkeypatch.context() as context:
        context.setattr(ledger, "MIGRATIONS", ledger.MIGRATIONS[:5])
        Ledger.initialize(path, expected)
    before = database_snapshot(path)
    wrong = expected.model_copy(update={"authority_scope_id": "other"})
    with pytest.raises(LedgerError) as raised:
        Ledger(path, wrong)
    assert raised.value.code is LedgerErrorCode.LEDGER_IDENTITY_MISMATCH
    assert database_snapshot(path) == before


def test_failed_domain_migration_keeps_committed_identity_and_is_atomic(tmp_path, monkeypatch):
    path = tmp_path / "atomic.db"
    monkeypatch.setattr(ledger, "MIGRATIONS", (("CREATE TABLE partial (id TEXT)", "INVALID"),))
    with pytest.raises(sqlite3.OperationalError):
        Ledger.initialize(path, identity())
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA application_id").fetchone()[0] == 0x4446524C
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        names = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            )
        }
        assert names == {
            "ledger_identity",
            "ledger_identity_no_update",
            "ledger_identity_no_delete",
        }


def test_failed_identity_bootstrap_rolls_back_all_identity_mutation(tmp_path, monkeypatch):
    path = tmp_path / "bootstrap.db"
    monkeypatch.setattr(ledger, "IDENTITY_UPDATE_TRIGGER_SQL", "INVALID")
    with pytest.raises(LedgerError) as raised:
        Ledger.initialize(path, identity())
    assert raised.value.code is LedgerErrorCode.IDENTITY_BOOTSTRAP_FAILURE
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA application_id").fetchone()[0] == 0
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 0
        assert (
            connection.execute(
                "SELECT name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
            ).fetchall()
            == []
        )


@pytest.mark.windows_smoke
def test_reparse_classification_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setattr(ledger, "_is_reparse", lambda _: True)
    with pytest.raises(LedgerError) as raised:
        Ledger.initialize(tmp_path / "ledger.db", identity())
    assert raised.value.code is LedgerErrorCode.UNSAFE_STATE_ROOT


def test_symlinked_state_root_and_ledger_file_are_rejected(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    root_link = tmp_path / "root-link"
    try:
        root_link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable on this platform")
    with pytest.raises(LedgerError) as raised:
        Ledger.initialize(root_link / "ledger.db", identity(), state_root=root_link)
    assert raised.value.code is LedgerErrorCode.UNSAFE_STATE_ROOT

    escaped_child = root_link / "new-state"
    with pytest.raises(LedgerError) as raised:
        Ledger.initialize_state_root(escaped_child, identity())
    assert raised.value.code is LedgerErrorCode.UNSAFE_STATE_ROOT
    assert not (target / "new-state").exists()

    real = initialized_ledger(target / "real.db")
    ledger_link = target / "ledger.db"
    ledger_link.symlink_to(real.path)
    with pytest.raises(LedgerError) as raised:
        Ledger(ledger_link, real.expected_identity, state_root=target)
    assert raised.value.code is LedgerErrorCode.UNSAFE_STATE_ROOT


def test_legacy_fingerprints_are_exact_and_documented():
    assert set(ledger.LEGACY_SCHEMA_FINGERPRINTS) == set(range(1, len(ledger.MIGRATIONS) + 1))
    for version, expected_hash in ledger.LEGACY_SCHEMA_FINGERPRINTS.items():
        connection = sqlite3.connect(":memory:")
        try:
            for index in range(version):
                for statement in ledger.MIGRATIONS[index]:
                    connection.execute(statement)
            entries = ledger._schema_entries(connection, include_identity=False)
            assert ledger._schema_fingerprint(entries) == expected_hash
        finally:
            connection.close()


def test_application_id_header_bytes_are_dfrl(tmp_path):
    path = tmp_path / "ledger.db"
    initialized_ledger(path)
    header = path.read_bytes()[:100]
    assert header[68:72] == bytes.fromhex("4446524c")


def test_identity_hash_does_not_include_metadata():
    expected = identity()
    payload = json.loads(canonical_ledger_identity(expected))
    assert set(payload) == {
        "family",
        "format_version",
        "instance_id",
        "authority_scope_kind",
        "authority_scope_id",
        "account_binding_hash",
    }
    assert hashlib.sha256(canonical_ledger_identity(expected)).hexdigest() == (
        ledger_identity_sha256(expected)
    )


def test_read_only_inspection_preserves_current_ledger_bytes(tmp_path):
    path = tmp_path / "ledger.db"
    expected = identity()
    initialized_ledger(path, expected)
    before = path.read_bytes()
    observed = Ledger.inspect_read_only(path, expected)
    assert observed.ledger_identity_sha256 == ledger_identity_sha256(expected)
    assert observed.domain_schema_version == len(ledger.MIGRATIONS)
    assert observed.reserved_count == observed.dispatched_count == observed.unknown_usage_count == 0
    assert path.read_bytes() == before


def test_read_only_inspection_refuses_migration_without_mutation(tmp_path, monkeypatch):
    path = tmp_path / "older.db"
    expected = identity()
    with monkeypatch.context() as context:
        context.setattr(ledger, "MIGRATIONS", ledger.MIGRATIONS[:5])
        Ledger.initialize(path, expected)
    before = database_snapshot(path)
    before_bytes = path.read_bytes()
    with pytest.raises(LedgerError) as raised:
        Ledger.inspect_read_only(path, expected)
    assert raised.value.code is LedgerErrorCode.UNSUPPORTED_LEDGER_SCHEMA_VERSION
    assert database_snapshot(path) == before
    assert path.read_bytes() == before_bytes
