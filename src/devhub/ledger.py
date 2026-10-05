"""Local durable accounting with an immutable, host-owned ledger identity."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from devhub import __version__

LEDGER_FAMILY: Literal["devfabric_resource_ledger"] = "devfabric_resource_ledger"
LEDGER_IDENTITY_FORMAT_VERSION: Literal[1] = 1
# 0x4446524C is ASCII "DFRL" in the big-endian database header representation.
DEVFABRIC_LEDGER_APPLICATION_ID = 0x4446524C

Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
InstanceId = Annotated[str, Field(pattern=r"^[a-f0-9]{32}$")]
AuthorityScopeId = Annotated[
    str, Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:@/-]+$")
]


class LedgerIdentityCoreV1(BaseModel):
    """Trusted logical authority. Filesystem location is deliberately excluded."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, validate_default=True)

    family: Literal["devfabric_resource_ledger"] = LEDGER_FAMILY
    format_version: Literal[1] = LEDGER_IDENTITY_FORMAT_VERSION
    instance_id: InstanceId
    authority_scope_kind: Literal["project", "qualification"]
    authority_scope_id: AuthorityScopeId
    account_binding_hash: Digest | None = None


class LedgerIdentityMetadataV1(BaseModel):
    """Immutable audit metadata; it is not part of reopen authority equality."""

    model_config = ConfigDict(extra="forbid", strict=True, frozen=True, validate_default=True)

    created_at: datetime
    created_by_runtime: Annotated[str, Field(min_length=1, max_length=128)]

    @field_validator("created_at")
    @classmethod
    def utc_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
            raise ValueError("created_at must be timezone-aware UTC")
        return value


def canonical_ledger_identity(identity: LedgerIdentityCoreV1) -> bytes:
    """Return the sole canonical byte representation used for identity hashing."""

    return json.dumps(
        identity.model_dump(mode="json"),
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def ledger_identity_sha256(identity: LedgerIdentityCoreV1) -> str:
    return hashlib.sha256(canonical_ledger_identity(identity)).hexdigest()


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
    (
        """CREATE TABLE capabilities (
            id TEXT PRIMARY KEY REFERENCES policies(id),
            revision TEXT NOT NULL, spec TEXT NOT NULL
        )""",
        "ALTER TABLE reservations ADD COLUMN capability_revision TEXT",
    ),
    (
        """CREATE TABLE events (
            sequence INTEGER PRIMARY KEY AUTOINCREMENT,
            id TEXT UNIQUE NOT NULL, project TEXT NOT NULL,
            reservation TEXT NOT NULL REFERENCES reservations(id),
            payload TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0
                CHECK(acknowledged IN (0,1))
        )""",
        "CREATE INDEX pending_events ON events(project, acknowledged, sequence)",
    ),
    (
        """CREATE TABLE quota_observations (
            scope TEXT PRIMARY KEY, spec TEXT NOT NULL
        )""",
    ),
    (
        """CREATE TABLE gemini_preflights (
            project TEXT PRIMARY KEY, spec TEXT NOT NULL,
            request_hash TEXT NOT NULL, tokens INTEGER CHECK(tokens > 0)
        )""",
    ),
    (
        """CREATE TABLE gemini_followup_permits (
            id TEXT PRIMARY KEY, project_number TEXT UNIQUE NOT NULL
                REFERENCES gemini_preflights(project),
            spec TEXT NOT NULL, claimed_ms INTEGER,
            tokens INTEGER CHECK(tokens > 0)
        )""",
    ),
)

IDENTITY_TABLE_SQL = """CREATE TABLE ledger_identity (
    singleton_key INTEGER PRIMARY KEY CHECK(singleton_key = 1),
    family TEXT NOT NULL,
    format_version INTEGER NOT NULL,
    instance_id TEXT NOT NULL,
    authority_scope_kind TEXT NOT NULL,
    authority_scope_id TEXT NOT NULL,
    account_binding_hash TEXT,
    identity_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    created_by_runtime TEXT NOT NULL
)"""
IDENTITY_UPDATE_TRIGGER_SQL = """CREATE TRIGGER ledger_identity_no_update
BEFORE UPDATE ON ledger_identity BEGIN
    SELECT RAISE(ABORT, 'ledger identity is immutable');
END"""
IDENTITY_DELETE_TRIGGER_SQL = """CREATE TRIGGER ledger_identity_no_delete
BEFORE DELETE ON ledger_identity BEGIN
    SELECT RAISE(ABORT, 'ledger identity is immutable');
END"""
IDENTITY_OBJECTS = {
    "ledger_identity",
    "ledger_identity_no_update",
    "ledger_identity_no_delete",
}


class LedgerBootstrapClassification(StrEnum):
    NEW_EMPTY = "NEW_EMPTY"
    VALID_IDENTIFIED_DEVFABRIC = "VALID_IDENTIFIED_DEVFABRIC"
    LEGACY_UNIDENTIFIED_DEVFABRIC = "LEGACY_UNIDENTIFIED_DEVFABRIC"
    FOREIGN_NONEMPTY = "FOREIGN_NONEMPTY"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"


class LedgerErrorCode(StrEnum):
    FOREIGN_DATABASE = "FOREIGN_DATABASE"
    LEGACY_IDENTITY_REQUIRED = "LEGACY_IDENTITY_REQUIRED"
    LEDGER_IDENTITY_MISMATCH = "LEDGER_IDENTITY_MISMATCH"
    UNSUPPORTED_LEDGER_IDENTITY_VERSION = "UNSUPPORTED_LEDGER_IDENTITY_VERSION"
    UNSUPPORTED_LEDGER_SCHEMA_VERSION = "UNSUPPORTED_LEDGER_SCHEMA_VERSION"
    UNSUPPORTED_LEDGER_JOURNAL = "UNSUPPORTED_LEDGER_JOURNAL"
    UNSAFE_STATE_ROOT = "UNSAFE_STATE_ROOT"
    IDENTITY_BOOTSTRAP_FAILURE = "IDENTITY_BOOTSTRAP_FAILURE"


class LedgerError(RuntimeError):
    def __init__(self, code: LedgerErrorCode, detail: str) -> None:
        self.code = code
        super().__init__(f"{code.value}: {detail}")


def _normalize_sql(value: str | None) -> str | None:
    return " ".join(value.split()) if value is not None else None


def _schema_entries(
    connection: sqlite3.Connection, *, include_identity: bool
) -> tuple[tuple[str, str, str, str | None], ...]:
    rows = connection.execute(
        """SELECT type,name,tbl_name,sql FROM sqlite_master
           WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"""
    ).fetchall()
    return tuple(
        (row[0], row[1], row[2], _normalize_sql(row[3]))
        for row in rows
        if include_identity or row[1] not in IDENTITY_OBJECTS
    )


def _schema_fingerprint(entries: tuple[tuple[str, str, str, str | None], ...]) -> str:
    payload = json.dumps(entries, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# Exact fingerprints produced by the repository's six historical migration levels.
# They intentionally exclude SQLite internal objects and the new ledger identity objects.
LEGACY_SCHEMA_FINGERPRINTS: dict[int, str] = {
    1: "b2bc96fa31b48c6e2225c608d127e39feb2162eb37917278bf185078c8696639",
    2: "afd91302e06a9c3ce90e4253f635f14344eecdefc71f612142f6556ed8c40c0b",
    3: "06588c1c404505bbb2cae1c7583535e0c0874bb6888270ac8ed6ef9eed5b758b",
    4: "57d2346be790a56b2ce4d61797ef3bd6cb827f1ac19ed72cc6380faa2a55cf75",
    5: "35bd9d59d04d8aa359d179182a1036aea0c91e903f729e87549d88cc5646fe97",
    6: "fa1a7bf67a70eb64d4fcfcd2cd1d167694739efbba07637ac3a21e7cd8875cc2",
}


def _is_reparse(stat_result: os.stat_result) -> bool:
    flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    attributes = getattr(stat_result, "st_file_attributes", 0)
    return bool(flag and attributes & flag)


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left)) == os.path.normcase(str(right))


def _validate_state_paths(state_root: Path, ledger_path: Path) -> tuple[Path, Path]:
    root = Path(os.path.abspath(state_root))
    path = Path(os.path.abspath(ledger_path))
    if path.parent != root:
        raise LedgerError(
            LedgerErrorCode.UNSAFE_STATE_ROOT, "ledger must be a direct child of state root"
        )
    try:
        root_stat = os.lstat(root)
    except OSError as error:
        raise LedgerError(
            LedgerErrorCode.UNSAFE_STATE_ROOT, "state root must already exist"
        ) from error
    if (
        not stat.S_ISDIR(root_stat.st_mode)
        or stat.S_ISLNK(root_stat.st_mode)
        or _is_reparse(root_stat)
    ):
        raise LedgerError(LedgerErrorCode.UNSAFE_STATE_ROOT, "state root is not a safe directory")
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as error:
        raise LedgerError(
            LedgerErrorCode.UNSAFE_STATE_ROOT, "state root cannot be resolved"
        ) from error
    if not _same_path(resolved_root, root):
        raise LedgerError(
            LedgerErrorCode.UNSAFE_STATE_ROOT,
            "state root traverses a symbolic link or reparse point",
        )
    if path.exists() or path.is_symlink():
        try:
            path_stat = os.lstat(path)
        except OSError as error:
            raise LedgerError(
                LedgerErrorCode.UNSAFE_STATE_ROOT, "ledger path cannot be inspected"
            ) from error
        if (
            not stat.S_ISREG(path_stat.st_mode)
            or stat.S_ISLNK(path_stat.st_mode)
            or _is_reparse(path_stat)
        ):
            raise LedgerError(LedgerErrorCode.UNSAFE_STATE_ROOT, "ledger path is not a safe file")
        if not _same_path(path.resolve(strict=True).parent, resolved_root):
            raise LedgerError(LedgerErrorCode.UNSAFE_STATE_ROOT, "ledger escapes state root")
    return root, path


def _validate_state_root_creation_ancestor(state_root: Path) -> None:
    """Refuse to create through an already present symlink/reparse ancestor."""

    ancestor = state_root
    while not ancestor.exists() and not ancestor.is_symlink():
        if ancestor.parent == ancestor:
            break
        ancestor = ancestor.parent
    try:
        ancestor_stat = os.lstat(ancestor)
    except OSError as error:
        raise LedgerError(
            LedgerErrorCode.UNSAFE_STATE_ROOT, "state-root creation ancestor is unavailable"
        ) from error
    if (
        not stat.S_ISDIR(ancestor_stat.st_mode)
        or stat.S_ISLNK(ancestor_stat.st_mode)
        or _is_reparse(ancestor_stat)
        or not _same_path(ancestor.resolve(strict=True), Path(os.path.abspath(ancestor)))
    ):
        raise LedgerError(
            LedgerErrorCode.UNSAFE_STATE_ROOT,
            "state-root creation would traverse a symbolic link or reparse point",
        )


class Ledger:
    """Durable authority; connections are never shared across threads."""

    def __init__(
        self,
        path: Path,
        expected_identity: LedgerIdentityCoreV1,
        *,
        state_root: Path | None = None,
    ) -> None:
        self.expected_identity = expected_identity
        self.identity_sha256 = ledger_identity_sha256(expected_identity)
        self.state_root, self.path = _validate_state_paths(state_root or path.parent, path)
        if not self.path.is_file():
            raise LedgerError(
                LedgerErrorCode.IDENTITY_BOOTSTRAP_FAILURE,
                "ledger is not initialized; explicit initialization is required",
            )
        self._inspect_existing_and_migrate()

    @classmethod
    def initialize_state_root(
        cls, state_root: Path, expected_identity: LedgerIdentityCoreV1
    ) -> Ledger:
        """Explicit provisioning helper shared by trusted runtime entry points."""

        root = Path(os.path.abspath(state_root))
        if not root.exists() and not root.is_symlink():
            _validate_state_root_creation_ancestor(root)
            try:
                root.mkdir(parents=True, exist_ok=False)
            except FileExistsError:
                pass  # A concurrent initializer still has to pass the checks below.
            except OSError as error:
                raise LedgerError(
                    LedgerErrorCode.UNSAFE_STATE_ROOT, "state root could not be created safely"
                ) from error
        return cls.initialize(root / "ledger.db", expected_identity, state_root=root)

    @classmethod
    def initialize(
        cls,
        path: Path,
        expected_identity: LedgerIdentityCoreV1,
        *,
        state_root: Path | None = None,
        metadata: LedgerIdentityMetadataV1 | None = None,
    ) -> Ledger:
        """Explicitly initialize NEW_EMPTY storage, then return a normal validated ledger."""

        root, safe_path = _validate_state_paths(state_root or path.parent, path)
        if not safe_path.exists():
            try:
                with safe_path.open("xb"):
                    pass
            except FileExistsError:
                pass  # A concurrent initializer still has to validate exact identity.
            except OSError as error:
                raise LedgerError(
                    LedgerErrorCode.IDENTITY_BOOTSTRAP_FAILURE,
                    "could not create an empty ledger file",
                ) from error
        _validate_state_paths(root, safe_path)
        temporary = object.__new__(cls)
        temporary.expected_identity = expected_identity
        temporary.identity_sha256 = ledger_identity_sha256(expected_identity)
        temporary.state_root = root
        temporary.path = safe_path
        temporary._initialize_or_validate(
            metadata
            or LedgerIdentityMetadataV1(
                created_at=datetime.now(UTC), created_by_runtime=f"codex-dev-hub/{__version__}"
            )
        )
        return cls(safe_path, expected_identity, state_root=root)

    def _raw_connect(self) -> sqlite3.Connection:
        _validate_state_paths(self.state_root, self.path)
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA synchronous = FULL")
            _validate_state_paths(self.state_root, self.path)
            return connection
        except BaseException:
            connection.close()
            raise

    def _initialize_or_validate(self, metadata: LedgerIdentityMetadataV1) -> None:
        connection = self._raw_connect()
        try:
            connection.execute("BEGIN EXCLUSIVE")
            classification = self._classify(connection)
            if classification is LedgerBootstrapClassification.NEW_EMPTY:
                try:
                    self._require_delete_journal(connection)
                    connection.execute(f"PRAGMA application_id = {DEVFABRIC_LEDGER_APPLICATION_ID}")
                    connection.execute(IDENTITY_TABLE_SQL)
                    connection.execute(
                        """INSERT INTO ledger_identity(
                            singleton_key,family,format_version,instance_id,
                            authority_scope_kind,authority_scope_id,account_binding_hash,
                            identity_sha256,created_at,created_by_runtime
                        ) VALUES (1,?,?,?,?,?,?,?,?,?)""",
                        (
                            self.expected_identity.family,
                            self.expected_identity.format_version,
                            self.expected_identity.instance_id,
                            self.expected_identity.authority_scope_kind,
                            self.expected_identity.authority_scope_id,
                            self.expected_identity.account_binding_hash,
                            self.identity_sha256,
                            metadata.created_at.isoformat(),
                            metadata.created_by_runtime,
                        ),
                    )
                    connection.execute(IDENTITY_UPDATE_TRIGGER_SQL)
                    connection.execute(IDENTITY_DELETE_TRIGGER_SQL)
                    if (
                        self._classify(connection)
                        is not LedgerBootstrapClassification.VALID_IDENTIFIED_DEVFABRIC
                    ):
                        raise ValueError("identity verification failed")
                    connection.commit()
                except BaseException as error:
                    connection.rollback()
                    if isinstance(error, LedgerError):
                        raise
                    raise LedgerError(
                        LedgerErrorCode.IDENTITY_BOOTSTRAP_FAILURE,
                        "identity bootstrap transaction failed",
                    ) from error
            elif classification is LedgerBootstrapClassification.VALID_IDENTIFIED_DEVFABRIC:
                self._require_delete_journal(connection)
                connection.commit()
            else:
                connection.rollback()
                self._raise_classification(classification)
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _inspect_existing_and_migrate(self) -> None:
        connection = self._raw_connect()
        try:
            connection.execute("BEGIN EXCLUSIVE")
            classification = self._classify(connection)
            if classification is not LedgerBootstrapClassification.VALID_IDENTIFIED_DEVFABRIC:
                connection.rollback()
                self._raise_classification(classification)
            self._require_delete_journal(connection)
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if version > len(MIGRATIONS):
                raise LedgerError(
                    LedgerErrorCode.UNSUPPORTED_LEDGER_SCHEMA_VERSION,
                    "database domain schema is newer than this runtime",
                )
            self._validate_domain_schema(connection, version)
            for index in range(version, len(MIGRATIONS)):
                for statement in MIGRATIONS[index]:
                    connection.execute(statement)
                connection.execute(f"PRAGMA user_version = {index + 1}")
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.close()

    def _classify(self, connection: sqlite3.Connection) -> LedgerBootstrapClassification:
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        user_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        all_entries = _schema_entries(connection, include_identity=True)
        names = {entry[1] for entry in all_entries}
        if application_id == 0 and user_version == 0 and not all_entries:
            return LedgerBootstrapClassification.NEW_EMPTY
        if "ledger_identity" in names:
            if application_id != DEVFABRIC_LEDGER_APPLICATION_ID:
                return LedgerBootstrapClassification.IDENTITY_MISMATCH
            return (
                LedgerBootstrapClassification.VALID_IDENTIFIED_DEVFABRIC
                if self._identity_matches(connection, names)
                else LedgerBootstrapClassification.IDENTITY_MISMATCH
            )
        domain = _schema_entries(connection, include_identity=False)
        legacy = LEGACY_SCHEMA_FINGERPRINTS.get(user_version) == _schema_fingerprint(domain)
        if application_id in {0, DEVFABRIC_LEDGER_APPLICATION_ID} and legacy:
            return LedgerBootstrapClassification.LEGACY_UNIDENTIFIED_DEVFABRIC
        return LedgerBootstrapClassification.FOREIGN_NONEMPTY

    def _identity_matches(self, connection: sqlite3.Connection, names: set[str]) -> bool:
        if not IDENTITY_OBJECTS <= names:
            return False
        entries = {entry[1]: entry for entry in _schema_entries(connection, include_identity=True)}
        expected_sql = {
            "ledger_identity": _normalize_sql(IDENTITY_TABLE_SQL),
            "ledger_identity_no_update": _normalize_sql(IDENTITY_UPDATE_TRIGGER_SQL),
            "ledger_identity_no_delete": _normalize_sql(IDENTITY_DELETE_TRIGGER_SQL),
        }
        if any(entries[name][3] != sql for name, sql in expected_sql.items()):
            return False
        try:
            rows = connection.execute(
                """SELECT singleton_key,family,format_version,instance_id,
                          authority_scope_kind,authority_scope_id,account_binding_hash,
                          identity_sha256,created_at,created_by_runtime
                   FROM ledger_identity"""
            ).fetchall()
        except sqlite3.Error:
            return False
        if len(rows) != 1 or rows[0][0] != 1:
            return False
        row = rows[0]
        if row[2] != LEDGER_IDENTITY_FORMAT_VERSION:
            raise LedgerError(
                LedgerErrorCode.UNSUPPORTED_LEDGER_IDENTITY_VERSION,
                "ledger identity format version is unsupported",
            )
        try:
            stored = LedgerIdentityCoreV1(
                family=row[1],
                format_version=row[2],
                instance_id=row[3],
                authority_scope_kind=row[4],
                authority_scope_id=row[5],
                account_binding_hash=row[6],
            )
            LedgerIdentityMetadataV1(
                created_at=datetime.fromisoformat(row[8]), created_by_runtime=row[9]
            )
        except (TypeError, ValueError):
            return False
        return (
            stored == self.expected_identity
            and row[7] == ledger_identity_sha256(stored)
            and row[7] == self.identity_sha256
        )

    def _validate_domain_schema(self, connection: sqlite3.Connection, version: int) -> None:
        entries = _schema_entries(connection, include_identity=False)
        if version == 0 and not entries:
            return
        expected = LEGACY_SCHEMA_FINGERPRINTS.get(version)
        if expected is None or _schema_fingerprint(entries) != expected:
            raise LedgerError(
                LedgerErrorCode.FOREIGN_DATABASE,
                "domain schema does not match a recognized DevFabric ledger version",
            )

    def _require_delete_journal(self, connection: sqlite3.Connection) -> None:
        if connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
            raise LedgerError(
                LedgerErrorCode.UNSUPPORTED_LEDGER_JOURNAL,
                "ledger requires rollback journal mode DELETE",
            )

    def _raise_classification(self, classification: LedgerBootstrapClassification) -> None:
        if classification is LedgerBootstrapClassification.LEGACY_UNIDENTIFIED_DEVFABRIC:
            raise LedgerError(
                LedgerErrorCode.LEGACY_IDENTITY_REQUIRED,
                "recognized legacy ledger requires an explicit reviewed adoption operation",
            )
        if classification is LedgerBootstrapClassification.FOREIGN_NONEMPTY:
            raise LedgerError(
                LedgerErrorCode.FOREIGN_DATABASE,
                "non-empty database is not a recognized DevFabric ledger",
            )
        raise LedgerError(
            LedgerErrorCode.LEDGER_IDENTITY_MISMATCH,
            "ledger identity does not match trusted host authority",
        )

    def connect(self) -> sqlite3.Connection:
        connection = self._raw_connect()
        try:
            connection.execute("BEGIN")
            classification = self._classify(connection)
            if classification is not LedgerBootstrapClassification.VALID_IDENTIFIED_DEVFABRIC:
                self._raise_classification(classification)
            self._require_delete_journal(connection)
            connection.commit()
            return connection
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            connection.close()
            raise

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._raw_connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            classification = self._classify(connection)
            if classification is not LedgerBootstrapClassification.VALID_IDENTIFIED_DEVFABRIC:
                self._raise_classification(classification)
            self._require_delete_journal(connection)
            yield connection
            connection.commit()
        except BaseException:
            if connection.in_transaction:
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
