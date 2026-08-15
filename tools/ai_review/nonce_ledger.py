"""Stdlib-only SQLite nonce-ledger contract shared by outer and coordinator code."""

from __future__ import annotations

import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path


NONCE_LEDGER_APPLICATION_ID = 1_095_062_094
NONCE_LEDGER_USER_VERSION = 1
NONCE_LEDGER_SCHEMA_SQL = (
    "CREATE TABLE used_nonces ("
    "nonce TEXT NOT NULL PRIMARY KEY "
    "CHECK(typeof(nonce) = 'text' AND length(nonce) BETWEEN 32 AND 128 "
    "AND nonce NOT GLOB '*[^0-9a-f]*'), "
    "reserved_at INTEGER NOT NULL "
    "CHECK(typeof(reserved_at) = 'integer' AND reserved_at >= 0)"
    ") WITHOUT ROWID"
)

_EXPECTED_SCHEMA = (("table", "used_nonces", "used_nonces", NONCE_LEDGER_SCHEMA_SQL),)
_EXPECTED_TABLE_INFO = (
    (0, "nonce", "TEXT", 1, None, 1),
    (1, "reserved_at", "INTEGER", 1, None, 0),
)
_EXPECTED_TABLE_XINFO = (
    (0, "nonce", "TEXT", 1, None, 1, 0),
    (1, "reserved_at", "INTEGER", 1, None, 0, 0),
)
_EXPECTED_INDEX_LIST = ((0, "sqlite_autoindex_used_nonces_1", 1, "pk", 0),)
_EXPECTED_INDEX_INFO = ((0, 0, "nonce"),)
_EXPECTED_INDEX_XINFO = (
    (0, 0, "nonce", 0, "BINARY", 1),
    (1, 1, "reserved_at", 0, "BINARY", 0),
)
_SIDECAR_SUFFIXES = ("-journal", "-wal", "-shm")


class NonceLedgerContractError(ValueError):
    """Raised when a persisted ledger is not the one exact trusted database format."""


@dataclass(frozen=True)
class NonceLedgerFileIdentity:
    device: int
    inode: int
    uid: int
    gid: int


def _contract_error() -> NonceLedgerContractError:
    return NonceLedgerContractError("nonce ledger database does not match the required contract")


def validate_nonce_ledger_file_metadata(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_identity: NonceLedgerFileIdentity | None = None,
) -> NonceLedgerFileIdentity:
    """Require the exact private regular-file boundary without following links."""

    absolute = Path(os.path.abspath(path))
    try:
        metadata = os.lstat(absolute)
    except OSError as exc:
        raise NonceLedgerContractError("nonce ledger file is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise NonceLedgerContractError("nonce ledger file must not be a symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise NonceLedgerContractError("nonce ledger must be a regular file")
    if metadata.st_nlink != 1:
        raise NonceLedgerContractError("nonce ledger file must not be a hardlink")
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise NonceLedgerContractError("nonce ledger file must have mode 0600")
    if (metadata.st_uid, metadata.st_gid) != (expected_uid, expected_gid):
        raise NonceLedgerContractError("nonce ledger file has an invalid owner")
    identity = NonceLedgerFileIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
    )
    if expected_identity is not None and identity != expected_identity:
        raise NonceLedgerContractError("nonce ledger file identity changed")
    return identity


def validate_nonce_ledger_directory(path: Path) -> None:
    """Reject SQLite sidecars and every other entry in the dedicated ledger directory."""

    absolute = Path(os.path.abspath(path))
    try:
        entries = tuple(absolute.parent.iterdir())
    except OSError as exc:
        raise NonceLedgerContractError("nonce ledger directory is unavailable") from exc
    unexpected = tuple(entry for entry in entries if entry.name != absolute.name)
    if unexpected:
        if any(
            entry.name == absolute.name + suffix
            for entry in unexpected
            for suffix in _SIDECAR_SUFFIXES
        ):
            raise NonceLedgerContractError(
                "nonce ledger directory contains a forbidden SQLite sidecar"
            )
        raise NonceLedgerContractError(
            "nonce ledger directory must contain only the ledger database"
        )


def _connect(path: Path, *, readonly: bool) -> sqlite3.Connection:
    mode = "ro" if readonly else "rw"
    connection: sqlite3.Connection | None = None
    try:
        connection = sqlite3.connect(
            path.as_uri() + f"?mode={mode}",
            uri=True,
            timeout=30,
            isolation_level=None,
        )
        connection.execute("PRAGMA trusted_schema=OFF")
        connection.execute("PRAGMA query_only=" + ("ON" if readonly else "OFF"))
        connection.execute("PRAGMA busy_timeout=30000")
        if not readonly:
            connection.execute("PRAGMA synchronous=FULL")
        return connection
    except sqlite3.Error as exc:
        if connection is not None:
            connection.close()
        raise _contract_error() from exc


def create_nonce_ledger_contract(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_identity: NonceLedgerFileIdentity,
) -> None:
    """Initialize an already exclusively-created empty database file."""

    validate_nonce_ledger_file_metadata(
        path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        expected_identity=expected_identity,
    )
    connection = _connect(path, readonly=False)
    try:
        validate_nonce_ledger_file_metadata(
            path,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            expected_identity=expected_identity,
        )
        journal_mode = connection.execute("PRAGMA journal_mode=DELETE").fetchone()
        if journal_mode != ("delete",):
            raise _contract_error()
        connection.execute("BEGIN EXCLUSIVE")
        connection.execute(NONCE_LEDGER_SCHEMA_SQL)
        connection.execute(f"PRAGMA application_id={NONCE_LEDGER_APPLICATION_ID}")
        connection.execute(f"PRAGMA user_version={NONCE_LEDGER_USER_VERSION}")
        connection.execute("COMMIT")
        validate_nonce_ledger_connection(connection)
        validate_nonce_ledger_file_metadata(
            path,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            expected_identity=expected_identity,
        )
    except NonceLedgerContractError:
        if connection.in_transaction:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        raise
    except sqlite3.Error as exc:
        if connection.in_transaction:
            try:
                connection.execute("ROLLBACK")
            except sqlite3.Error:
                pass
        raise _contract_error() from exc
    finally:
        connection.close()
    validate_nonce_ledger_file_metadata(
        path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        expected_identity=expected_identity,
    )
    validate_nonce_ledger_directory(path)


def validate_nonce_ledger_connection(connection: sqlite3.Connection) -> None:
    """Validate schema, indexes, persistent PRAGMAs, rows, and database integrity."""

    try:
        databases = tuple(connection.execute("PRAGMA database_list"))
        if len(databases) != 1 or databases[0][0:2] != (0, "main"):
            raise _contract_error()
        scalar_contract = (
            ("PRAGMA application_id", NONCE_LEDGER_APPLICATION_ID),
            ("PRAGMA user_version", NONCE_LEDGER_USER_VERSION),
            ("PRAGMA journal_mode", "delete"),
            ("PRAGMA locking_mode", "normal"),
            ("PRAGMA auto_vacuum", 0),
            ("PRAGMA encoding", "UTF-8"),
            ("PRAGMA read_uncommitted", 0),
            ("PRAGMA writable_schema", 0),
        )
        for query, expected in scalar_contract:
            row = connection.execute(query).fetchone()
            if row != (expected,):
                raise _contract_error()

        schema = tuple(
            connection.execute(
                "SELECT type, name, tbl_name, sql FROM sqlite_schema ORDER BY type, name"
            )
        )
        if schema != _EXPECTED_SCHEMA:
            raise _contract_error()
        if tuple(connection.execute("PRAGMA table_info(used_nonces)")) != _EXPECTED_TABLE_INFO:
            raise _contract_error()
        if tuple(connection.execute("PRAGMA table_xinfo(used_nonces)")) != _EXPECTED_TABLE_XINFO:
            raise _contract_error()
        if tuple(connection.execute("PRAGMA index_list(used_nonces)")) != _EXPECTED_INDEX_LIST:
            raise _contract_error()
        if (
            tuple(connection.execute("PRAGMA index_info(sqlite_autoindex_used_nonces_1)"))
            != _EXPECTED_INDEX_INFO
        ):
            raise _contract_error()
        if (
            tuple(connection.execute("PRAGMA index_xinfo(sqlite_autoindex_used_nonces_1)"))
            != _EXPECTED_INDEX_XINFO
        ):
            raise _contract_error()
        if tuple(connection.execute("PRAGMA foreign_key_list(used_nonces)")):
            raise _contract_error()
        if tuple(connection.execute("PRAGMA foreign_key_check")):
            raise _contract_error()
        if connection.execute("PRAGMA integrity_check(1)").fetchone() != ("ok",):
            raise _contract_error()
        invalid_row = connection.execute(
            "SELECT 1 FROM used_nonces WHERE "
            "typeof(nonce) != 'text' OR length(nonce) NOT BETWEEN 32 AND 128 "
            "OR nonce GLOB '*[^0-9a-f]*' OR typeof(reserved_at) != 'integer' "
            "OR reserved_at < 0 LIMIT 1"
        ).fetchone()
        duplicate = connection.execute(
            "SELECT 1 FROM used_nonces GROUP BY nonce HAVING count(*) != 1 LIMIT 1"
        ).fetchone()
        if invalid_row is not None or duplicate is not None:
            raise _contract_error()
    except NonceLedgerContractError:
        raise
    except sqlite3.Error as exc:
        raise _contract_error() from exc


def validate_existing_nonce_ledger(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
) -> NonceLedgerFileIdentity:
    """Read-only validation for an existing production ledger."""

    identity = validate_nonce_ledger_file_metadata(
        path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    validate_nonce_ledger_directory(path)
    connection = _connect(path, readonly=True)
    validation_error: NonceLedgerContractError | None = None
    try:
        validate_nonce_ledger_file_metadata(
            path,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            expected_identity=identity,
        )
        validate_nonce_ledger_connection(connection)
        validate_nonce_ledger_file_metadata(
            path,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            expected_identity=identity,
        )
    except NonceLedgerContractError as exc:
        validation_error = exc
    finally:
        connection.close()
    validate_nonce_ledger_file_metadata(
        path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        expected_identity=identity,
    )
    validate_nonce_ledger_directory(path)
    if validation_error is not None:
        raise validation_error
    return identity


def connect_existing_nonce_ledger_rw(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    expected_identity: NonceLedgerFileIdentity,
) -> sqlite3.Connection:
    """Open an existing validated ledger without permitting SQLite to create a replacement."""

    validate_nonce_ledger_file_metadata(
        path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        expected_identity=expected_identity,
    )
    connection = _connect(path, readonly=False)
    try:
        validate_nonce_ledger_file_metadata(
            path,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            expected_identity=expected_identity,
        )
    except Exception:
        connection.close()
        raise
    return connection
