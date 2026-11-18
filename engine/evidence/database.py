"""Hardened SQLite connection and transaction helpers for KEKKAI evidence."""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator


MIN_SQLITE_VERSION = (3, 37, 0)
BUSY_TIMEOUT_MS = 5000


class EvidenceDatabaseError(RuntimeError):
    """Raised when the evidence database cannot be opened safely."""


def utc_now_iso() -> str:
    """Return a fixed-width UTC timestamp suitable for BINARY sorting."""
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def normalize_utc_timestamp(value: str, field_name: str = "timestamp") -> str:
    """Normalize an explicit UTC ISO-8601 timestamp to six fractional digits."""
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{field_name} must be an explicit UTC timestamp ending in 'Z'.")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError(f"{field_name} is not a valid ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must use UTC.")
    return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def canonical_json(value: object) -> str:
    """Serialize JSON deterministically, refusing NaN and infinity."""
    try:
        encoded = json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        )
        json.loads(encoded)
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError(f"Value is not valid JSON data: {exc}") from exc
    return encoded


def _reject_symlink_components(path: Path) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise EvidenceDatabaseError(f"Cannot inspect database path {current}: {exc}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise EvidenceDatabaseError(f"Database path contains a symlink: {current}")
    return absolute


def ensure_database_file(db_path: str | Path) -> Path:
    """Create a new database file as 0600, or validate an existing one."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise EvidenceDatabaseError("Refusing to operate the evidence database as root.")
    path = _reject_symlink_components(Path(db_path).expanduser())
    parent = path.parent
    try:
        parent_info = parent.stat(follow_symlinks=False)
    except OSError as exc:
        raise EvidenceDatabaseError(f"Cannot inspect database directory: {exc}") from exc
    if not stat.S_ISDIR(parent_info.st_mode):
        raise EvidenceDatabaseError("Database parent must be a real directory.")
    if parent_info.st_uid != os.getuid() or stat.S_IMODE(parent_info.st_mode) != 0o700:
        raise EvidenceDatabaseError("Database directory must be owned by the current user with mode 0700.")

    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        descriptor = None
    except OSError as exc:
        raise EvidenceDatabaseError(f"Cannot create evidence database securely: {exc}") from exc
    if descriptor is not None:
        try:
            os.fchmod(descriptor, 0o600)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            parent_fd = os.open(parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
        except OSError as exc:
            raise EvidenceDatabaseError(f"Cannot sync database directory: {exc}") from exc

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise EvidenceDatabaseError(f"Cannot safely open evidence database: {exc}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise EvidenceDatabaseError("Evidence database must be a regular file.")
        if info.st_uid != os.getuid():
            raise EvidenceDatabaseError("Evidence database must be owned by the current user.")
        if stat.S_IMODE(info.st_mode) != 0o600:
            raise EvidenceDatabaseError("Evidence database must have mode 0600.")
    finally:
        os.close(descriptor)
    return path


def open_database(db_path: str | Path) -> sqlite3.Connection:
    """Open a private file-backed database and enforce all connection PRAGMAs."""
    if sqlite3.sqlite_version_info < MIN_SQLITE_VERSION:
        raise EvidenceDatabaseError(
            f"SQLite >= {'.'.join(map(str, MIN_SQLITE_VERSION))} is required; "
            f"found {sqlite3.sqlite_version}."
        )
    path = ensure_database_file(db_path)
    try:
        connection = sqlite3.connect(
            str(path), timeout=BUSY_TIMEOUT_MS / 1000,
            isolation_level=None, detect_types=0,
        )
    except sqlite3.Error as exc:
        raise EvidenceDatabaseError(f"Cannot open evidence database: {exc}") from exc

    try:
        # Keep this order: trusted_schema is disabled before schema content is used.
        connection.execute("PRAGMA trusted_schema = OFF")
        if connection.execute("PRAGMA trusted_schema").fetchone() != (0,):
            raise EvidenceDatabaseError("SQLite trusted_schema could not be disabled.")

        connection.execute("PRAGMA cell_size_check = ON")
        if connection.execute("PRAGMA cell_size_check").fetchone() != (1,):
            raise EvidenceDatabaseError("SQLite cell_size_check could not be enabled.")

        connection.execute(f"PRAGMA busy_timeout = {BUSY_TIMEOUT_MS}")
        if connection.execute("PRAGMA busy_timeout").fetchone() != (BUSY_TIMEOUT_MS,):
            raise EvidenceDatabaseError("SQLite busy_timeout could not be configured.")

        connection.execute("PRAGMA foreign_keys = ON")
        if connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
            raise EvidenceDatabaseError("SQLite foreign-key enforcement could not be enabled.")

        journal_mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
        if not journal_mode or str(journal_mode[0]).casefold() != "wal":
            raise EvidenceDatabaseError("SQLite refused WAL journal mode.")

        connection.execute("PRAGMA synchronous = FULL")
        if connection.execute("PRAGMA synchronous").fetchone() != (2,):
            raise EvidenceDatabaseError("SQLite synchronous=FULL could not be configured.")
        return connection
    except BaseException:
        connection.close()
        raise


@contextlib.contextmanager
def immediate_transaction(
    connection: sqlite3.Connection,
) -> Iterator[sqlite3.Connection]:
    """Run an explicit BEGIN IMMEDIATE transaction with BaseException rollback."""
    if connection.in_transaction:
        raise EvidenceDatabaseError("Cannot nest BEGIN IMMEDIATE on an active transaction.")
    connection.execute("BEGIN IMMEDIATE")
    try:
        yield connection
    except BaseException:
        if connection.in_transaction:
            connection.execute("ROLLBACK")
        raise
    else:
        try:
            connection.execute("COMMIT")
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
