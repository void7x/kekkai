"""Checksum-pinned, transactional SQLite migrations for KEKKAI evidence."""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import sqlite3
import stat
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .database import EvidenceDatabaseError, immediate_transaction, open_database, utc_now_iso
from .store import EvidenceStoreError, _open_directory_path


MIGRATION_001_SHA256 = "732097720fba2a367a2278f8c34384294ea75676deecfc6c198464a78208d87f"
MIGRATION_002_SHA256 = "c7d66bbd5c36fcdff576fd3461e9457b61b384a17fbc3114d0cd1e663513c0d7"
DEFAULT_MIN_FREE_RESERVE_BYTES = 64 * 1024 * 1024
SQLITE_WAL_HEADROOM_BYTES = 4 * 1024 * 1024
MIN_FREE_INODES = 64


class MigrationError(RuntimeError):
    """Raised when migration history or a schema update is unsafe."""


@dataclass(frozen=True)
class Migration:
    version: int
    name: str
    path: Path
    checksum_sha256: str


MIGRATIONS = (
    Migration(
        version=1,
        name="001_initial_evidence_schema",
        path=Path(__file__).with_name("sql") / "001_initial_evidence_schema.sql",
        checksum_sha256=MIGRATION_001_SHA256,
    ),
    Migration(
        version=2,
        name="002_sanitizer_runs",
        path=Path(__file__).with_name("sql") / "002_sanitizer_runs.sql",
        checksum_sha256=MIGRATION_002_SHA256,
    ),
)


def split_sql_statements(script: str) -> tuple[str, ...]:
    """Split SQL using SQLite's parser, preserving CREATE TRIGGER bodies."""
    statements: list[str] = []
    pending = ""
    for line in script.splitlines(keepends=True):
        pending += line
        if sqlite3.complete_statement(pending):
            statement = pending.strip()
            pending = ""
            if not statement:
                continue
            _reject_transaction_control(statement)
            statements.append(statement)
    if pending.strip():
        raise MigrationError("Migration SQL ends with an incomplete statement.")
    return tuple(statements)


def _reject_transaction_control(statement: str) -> None:
    """Reject top-level statements that could escape migration transaction control."""
    without_leading_comments = statement
    while True:
        stripped = without_leading_comments.lstrip()
        if stripped.startswith("--"):
            newline = stripped.find("\n")
            if newline < 0:
                return
            without_leading_comments = stripped[newline + 1 :]
            continue
        if stripped.startswith("/*"):
            end = stripped.find("*/", 2)
            if end < 0:
                raise MigrationError("Unterminated SQL comment in migration.")
            without_leading_comments = stripped[end + 2 :]
            continue
        break
    match = re.match(r"([A-Za-z]+)", without_leading_comments.lstrip())
    if match and match.group(1).upper() in {
        "BEGIN", "COMMIT", "END", "ROLLBACK", "SAVEPOINT", "RELEASE",
        "VACUUM", "ATTACH", "DETACH", "PRAGMA",
    }:
        raise MigrationError(
            f"Migration contains forbidden transaction-control statement: {match.group(1)}"
        )


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _lock_file(path: Path, *, parent_fd: int | None = None):
    """Open and exclusively lock the evidence lock file without following links."""
    if parent_fd is None:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        target = path
    else:
        target = path.name
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(target, flags, 0o600, dir_fd=parent_fd)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        os.close(descriptor)
        raise MigrationError("Evidence lock must be a private regular file owned by the current user.")
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    return descriptor


def _regular_file_size(path: Path, *, missing_ok: bool = False) -> int:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except FileNotFoundError:
        if missing_ok:
            return 0
        raise
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            raise MigrationError(f"Backup input is not a regular user-owned file: {path.name}")
        return info.st_size
    finally:
        os.close(descriptor)


def _sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    os.lseek(descriptor, 0, os.SEEK_SET)
    while True:
        chunk = os.read(descriptor, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _write_all(descriptor: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError("Short write while creating migration backup sidecar.")
        view = view[written:]


def _atomic_backup(
    connection: sqlite3.Connection,
    backups_dir: Path,
    db_path: Path,
    *,
    min_free_reserve_bytes: int = DEFAULT_MIN_FREE_RESERVE_BYTES,
) -> Path:
    """Create a verified, read-only SQLite online backup before a schema upgrade."""
    if min_free_reserve_bytes < 0:
        raise ValueError("min_free_reserve_bytes cannot be negative.")
    backups_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    directory_fd = os.open(
        backups_dir,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        info = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise MigrationError("Backup directory must be private and owned by the current user.")
        capacity = os.fstatvfs(directory_fd)
        database_bytes = _regular_file_size(db_path)
        wal_bytes = _regular_file_size(Path(str(db_path) + "-wal"), missing_ok=True)
        required_bytes = (
            min_free_reserve_bytes
            + 2 * (database_bytes + wal_bytes)
            + SQLITE_WAL_HEADROOM_BYTES
        )
        available_bytes = capacity.f_bavail * capacity.f_frsize
        if available_bytes < required_bytes:
            raise MigrationError(
                f"Insufficient free space for pre-migration backup: need {required_bytes} bytes, "
                f"have {available_bytes}."
            )
        available_inodes = getattr(capacity, "f_favail", -1)
        if available_inodes >= 0 and available_inodes < MIN_FREE_INODES:
            raise MigrationError("Insufficient free inodes for pre-migration backup; need at least 64.")

        token = uuid.uuid4().hex[:12]
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        final = backups_dir / f"kekkai-pre-migration-{stamp}-{token}.db"
        temporary = backups_dir / f".backup-{uuid.uuid4().hex}.tmp"
        sidecar_tmp: Path | None = None
        backup_linked = False
        sidecar_linked = False
        destination = None
        descriptor = os.open(
            temporary,
            os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        os.close(descriptor)
        try:
            destination = sqlite3.connect(str(temporary), isolation_level=None)
            connection.backup(destination)
            result = destination.execute("PRAGMA integrity_check").fetchall()
            if result != [("ok",)]:
                raise MigrationError(f"Pre-migration backup failed integrity_check: {result!r}")
            destination.close()
            destination = None

            file_fd = os.open(
                temporary,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                os.fchmod(file_fd, 0o400)
                os.fsync(file_fd)
                digest = _sha256_descriptor(file_fd)
            finally:
                os.close(file_fd)

            os.link(temporary, final, follow_symlinks=False)
            backup_linked = True
            temporary.unlink()
            os.fsync(directory_fd)

            sidecar_tmp = backups_dir / f".sidecar-{uuid.uuid4().hex}.tmp"
            sidecar_final = Path(str(final) + ".sha256")
            sidecar_fd = os.open(
                sidecar_tmp,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                _write_all(sidecar_fd, f"{digest}  {final.name}\n".encode("ascii"))
                os.fchmod(sidecar_fd, 0o400)
                os.fsync(sidecar_fd)
            finally:
                os.close(sidecar_fd)
            os.link(sidecar_tmp, sidecar_final, follow_symlinks=False)
            sidecar_linked = True
            sidecar_tmp.unlink()
            sidecar_tmp = None
            os.fsync(directory_fd)
            return final
        finally:
            if destination is not None:
                destination.close()
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            if sidecar_tmp is not None:
                try:
                    sidecar_tmp.unlink()
                except FileNotFoundError:
                    pass
            if backup_linked and not sidecar_linked:
                try:
                    final.unlink()
                    os.fsync(directory_fd)
                except FileNotFoundError:
                    pass
    finally:
        os.close(directory_fd)

def _load_migration(migration: Migration) -> tuple[str, tuple[str, ...]]:
    try:
        raw = migration.path.read_bytes()
    except OSError as exc:
        raise MigrationError(f"Cannot read migration {migration.name}: {exc}") from exc
    digest = hashlib.sha256(raw).hexdigest()
    if digest != migration.checksum_sha256:
        raise MigrationError(f"Migration checksum mismatch: {migration.name}.")
    try:
        sql = raw.decode("utf-8")
    except UnicodeError as exc:
        raise MigrationError(f"Migration is not UTF-8: {migration.name}.") from exc
    return digest, split_sql_statements(sql)


def run_migrations(
    evidence_root: str | Path,
    *,
    min_free_reserve_bytes: int = DEFAULT_MIN_FREE_RESERVE_BYTES,
) -> int:
    """Apply all known migrations atomically; return the final schema version."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise MigrationError("Refusing evidence migrations as root.")
    if min_free_reserve_bytes < 0:
        raise ValueError("min_free_reserve_bytes cannot be negative.")
    root = Path(os.path.abspath(Path(evidence_root).expanduser()))
    project_root = Path(__file__).resolve().parents[2]
    if (
        root == project_root
        or root in project_root.parents
        or project_root in root.parents
    ):
        raise MigrationError("Evidence store must be outside the repository checkout.")
    db_path = root / "db" / "kekkai.db"
    lock_path = root / "evidence.lock"
    backups_dir = root / "backups"

    try:
        root_fd = _open_directory_path(root, create=False)
    except EvidenceStoreError as exc:
        raise MigrationError(f"Evidence root is unsafe: {exc}") from exc
    lock_fd = None
    try:
        lock_fd = _lock_file(lock_path, parent_fd=root_fd)
        connection = open_database(db_path)
        try:
            loaded_migrations = {
                item.version: _load_migration(item) for item in MIGRATIONS
            }
            quick = connection.execute("PRAGMA quick_check").fetchall()
            if quick != [("ok",)]:
                raise MigrationError(f"Evidence database quick_check failed: {quick!r}")
            has_history = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
            ).fetchone() is not None
            if not has_history:
                if connection.execute("PRAGMA user_version").fetchone() != (0,):
                    raise MigrationError("Database has a user_version but no migration history.")
                current = 0
            else:
                rows = connection.execute(
                    "SELECT version, name, checksum_sha256 FROM schema_migrations ORDER BY version"
                ).fetchall()
                if not rows:
                    raise MigrationError("Migration history table exists but is empty.")
                versions = [row[0] for row in rows]
                if versions != list(range(1, len(versions) + 1)):
                    raise MigrationError("Applied migration versions are not contiguous.")
                known = {item.version: item for item in MIGRATIONS}
                for version, name, checksum in rows:
                    migration = known.get(version)
                    if migration is None:
                        raise MigrationError(f"Database schema version {version} is newer than this code.")
                    if name != migration.name or checksum != migration.checksum_sha256:
                        raise MigrationError(f"Applied migration history mismatch at version {version}.")
                current = versions[-1]
            user_version = connection.execute("PRAGMA user_version").fetchone()[0]
            if user_version != current:
                raise MigrationError(
                    f"PRAGMA user_version ({user_version}) does not match migration history ({current})."
                )

            pending = [item for item in MIGRATIONS if item.version > current]
            if current and pending:
                try:
                    _atomic_backup(
                        connection, backups_dir, db_path,
                        min_free_reserve_bytes=min_free_reserve_bytes,
                    )
                except (OSError, sqlite3.Error) as exc:
                    if isinstance(exc, MigrationError):
                        raise
                    raise MigrationError(f"Pre-migration backup failed: {exc}") from exc
            for migration in pending:
                digest, statements = loaded_migrations[migration.version]
                try:
                    with immediate_transaction(connection):
                        for statement in statements:
                            connection.execute(statement)
                        fk_errors = connection.execute("PRAGMA foreign_key_check").fetchall()
                        if fk_errors:
                            raise MigrationError(f"Migration created foreign-key violations: {fk_errors!r}")
                        connection.execute(
                            "INSERT INTO schema_migrations(version, name, checksum_sha256, applied_at) VALUES (?, ?, ?, ?)",
                            (migration.version, migration.name, digest, utc_now_iso()),
                        )
                        connection.execute(f"PRAGMA user_version = {migration.version}")
                except (sqlite3.Error, EvidenceDatabaseError) as exc:
                    if isinstance(exc, MigrationError):
                        raise
                    raise MigrationError(f"Migration {migration.name} failed: {exc}") from exc
                if connection.execute("PRAGMA foreign_keys").fetchone() != (1,):
                    raise MigrationError("Foreign-key enforcement was disabled during migration.")
                if connection.execute("PRAGMA user_version").fetchone() != (migration.version,):
                    raise MigrationError("SQLite user_version did not commit with the migration.")
                current = migration.version
            return current
        finally:
            connection.close()
    finally:
        if lock_fd is not None:
            fcntl.flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        os.close(root_fd)
