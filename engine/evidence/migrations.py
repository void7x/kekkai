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


MIGRATION_001_SHA256 = "94728e3ee54941e419bf3f32c050ce2a5f771aeb2eeb72da5504ee456f6f47bd"


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


def _lock_file(path: Path):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    info = os.fstat(descriptor)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
        os.close(descriptor)
        raise MigrationError("Evidence lock must be a private regular file owned by the current user.")
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    return descriptor


def _atomic_backup(connection: sqlite3.Connection, backups_dir: Path) -> Path:
    """Create a verified, read-only SQLite online backup before a schema upgrade."""
    backups_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = backups_dir.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise MigrationError("Backup directory must be private and owned by the current user.")

    token = uuid.uuid4().hex[:12]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    final = backups_dir / f"kekkai-pre-migration-{stamp}-{token}.db"
    temporary = backups_dir / f".backup-{uuid.uuid4().hex}.tmp"
    descriptor = os.open(
        temporary,
        os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    os.close(descriptor)
    destination = None
    try:
        destination = sqlite3.connect(str(temporary), isolation_level=None)
        connection.backup(destination)
        result = destination.execute("PRAGMA integrity_check").fetchall()
        if result != [("ok",)]:
            raise MigrationError(f"Pre-migration backup failed integrity_check: {result!r}")
        destination.close()
        destination = None
        file_fd = os.open(temporary, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fchmod(file_fd, 0o400)
            os.fsync(file_fd)
        finally:
            os.close(file_fd)
        digest = _sha256_file(temporary)
        os.link(temporary, final, follow_symlinks=False)
        temporary.unlink()
        directory_fd = os.open(backups_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)

        sidecar_tmp = backups_dir / f".sidecar-{uuid.uuid4().hex}.tmp"
        sidecar_final = Path(str(final) + ".sha256")
        sidecar_fd = os.open(
            sidecar_tmp,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            os.write(sidecar_fd, f"{digest}  {final.name}\n".encode("ascii"))
            os.fchmod(sidecar_fd, 0o400)
            os.fsync(sidecar_fd)
        finally:
            os.close(sidecar_fd)
        os.link(sidecar_tmp, sidecar_final, follow_symlinks=False)
        sidecar_tmp.unlink()
        directory_fd = os.open(backups_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return final
    finally:
        if destination is not None:
            destination.close()
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


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


def run_migrations(evidence_root: str | Path) -> int:
    """Apply all known migrations atomically; return the final schema version."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise MigrationError("Refusing evidence migrations as root.")
    root = Path(evidence_root).expanduser().absolute()
    db_path = root / "db" / "kekkai.db"
    lock_path = root / "evidence.lock"
    backups_dir = root / "backups"

    lock_fd = _lock_file(lock_path)
    try:
        connection = open_database(db_path)
        try:
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
                current = versions[-1] if versions else 0
            user_version = connection.execute("PRAGMA user_version").fetchone()[0]
            if user_version != current:
                raise MigrationError(
                    f"PRAGMA user_version ({user_version}) does not match migration history ({current})."
                )

            pending = [item for item in MIGRATIONS if item.version > current]
            if current and pending:
                _atomic_backup(connection, backups_dir)
            for migration in pending:
                digest, statements = _load_migration(migration)
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
        fcntl.flock(lock_fd, fcntl.LOCK_UN)
        os.close(lock_fd)
