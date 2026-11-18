"""Content-addressed, immutable filesystem artifact storage for KEKKAI."""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import os
import stat
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


MAX_ARTIFACT_BYTES = 16 * 1024 * 1024
SQLITE_WAL_HEADROOM_BYTES = 4 * 1024 * 1024
DEFAULT_MIN_FREE_RESERVE_BYTES = 64 * 1024 * 1024
MIN_FREE_INODES = 64


class EvidenceStoreError(RuntimeError):
    """Raised when the evidence store cannot be used safely."""


class EvidenceIntegrityError(EvidenceStoreError):
    """Raised when stored evidence fails an integrity or ownership check."""


@dataclass(frozen=True)
class StoredArtifact:
    sha256: str
    size_bytes: int
    storage_relpath: str
    path: Path


@dataclass(frozen=True)
class StoreVerification:
    verified_count: int
    missing: tuple[str, ...]
    corrupt: tuple[str, ...]
    unreferenced: tuple[str, ...]
    stale_staging: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not (self.missing or self.corrupt or self.unreferenced or self.stale_staging)


def _open_directory_path(path: Path, *, create: bool, final_mode: int | None = 0o700) -> int:
    """Open an absolute directory without following any symlink component."""
    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.is_absolute():
        raise EvidenceStoreError("Evidence store path must be absolute.")
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(absolute.anchor, flags)
    parts = absolute.parts[1:]
    try:
        for index, part in enumerate(parts):
            is_final = index == len(parts) - 1
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise EvidenceStoreError(f"Evidence directory does not exist: {absolute}")
                os.mkdir(part, (final_mode if final_mode is not None else 0o700) if is_final else 0o700, dir_fd=descriptor)
                os.fsync(descriptor)
                child = os.open(part, flags, dir_fd=descriptor)
                if is_final and final_mode is not None:
                    os.fchmod(child, final_mode)
            info = os.fstat(child)
            if not stat.S_ISDIR(info.st_mode):
                os.close(child)
                raise EvidenceStoreError(f"Evidence path component is not a directory: {part}")
            if is_final and final_mode is not None and (
                info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != final_mode
            ):
                os.close(child)
                raise EvidenceStoreError(
                    f"Evidence root must be owned by the current user with mode {final_mode:04o}."
                )
            os.close(descriptor)
            descriptor = child
        if not parts:
            raise EvidenceStoreError("Filesystem root cannot be used as an evidence store.")
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise EvidenceStoreError(f"Cannot safely traverse evidence directory {absolute}: {exc}") from exc
    except BaseException:
        os.close(descriptor)
        raise


def _open_or_create_child(parent_fd: int, name: str, *, mode: int = 0o700) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        child = os.open(name, flags, dir_fd=parent_fd)
    except FileNotFoundError:
        os.mkdir(name, mode, dir_fd=parent_fd)
        os.fsync(parent_fd)
        child = os.open(name, flags, dir_fd=parent_fd)
    info = os.fstat(child)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != mode
    ):
        os.close(child)
        raise EvidenceStoreError(f"Evidence directory {name!r} must be owned by the current user with mode {mode:04o}.")
    return child


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("Short write while publishing evidence artifact.")
        view = view[written:]


class EvidenceStore:
    """Private content-addressed store using descriptor-relative POSIX operations.

    The lock serializes publication and recovery. The same-UID threat boundary is
    explicit: filesystem modes and SQLite triggers prevent accidental changes,
    not deliberate tampering by a process with the owner's UID.
    """

    def __init__(
        self,
        evidence_root: str | Path,
        *,
        max_artifact_bytes: int = MAX_ARTIFACT_BYTES,
        min_free_reserve_bytes: int = DEFAULT_MIN_FREE_RESERVE_BYTES,
        protected_paths: tuple[str | Path, ...] = (),
    ) -> None:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            raise EvidenceStoreError("Refusing to initialize the evidence store as root.")
        if not 1 <= max_artifact_bytes <= MAX_ARTIFACT_BYTES:
            raise ValueError(f"max_artifact_bytes must be between 1 and {MAX_ARTIFACT_BYTES}.")
        if min_free_reserve_bytes < 0:
            raise ValueError("min_free_reserve_bytes cannot be negative.")
        raw_root = Path(evidence_root).expanduser()
        if not raw_root.is_absolute():
            raise EvidenceStoreError("evidence_root must be an absolute path.")
        normalized_root = Path(os.path.abspath(raw_root))
        for protected in protected_paths:
            candidate = Path(os.path.abspath(Path(protected).expanduser()))
            if (
                normalized_root == candidate
                or normalized_root in candidate.parents
                or candidate in normalized_root.parents
            ):
                raise EvidenceStoreError(f"Evidence root overlaps a protected path: {candidate}")

        self.root = normalized_root
        self.max_artifact_bytes = max_artifact_bytes
        self.min_free_reserve_bytes = min_free_reserve_bytes
        self._root_fd = _open_directory_path(self.root, create=True)
        self._fds: list[int] = [self._root_fd]
        try:
            self.db_fd = self._child("db")
            self.backups_fd = self._child("backups")
            self.staging_fd = self._child("staging")
            self.objects_fd = self._child("objects")
            self.objects_sha256_fd = self._child_from(self.objects_fd, "sha256")
            devices = {
                os.fstat(fd).st_dev
                for fd in (self.db_fd, self.staging_fd, self.objects_sha256_fd, self.backups_fd)
            }
            if len(devices) != 1:
                raise EvidenceStoreError("Database, staging, objects and backups must share one filesystem.")
            self._expected_dev = devices.pop()
            self.database_path = self.root / "db" / "kekkai.db"
            self.lock_path = self.root / "evidence.lock"
            self._ensure_store_version()
            self._lock_fd = self._open_private_file(self._root_fd, "evidence.lock", 0o600)
            self._fds.append(self._lock_fd)
            self._ensure_database_file()
            with self._exclusive_lock():
                self._remove_stale_staging()
        except BaseException:
            self.close()
            raise

    def _child(self, name: str) -> int:
        descriptor = _open_or_create_child(self._root_fd, name)
        self._fds.append(descriptor)
        return descriptor

    def _child_from(self, parent_fd: int, name: str) -> int:
        descriptor = _open_or_create_child(parent_fd, name)
        self._fds.append(descriptor)
        return descriptor

    @staticmethod
    def _open_private_file(parent_fd: int, name: str, mode: int) -> int:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        try:
            descriptor = os.open(name, flags, mode, dir_fd=parent_fd)
        except OSError as exc:
            raise EvidenceStoreError(f"Cannot safely open {name}: {exc}") from exc
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != mode:
            os.close(descriptor)
            raise EvidenceStoreError(f"{name} must be a private regular file with mode {mode:04o}.")
        return descriptor

    def _ensure_store_version(self) -> None:
        try:
            descriptor = os.open(
                "STORE_VERSION",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o400,
                dir_fd=self._root_fd,
            )
        except FileExistsError:
            descriptor = os.open(
                "STORE_VERSION", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=self._root_fd
            )
            try:
                info = os.fstat(descriptor)
                content = os.read(descriptor, 32)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o400
                    or content != b"1\n"
                ):
                    raise EvidenceStoreError("STORE_VERSION is invalid or has unsafe permissions.")
            finally:
                os.close(descriptor)
            return
        try:
            _write_all(descriptor, b"1\n")
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(self._root_fd)

    def _ensure_database_file(self) -> None:
        try:
            descriptor = os.open(
                "kekkai.db",
                os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=self.db_fd,
            )
        except FileExistsError:
            descriptor = os.open(
                "kekkai.db", os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0), dir_fd=self.db_fd
            )
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600:
                raise EvidenceStoreError("kekkai.db must be a regular file owned by the current user with mode 0600.")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.fsync(self.db_fd)

    @contextlib.contextmanager
    def _exclusive_lock(self) -> Iterator[None]:
        fcntl.flock(self._lock_fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(self._lock_fd, fcntl.LOCK_UN)

    def _remove_stale_staging(self) -> None:
        removed = False
        for name in os.listdir(self.staging_fd):
            if not (name.startswith(".ingest-") and name.endswith(".tmp")):
                continue
            info = os.stat(name, dir_fd=self.staging_fd, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise EvidenceIntegrityError(f"Unsafe stale staging entry: {name}")
            os.unlink(name, dir_fd=self.staging_fd)
            removed = True
        if removed:
            os.fsync(self.staging_fd)

    def _check_capacity(self, candidate_size: int) -> None:
        info = os.fstatvfs(self._root_fd)
        required = self.min_free_reserve_bytes + (2 * candidate_size) + SQLITE_WAL_HEADROOM_BYTES
        available = info.f_bavail * info.f_frsize
        if available < required:
            raise EvidenceStoreError(
                f"Evidence filesystem reserve insufficient: need {required} bytes, have {available}."
            )
        available_inodes = getattr(info, "f_favail", -1)
        total_inodes = getattr(info, "f_files", 0)
        if total_inodes > 0 and available_inodes >= 0 and available_inodes < MIN_FREE_INODES:
            raise EvidenceStoreError("Evidence filesystem has fewer than 64 free inodes.")

    def _open_shard(self, digest: str, *, create: bool) -> tuple[int, int]:
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("Artifact SHA-256 must be 64 lowercase hexadecimal characters.")
        first, second = digest[:2], digest[2:4]
        if create:
            try:
                os.mkdir(first, 0o700, dir_fd=self.objects_sha256_fd)
                os.fsync(self.objects_sha256_fd)
            except FileExistsError:
                pass
        try:
            first_fd = os.open(
                first,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self.objects_sha256_fd,
            )
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise EvidenceIntegrityError(f"First-level artifact shard is unsafe: {first}") from exc
        info = os.fstat(first_fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700 or info.st_dev != self._expected_dev:
            os.close(first_fd)
            raise EvidenceIntegrityError("First-level artifact shard is unsafe.")
        try:
            if create:
                try:
                    os.mkdir(second, 0o700, dir_fd=first_fd)
                    os.fsync(first_fd)
                except FileExistsError:
                    pass
            try:
                second_fd = os.open(
                    second,
                    os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=first_fd,
                )
            except FileNotFoundError:
                raise
            except OSError as exc:
                raise EvidenceIntegrityError(f"Second-level artifact shard is unsafe: {second}") from exc
            info = os.fstat(second_fd)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700 or info.st_dev != self._expected_dev:
                os.close(second_fd)
                raise EvidenceIntegrityError("Second-level artifact shard is unsafe.")
            return first_fd, second_fd
        except BaseException:
            os.close(first_fd)
            raise

    def _verify_object(self, shard_fd: int, digest: str, expected_size: int | None = None) -> StoredArtifact:
        name = digest + ".bin"
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=shard_fd,
            )
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise EvidenceIntegrityError(f"Artifact object cannot be opened safely: {name}") from exc
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o400
                or info.st_nlink != 1
                or (expected_size is not None and info.st_size != expected_size)
                or info.st_size < 0
                or info.st_size > self.max_artifact_bytes
            ):
                raise EvidenceIntegrityError(f"Artifact object metadata is invalid: {name}")
            hasher = hashlib.sha256()
            observed = 0
            os.lseek(descriptor, 0, os.SEEK_SET)
            while True:
                chunk = os.read(descriptor, 1024 * 1024)
                if not chunk:
                    break
                observed += len(chunk)
                hasher.update(chunk)
            if observed != info.st_size or hasher.hexdigest() != digest:
                raise EvidenceIntegrityError(f"Artifact content hash mismatch: {name}")
        finally:
            os.close(descriptor)
        relpath = f"objects/sha256/{digest[:2]}/{digest[2:4]}/{digest}.bin"
        return StoredArtifact(digest, info.st_size, relpath, self.root / relpath)

    def publish_bytes(self, content: bytes) -> StoredArtifact:
        """Publish a byte sequence as a content-addressed immutable object."""
        if not isinstance(content, bytes):
            raise TypeError("content must be bytes")
        if len(content) > self.max_artifact_bytes:
            raise EvidenceStoreError("Artifact exceeds the configured maximum size.")
        with self._exclusive_lock():
            self._check_capacity(len(content))
            digest = hashlib.sha256(content).hexdigest()
            temp_name = f".ingest-{uuid.uuid4().hex}.tmp"
            stage_fd = os.open(
                temp_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                0o600,
                dir_fd=self.staging_fd,
            )
            first_fd = second_fd = None
            try:
                _write_all(stage_fd, content)
                os.fchmod(stage_fd, 0o400)
                os.fsync(stage_fd)
                first_fd, second_fd = self._open_shard(digest, create=True)
                try:
                    os.link(
                        temp_name, digest + ".bin",
                        src_dir_fd=self.staging_fd, dst_dir_fd=second_fd,
                        follow_symlinks=False,
                    )
                    os.fsync(second_fd)
                except FileExistsError:
                    pass
            finally:
                os.close(stage_fd)
                try:
                    os.unlink(temp_name, dir_fd=self.staging_fd)
                except FileNotFoundError:
                    pass
                os.fsync(self.staging_fd)
            try:
                return self._verify_object(second_fd, digest, len(content))
            finally:
                if second_fd is not None:
                    os.close(second_fd)
                if first_fd is not None:
                    os.close(first_fd)

    def publish_file(self, source_path: str | Path) -> StoredArtifact:
        """Copy a regular source file into staging, hash, then publish without overwrite."""
        source = Path(source_path).expanduser()
        if not source.is_absolute():
            raise EvidenceStoreError("Source artifact path must be absolute.")
        parent_fd = _open_directory_path(source.parent, create=False, final_mode=None)
        source_fd = None
        try:
            source_fd = os.open(
                source.name,
                os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
            before = os.fstat(source_fd)
            if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid():
                raise EvidenceStoreError("Source artifact must be a regular file owned by the current user.")
            if before.st_size < 0 or before.st_size > self.max_artifact_bytes:
                raise EvidenceStoreError("Source artifact exceeds the configured size limit.")
            with self._exclusive_lock():
                self._check_capacity(before.st_size)
                temp_name = f".ingest-{uuid.uuid4().hex}.tmp"
                stage_fd = os.open(
                    temp_name,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                    0o600,
                    dir_fd=self.staging_fd,
                )
                first_fd = second_fd = None
                try:
                    hasher = hashlib.sha256()
                    total = 0
                    while True:
                        chunk = os.read(source_fd, 1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > self.max_artifact_bytes:
                            raise EvidenceStoreError("Source grew beyond the artifact size limit while reading.")
                        hasher.update(chunk)
                        _write_all(stage_fd, chunk)
                    after = os.fstat(source_fd)
                    stable_before = (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                    stable_after = (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                    if total != before.st_size or stable_before != stable_after:
                        raise EvidenceStoreError("Source artifact changed while it was being copied.")
                    digest = hasher.hexdigest()
                    os.fchmod(stage_fd, 0o400)
                    os.fsync(stage_fd)
                    first_fd, second_fd = self._open_shard(digest, create=True)
                    try:
                        os.link(
                            temp_name, digest + ".bin",
                            src_dir_fd=self.staging_fd, dst_dir_fd=second_fd,
                            follow_symlinks=False,
                        )
                        os.fsync(second_fd)
                    except FileExistsError:
                        pass
                finally:
                    os.close(stage_fd)
                    try:
                        os.unlink(temp_name, dir_fd=self.staging_fd)
                    except FileNotFoundError:
                        pass
                    os.fsync(self.staging_fd)
                try:
                    return self._verify_object(second_fd, digest, total)
                finally:
                    if second_fd is not None:
                        os.close(second_fd)
                    if first_fd is not None:
                        os.close(first_fd)
        except OSError as exc:
            if isinstance(exc, EvidenceStoreError):
                raise
            raise EvidenceStoreError(f"Cannot publish source artifact: {exc}") from exc
        finally:
            if source_fd is not None:
                os.close(source_fd)
            os.close(parent_fd)

    def read_verified_artifact(self, digest: str) -> bytes:
        """Return artifact bytes only after verifying the exact opened inode."""
        with self._exclusive_lock():
            first_fd, second_fd = self._open_shard(digest, create=False)
            try:
                descriptor = os.open(
                    digest + ".bin",
                    os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
                    dir_fd=second_fd,
                )
                try:
                    info = os.fstat(descriptor)
                    if (
                        not stat.S_ISREG(info.st_mode)
                        or info.st_uid != os.getuid()
                        or stat.S_IMODE(info.st_mode) != 0o400
                        or info.st_nlink != 1
                        or info.st_size < 0
                        or info.st_size > self.max_artifact_bytes
                    ):
                        raise EvidenceIntegrityError("Artifact metadata is unsafe during read.")
                    chunks: list[bytes] = []
                    hasher = hashlib.sha256()
                    total = 0
                    while True:
                        chunk = os.read(descriptor, 1024 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        hasher.update(chunk)
                        chunks.append(chunk)
                    if total != info.st_size or hasher.hexdigest() != digest:
                        raise EvidenceIntegrityError("Artifact content hash mismatch during read.")
                    return b"".join(chunks)
                finally:
                    os.close(descriptor)
            finally:
                os.close(second_fd)
                os.close(first_fd)

    def verify_evidence_store(self, connection) -> StoreVerification:
        """Compare registered artifact rows with immutable objects under the store lock."""
        with self._exclusive_lock():
            rows = connection.execute(
                "SELECT sha256, size_bytes FROM artifacts ORDER BY sha256"
            ).fetchall()
            expected = {row[0]: row[1] for row in rows}
            missing: list[str] = []
            corrupt: list[str] = []
            verified = 0
            for digest, size in expected.items():
                try:
                    first_fd, second_fd = self._open_shard(digest, create=False)
                    try:
                        self._verify_object(second_fd, digest, size)
                    finally:
                        os.close(second_fd)
                        os.close(first_fd)
                    verified += 1
                except FileNotFoundError:
                    missing.append(digest)
                except (OSError, EvidenceIntegrityError, ValueError):
                    corrupt.append(digest)

            def valid_shard(name: str, info: os.stat_result) -> bool:
                return (
                    len(name) == 2
                    and all(char in "0123456789abcdef" for char in name)
                    and stat.S_ISDIR(info.st_mode)
                    and info.st_uid == os.getuid()
                    and stat.S_IMODE(info.st_mode) == 0o700
                    and info.st_dev == self._expected_dev
                )

            unreferenced: list[str] = []
            for first in sorted(os.listdir(self.objects_sha256_fd)):
                first_info = os.stat(
                    first, dir_fd=self.objects_sha256_fd, follow_symlinks=False
                )
                if not valid_shard(first, first_info):
                    corrupt.append(first)
                    continue
                try:
                    first_fd = os.open(
                        first,
                        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                        | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=self.objects_sha256_fd,
                    )
                except OSError:
                    corrupt.append(first)
                    continue
                try:
                    for second in sorted(os.listdir(first_fd)):
                        second_info = os.stat(
                            second, dir_fd=first_fd, follow_symlinks=False
                        )
                        if not valid_shard(second, second_info):
                            corrupt.append(f"{first}/{second}")
                            continue
                        try:
                            second_fd = os.open(
                                second,
                                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                                | getattr(os, "O_NOFOLLOW", 0),
                                dir_fd=first_fd,
                            )
                        except OSError:
                            corrupt.append(f"{first}/{second}")
                            continue
                        try:
                            for filename in sorted(os.listdir(second_fd)):
                                digest = filename[:-4] if filename.endswith(".bin") else ""
                                canonical_location = (
                                    len(digest) == 64
                                    and all(char in "0123456789abcdef" for char in digest)
                                    and digest in expected
                                    and filename == digest + ".bin"
                                    and first == digest[:2]
                                    and second == digest[2:4]
                                )
                                if not canonical_location:
                                    unreferenced.append(
                                        f"{first}/{second}/{filename}"
                                    )
                        finally:
                            os.close(second_fd)
                finally:
                    os.close(first_fd)

            stale = tuple(sorted(os.listdir(self.staging_fd)))
            return StoreVerification(
                verified_count=verified,
                missing=tuple(missing),
                corrupt=tuple(corrupt),
                unreferenced=tuple(unreferenced),
                stale_staging=stale,
            )

    def close(self) -> None:
        """Close all retained directory descriptors."""
        for descriptor in reversed(getattr(self, "_fds", [])):
            try:
                os.close(descriptor)
            except OSError:
                pass
        self._fds = []

    def __enter__(self) -> "EvidenceStore":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()
