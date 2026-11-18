"""Stable, bounded identities for the seed corpus used by an AFL++ campaign."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path


MAX_SEED_ENTRIES = 4096
MAX_SEED_TOTAL_BYTES = 512 * 1024 * 1024
MAX_IDENTITY_FILE_BYTES = 1024 * 1024


class SeedManifestError(ValueError):
    """Raised when a seed corpus or identity file cannot be hashed safely."""


@dataclass(frozen=True)
class SeedManifest:
    sha256: str
    seed_count: int
    total_bytes: int
    entries: tuple[tuple[str, int, str], ...]


@dataclass(frozen=True)
class StableFileHash:
    sha256: str
    size_bytes: int
    snapshot: tuple[int, int, int, int, int]


def _snapshot(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _open_directory(path: str | Path) -> int:
    absolute = Path(os.path.abspath(os.fspath(Path(path).expanduser())))
    if not absolute.is_absolute():
        raise SeedManifestError("Directory path must be absolute.")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(absolute.anchor, flags)
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            info = os.fstat(child)
            if not stat.S_ISDIR(info.st_mode):
                os.close(child)
                raise SeedManifestError(f"Path component is not a directory: {part}")
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid():
            raise SeedManifestError("Directory must be owned by the current user.")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def hash_stable_file(
    path: str | Path,
    *,
    max_bytes: int = MAX_IDENTITY_FILE_BYTES,
) -> StableFileHash:
    """Hash one regular user-owned file without following links or tolerating races."""
    source = Path(path).expanduser()
    if not source.is_absolute():
        raise SeedManifestError("Identity file path must be absolute.")
    parent_fd = _open_directory(source.parent)
    descriptor = None
    try:
        descriptor = os.open(
            source.name,
            os.O_RDONLY
            | getattr(os, "O_NONBLOCK", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid():
            raise SeedManifestError("Identity input must be a regular user-owned file.")
        if before.st_size < 0 or before.st_size > max_bytes:
            raise SeedManifestError(f"Identity input exceeds the {max_bytes}-byte limit.")
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise SeedManifestError(f"Identity input exceeds the {max_bytes}-byte limit.")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if total != before.st_size or _snapshot(before) != _snapshot(after):
            raise SeedManifestError("Identity input changed while it was being hashed.")
        named = os.stat(source.name, dir_fd=parent_fd, follow_symlinks=False)
        if _snapshot(named) != _snapshot(before):
            raise SeedManifestError("Identity input path changed while it was being hashed.")
        return StableFileHash(
            sha256=digest.hexdigest(),
            size_bytes=total,
            snapshot=_snapshot(after),
        )
    except OSError as exc:
        raise SeedManifestError(f"Cannot safely hash identity input: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)
        os.close(parent_fd)


def build_seed_manifest(
    seed_dir: str | Path,
    *,
    max_file_bytes: int | None = None,
    max_entries: int = MAX_SEED_ENTRIES,
    max_total_bytes: int = MAX_SEED_TOTAL_BYTES,
) -> SeedManifest:
    """Build a deterministic manifest of direct regular seed files.

    Plain direct subdirectories are ignored, matching adapter preflight's
    current AFL seed-directory contract. Symlinks and special files fail closed.
    """
    if max_entries < 1 or max_total_bytes < 0:
        raise ValueError("Seed manifest limits are invalid.")
    root_fd = _open_directory(seed_dir)
    try:
        names = sorted(os.listdir(root_fd))
        if len(names) > max_entries:
            raise SeedManifestError(f"Seed directory exceeds the {max_entries}-entry limit.")

        snapshots: dict[str, tuple[int, int, int, int, int]] = {}
        entry_types: dict[str, str] = {}
        entries: list[tuple[str, int, str]] = []
        total_bytes = 0

        for name in names:
            info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                raise SeedManifestError(f"Symlink is not allowed in the seed corpus: {name}")
            if stat.S_ISDIR(info.st_mode):
                entry_types[name] = "directory"
                snapshots[name] = _snapshot(info)
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
                raise SeedManifestError(f"Seed entry is not a regular user-owned file: {name}")
            if info.st_size < 0 or (max_file_bytes is not None and info.st_size > max_file_bytes):
                raise SeedManifestError(f"Seed file exceeds the configured input limit: {name}")
            total_bytes += info.st_size
            if total_bytes > max_total_bytes:
                raise SeedManifestError(f"Seed corpus exceeds the {max_total_bytes}-byte total limit.")
            snapshots[name] = _snapshot(info)
            entry_types[name] = "file"

            descriptor = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_NONBLOCK", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_CLOEXEC", 0),
                dir_fd=root_fd,
            )
            try:
                before = os.fstat(descriptor)
                if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid():
                    raise SeedManifestError(f"Seed file became unsafe while opening: {name}")
                if _snapshot(before) != snapshots[name]:
                    raise SeedManifestError(f"Seed file changed before hashing: {name}")
                hasher = hashlib.sha256()
                copied = 0
                while True:
                    chunk = os.read(descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if max_file_bytes is not None and copied > max_file_bytes:
                        raise SeedManifestError(f"Seed file grew beyond its input limit: {name}")
                    if total_bytes > max_total_bytes:
                        raise SeedManifestError("Seed corpus exceeded its total size limit.")
                    hasher.update(chunk)
                after = os.fstat(descriptor)
                if copied != before.st_size or _snapshot(before) != _snapshot(after):
                    raise SeedManifestError(f"Seed file changed while hashing: {name}")
                named = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
                if _snapshot(named) != _snapshot(after):
                    raise SeedManifestError(f"Seed file path changed while hashing: {name}")
                entries.append((name, copied, hasher.hexdigest()))
            finally:
                os.close(descriptor)

        if not entries or not any(size > 0 for _, size, _ in entries):
            raise SeedManifestError("Seed corpus must contain at least one non-empty regular file.")

        after_names = sorted(os.listdir(root_fd))
        if after_names != names:
            raise SeedManifestError("Seed directory entries changed while the manifest was computed.")
        for name in names:
            current = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if _snapshot(current) != snapshots[name]:
                raise SeedManifestError(f"Seed directory entry changed while hashing: {name}")

        manifest_bytes = json.dumps(
            [
                {"name": name, "size_bytes": size, "sha256": digest}
                for name, size, digest in entries
            ],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return SeedManifest(
            sha256=hashlib.sha256(manifest_bytes).hexdigest(),
            seed_count=len(entries),
            total_bytes=total_bytes,
            entries=tuple(entries),
        )
    except OSError as exc:
        raise SeedManifestError(f"Cannot safely inspect seed directory: {exc}") from exc
    finally:
        os.close(root_fd)
