"""Authenticate the pinned libpng release archive and its extracted source tree."""

from __future__ import annotations

import hashlib
import os
import stat
import tarfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath


LIBPNG_SOURCE_ARCHIVE_SHA256 = (
    "d80dd2a38a37f803cb9b6ac7b14bd6e74ddc3b654780a8380bdf93523fdb4389"
)
_ARCHIVE_ROOT = "libpng-1.6.59"
_MAX_ARCHIVE_BYTES = 16 * 1024 * 1024
_MAX_ENTRIES = 10_000
_MAX_TREE_BYTES = 128 * 1024 * 1024


class SourceIdentityError(ValueError):
    """Raised when a source archive or extracted source tree is not authentic."""


@dataclass(frozen=True)
class SourceIdentity:
    archive_sha256: str
    tree_sha256: str


def _sha256_file(
    path: Path,
    *,
    max_bytes: int | None = None,
    expected_size: int | None = None,
) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            if max_bytes is not None and size > max_bytes:
                raise SourceIdentityError(
                    f"File exceeds the configured size limit: {path}"
                )
            digest.update(chunk)
    if expected_size is not None and size != expected_size:
        raise SourceIdentityError(
            f"File size changed while being read: {path}"
        )
    return digest.hexdigest(), size


def _normal_member_name(member: tarfile.TarInfo) -> str:
    raw_name = member.name.rstrip("/") if member.isdir() else member.name
    if not raw_name or "\\" in raw_name:
        raise SourceIdentityError(f"Unsafe archive member name: {member.name!r}")
    path = PurePosixPath(raw_name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise SourceIdentityError(f"Unsafe archive member path: {member.name!r}")
    if path.as_posix() != raw_name or not path.parts or path.parts[0] != _ARCHIVE_ROOT:
        raise SourceIdentityError(f"Unexpected archive member path: {member.name!r}")
    return "/".join(path.parts[1:])


def _archive_entries(archive_path: Path) -> dict[str, tuple[str, int, int, str]]:
    entries: dict[str, tuple[str, int, int, str]] = {}
    total_bytes = 0
    try:
        with tarfile.open(archive_path, mode="r:xz") as archive:
            members = archive.getmembers()
            if not members or len(members) > _MAX_ENTRIES:
                raise SourceIdentityError("Source archive has an invalid entry count.")
            for member in members:
                relative = _normal_member_name(member)
                if not relative:
                    if not member.isdir():
                        raise SourceIdentityError("Archive root entry is not a directory.")
                    continue
                if relative in entries:
                    raise SourceIdentityError(f"Duplicate archive path: {relative}")
                executable_bits = member.mode & 0o111
                if member.isdir():
                    entries[relative] = ("dir", 0, executable_bits, "")
                    continue
                if not member.isfile() or member.size < 0:
                    raise SourceIdentityError(
                        f"Archive contains a link or special file: {member.name}"
                    )
                total_bytes += member.size
                if total_bytes > _MAX_TREE_BYTES:
                    raise SourceIdentityError("Source archive expands beyond the size limit.")
                stream = archive.extractfile(member)
                if stream is None:
                    raise SourceIdentityError(f"Cannot read archive member: {member.name}")
                digest = hashlib.sha256()
                observed_size = 0
                with stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                        observed_size += len(chunk)
                        digest.update(chunk)
                if observed_size != member.size:
                    raise SourceIdentityError(f"Truncated archive member: {member.name}")
                entries[relative] = ("file", observed_size, executable_bits, digest.hexdigest())
    except (OSError, tarfile.TarError, EOFError) as exc:
        raise SourceIdentityError(f"Cannot read pinned source archive: {exc}") from exc

    for name, (kind, _, _, _) in entries.items():
        parent = PurePosixPath(name).parent
        while str(parent) != ".":
            parent_name = parent.as_posix()
            parent_entry = entries.get(parent_name)
            if parent_entry is None or parent_entry[0] != "dir":
                raise SourceIdentityError(f"Archive member has no directory parent: {name}")
            parent = parent.parent
    return entries


def _source_entries(source_dir: Path) -> dict[str, tuple[str, int, int, str]]:
    try:
        root_stat = source_dir.lstat()
    except OSError as exc:
        raise SourceIdentityError(f"Cannot inspect source directory: {exc}") from exc
    if stat.S_ISLNK(root_stat.st_mode) or not stat.S_ISDIR(root_stat.st_mode):
        raise SourceIdentityError("Extracted source path must be a real directory, not a symlink.")

    entries: dict[str, tuple[str, int, int, str]] = {}
    total_bytes = 0

    def walk(directory: Path, prefix: PurePosixPath) -> None:
        nonlocal total_bytes
        try:
            children = []
            with os.scandir(directory) as iterator:
                for child in iterator:
                    if len(entries) + len(children) >= _MAX_ENTRIES:
                        raise SourceIdentityError(
                            "Extracted source tree exceeds the entry-count limit."
                        )
                    children.append(child)
            children.sort(key=lambda item: item.name)
        except OSError as exc:
            raise SourceIdentityError(
                f"Cannot enumerate source directory {directory}: {exc}"
            ) from exc

        for child in children:
            if len(entries) >= _MAX_ENTRIES:
                raise SourceIdentityError(
                    "Extracted source tree exceeds the entry-count limit."
                )

            relative = prefix / child.name
            name = relative.as_posix()
            try:
                info = child.stat(follow_symlinks=False)
            except OSError as exc:
                raise SourceIdentityError(
                    f"Cannot inspect source entry {name}: {exc}"
                ) from exc

            executable_bits = stat.S_IMODE(info.st_mode) & 0o111
            if stat.S_ISLNK(info.st_mode):
                raise SourceIdentityError(
                    f"Extracted source contains a symlink: {name}"
                )
            if name in entries:
                raise SourceIdentityError(f"Duplicate source path: {name}")

            if stat.S_ISDIR(info.st_mode):
                entries[name] = ("dir", 0, executable_bits, "")
                walk(Path(child.path), relative)
            elif stat.S_ISREG(info.st_mode):
                remaining_bytes = _MAX_TREE_BYTES - total_bytes
                if info.st_size < 0 or info.st_size > remaining_bytes:
                    raise SourceIdentityError(
                        "Extracted source tree exceeds the size limit."
                    )
                file_path = Path(child.path)
                digest, size = _sha256_file(
                    file_path,
                    max_bytes=remaining_bytes,
                    expected_size=info.st_size,
                )
                total_bytes += size
                entries[name] = ("file", size, executable_bits, digest)
            else:
                raise SourceIdentityError(
                    f"Extracted source contains a special file: {name}"
                )

    walk(source_dir, PurePosixPath())
    return entries

def _tree_digest(entries: dict[str, tuple[str, int, int, str]]) -> str:
    digest = hashlib.sha256()
    for name, (kind, size, executable_bits, content_hash) in sorted(entries.items()):
        row = f"{kind}\0{name}\0{size}\0{executable_bits:o}\0{content_hash}\n"
        digest.update(row.encode("utf-8"))
    return digest.hexdigest()



def verify_libpng_source_identity(
    source_dir: str | Path,
    archive_path: str | Path | None,
) -> SourceIdentity:
    """Verify archive authenticity and exact equivalence of the extracted tree."""
    if archive_path is None:
        raise SourceIdentityError("Adapter does not specify the pinned source archive.")
    source = Path(source_dir)
    archive = Path(archive_path)
    try:
        archive_info = archive.lstat()
    except OSError as exc:
        raise SourceIdentityError(f"Cannot inspect source archive: {exc}") from exc
    if stat.S_ISLNK(archive_info.st_mode) or not stat.S_ISREG(archive_info.st_mode):
        raise SourceIdentityError("Source archive must be a regular, non-symlink file.")
    if archive_info.st_size <= 0 or archive_info.st_size > _MAX_ARCHIVE_BYTES:
        raise SourceIdentityError("Source archive has an invalid size.")

    archive_hash, _ = _sha256_file(
        archive,
        max_bytes=_MAX_ARCHIVE_BYTES,
        expected_size=archive_info.st_size,
    )
    if archive_hash != LIBPNG_SOURCE_ARCHIVE_SHA256:
        raise SourceIdentityError(
            "Source archive SHA-256 does not match the independently pinned libpng release."
        )

    archive_entries = _archive_entries(archive)
    source_entries = _source_entries(source)
    if source_entries != archive_entries:
        missing = sorted(set(archive_entries) - set(source_entries))[:5]
        extra = sorted(set(source_entries) - set(archive_entries))[:5]
        changed = sorted(
            name for name in set(source_entries) & set(archive_entries)
            if source_entries[name] != archive_entries[name]
        )[:5]
        raise SourceIdentityError(
            "Extracted libpng source tree differs from the authenticated archive "
            f"(missing={missing}, extra={extra}, changed={changed})."
        )

    return SourceIdentity(
        archive_sha256=archive_hash,
        tree_sha256=_tree_digest(source_entries),
    )
