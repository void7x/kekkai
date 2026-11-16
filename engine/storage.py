"""Fail-closed verification for KEKKAI's dedicated campaign filesystem."""

from __future__ import annotations

import os
import re
import stat
import struct
import uuid
from dataclasses import dataclass
from pathlib import Path


CAMPAIGN_STORAGE_BYTES = 4 * 1024 * 1024 * 1024
_REQUIRED_MOUNT_OPTIONS = frozenset({"nodev", "nosuid", "noexec"})


class StorageError(RuntimeError):
    """Raised when the dedicated campaign volume cannot be authenticated."""


@dataclass(frozen=True)
class MountRecord:
    major_minor: str
    root: str
    mountpoint: Path
    options: frozenset[str]
    filesystem: str
    source: str


@dataclass(frozen=True)
class StorageVerification:
    image: Path
    mountpoint: Path
    device: str
    filesystem_uuid: str
    capacity_bytes: int
    available_bytes: int


def _decode_mount_field(value: str) -> str:
    """Decode the octal escapes used by /proc/self/mountinfo."""
    return re.sub(
        r"\\([0-7]{3})",
        lambda match: chr(int(match.group(1), 8)),
        value,
    )


def _parse_mountinfo_text(contents: str) -> tuple[MountRecord, ...]:
    records: list[MountRecord] = []
    for line_number, line in enumerate(contents.splitlines(), start=1):
        if not line.strip():
            continue
        if " - " not in line:
            raise StorageError(f"Malformed mountinfo line {line_number}.")
        left, right = line.split(" - ", 1)
        before = left.split()
        after = right.split()
        if len(before) < 6 or len(after) < 3:
            raise StorageError(f"Incomplete mountinfo line {line_number}.")
        major_minor = before[2]
        if re.fullmatch(r"[0-9]+:[0-9]+", major_minor) is None:
            raise StorageError(f"Invalid device number on mountinfo line {line_number}.")
        records.append(
            MountRecord(
                major_minor=major_minor,
                root=_decode_mount_field(before[3]),
                mountpoint=Path(_decode_mount_field(before[4])),
                options=frozenset(before[5].split(",")),
                filesystem=after[0],
                source=_decode_mount_field(after[1]),
            )
        )
    return tuple(records)


def _reject_symlink_components(path: Path, label: str) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        if current.is_symlink():
            raise StorageError(f"{label} contains a symlink component: {current}")


def _read_ext4_uuid(image: Path) -> str:
    """Read ext4's UUID directly from its superblock without mounting it."""
    _reject_symlink_components(image, "Campaign storage image")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(image, flags)
    except OSError as exc:
        raise StorageError(f"Cannot safely open campaign storage image: {exc}") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise StorageError("Campaign storage image must be a regular file.")
        if info.st_size != CAMPAIGN_STORAGE_BYTES:
            raise StorageError(
                f"Campaign storage image must be exactly {CAMPAIGN_STORAGE_BYTES} bytes; "
                f"found {info.st_size}."
            )
        if info.st_uid != os.getuid():
            raise StorageError("Campaign storage image must be owned by the current user.")
        if info.st_mode & 0o022:
            raise StorageError("Campaign storage image must not be group- or world-writable.")
        superblock = os.pread(descriptor, 1024, 1024)
        if len(superblock) != 1024:
            raise StorageError("Could not read the complete ext4 superblock.")
        if struct.unpack_from("<H", superblock, 0x38)[0] != 0xEF53:
            raise StorageError("Campaign storage image does not contain an ext filesystem superblock.")
        raw_uuid = superblock[0x68:0x78]
        if len(raw_uuid) != 16:
            raise StorageError("Campaign storage image contains an invalid filesystem UUID.")
        return str(uuid.UUID(bytes=raw_uuid))
    finally:
        os.close(descriptor)


def verify_campaign_storage(
    image_path: str | Path,
    expected_uuid: str,
    mountpoint_path: str | Path,
    *,
    mountinfo_path: str | Path = "/proc/self/mountinfo",
    sys_dev_block: str | Path = "/sys/dev/block",
) -> StorageVerification:
    """Authenticate the configured ext4 image as the exact campaign mount.

    The mountpoint itself must be the filesystem root. Nested mounts are
    rejected so campaign output cannot escape the 4 GiB filesystem.
    """
    try:
        image_input = Path(image_path).expanduser()
        _reject_symlink_components(image_input, "Campaign storage image")
        expected_image = image_input.resolve(strict=True)
        mountpoint_input = Path(mountpoint_path).expanduser()
        _reject_symlink_components(mountpoint_input, "Campaign storage mountpoint")
        mountpoint = mountpoint_input.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise StorageError(f"Cannot resolve storage image or mountpoint: {exc}") from exc

    if not mountpoint.is_dir():
        raise StorageError(f"Campaign storage mountpoint is not a directory: {mountpoint}")

    actual_uuid = _read_ext4_uuid(expected_image)
    try:
        normalized_expected_uuid = str(uuid.UUID(expected_uuid))
    except (ValueError, AttributeError, TypeError) as exc:
        raise StorageError("Configured campaign storage UUID is invalid.") from exc
    if actual_uuid != normalized_expected_uuid:
        raise StorageError(
            f"Campaign storage image UUID mismatch: expected {normalized_expected_uuid}, "
            f"found {actual_uuid}."
        )

    try:
        records = _parse_mountinfo_text(Path(mountinfo_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise StorageError(f"Cannot read process mount table: {exc}") from exc

    matches = [record for record in records if record.mountpoint == mountpoint]
    if len(matches) != 1:
        raise StorageError(
            f"Dedicated campaign filesystem is not mounted exactly once at {mountpoint}."
        )
    record = matches[0]

    if record.filesystem != "ext4":
        raise StorageError(f"Campaign storage must be ext4; mounted filesystem is {record.filesystem!r}.")
    if record.root != "/":
        raise StorageError("Campaign mount must expose the root of the dedicated filesystem.")
    missing_options = _REQUIRED_MOUNT_OPTIONS - record.options
    if missing_options:
        raise StorageError(
            "Campaign storage mount is missing required options: "
            + ", ".join(sorted(missing_options))
            + "."
        )

    for other in records:
        if other.mountpoint != mountpoint and mountpoint in other.mountpoint.parents:
            raise StorageError(
                f"Nested mount inside campaign storage is not allowed: {other.mountpoint}"
            )

    try:
        mount_info = os.stat(mountpoint, follow_symlinks=False)
    except OSError as exc:
        raise StorageError(f"Cannot inspect campaign mountpoint: {exc}") from exc
    if not stat.S_ISDIR(mount_info.st_mode):
        raise StorageError("Campaign mountpoint is not a plain directory.")
    observed_device = f"{os.major(mount_info.st_dev)}:{os.minor(mount_info.st_dev)}"
    if observed_device != record.major_minor:
        raise StorageError("Campaign mountpoint device does not match mountinfo.")

    source = Path(record.source)
    try:
        source_info = os.stat(source, follow_symlinks=True)
    except OSError as exc:
        raise StorageError(f"Cannot inspect mounted loop device {record.source!r}: {exc}") from exc
    if not stat.S_ISBLK(source_info.st_mode):
        raise StorageError("Campaign filesystem source is not a block device.")
    source_device = f"{os.major(source_info.st_rdev)}:{os.minor(source_info.st_rdev)}"
    if source_device != record.major_minor:
        raise StorageError("Mounted block-device identity does not match mountinfo.")

    backing_file_record = Path(sys_dev_block) / record.major_minor / "loop" / "backing_file"
    try:
        backing_text = backing_file_record.read_text(encoding="utf-8").strip()
        if not backing_text or not Path(backing_text).is_absolute() or " (deleted)" in backing_text:
            raise StorageError("Loop device does not report a stable absolute backing-file path.")
        backing_file = Path(backing_text).resolve(strict=True)
    except (OSError, RuntimeError, UnicodeError) as exc:
        raise StorageError(f"Cannot verify loop-device backing image: {exc}") from exc
    if backing_file != expected_image:
        raise StorageError(
            f"Mounted loop device uses a different image: {backing_file}; "
            f"expected {expected_image}."
        )

    try:
        filesystem = os.statvfs(mountpoint)
    except OSError as exc:
        raise StorageError(f"Cannot inspect campaign filesystem capacity: {exc}") from exc
    capacity_bytes = filesystem.f_blocks * filesystem.f_frsize
    available_bytes = filesystem.f_bavail * filesystem.f_frsize
    image_size = expected_image.stat().st_size
    if capacity_bytes <= 0 or capacity_bytes > image_size:
        raise StorageError("Mounted filesystem capacity is inconsistent with the storage image size.")

    return StorageVerification(
        image=expected_image,
        mountpoint=mountpoint,
        device=record.source,
        filesystem_uuid=actual_uuid,
        capacity_bytes=capacity_bytes,
        available_bytes=available_bytes,
    )
