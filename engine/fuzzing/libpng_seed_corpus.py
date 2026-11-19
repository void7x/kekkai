"""Deterministic supplemental PNG seeds for the libpng pilot corpus."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import os
import secrets
import stat
import struct
import zlib
from dataclasses import dataclass
from pathlib import Path

from engine.evidence.seed_manifest import (
    SeedManifest,
    SeedManifestError,
    build_seed_manifest_from_fd,
    open_seed_directory,
)


LIBPNG_BASE_SEED_FILES = frozenset({
    "valid.png",
    "adam7.png",
    "malformed.png",
    "truncated.png",
    "width_over_limit.png",
    "height_over_limit.png",
    "pixels_over_limit.png",
    "row_boundary_64k.png",
    "chunk_over_limit.png",
    "chunk_cache_over_limit.png",
})

LIBPNG_ADDITIONAL_SEED_CASES = (
    ("grayscale_1bit", "grayscale_1bit.png"),
    ("grayscale_4bit", "grayscale_4bit.png"),
    ("grayscale_16bit", "grayscale_16bit.png"),
    ("rgb_16bit", "rgb_16bit.png"),
    ("indexed_2bit_trns", "indexed_2bit_trns.png"),
    ("gray_alpha_8bit", "gray_alpha_8bit.png"),
    ("rgba_16bit_adam7", "rgba_16bit_adam7.png"),
    ("rgba8_filters_ancillary", "rgba8_filters_ancillary.png"),
)

ADDITIONAL_SEED_IHDR = {
    "grayscale_1bit": (17, 9, 1, 0, 0, 0, 0),
    "grayscale_4bit": (13, 9, 4, 0, 0, 0, 0),
    "grayscale_16bit": (7, 5, 16, 0, 0, 0, 0),
    "rgb_16bit": (9, 7, 16, 2, 0, 0, 0),
    "indexed_2bit_trns": (11, 9, 2, 3, 0, 0, 0),
    "gray_alpha_8bit": (9, 7, 8, 4, 0, 0, 0),
    "rgba_16bit_adam7": (19, 13, 16, 6, 0, 0, 1),
    "rgba8_filters_ancillary": (17, 11, 8, 6, 0, 0, 0),
}

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_ADAM7_PASSES = (
    (0, 0, 8, 8),
    (4, 0, 8, 8),
    (0, 4, 4, 8),
    (2, 0, 4, 4),
    (0, 2, 2, 4),
    (1, 0, 2, 2),
    (0, 1, 1, 2),
)
_CHANNELS = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}


class SeedCorpusError(RuntimeError):
    """Raised when a supplemental seed corpus cannot be prepared safely."""


@dataclass(frozen=True)
class SeedCorpusPreparation:
    destination: Path
    seed_manifest: SeedManifest
    added_seed_names: tuple[str, ...]


@dataclass(frozen=True)
class _PngSpec:
    width: int
    height: int
    bit_depth: int
    color_type: int
    interlace: int = 0
    salt: int = 1
    palette: bytes | None = None
    transparency: bytes | None = None
    ancillary: bool = False
    split_idat: bool = False


def _png_chunk(kind: bytes, payload: bytes) -> bytes:
    checksum = zlib.crc32(kind + payload) & 0xFFFFFFFF
    return (
        struct.pack(">I", len(payload))
        + kind
        + payload
        + struct.pack(">I", checksum)
    )


def _paeth(left: int, above: int, upper_left: int) -> int:
    estimate = left + above - upper_left
    left_distance = abs(estimate - left)
    above_distance = abs(estimate - above)
    diagonal_distance = abs(estimate - upper_left)
    if left_distance <= above_distance and left_distance <= diagonal_distance:
        return left
    if above_distance <= diagonal_distance:
        return above
    return upper_left


def _filter_row(
    raw: bytes,
    previous: bytes,
    bytes_per_pixel: int,
    filter_type: int,
) -> bytes:
    filtered = bytearray(len(raw))
    for index, value in enumerate(raw):
        left = raw[index - bytes_per_pixel] if index >= bytes_per_pixel else 0
        above = previous[index] if previous else 0
        upper_left = (
            previous[index - bytes_per_pixel]
            if previous and index >= bytes_per_pixel else 0
        )
        if filter_type == 0:
            predictor = 0
        elif filter_type == 1:
            predictor = left
        elif filter_type == 2:
            predictor = above
        elif filter_type == 3:
            predictor = (left + above) // 2
        elif filter_type == 4:
            predictor = _paeth(left, above, upper_left)
        else:
            raise ValueError(f"Unsupported PNG filter type: {filter_type}")
        filtered[index] = (value - predictor) & 0xFF
    return bytes(filtered)


def _pack_samples(samples: list[int], bit_depth: int) -> bytes:
    maximum = (1 << bit_depth) - 1
    if any(sample < 0 or sample > maximum for sample in samples):
        raise ValueError("PNG sample value is outside the selected bit depth.")
    if bit_depth == 8:
        return bytes(samples)
    if bit_depth == 16:
        return b"".join(struct.pack(">H", sample) for sample in samples)

    output = bytearray()
    accumulator = 0
    bits_used = 0
    for sample in samples:
        accumulator = (accumulator << bit_depth) | sample
        bits_used += bit_depth
        if bits_used == 8:
            output.append(accumulator)
            accumulator = 0
            bits_used = 0
    if bits_used:
        output.append(accumulator << (8 - bits_used))
    return bytes(output)


def _row_samples(
    x_values: range,
    y_value: int,
    *,
    bit_depth: int,
    color_type: int,
    salt: int,
) -> list[int]:
    channels = _CHANNELS[color_type]
    maximum = (1 << bit_depth) - 1
    samples: list[int] = []
    for x_value in x_values:
        for channel in range(channels):
            if color_type == 3:
                sample = (x_value * 3 + y_value * 5 + salt) % 4
            else:
                sample = (
                    x_value * (channel + 3)
                    + y_value * (channel + 5)
                    + salt * 11
                    + channel * 19
                ) % (maximum + 1)
            samples.append(sample)
    return samples


def _image_data(spec: _PngSpec) -> bytes:
    channels = _CHANNELS[spec.color_type]
    bits_per_pixel = channels * spec.bit_depth
    bytes_per_pixel = max(1, (bits_per_pixel + 7) // 8)
    passes = _ADAM7_PASSES if spec.interlace else ((0, 0, 1, 1),)
    raw_image = bytearray()
    row_number = 0

    for x_start, y_start, x_step, y_step in passes:
        pass_width = (
            (spec.width - x_start + x_step - 1) // x_step
            if spec.width > x_start else 0
        )
        pass_height = (
            (spec.height - y_start + y_step - 1) // y_step
            if spec.height > y_start else 0
        )
        if pass_width == 0 or pass_height == 0:
            continue

        previous = b""
        x_values = range(x_start, spec.width, x_step)
        for pass_row in range(pass_height):
            y_value = y_start + pass_row * y_step
            samples = _row_samples(
                x_values,
                y_value,
                bit_depth=spec.bit_depth,
                color_type=spec.color_type,
                salt=spec.salt,
            )
            row = _pack_samples(samples, spec.bit_depth)
            filter_type = (row_number + spec.salt) % 5
            filtered = _filter_row(
                row,
                previous,
                bytes_per_pixel,
                filter_type,
            )
            raw_image.append(filter_type)
            raw_image.extend(filtered)
            previous = row
            row_number += 1

    return zlib.compress(bytes(raw_image), level=9)


def _make_png(spec: _PngSpec) -> bytes:
    ihdr = struct.pack(
        ">IIBBBBB",
        spec.width,
        spec.height,
        spec.bit_depth,
        spec.color_type,
        0,
        0,
        spec.interlace,
    )
    chunks = [_png_chunk(b"IHDR", ihdr)]

    if spec.palette is not None:
        chunks.append(_png_chunk(b"PLTE", spec.palette))
    if spec.transparency is not None:
        chunks.append(_png_chunk(b"tRNS", spec.transparency))
    if spec.ancillary:
        chunks.extend((
            _png_chunk(b"gAMA", struct.pack(">I", 45455)),
            _png_chunk(b"sRGB", b"\x00"),
            _png_chunk(b"pHYs", struct.pack(">IIB", 3780, 3780, 1)),
            _png_chunk(b"tEXt", b"Comment\x00KEKKAI supplemental seed"),
        ))

    compressed = _image_data(spec)
    if spec.split_idat and len(compressed) >= 3:
        first = max(1, len(compressed) // 3)
        second = max(first + 1, (2 * len(compressed)) // 3)
        parts = (compressed[:first], compressed[first:second], compressed[second:])
        chunks.extend(_png_chunk(b"IDAT", part) for part in parts if part)
    else:
        chunks.append(_png_chunk(b"IDAT", compressed))

    if spec.ancillary:
        chunks.append(_png_chunk(b"vpAg", b"KEKKAI"))
        chunks.append(_png_chunk(b"tEXt", b"Source\x00deterministic local generator"))
    chunks.append(_png_chunk(b"IEND", b""))
    return _PNG_SIGNATURE + b"".join(chunks)


def generate_additional_seed_bytes() -> dict[str, bytes]:
    """Return eight deterministic, valid PNG inputs without writing files."""
    specs = {
        "grayscale_1bit.png": _PngSpec(17, 9, 1, 0, salt=1),
        "grayscale_4bit.png": _PngSpec(13, 9, 4, 0, salt=2),
        "grayscale_16bit.png": _PngSpec(
            7, 5, 16, 0, salt=3, transparency=struct.pack(">H", 0x1234)
        ),
        "rgb_16bit.png": _PngSpec(9, 7, 16, 2, salt=4, split_idat=True),
        "indexed_2bit_trns.png": _PngSpec(
            11,
            9,
            2,
            3,
            salt=5,
            palette=bytes((
                0x10, 0x20, 0x30,
                0x80, 0x40, 0x20,
                0x20, 0xA0, 0x60,
                0xF0, 0xE0, 0xD0,
            )),
            transparency=b"\x00\x80\xFF\x40",
        ),
        "gray_alpha_8bit.png": _PngSpec(9, 7, 8, 4, salt=6),
        "rgba_16bit_adam7.png": _PngSpec(
            19, 13, 16, 6, interlace=1, salt=7
        ),
        "rgba8_filters_ancillary.png": _PngSpec(
            17, 11, 8, 6, salt=8, ancillary=True, split_idat=True
        ),
    }
    return {
        filename: _make_png(spec)
        for filename, spec in specs.items()
    }


def _snapshot(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _read_seed_at(
    directory_fd: int,
    name: str,
    *,
    expected_size: int,
    expected_sha256: str,
    maximum_bytes: int,
) -> bytes:
    descriptor = os.open(
        name,
        os.O_RDONLY
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0),
        dir_fd=directory_fd,
    )
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid():
            raise SeedCorpusError(f"Source seed is not a regular user-owned file: {name}")
        if before.st_size != expected_size or before.st_size > maximum_bytes:
            raise SeedCorpusError(f"Source seed size changed or exceeds the limit: {name}")

        content = bytearray()
        digest = hashlib.sha256()
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            content.extend(chunk)
            digest.update(chunk)
            if len(content) > maximum_bytes:
                raise SeedCorpusError(f"Source seed grew beyond its limit: {name}")

        after = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            len(content) != expected_size
            or _snapshot(before) != _snapshot(after)
            or _snapshot(named) != _snapshot(after)
            or digest.hexdigest() != expected_sha256
        ):
            raise SeedCorpusError(f"Source seed changed while being copied: {name}")
        return bytes(content)
    except OSError as exc:
        raise SeedCorpusError(f"Cannot safely read source seed {name}: {exc}") from exc
    finally:
        os.close(descriptor)


def _write_new_file_at(directory_fd: int, name: str, content: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    try:
        view = memoryview(content)
        offset = 0
        while offset < len(view):
            written = os.write(descriptor, view[offset:])
            if written <= 0:
                raise OSError("Seed file write made no progress.")
            offset += written
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _create_staging_directory_at(
    parent_fd: int,
    prefix: str,
) -> tuple[str, int]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    for _attempt in range(128):
        name = f"{prefix}{secrets.token_hex(16)}"
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            continue

        descriptor = None
        try:
            descriptor = os.open(name, flags, dir_fd=parent_fd)
            info = os.fstat(descriptor)
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
                raise SeedCorpusError("Staging directory is not a user-owned directory.")
            return name, descriptor
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            try:
                os.rmdir(name, dir_fd=parent_fd)
            except OSError:
                pass
            raise

    raise SeedCorpusError("Could not allocate a unique staging directory name.")


def _same_directory(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(first.st_mode)
        and stat.S_ISDIR(second.st_mode)
        and first.st_dev == second.st_dev
        and first.st_ino == second.st_ino
    )


def _cleanup_staging_directory_at(
    parent_fd: int,
    staging_name: str,
    staging_fd: int,
) -> None:
    """Best-effort cleanup using only the retained parent/staging descriptors."""
    try:
        opened_info = os.fstat(staging_fd)
        named_info = os.stat(
            staging_name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if not _same_directory(opened_info, named_info):
            return

        # The staging layout is deliberately flat. Never recurse into an
        # unexpected directory or follow a symlink during failure cleanup.
        for name in os.listdir(staging_fd):
            entry_info = os.stat(name, dir_fd=staging_fd, follow_symlinks=False)
            if stat.S_ISDIR(entry_info.st_mode):
                return
            os.unlink(name, dir_fd=staging_fd)

        os.fsync(staging_fd)
        current_info = os.stat(
            staging_name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if _same_directory(os.fstat(staging_fd), current_info):
            os.rmdir(staging_name, dir_fd=parent_fd)
            os.fsync(parent_fd)
    except OSError:
        # Cleanup must not follow a replaced path or mask the original failure.
        return


def _verify_parent_path_binding(parent: Path, parent_fd: int) -> None:
    """Refuse to return a pathname that no longer names the retained parent."""
    try:
        opened_info = os.fstat(parent_fd)
        named_info = os.stat(parent, follow_symlinks=False)
    except OSError as exc:
        raise SeedCorpusError(
            "Destination parent path changed during preparation."
        ) from exc
    if (
        opened_info.st_dev != named_info.st_dev
        or opened_info.st_ino != named_info.st_ino
        or not stat.S_ISDIR(named_info.st_mode)
    ):
        raise SeedCorpusError(
            "Destination parent path changed during preparation; "
            "the published corpus remains in the originally opened directory."
        )


def _overlaps(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _rename_directory_noreplace(parent_fd: int, source_name: str, destination_name: str) -> None:
    """Atomically publish a directory without replacing any destination."""
    libc = ctypes.CDLL(None, use_errno=True)
    renameat2 = getattr(libc, "renameat2", None)
    if renameat2 is None:
        raise SeedCorpusError(
            "Atomic no-replace directory publication is unavailable; refusing to publish."
        )
    renameat2.argtypes = (
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        parent_fd, os.fsencode(source_name),
        parent_fd, os.fsencode(destination_name),
        1,  # Linux RENAME_NOREPLACE
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in (errno.EEXIST, errno.ENOTEMPTY):
        raise SeedCorpusError(
            "Destination appeared during preparation; refusing to overwrite it."
        )
    if error_number in (
        errno.ENOSYS, errno.EINVAL, getattr(errno, "EOPNOTSUPP", errno.EINVAL)
    ):
        raise SeedCorpusError(
            "Atomic no-replace directory publication is unsupported; refusing to publish."
        )
    raise OSError(error_number, os.strerror(error_number), destination_name)


def prepare_libpng_seed_corpus(
    source_dir: str | Path,
    destination_dir: str | Path,
    *,
    repository_root: str | Path,
    target_source_root: str | Path,
    campaign_output_parent: str | Path,
    max_input_bytes: int = 8 * 1024 * 1024,
) -> SeedCorpusPreparation:
    """Copy the original corpus into a new external, descriptor-anchored directory."""
    if isinstance(max_input_bytes, bool) or not isinstance(max_input_bytes, int) or max_input_bytes < 1:
        raise SeedCorpusError("The maximum input size must be a positive integer.")

    source = Path(source_dir).expanduser()
    destination_input = Path(destination_dir).expanduser()
    if not source.is_absolute() or not destination_input.is_absolute():
        raise SeedCorpusError("Source and destination paths must be absolute.")

    parent_input = destination_input.parent
    try:
        parent = parent_input.resolve(strict=True)
        if Path(os.path.abspath(parent_input)) != parent:
            raise SeedCorpusError("Destination parent contains a symlink component.")
        if not parent.is_dir() or not os.access(parent, os.W_OK | os.X_OK):
            raise SeedCorpusError("Destination parent is not a writable directory.")
        if os.stat(parent).st_uid != os.getuid():
            raise SeedCorpusError("Destination parent must be owned by the current user.")
    except (OSError, RuntimeError, ValueError) as exc:
        if isinstance(exc, SeedCorpusError):
            raise
        raise SeedCorpusError(f"Cannot resolve destination parent: {exc}") from exc

    if destination_input.name in {"", ".", ".."}:
        raise SeedCorpusError("Destination directory name is invalid.")
    destination = parent / destination_input.name

    protected = (
        ("repository", repository_root),
        ("target source", target_source_root),
        ("campaign output", campaign_output_parent),
    )
    for label, protected_path in protected:
        try:
            protected_root = Path(protected_path).expanduser().resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as exc:
            raise SeedCorpusError(f"Cannot resolve protected {label} path: {exc}") from exc
        if _overlaps(destination, protected_root):
            raise SeedCorpusError(
                f"Destination overlaps the protected {label} path: {protected_root}"
            )

    candidate_bytes = generate_additional_seed_bytes()
    parent_fd = None
    source_fd = None
    staging_fd = None
    staging_name = None
    published = False
    try:
        # Open both directories once. All later corpus I/O is relative to these
        # descriptors so renaming/replacing their pathnames cannot redirect it.
        source_fd = open_seed_directory(source)
        source_manifest = build_seed_manifest_from_fd(
            source_fd,
            max_file_bytes=max_input_bytes,
        )

        source_names = {name for name, _, _ in source_manifest.entries}
        missing = sorted(LIBPNG_BASE_SEED_FILES - source_names)
        unexpected = sorted(source_names - LIBPNG_BASE_SEED_FILES)
        if missing or unexpected:
            details = []
            if missing:
                details.append(
                    "missing required pilot seeds: " + ", ".join(missing)
                )
            if unexpected:
                details.append("unexpected entries: " + ", ".join(unexpected))
            raise SeedCorpusError(
                "Original seed corpus must contain exactly the ten approved pilot seeds ("
                + "; ".join(details)
                + ")."
            )

        collisions = sorted(source_names.intersection(candidate_bytes))
        if collisions:
            raise SeedCorpusError(
                "Original corpus already contains supplemental filenames: "
                + ", ".join(collisions)
            )

        parent_fd = open_seed_directory(parent)
        parent_info = os.fstat(parent_fd)
        named_parent_info = os.stat(parent, follow_symlinks=False)
        if not _same_directory(parent_info, named_parent_info):
            raise SeedCorpusError("Destination parent changed while it was being opened.")

        try:
            os.stat(destination.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SeedCorpusError(
                f"Destination already exists; refusing to overwrite: {destination}"
            )

        staging_name, staging_fd = _create_staging_directory_at(
            parent_fd,
            f".{destination.name}.tmp-",
        )

        for name, size, digest in source_manifest.entries:
            content = _read_seed_at(
                source_fd,
                name,
                expected_size=size,
                expected_sha256=digest,
                maximum_bytes=max_input_bytes,
            )
            _write_new_file_at(staging_fd, name, content)

        from engine.fuzzing.smoke import _validate_seed_fixture_data

        case_by_filename = {
            filename: case_name
            for case_name, filename in LIBPNG_ADDITIONAL_SEED_CASES
        }
        for filename, content in candidate_bytes.items():
            if len(content) > max_input_bytes:
                raise SeedCorpusError(f"Generated seed exceeds the input limit: {filename}")
            _validate_seed_fixture_data(case_by_filename[filename], content)
            _write_new_file_at(staging_fd, filename, content)

        try:
            copied_source_manifest = build_seed_manifest_from_fd(
                source_fd,
                max_file_bytes=max_input_bytes,
            )
            final_manifest = build_seed_manifest_from_fd(
                staging_fd,
                max_file_bytes=max_input_bytes,
            )
        except (OSError, ValueError, RuntimeError, SeedManifestError) as exc:
            raise SeedCorpusError(f"Prepared seed corpus failed validation: {exc}") from exc

        if copied_source_manifest.sha256 != source_manifest.sha256:
            raise SeedCorpusError("Original seed corpus changed during preparation.")

        expected_entries = {
            name: (size, digest)
            for name, size, digest in source_manifest.entries
        }
        expected_entries.update({
            filename: (len(content), hashlib.sha256(content).hexdigest())
            for filename, content in candidate_bytes.items()
        })
        observed_entries = {
            name: (size, digest)
            for name, size, digest in final_manifest.entries
        }
        if observed_entries != expected_entries:
            raise SeedCorpusError(
                "Prepared corpus does not exactly match the verified original "
                "seeds and generated candidates."
            )
        if final_manifest.seed_count != source_manifest.seed_count + len(candidate_bytes):
            raise SeedCorpusError("Prepared corpus has an unexpected seed count.")

        staging_info = os.fstat(staging_fd)
        named_staging_info = os.stat(
            staging_name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if not _same_directory(staging_info, named_staging_info):
            raise SeedCorpusError("Staging directory entry changed before publication.")

        os.fsync(staging_fd)
        _rename_directory_noreplace(
            parent_fd,
            staging_name,
            destination.name,
        )
        published = True

        published_info = os.stat(
            destination.name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if not _same_directory(os.fstat(staging_fd), published_info):
            raise SeedCorpusError(
                "Published destination does not match the verified staging directory."
            )

        os.fsync(parent_fd)
        _verify_parent_path_binding(parent, parent_fd)

        return SeedCorpusPreparation(
            destination=destination,
            seed_manifest=final_manifest,
            added_seed_names=tuple(sorted(candidate_bytes)),
        )
    except SeedCorpusError:
        raise
    except (OSError, ValueError, RuntimeError) as exc:
        raise SeedCorpusError(f"Could not prepare supplemental seed corpus: {exc}") from exc
    finally:
        if (
            not published
            and parent_fd is not None
            and staging_fd is not None
            and staging_name is not None
        ):
            _cleanup_staging_directory_at(parent_fd, staging_name, staging_fd)
        if staging_fd is not None:
            os.close(staging_fd)
        if source_fd is not None:
            os.close(source_fd)
        if parent_fd is not None:
            os.close(parent_fd)
