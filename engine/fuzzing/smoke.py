"""Bounded standalone smoke validation for the KEKKAI libpng harness."""

from __future__ import annotations

import math
import os
import struct
import subprocess
import tempfile
import time
import zlib
from dataclasses import dataclass
from pathlib import Path

from engine.adapters.config import AdapterConfig
from engine.processes import ProcessInterruptedError, run_process_group


class HarnessSmokeError(RuntimeError):
    """Raised when smoke validation cannot safely be initialized."""


@dataclass(frozen=True)
class SmokeCaseResult:
    name: str
    status: str
    expected_exit_code: int
    actual_exit_code: int | None
    elapsed_seconds: float
    message: str
    stdout: str
    stderr: str


@dataclass(frozen=True)
class HarnessSmokeReport:
    target_name: str
    target_version: str
    results: tuple[SmokeCaseResult, ...]

    @property
    def passed(self) -> bool:
        """True only when every planned smoke case passed."""
        return bool(self.results) and all(
            result.status == "passed" for result in self.results
        )

    @property
    def failed_cases(self) -> tuple[SmokeCaseResult, ...]:
        return tuple(
            result for result in self.results if result.status == "failed"
        )

    def format(self) -> str:
        outcome = "PASS" if self.passed else "FAIL"
        lines = [
            f"Harness smoke validation: {outcome}",
            f"Target: {self.target_name} {self.target_version}",
            f"Cases: {len(self.results)}",
            f"Failures: {len(self.failed_cases)}",
        ]

        for result in self.results:
            exit_description = (
                "not available"
                if result.actual_exit_code is None
                else str(result.actual_exit_code)
            )
            lines.append(
                f"[{result.status.upper()}] {result.name}: "
                f"{result.message} "
                f"(expected exit {result.expected_exit_code}, "
                f"actual {exit_description}, "
                f"{result.elapsed_seconds:.3f}s)"
            )

            if result.stdout:
                lines.append(f"  stdout: {result.stdout.strip()}")

            if result.stderr:
                lines.append(f"  stderr: {result.stderr.strip()}")

        return "\n".join(lines)


# These are the known, reviewed fixtures in the libpng pilot corpus.
# Ordinary valid and invalid PNG data should be handled without a harness
# failure. A missing input file is tested separately as an I/O failure.
LIBPNG_SEED_CASES = (
    ("valid_png", "valid.png"),
    ("adam7_png", "adam7.png"),
    ("malformed_png", "malformed.png"),
    ("truncated_png", "truncated.png"),
    ("width_limit", "width_over_limit.png"),
    ("height_limit", "height_over_limit.png"),
    ("pixel_limit", "pixels_over_limit.png"),
    ("row_boundary", "row_boundary_64k.png"),
    ("chunk_allocation_limit", "chunk_over_limit.png"),
    ("chunk_cache_limit", "chunk_cache_over_limit.png"),
)

_MAX_CAPTURE_BYTES = 16 * 1024
_MAX_OUTPUT_FILE_BYTES = 64 * 1024

_PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_MAX_IMAGE_WIDTH = 8192
_MAX_IMAGE_HEIGHT = 8192
_MAX_TOTAL_PIXELS = 16_000_000
_MAX_ROW_BYTES = 64 * 1024
_MAX_CHUNK_BYTES = 256 * 1024
_MAX_CACHED_CHUNKS = 128
_MAX_PNG_DECOMPRESSED_BYTES = 128 * 1024 * 1024
_PNG_DECOMPRESS_INPUT_CHUNK_BYTES = 64 * 1024
_PNG_DECOMPRESS_OUTPUT_CHUNK_BYTES = 64 * 1024


def _inspect_png_fixture(
    data: bytes,
) -> tuple[tuple[int, ...], tuple[tuple[bytes, bytes], ...], bool]:
    """Parse PNG chunk boundaries and CRCs without trusting the filename."""
    if not data.startswith(_PNG_SIGNATURE):
        raise ValueError("PNG signature is invalid.")

    offset = len(_PNG_SIGNATURE)
    chunks: list[tuple[bytes, bytes]] = []
    has_iend = False

    while offset < len(data):
        remaining = len(data) - offset
        if remaining < 12:
            raise ValueError("PNG ends inside a chunk header or CRC.")

        length = struct.unpack(">I", data[offset:offset + 4])[0]
        kind = data[offset + 4:offset + 8]

        if length > remaining - 12:
            raise ValueError(f"PNG {kind!r} chunk exceeds the remaining file.")

        payload_start = offset + 8
        payload_end = payload_start + length
        chunk_end = payload_end + 4

        payload = data[payload_start:payload_end]
        expected_crc = struct.unpack(">I", data[payload_end:chunk_end])[0]
        actual_crc = zlib.crc32(data[offset + 4:payload_end]) & 0xffffffff

        if actual_crc != expected_crc:
            raise ValueError(f"PNG {kind.decode('ascii', 'replace')} CRC mismatch.")

        chunks.append((kind, payload))
        offset = chunk_end

        if kind == b"IEND":
            if length != 0:
                raise ValueError("PNG IEND chunk must be empty.")
            has_iend = True
            break

    if has_iend and offset != len(data):
        raise ValueError("PNG contains trailing bytes after IEND.")

    if not chunks or chunks[0][0] != b"IHDR" or len(chunks[0][1]) != 13:
        raise ValueError("PNG must begin with exactly one valid IHDR chunk.")

    if sum(kind == b"IHDR" for kind, _ in chunks) != 1:
        raise ValueError("PNG must contain exactly one IHDR chunk.")

    if not any(kind == b"IDAT" for kind, _ in chunks):
        raise ValueError("PNG has no IDAT image-data chunk.")

    ihdr = struct.unpack(">IIBBBBB", chunks[0][1])
    return ihdr, tuple(chunks), has_iend


def _validate_png_image_data(
    ihdr: tuple[int, ...],
    chunks: tuple[tuple[bytes, bytes], ...],
) -> None:
    """Validate IDAT with bounded streaming decompression and scanline checks."""
    width, height, bit_depth, color_type, _, _, interlace = ihdr
    channels_by_type = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}

    channels = channels_by_type.get(color_type)
    if channels is None:
        raise ValueError("Fixture uses an unsupported PNG color type.")
    if width <= 0 or height <= 0 or bit_depth not in {1, 2, 4, 8, 16}:
        raise ValueError("PNG dimensions or bit depth are invalid.")
    if width > _MAX_IMAGE_WIDTH or height > _MAX_IMAGE_HEIGHT:
        raise ValueError("PNG dimensions exceed the configured harness limits.")
    if width * height > _MAX_TOTAL_PIXELS:
        raise ValueError("PNG dimensions exceed the configured total-pixel limit.")

    bits_per_pixel = channels * bit_depth
    if interlace == 0:
        passes = ((0, 0, 1, 1),)
    elif interlace == 1:
        passes = (
            (0, 0, 8, 8),
            (4, 0, 8, 8),
            (0, 4, 4, 8),
            (2, 0, 4, 4),
            (0, 2, 2, 4),
            (1, 0, 2, 2),
            (0, 1, 1, 2),
        )
    else:
        raise ValueError("PNG interlace method is invalid.")

    # Keep only per-row byte counts, never the complete decompressed image.
    row_lengths: list[int] = []
    expected_size = 0
    for x_start, y_start, x_step, y_step in passes:
        pass_width = (
            (width - x_start + x_step - 1) // x_step
            if width > x_start else 0
        )
        pass_height = (
            (height - y_start + y_step - 1) // y_step
            if height > y_start else 0
        )
        if not pass_width or not pass_height:
            continue

        row_bytes = (pass_width * bits_per_pixel + 7) // 8
        row_size = row_bytes + 1  # One filter byte precedes every scanline.
        expected_size += pass_height * row_size
        if expected_size > _MAX_PNG_DECOMPRESSED_BYTES:
            raise ValueError(
                "PNG expected decompressed image data exceeds the 128 MiB limit."
            )
        row_lengths.extend([row_size] * pass_height)

    if not row_lengths:
        raise ValueError("PNG image has no non-empty scanlines.")

    compressed = b"".join(
        payload for kind, payload in chunks if kind == b"IDAT"
    )
    if not compressed:
        raise ValueError("PNG has no compressed image data.")

    decoder = zlib.decompressobj()
    row_index = 0
    row_remaining = row_lengths[0]
    filter_pending = True
    produced_size = 0

    def consume_output(output: bytes) -> None:
        nonlocal row_index, row_remaining, filter_pending, produced_size
        if not output:
            return
        produced_size += len(output)
        if produced_size > expected_size:
            raise ValueError(
                "PNG IDAT expands beyond the decompressed size required by IHDR."
            )

        offset = 0
        while offset < len(output):
            if row_index >= len(row_lengths):
                raise ValueError("PNG image data contains extra scanline bytes.")

            available = len(output) - offset
            consumed = min(row_remaining, available)
            if filter_pending:
                filter_type = output[offset]
                if filter_type > 4:
                    raise ValueError(f"Invalid PNG filter type: {filter_type}.")
                filter_pending = False

            offset += consumed
            row_remaining -= consumed
            if row_remaining == 0:
                row_index += 1
                if row_index < len(row_lengths):
                    row_remaining = row_lengths[row_index]
                    filter_pending = True

    def feed_compressed(data: bytes) -> None:
        pending = data
        while pending:
            previous_pending_size = len(pending)
            try:
                output = decoder.decompress(
                    pending, _PNG_DECOMPRESS_OUTPUT_CHUNK_BYTES
                )
            except zlib.error as exc:
                raise ValueError(
                    f"PNG IDAT data is not valid zlib data: {exc}"
                ) from exc
            consume_output(output)
            pending = decoder.unconsumed_tail
            if pending and len(pending) == previous_pending_size and not output:
                raise ValueError("PNG decompressor made no progress.")

    for offset in range(0, len(compressed), _PNG_DECOMPRESS_INPUT_CHUNK_BYTES):
        feed_compressed(
            compressed[offset:offset + _PNG_DECOMPRESS_INPUT_CHUNK_BYTES]
        )

    # Drain output buffered internally by zlib without allowing an unbounded
    # allocation. A fixed output size is enforced on every decompressor call.
    while True:
        try:
            output = decoder.decompress(b"", _PNG_DECOMPRESS_OUTPUT_CHUNK_BYTES)
        except zlib.error as exc:
            raise ValueError(f"PNG IDAT decompression failed: {exc}") from exc
        if not output:
            break
        consume_output(output)

    if not decoder.eof or decoder.unused_data or decoder.unconsumed_tail:
        raise ValueError("PNG IDAT zlib stream is incomplete or has trailing data.")
    if produced_size != expected_size or row_index != len(row_lengths):
        raise ValueError("PNG image data has an unexpected decompressed length.")

def _validate_seed_fixture(case_name: str, path: Path) -> None:
    """Verify that a named smoke fixture really represents its intended case."""
    data = path.read_bytes()

    if case_name == "malformed_png":
        if not data or data.startswith(_PNG_SIGNATURE):
            raise ValueError("Malformed fixture must have a non-PNG signature.")
        return

    ihdr, chunks, has_iend = _inspect_png_fixture(data)
    width, height, bit_depth, color_type, compression, filtering, interlace = ihdr
    chunk_types = [kind for kind, _ in chunks]
    text_payloads = [
        payload for kind, payload in chunks if kind == b"tEXt"
    ]
    text_lengths = [len(payload) for payload in text_payloads]
    for payload in text_payloads:
        separator = payload.find(b"\\x00")
        if separator < 1 or separator > 79:
            raise ValueError(
                "tEXt keyword must have a NUL separator after 1 to 79 bytes."
            )
        if b"\\x00" in payload[separator + 1:]:
            raise ValueError("tEXt text field must not contain a NUL byte.")

    if compression != 0 or filtering != 0:
        raise ValueError("PNG compression and filter methods must be zero.")

    if case_name == "truncated_png":
        if ihdr != (1, 1, 8, 6, 0, 0, 0):
            raise ValueError("Truncated fixture has unexpected IHDR metadata.")
        if has_iend or chunk_types[-1] != b"IDAT":
            raise ValueError("Truncated fixture must end after complete IDAT data.")
        _validate_png_image_data(ihdr, chunks)
        return

    if not has_iend:
        raise ValueError("PNG fixture must contain a final IEND chunk.")

    if case_name == "valid_png":
        if ihdr != (1, 1, 8, 6, 0, 0, 0):
            raise ValueError("Valid PNG fixture has unexpected IHDR metadata.")
        _validate_png_image_data(ihdr, chunks)

    elif case_name == "adam7_png":
        if ihdr != (8, 8, 8, 6, 0, 0, 1):
            raise ValueError("Adam7 fixture must be an 8x8 interlaced RGBA PNG.")
        _validate_png_image_data(ihdr, chunks)

    elif case_name == "width_limit":
        if width <= _MAX_IMAGE_WIDTH:
            raise ValueError("Width fixture does not exceed the 8192-pixel limit.")

    elif case_name == "height_limit":
        if height <= _MAX_IMAGE_HEIGHT:
            raise ValueError("Height fixture does not exceed the 8192-pixel limit.")

    elif case_name == "pixel_limit":
        if (
            width < 1 or height < 1
            or width > _MAX_IMAGE_WIDTH
            or height > _MAX_IMAGE_HEIGHT
        ):
            raise ValueError(
                "Pixel-limit fixture must remain within individual dimension limits."
            )
        if width * height <= _MAX_TOTAL_PIXELS:
            raise ValueError("Pixel fixture does not exceed the total-pixel limit.")

    elif case_name == "row_boundary":
        channels_by_type = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}
        channels = channels_by_type.get(color_type)
        if channels is None:
            raise ValueError("Row-boundary fixture has an unsupported color type.")
        row_bytes = (width * channels * bit_depth + 7) // 8
        if row_bytes != _MAX_ROW_BYTES:
            raise ValueError("Row-boundary fixture must be exactly 64 KiB per row.")
        if ihdr != (8192, 1, 16, 6, 0, 0, 0):
            raise ValueError("Row-boundary fixture has unexpected IHDR metadata.")
        _validate_png_image_data(ihdr, chunks)

    elif case_name == "chunk_allocation_limit":
        if not text_lengths or max(text_lengths) <= _MAX_CHUNK_BYTES:
            raise ValueError("Fixture has no tEXt chunk larger than 256 KiB.")
        _validate_png_image_data(ihdr, chunks)

    elif case_name == "chunk_cache_limit":
        idat_index = chunk_types.index(b"IDAT")
        before_idat = sum(
            1 for kind, _ in chunks[:idat_index] if kind == b"tEXt"
        )
        after_idat = sum(
            1 for kind, _ in chunks[idat_index + 1:] if kind == b"tEXt"
        )
        if max(before_idat, after_idat) <= _MAX_CACHED_CHUNKS:
            raise ValueError(
                "Fixture does not exceed the 128-chunk cache limit "
                "within either info structure."
            )
        _validate_png_image_data(ihdr, chunks)

    else:
        raise ValueError(f"No semantic expectations exist for {case_name!r}.")




def _read_bounded_output(stream) -> str:
    """Read at most the last 16 KiB from a temporary output stream."""
    stream.flush()
    stream.seek(0, os.SEEK_END)
    total_bytes = stream.tell()
    start = max(0, total_bytes - _MAX_CAPTURE_BYTES)
    stream.seek(start)
    data = stream.read(_MAX_CAPTURE_BYTES)

    content = data.decode("utf-8", errors="replace")
    if start:
        content = (
            f"[Earlier output omitted: {start} bytes]\n"
            + content
        )

    return content


def _paths_overlap(first: Path, second: Path) -> bool:
    """Return whether either path contains the other."""
    return (
        first == second
        or first in second.parents
        or second in first.parents
    )


def _memory_limit_callback(memory_mib: int):
    """Create a POSIX child-process address-space limit callback."""
    if os.name != "posix":
        raise HarnessSmokeError(
            "Memory-limited smoke execution currently requires POSIX."
        )

    try:
        import resource
    except ImportError as exc:
        raise HarnessSmokeError(
            "The Python resource module is unavailable."
        ) from exc

    if not hasattr(resource, "RLIMIT_AS"):
        raise HarnessSmokeError(
            "This platform does not support RLIMIT_AS."
        )

    if not hasattr(resource, "RLIMIT_FSIZE"):
        raise HarnessSmokeError(
            "This platform does not support RLIMIT_FSIZE."
        )

    requested_bytes = memory_mib * 1024 * 1024

    def apply_limit() -> None:
        address_soft, address_hard = resource.getrlimit(
            resource.RLIMIT_AS
        )
        effective_address = requested_bytes

        for current_limit in (address_soft, address_hard):
            if current_limit != resource.RLIM_INFINITY:
                effective_address = min(
                    effective_address,
                    current_limit,
                )

        resource.setrlimit(
            resource.RLIMIT_AS,
            (effective_address, effective_address),
        )

        file_soft, file_hard = resource.getrlimit(
            resource.RLIMIT_FSIZE
        )
        effective_file = _MAX_OUTPUT_FILE_BYTES

        for current_limit in (file_soft, file_hard):
            if current_limit != resource.RLIM_INFINITY:
                effective_file = min(effective_file, current_limit)

        resource.setrlimit(
            resource.RLIMIT_FSIZE,
            (effective_file, effective_file),
        )

    return apply_limit


def run_harness_smoke(
    config: AdapterConfig,
    project_root: str | Path,
    timeout_seconds: float = 5.0,
) -> HarnessSmokeReport:
    """Run a fixed set of bounded libpng harness smoke cases.

    This function executes only the configured harness binary. It never
    invokes AFL++, builds software, writes campaign output or modifies the
    configured seed corpus.

    Temporary empty, oversized and missing-file cases live in a temporary
    directory outside the repository. The harness is never run as root.
    """
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(timeout_seconds)
        or not 0.1 <= timeout_seconds <= 60.0
    ):
        raise HarnessSmokeError(
            "Per-case timeout must be between 0.1 and 60 seconds."
        )

    if config.target.name.casefold() != "libpng":
        raise HarnessSmokeError(
            "Smoke validation is currently implemented only for libpng."
        )

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise HarnessSmokeError(
            "Refusing to execute the target harness as root."
        )

    try:
        root = Path(project_root).expanduser().resolve(strict=True)
        source_dir = config.target.source_dir.resolve(strict=True)
        binary = config.target.harness_binary.resolve(strict=True)
        seed_dir = config.target.seed_dir.resolve(strict=True)
        temporary_parent = Path(tempfile.gettempdir()).resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise HarnessSmokeError(
            f"Unable to resolve smoke-test paths: {exc}"
        ) from exc

    if not root.is_dir():
        raise HarnessSmokeError("Project root is not a directory.")

    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise HarnessSmokeError(
            f"Harness binary is missing or not executable: {binary}"
        )

    if not source_dir.is_dir():
        raise HarnessSmokeError(
            f"Target source directory is missing: {source_dir}"
        )

    if not seed_dir.is_dir():
        raise HarnessSmokeError(
            f"Seed directory is missing: {seed_dir}"
        )

    if not temporary_parent.is_dir():
        raise HarnessSmokeError(
            f"Temporary parent is not a directory: {temporary_parent}"
        )

    if (
        temporary_parent == root
        or root in temporary_parent.parents
        or temporary_parent == source_dir
        or source_dir in temporary_parent.parents
    ):
        raise HarnessSmokeError(
            "System temporary directory is inside the repository "
            "or target source tree."
        )

    # This harness requires no inherited user environment. Avoid dynamic
    # loader injection, AFL overrides and unrelated shell configuration.
    child_environment = {
        "PATH": os.defpath,
        "LC_ALL": "C",
        "KEKKAI_HARNESS_DIAGNOSTICS": "1",
    }

    memory_limit_callback = _memory_limit_callback(
        config.limits.memory_mib
    )

    results: list[SmokeCaseResult] = []

    def record_unexecuted_failure(name: str, message: str) -> None:
        results.append(
            SmokeCaseResult(
                name=name,
                status="failed",
                expected_exit_code=0,
                actual_exit_code=None,
                elapsed_seconds=0.0,
                message=message,
                stdout="",
                stderr="",
            )
        )

    def execute_case(
        name: str,
        input_path: Path,
        expected_exit_code: int,
        purpose: str,
    ) -> None:
        started = time.monotonic()
        actual_exit_code: int | None = None
        failure_message = ""

        # Temporary output files keep captured process output out of the
        # repository and bound how much output is returned in the report.
        with tempfile.TemporaryFile(mode="w+b") as stdout_file:
            with tempfile.TemporaryFile(mode="w+b") as stderr_file:
                try:
                    completed = run_process_group(
                        [str(binary), str(input_path)],
                        cwd=root,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout_file,
                        stderr=stderr_file,
                        env=child_environment,
                        timeout=timeout_seconds,
                        preexec_fn=memory_limit_callback,
                        check=False,
                        shell=False,
                    )
                    actual_exit_code = completed.returncode
                except ProcessInterruptedError:
                    raise
                except subprocess.TimeoutExpired:
                    failure_message = (
                        f"Exceeded the {timeout_seconds:.2f}s timeout; "
                        "the complete process group was terminated and reaped."
                    )
                except OSError as exc:
                    failure_message = (
                        f"Unable to execute harness: {exc}"
                    )
                except subprocess.SubprocessError as exc:
                    failure_message = (
                        f"Unable to start harness with resource limits: {exc}"
                    )

                elapsed = time.monotonic() - started
                stdout_text = _read_bounded_output(stdout_file)
                stderr_text = _read_bounded_output(stderr_file)

        if failure_message:
            status = "failed"
            message = failure_message
        elif actual_exit_code != expected_exit_code:
            status = "failed"
            message = (
                f"{purpose}; exit status did not match expectation."
            )
        else:
            status = "passed"
            message = purpose

        results.append(
            SmokeCaseResult(
                name=name,
                status=status,
                expected_exit_code=expected_exit_code,
                actual_exit_code=actual_exit_code,
                elapsed_seconds=elapsed,
                message=message,
                stdout=stdout_text,
                stderr=stderr_text,
            )
        )

    # Run the fixed representative seed set. Missing, symlinked or
    # oversized fixtures fail explicitly rather than being silently skipped.
    for case_name, filename in LIBPNG_SEED_CASES:
        input_path = seed_dir / filename

        if input_path.is_symlink() or not input_path.is_file():
            record_unexecuted_failure(
                case_name,
                f"Required regular seed file is missing or unsafe: {filename}",
            )
            continue

        try:
            input_size = input_path.stat(follow_symlinks=False).st_size
        except OSError as exc:
            record_unexecuted_failure(
                case_name,
                f"Cannot inspect seed file {filename}: {exc}",
            )
            continue

        if input_size > config.limits.max_input_bytes:
            record_unexecuted_failure(
                case_name,
                f"Seed file exceeds configured input limit: {filename}",
            )
            continue

        try:
            _validate_seed_fixture(case_name, input_path)
        except (OSError, ValueError) as exc:
            record_unexecuted_failure(
                case_name,
                f"Fixture semantic validation failed for {filename}: {exc}",
            )
            continue

        execute_case(
            case_name,
            input_path,
            expected_exit_code=0,
            purpose=(
                f"Fixture semantics verified; input was handled without "
                f"a harness failure ({filename}, {input_size} bytes)."
            ),
        )

    # Create short-lived special fixtures outside the repository and seed
    # corpus. The oversized fixture is sparse; the harness checks its file
    # length before attempting to read its contents.
    try:
        with tempfile.TemporaryDirectory(
            prefix="kekkai-harness-smoke-",
            dir=temporary_parent,
        ) as temporary_directory:
            temporary_root = Path(temporary_directory).resolve(strict=True)

            if (
                _paths_overlap(temporary_root, root)
                or _paths_overlap(temporary_root, source_dir)
            ):
                raise HarnessSmokeError(
                    "Created smoke-test temporary directory overlaps "
                    "the repository or target source tree."
                )

            empty_path = temporary_root / "empty.png"
            empty_path.write_bytes(b"")

            oversized_path = temporary_root / "oversized.png"
            with oversized_path.open("wb") as oversized_file:
                oversized_file.truncate(
                    config.limits.max_input_bytes + 1
                )

            missing_path = temporary_root / "missing-input.png"

            execute_case(
                "empty_input",
                empty_path,
                expected_exit_code=0,
                purpose="Empty input was rejected through the normal parser path.",
            )

            execute_case(
                "oversized_input",
                oversized_path,
                expected_exit_code=0,
                purpose=(
                    "Input larger than the configured limit was rejected "
                    "without a harness failure."
                ),
            )

            execute_case(
                "missing_input_file",
                missing_path,
                expected_exit_code=2,
                purpose=(
                    "Missing input file was classified as an input/harness "
                    "failure."
                ),
            )
    except OSError as exc:
        record_unexecuted_failure(
            "temporary_fixtures",
            f"Could not create temporary smoke fixtures: {exc}",
        )

    return HarnessSmokeReport(
        target_name=config.target.name,
        target_version=config.target.version,
        results=tuple(results),
    )
