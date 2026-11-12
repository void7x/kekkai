"""Bounded standalone smoke validation for the KEKKAI libpng harness."""

from __future__ import annotations

import math
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from engine.adapters.config import AdapterConfig


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
                    completed = subprocess.run(
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
                except subprocess.TimeoutExpired:
                    failure_message = (
                        f"Exceeded the {timeout_seconds:.2f}s timeout; "
                        "subprocess.run terminated and reaped the process."
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

        execute_case(
            case_name,
            input_path,
            expected_exit_code=0,
            purpose=(
                f"Input was handled without a harness failure "
                f"({filename}, {input_size} bytes)."
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
