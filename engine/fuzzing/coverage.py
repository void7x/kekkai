"""AFL++ coverage-feedback validation for the KEKKAI libpng adapter."""

from __future__ import annotations

import hashlib
import math
import os
import re
import shutil
import stat
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from engine.adapters.config import AdapterConfig
from engine.fuzzing.smoke import LIBPNG_SEED_CASES

_MAX_PROCESS_OUTPUT_BYTES = 8 * 1024 * 1024
_MAX_CAPTURED_PROCESS_OUTPUT_BYTES = 4096
_MAX_COVERAGE_MAP_BYTES = 8 * 1024 * 1024


class CoverageValidationError(RuntimeError):
    """Raised when coverage validation cannot safely be initialized."""


@dataclass(frozen=True)
class CoverageCaseResult:
    name: str
    status: str
    tuple_count: int
    sha256: str | None
    elapsed_seconds: float
    message: str
    stderr: str


@dataclass(frozen=True)
class CoverageReport:
    target_name: str
    target_version: str
    tool_version: str | None
    tool_status: str
    tool_message: str
    cases: tuple[CoverageCaseResult, ...]
    distinct_map_count: int
    diversity_status: str
    repeat_runs: tuple[CoverageCaseResult, ...]
    repeatability_status: str

    @property
    def passed(self) -> bool:
        return (
            self.tool_status == "passed"
            and len(self.cases) == len(LIBPNG_SEED_CASES)
            and all(case.status == "passed" for case in self.cases)
            and self.diversity_status == "passed"
            and len(self.repeat_runs) == 2
            and all(run.status == "passed" for run in self.repeat_runs)
            and self.repeatability_status == "passed"
        )

    @property
    def failed_cases(self) -> tuple[CoverageCaseResult, ...]:
        return tuple(
            case
            for case in self.cases + self.repeat_runs
            if case.status == "failed"
        )

    def format(self) -> str:
        outcome = "PASS" if self.passed else "FAIL"
        lines = [
            f"Coverage validation: {outcome}",
            f"Target: {self.target_name} {self.target_version}",
            f"AFL-showmap: {self.tool_version or 'unknown'} "
            f"[{self.tool_status}]",
            f"Tool: {self.tool_message}",
            f"Seed maps: {len(self.cases)}",
        ]

        for case in self.cases:
            lines.append(
                f"[{case.status.upper()}] {case.name}: "
                f"{case.tuple_count} tuples; "
                f"SHA-256={case.sha256 or 'unavailable'}; "
                f"{case.elapsed_seconds:.3f}s; {case.message}"
            )
            if case.stderr:
                lines.append(f"  stderr: {case.stderr}")

        lines.extend(
            [
                f"Distinct seed maps: {self.distinct_map_count} "
                f"[{self.diversity_status}]",
                f"Adam7 repeatability: {self.repeatability_status}",
            ]
        )

        for run in self.repeat_runs:
            lines.append(
                f"[{run.status.upper()}] {run.name}: "
                f"{run.tuple_count} tuples; "
                f"SHA-256={run.sha256 or 'unavailable'}; "
                f"{run.elapsed_seconds:.3f}s; {run.message}"
            )

        return "\n".join(lines)


def _is_within(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _bounded_text(value: str | bytes | None, maximum: int = 4096) -> str:
    if value is None:
        return ""

    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")

    if len(value) > maximum:
        return "[Earlier output omitted]\n" + value[-maximum:]

    return value



def _file_size_limit_callback(maximum_bytes: int):
    """Set a bounded child-process file-size limit without raising limits."""
    if os.name != "posix":
        raise OSError("Bounded subprocess output requires POSIX.")

    try:
        import resource
    except ImportError as exc:
        raise OSError("The resource module is unavailable.") from exc

    if not hasattr(resource, "RLIMIT_FSIZE"):
        raise OSError("RLIMIT_FSIZE is unavailable.")

    def apply_limit() -> None:
        soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
        effective_limit = maximum_bytes

        for current in (soft_limit, hard_limit):
            if current != resource.RLIM_INFINITY:
                effective_limit = min(effective_limit, current)

        resource.setrlimit(
            resource.RLIMIT_FSIZE,
            (effective_limit, hard_limit),
        )

    return apply_limit


def _read_process_output(stream) -> tuple[int, str]:
    """Read only a bounded tail from a subprocess output file."""
    stream.flush()
    size = os.fstat(stream.fileno()).st_size
    start = max(0, size - _MAX_CAPTURED_PROCESS_OUTPUT_BYTES)
    stream.seek(start)
    content = stream.read(
        _MAX_CAPTURED_PROCESS_OUTPUT_BYTES
    ).decode("utf-8", errors="replace")

    if start:
        content = f"[Earlier output omitted: {start} bytes]\\n" + content

    return size, content


def _run_bounded_process(
    command: list[str],
    *,
    cwd: Path,
    timeout: float,
    env: dict[str, str],
) -> tuple[int, int, str, int, str]:
    """Run a process with bounded output files and bounded memory capture."""
    with (
        tempfile.TemporaryFile(mode="w+b") as stdout_file,
        tempfile.TemporaryFile(mode="w+b") as stderr_file,
    ):
        completed = subprocess.run(
            command,
            cwd=cwd,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            timeout=timeout,
            check=False,
            shell=False,
            env=env,
            preexec_fn=_file_size_limit_callback(
                _MAX_PROCESS_OUTPUT_BYTES
            ),
        )

        stdout_size, stdout_text = _read_process_output(stdout_file)
        stderr_size, stderr_text = _read_process_output(stderr_file)

    return (
        completed.returncode,
        stdout_size,
        stdout_text,
        stderr_size,
        stderr_text,
    )


def _not_run_case(name: str, message: str) -> CoverageCaseResult:
    return CoverageCaseResult(
        name=name,
        status="not_run",
        tuple_count=0,
        sha256=None,
        elapsed_seconds=0.0,
        message=message,
        stderr="",
    )

def _read_coverage_map(path: Path) -> bytes:
    """Read a regular coverage map without exceeding the configured limit."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW

    descriptor = os.open(path, flags)

    try:
        metadata = os.fstat(descriptor)

        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("Coverage map is not a regular file.")

        if metadata.st_size > _MAX_COVERAGE_MAP_BYTES:
            raise ValueError(
                f"Coverage map exceeds the "
                f"{_MAX_COVERAGE_MAP_BYTES}-byte limit."
            )

        stream = os.fdopen(descriptor, "rb")
        descriptor = -1

        with stream:
            content = stream.read(_MAX_COVERAGE_MAP_BYTES + 1)

        if len(content) > _MAX_COVERAGE_MAP_BYTES:
            raise ValueError(
                f"Coverage map exceeds the "
                f"{_MAX_COVERAGE_MAP_BYTES}-byte limit."
            )

        return content
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _parse_map(map_bytes: bytes) -> int:
    """Validate AFL++ 4.33c textual map format and return tuple count."""
    if not map_bytes:
        raise ValueError("Coverage map is empty.")

    try:
        text = map_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("Coverage map is not ASCII text.") from exc

    lines = text.splitlines()
    if not lines:
        raise ValueError("Coverage map contains no tuple entries.")

    seen_locations: set[str] = set()

    for line_number, line in enumerate(lines, start=1):
        match = re.fullmatch(r"([0-9A-Fa-f]{6}):([0-9]+)", line)

        if match is None:
            raise ValueError(
                f"Invalid coverage tuple at line {line_number}: {line!r}."
            )

        location, value_text = match.groups()

        if location in seen_locations:
            raise ValueError(
                f"Duplicate coverage location at line {line_number}: "
                f"{location}."
            )

        if int(value_text) <= 0:
            raise ValueError(
                f"Non-positive tuple value at line {line_number}."
            )

        seen_locations.add(location)

    return len(lines)


def _failed_case(
    name: str,
    message: str,
    elapsed_seconds: float = 0.0,
    stderr: str = "",
) -> CoverageCaseResult:
    return CoverageCaseResult(
        name=name,
        status="failed",
        tuple_count=0,
        sha256=None,
        elapsed_seconds=elapsed_seconds,
        message=message,
        stderr=_bounded_text(stderr),
    )


def validate_coverage(
    config: AdapterConfig,
    project_root: str | Path,
) -> CoverageReport:
    """Collect individual per-input maps and test diversity/repeatability.

    Uses only the fixed PATH-resolved 'afl-showmap' executable.

    Important:
    - Runs one input per process using a direct testcase path.
    - Does not use afl-showmap directory-scanning mode or -C mode.
    - Does not execute afl-fuzz.
    - Does not modify the original seed corpus.
    - Writes maps only into a temporary directory outside the repository.
    - Uses the adapter's configured target memory and execution timeout.
    """
    if config.target.name.casefold() != "libpng":
        raise CoverageValidationError(
            "Coverage validation is currently implemented only for libpng."
        )

    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise CoverageValidationError(
            "Refusing to run AFL++ coverage validation as root."
        )

    try:
        root = Path(project_root).expanduser().resolve(strict=True)
        binary = config.target.harness_binary.resolve(strict=True)
        seed_dir = config.target.seed_dir.resolve(strict=True)
        temporary_root = Path(tempfile.gettempdir()).resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise CoverageValidationError(
            f"Unable to resolve coverage paths: {exc}"
        ) from exc

    if not root.is_dir():
        raise CoverageValidationError("Project root must be a directory.")

    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise CoverageValidationError(
            f"Harness binary is missing or not executable: {binary}"
        )

    if not seed_dir.is_dir():
        raise CoverageValidationError(
            f"Seed directory is missing: {seed_dir}"
        )

    if _is_within(temporary_root, root):
        raise CoverageValidationError(
            "The system temporary directory is inside the repository. "
            "Coverage maps must remain outside tracked source."
        )

    showmap_path = shutil.which("afl-showmap")
    if showmap_path is None:
        return CoverageReport(
            target_name=config.target.name,
            target_version=config.target.version,
            tool_version=None,
            tool_status="failed",
            tool_message="Cannot find the approved afl-showmap executable on PATH.",
            cases=(),
            distinct_map_count=0,
            diversity_status="not_run",
            repeat_runs=(),
            repeatability_status="not_run",
        )

    showmap = Path(showmap_path).resolve(strict=True)
    if not showmap.is_file() or not os.access(showmap, os.X_OK):
        return CoverageReport(
            target_name=config.target.name,
            target_version=config.target.version,
            tool_version=None,
            tool_status="failed",
            tool_message=f"Resolved afl-showmap is not executable: {showmap}",
            cases=(),
            distinct_map_count=0,
            diversity_status="not_run",
            repeat_runs=(),
            repeatability_status="not_run",
        )

    # Remove inherited AFL configuration so an interactive shell or a
    # previous diagnostic command cannot silently change this validation.
    child_environment = os.environ.copy()
    for key in tuple(child_environment):
        if key.startswith("AFL_") or key.startswith("__AFL_"):
            child_environment.pop(key, None)

    try:
        (
            version_returncode,
            version_stdout_size,
            version_stdout,
            version_stderr_size,
            version_stderr,
        ) = _run_bounded_process(
            [str(showmap), "-h"],
            cwd=root,
            timeout=5,
            env=child_environment,
        )
    except subprocess.TimeoutExpired:
        tool_version = None
        tool_status = "failed"
        tool_message = "afl-showmap -h timed out after five seconds."
    except OSError as exc:
        tool_version = None
        tool_status = "failed"
        tool_message = f"Could not execute afl-showmap: {exc}"
    else:
        version_text = (
            version_stdout + "\n" + version_stderr
        )
        match = re.search(
            r"afl-showmap\+\+([0-9A-Za-z.+_-]+)",
            version_text,
        )

        tool_version = match.group(1) if match else None

        # AFL++ 4.33c prints its help banner and returns status 1 for -h.
        if (
            version_stdout_size >= _MAX_PROCESS_OUTPUT_BYTES
            or version_stderr_size >= _MAX_PROCESS_OUTPUT_BYTES
        ):
            tool_status = "failed"
            tool_message = "afl-showmap -h exceeded the 8 MiB output limit."
        elif version_returncode not in (0, 1):
            tool_status = "failed"
            tool_message = (
                "afl-showmap -h exited with unexpected status "
                f"{version_returncode}."
            )
        elif tool_version != config.fuzzer.expected_version:
            tool_status = "failed"
            tool_message = (
                f"Expected AFL++ {config.fuzzer.expected_version}; "
                f"observed {tool_version or 'unrecognized version'}."
            )
        else:
            tool_status = "passed"
            tool_message = (
                f"Version matches {config.fuzzer.expected_version}; "
                f"help exit status {version_returncode} accepted."
            )

    if tool_status != "passed":
        return CoverageReport(
            target_name=config.target.name,
            target_version=config.target.version,
            tool_version=tool_version,
            tool_status=tool_status,
            tool_message=tool_message,
            cases=(),
            distinct_map_count=0,
            diversity_status="not_run",
            repeat_runs=(),
            repeatability_status="not_run",
        )

    cases: list[CoverageCaseResult] = []
    repeat_runs: list[CoverageCaseResult] = []
    seen_hashes: set[str] = set()

    external_timeout = max(
        5.0,
        config.limits.timeout_ms / 1000.0 + 5.0,
    )

    def run_one(
        name: str,
        input_path: Path,
        map_path: Path,
    ) -> CoverageCaseResult:
        started = time.monotonic()

        command = [
            str(showmap),
            "-e",
            "-o",
            str(map_path),
            "-m",
            str(config.limits.memory_mib),
            "-t",
            str(config.limits.timeout_ms),
            "--",
            str(binary),
            str(input_path),
        ]

        try:
            (
                completed_returncode,
                stdout_size,
                _stdout_text,
                stderr_size,
                stderr,
            ) = _run_bounded_process(
                command,
                cwd=root,
                timeout=external_timeout,
                env=child_environment,
            )
        except subprocess.TimeoutExpired as exc:
            elapsed = time.monotonic() - started
            return _failed_case(
                name,
                f"afl-showmap process timed out after exceeding the "
                f"{external_timeout:.1f}s outer limit.",
                elapsed,
                _bounded_text(exc.stderr),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            elapsed = time.monotonic() - started
            return _failed_case(
                name,
                f"Could not complete afl-showmap: {exc}",
                elapsed,
            )

        elapsed = time.monotonic() - started

        if (
            stdout_size >= _MAX_PROCESS_OUTPUT_BYTES
            or stderr_size >= _MAX_PROCESS_OUTPUT_BYTES
        ):
            return _failed_case(
                name,
                "afl-showmap output reached the 8 MiB per-stream limit.",
                elapsed,
                stderr,
            )

        if completed_returncode != 0:
            return _failed_case(
                name,
                f"afl-showmap exited with status {completed_returncode}.",
                elapsed,
                stderr,
            )

        try:
            map_bytes = _read_coverage_map(map_path)
            tuple_count = _parse_map(map_bytes)
        except (OSError, ValueError) as exc:
            return _failed_case(
                name,
                f"Coverage map validation failed: {exc}",
                elapsed,
                stderr,
            )

        digest = hashlib.sha256(map_bytes).hexdigest()

        return CoverageCaseResult(
            name=name,
            status="passed",
            tuple_count=tuple_count,
            sha256=digest,
            elapsed_seconds=elapsed,
            message="Non-empty, valid coverage map captured.",
            stderr=stderr,
        )

    with tempfile.TemporaryDirectory(
        prefix="kekkai-coverage-",
        dir=temporary_root,
    ) as temporary_directory:
        temporary = Path(temporary_directory)

        # One process per seed. Direct paths avoid the AFL++ 4.33c
        # directory-scanning/forkserver failure observed in this environment.
        for case_name, filename in LIBPNG_SEED_CASES:
            input_path = seed_dir / filename
            map_path = temporary / f"{case_name}.map"

            if input_path.is_symlink() or not input_path.is_file():
                result = _failed_case(
                    case_name,
                    f"Required seed is missing or unsafe: {filename}.",
                )
            else:
                try:
                    input_size = input_path.stat(
                        follow_symlinks=False
                    ).st_size
                except OSError as exc:
                    result = _failed_case(
                        case_name,
                        f"Cannot inspect seed file: {exc}",
                    )
                else:
                    if input_size == 0:
                        result = _failed_case(
                            case_name,
                            "Coverage seed must be non-empty.",
                        )
                    elif input_size > config.limits.max_input_bytes:
                        result = _failed_case(
                            case_name,
                            "Seed exceeds the configured input-size limit.",
                        )
                    else:
                        result = run_one(
                            case_name,
                            input_path,
                            map_path,
                        )

            cases.append(result)
            if result.status == "passed" and result.sha256 is not None:
                seen_hashes.add(result.sha256)

        all_seed_cases_passed = (
            len(cases) == len(LIBPNG_SEED_CASES)
            and all(case.status == "passed" for case in cases)
        )

        distinct_map_count = len(seen_hashes)

        if all_seed_cases_passed:
            diversity_status = (
                "passed" if distinct_map_count > 1 else "failed"
            )
        else:
            diversity_status = "not_run"

        # Repeat the exact same Adam7 input in two separate afl-showmap
        # processes. No map IDs are compared across different builds.
        adam7_path = seed_dir / "adam7.png"

        if not adam7_path.is_file() or adam7_path.is_symlink():
            repeat_runs.extend(
                [
                    _failed_case("adam7_repeat_1", "Adam7 seed is unavailable."),
                    _failed_case("adam7_repeat_2", "Adam7 seed is unavailable."),
                ]
            )
        else:
            for index in (1, 2):
                repeat_runs.append(
                    run_one(
                        f"adam7_repeat_{index}",
                        adam7_path,
                        temporary / f"adam7_repeat_{index}.map",
                    )
                )

        initial_adam7 = next(
            (case for case in cases if case.name == "adam7_png"),
            None,
        )

        if (
            len(repeat_runs) == 2
            and all(run.status == "passed" for run in repeat_runs)
            and initial_adam7 is not None
            and initial_adam7.status == "passed"
            and initial_adam7.sha256 is not None
        ):
            all_adam7_hashes = {
                initial_adam7.sha256,
                repeat_runs[0].sha256,
                repeat_runs[1].sha256,
            }
            repeatability_status = (
                "passed" if len(all_adam7_hashes) == 1 else "failed"
            )
        else:
            repeatability_status = "failed"

    return CoverageReport(
        target_name=config.target.name,
        target_version=config.target.version,
        tool_version=tool_version,
        tool_status=tool_status,
        tool_message=tool_message,
        cases=tuple(cases),
        distinct_map_count=distinct_map_count,
        diversity_status=diversity_status,
        repeat_runs=tuple(repeat_runs),
        repeatability_status=repeatability_status,
    )
