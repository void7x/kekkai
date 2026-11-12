"""Bounded execution and verification of the fixed libpng build profile."""

from __future__ import annotations

import hashlib
import json
import os
import resource
import shlex
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from engine.adapters.config import AdapterConfig
from engine.build.libpng import BuildError, build_command_plan


class BuildState(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


@dataclass(frozen=True)
class BuildResult:
    status: BuildState
    build_dir: Path
    metadata_path: Path
    started_at: str
    ended_at: str
    message: str
    artifacts: tuple[tuple[str, str], ...]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_metadata(build_dir: Path, metadata: dict) -> None:
    temporary = build_dir / f".build-{uuid.uuid4().hex}.tmp"
    destination = build_dir / "build.json"
    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(metadata, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _set_child_limits(memory_mib: int, cpu_seconds: int) -> None:
    memory_limit = memory_mib * 1024 * 1024
    soft, hard = resource.getrlimit(resource.RLIMIT_AS)

    new_hard = (
        memory_limit
        if hard == resource.RLIM_INFINITY
        else min(memory_limit, hard)
    )
    new_soft = (
        memory_limit
        if soft == resource.RLIM_INFINITY
        else min(memory_limit, soft)
    )
    new_soft = min(new_soft, new_hard)
    resource.setrlimit(resource.RLIMIT_AS, (new_soft, new_hard))

    soft, hard = resource.getrlimit(resource.RLIMIT_CPU)
    desired_cpu = max(1, cpu_seconds)
    new_hard = (
        desired_cpu
        if hard == resource.RLIM_INFINITY
        else min(desired_cpu, hard)
    )
    new_soft = (
        desired_cpu
        if soft == resource.RLIM_INFINITY
        else min(desired_cpu, soft)
    )
    new_soft = min(new_soft, new_hard)
    resource.setrlimit(resource.RLIMIT_CPU, (new_soft, new_hard))


def _group_exists(process_id: int) -> bool:
    try:
        os.killpg(process_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _signal_group(process, requested_signal: int) -> None:
    try:
        os.killpg(process.pid, requested_signal)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.send_signal(requested_signal)
        except ProcessLookupError:
            pass


def _stop_group(process) -> int | None:
    for requested_signal, grace in (
        (signal.SIGINT, 5),
        (signal.SIGTERM, 3),
        (signal.SIGKILL, 2),
    ):
        if not _group_exists(process.pid):
            break

        _signal_group(process, requested_signal)
        deadline = time.monotonic() + grace
        while _group_exists(process.pid) and time.monotonic() < deadline:
            process.poll()
            time.sleep(0.05)

    return process.poll()


def _drain_to_log(
    stream,
    log_path: Path,
    maximum: int,
    counter: list,
    errors: list[str],
) -> None:
    marker = b"\n[KEKKAI: build output truncated at configured log limit]\n"
    payload_limit = maximum - len(marker)

    try:
        with log_path.open("ab") as log:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break

                retained = counter[0]
                available = max(0, payload_limit - retained)
                if available:
                    part = chunk[:available]
                    log.write(part)
                    counter[0] += len(part)

                if len(chunk) > available and not counter[1]:
                    log.write(marker)
                    counter[0] += len(marker)
                    counter[1] = True
    except OSError as exc:
        errors.append(f"{log_path.name}: {exc}")
        while stream.read(65536):
            pass


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _regular_artifact(path: Path, maximum: int) -> None:
    if path.is_symlink() or not path.is_file():
        raise BuildError(f"Expected a regular build artifact: {path}")
    if path.stat().st_size == 0 or path.stat().st_size > maximum:
        raise BuildError(f"Build artifact has an invalid size: {path}")


def verify_build_outputs(build_dir: Path) -> dict[str, str]:
    """Verify generated configuration, compiler use and required artifacts."""
    cache_path = build_dir / "CMakeCache.txt"
    database_path = build_dir / "compile_commands.json"
    header_path = build_dir / "pnglibconf.h"
    archive_path = build_dir / "libpng16.a"
    binary_path = build_dir / "kekkai_png_harness"

    for artifact in (cache_path, database_path, header_path, archive_path, binary_path):
        _regular_artifact(artifact, 64 * 1024 * 1024)

    if not os.access(binary_path, os.X_OK):
        raise BuildError("Built harness is not executable.")

    cache = cache_path.read_text(encoding="utf-8")
    expected_cache = {
        "CMAKE_BUILD_TYPE": "RelWithDebInfo",
        "CMAKE_C_COMPILER": "/usr/bin/afl-clang-fast",
        "CMAKE_GENERATOR": "Ninja",
        "CMAKE_MAKE_PROGRAM": "/usr/bin/ninja",
        "CMAKE_EXPORT_COMPILE_COMMANDS": "ON",
        "CMAKE_POSITION_INDEPENDENT_CODE": "ON",
        "AWK": "/usr/bin/gawk",
        "PNG_BUILD_ZLIB": "OFF",
        "PNG_EXECUTABLES": "ON",
        "PNG_HARDWARE_OPTIMIZATIONS": "ON",
        "PNG_INTEL_SSE": "on",
        "PNG_STATIC": "ON",
        "PNG_SHARED": "OFF",
        "PNG_TESTS": "OFF",
        "PNG_TOOLS": "OFF",
        "PNG_FRAMEWORK": "OFF",
        "ZLIB_INCLUDE_DIR": "/usr/include",
        "ZLIB_LIBRARY_RELEASE": "/usr/lib/x86_64-linux-gnu/libz.so",
    }

    for key, expected in expected_cache.items():
        observed = [
            line.split("=", 1)[1]
            for line in cache.splitlines()
            if line.startswith(key + ":") and "=" in line
        ]
        if observed != [expected]:
            raise BuildError(
                f"CMake setting {key} mismatch: expected {expected!r}, "
                f"observed {observed!r}."
            )

    required_features = (
        "PNG_READ_SUPPORTED",
        "PNG_SEQUENTIAL_READ_SUPPORTED",
        "PNG_READ_ANCILLARY_CHUNKS_SUPPORTED",
        "PNG_READ_INTERLACING_SUPPORTED",
        "PNG_SETJMP_SUPPORTED",
        "PNG_SET_USER_LIMITS_SUPPORTED",
    )
    header = header_path.read_text(encoding="utf-8")
    for feature in required_features:
        if f"#define {feature}" not in header:
            raise BuildError(f"Generated pnglibconf.h lacks {feature}.")

    database = json.loads(database_path.read_text(encoding="utf-8"))
    if not isinstance(database, list) or len(database) != 17:
        raise BuildError(
            "Expected 17 libpng translation units in compile_commands.json."
        )

    expected_compiler = Path("/usr/bin/afl-clang-fast").resolve(strict=True)
    for entry in database:
        if not isinstance(entry, dict):
            raise BuildError("Invalid compile database entry.")
        arguments = entry.get("arguments")
        if isinstance(arguments, list) and arguments:
            compiler_value = arguments[0]
        elif isinstance(entry.get("command"), str):
            parsed = shlex.split(entry["command"])
            compiler_value = parsed[0] if parsed else ""
        else:
            raise BuildError("Compile database entry has no command.")

        try:
            actual_compiler = Path(compiler_value).resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as exc:
            raise BuildError("Cannot resolve compile database compiler.") from exc
        if actual_compiler != expected_compiler:
            raise BuildError(
                "A translation unit does not use the pinned AFL++ compiler."
            )

    return {
        "harness_source_sha256": _sha256(
            Path(__file__).resolve().parents[2]
            / "targets/libpng/png_read_harness.c"
        ),
        "harness_binary_sha256": _sha256(binary_path),
        "library_archive_sha256": _sha256(archive_path),
        "cmake_cache_sha256": _sha256(cache_path),
        "compile_database_sha256": _sha256(database_path),
        "generated_header_sha256": _sha256(header_path),
    }


def run_libpng_build(
    config: AdapterConfig,
    project_root: str | Path,
) -> BuildResult:
    """Run the fixed clean build with bounded resources and persistent logs."""
    if config.build is None:
        raise BuildError("Adapter has no build configuration.")

    plan = build_command_plan(config, project_root)
    build_dir = plan.build_dir
    build_dir.mkdir(mode=0o700)

    stdout_path = build_dir / "stdout.log"
    stderr_path = build_dir / "stderr.log"
    stdout_path.touch(mode=0o600)
    stderr_path.touch(mode=0o600)

    started_at = _utc_now()
    metadata_path = build_dir / "build.json"
    metadata = {
        "schema_version": 1,
        "status": BuildState.RUNNING.value,
        "target": config.target.name,
        "target_version": config.target.version,
        "profile": config.build.profile,
        "build_dir": str(build_dir),
        "adapter_config": str(config.config_path),
        "jobs": config.build.jobs,
        "timeout_seconds": config.build.timeout_seconds,
        "memory_mib_per_process": config.build.memory_mib,
        "log_limit_bytes_per_stream": config.build.log_limit_bytes,
        "environment": dict(plan.environment),
        "steps": [
            {
                "name": step.name,
                "command": list(step.command),
                "status": "pending",
                "exit_code": None,
            }
            for step in plan.steps
        ],
        "started_at": started_at,
        "ended_at": None,
        "message": "Build initialized.",
        "artifacts": {},
        "log_errors": [],
    }

    try:
        _write_metadata(build_dir, metadata)
    except OSError as exc:
        raise BuildError(f"Cannot persist initial build metadata: {exc}") from exc

    status = BuildState.RUNNING
    message = "All build steps completed and outputs verified."
    exit_code = None
    artifacts: dict[str, str] = {}
    errors: list[str] = []
    stdout_counter = [0, False]
    stderr_counter = [0, False]
    deadline = time.monotonic() + config.build.timeout_seconds
    root = Path(project_root).expanduser().resolve(strict=True)

    for step_record, step in zip(metadata["steps"], plan.steps):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            status = BuildState.FAILED
            message = "Build exceeded its total external watchdog."
            break

        step_record["status"] = "running"
        step_record["started_at"] = _utc_now()
        try:
            _write_metadata(build_dir, metadata)
        except OSError as exc:
            status = BuildState.FAILED
            message = f"Cannot persist build step metadata: {exc}"
            break

        try:
            process = subprocess.Popen(
                step.command,
                cwd=root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                env=dict(plan.environment),
                close_fds=True,
                start_new_session=True,
                bufsize=0,
                preexec_fn=lambda: _set_child_limits(
                    config.build.memory_mib,
                    config.build.timeout_seconds,
                ),
            )
        except OSError as exc:
            status = BuildState.FAILED
            message = f"Could not start build step {step.name}: {exc}"
            step_record["status"] = "failed"
            step_record["message"] = message
            step_record["ended_at"] = _utc_now()
            break

        stdout_thread = threading.Thread(
            target=_drain_to_log,
            args=(
                process.stdout, stdout_path, config.build.log_limit_bytes,
                stdout_counter, errors,
            ),
            name=f"kekkai-build-{step.name}-stdout",
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=_drain_to_log,
            args=(
                process.stderr, stderr_path, config.build.log_limit_bytes,
                stderr_counter, errors,
            ),
            name=f"kekkai-build-{step.name}-stderr",
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()

        try:
            exit_code = process.wait(timeout=max(0.01, remaining))
            if exit_code == 0:
                step_record["status"] = "completed"
            else:
                step_record["status"] = "failed"
                status = BuildState.FAILED
                message = f"Build step {step.name} exited with status {exit_code}."
        except subprocess.TimeoutExpired:
            exit_code = _stop_group(process)
            step_record["status"] = "failed"
            status = BuildState.FAILED
            message = f"Build step {step.name} exceeded the total watchdog."
        except KeyboardInterrupt:
            exit_code = _stop_group(process)
            step_record["status"] = "interrupted"
            status = BuildState.INTERRUPTED
            message = "Build interrupted by the operator."
        except OSError as exc:
            exit_code = _stop_group(process)
            step_record["status"] = "failed"
            status = BuildState.FAILED
            message = f"Error waiting for build step {step.name}: {exc}"

        stdout_thread.join(timeout=10)
        stderr_thread.join(timeout=10)

        if stdout_thread.is_alive() or stderr_thread.is_alive():
            _stop_group(process)
            stdout_thread.join(timeout=5)
            stderr_thread.join(timeout=5)
            errors.append(f"Output streams for {step.name} did not close cleanly.")

        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()

        step_record["exit_code"] = exit_code
        step_record["ended_at"] = _utc_now()
        if errors and status == BuildState.RUNNING:
            status = BuildState.FAILED
            message = "Build completed a step, but log capture failed."

        try:
            _write_metadata(build_dir, metadata)
        except OSError as exc:
            status = BuildState.FAILED
            message = f"Cannot persist build step result: {exc}"

        if status != BuildState.RUNNING:
            break

    if status == BuildState.RUNNING:
        try:
            artifacts = verify_build_outputs(build_dir)
            status = BuildState.COMPLETED
        except (BuildError, OSError, UnicodeError, ValueError) as exc:
            status = BuildState.FAILED
            message = f"Build output verification failed: {exc}"

    ended_at = _utc_now()
    metadata.update({
        "status": status.value,
        "ended_at": ended_at,
        "exit_code": exit_code,
        "message": message,
        "artifacts": artifacts,
        "log_errors": errors,
    })

    try:
        _write_metadata(build_dir, metadata)
    except OSError as exc:
        status = BuildState.FAILED
        message = f"Could not persist final build metadata: {exc}"

    return BuildResult(
        status=status,
        build_dir=build_dir,
        metadata_path=metadata_path,
        started_at=started_at,
        ended_at=ended_at,
        message=message,
        artifacts=tuple(sorted(artifacts.items())),
    )
