"""Bounded execution and verification of the fixed libpng build profile."""

from __future__ import annotations

import ctypes
import errno
import hashlib
import json
import os
import resource
import shlex
import signal
import stat
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from engine.adapters.config import AdapterConfig
from engine.build.artifact_limits import MAX_BUILD_ARTIFACT_BYTES
from engine.build.libpng import BuildError, build_command_plan
from engine.processes import (
    ProcessGroupRegistry, process_group_has_live_members, process_groups_guarded,
    signal_process_group, stop_process_group,
)


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
    return process_group_has_live_members(process_id)


def _signal_group(process, requested_signal: int) -> None:
    signal_process_group(process.pid, requested_signal)


def _stop_group(process) -> int | None:
    return stop_process_group(
        process.pid,
        process=process,
        graces=(5.0, 3.0, 2.0),
    )


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
        _regular_artifact(artifact, MAX_BUILD_ARTIFACT_BYTES)

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


def _rename_directory_no_replace(source: Path, destination: Path) -> None:
    """Atomically move a directory without replacing an existing destination."""
    if os.name != "posix":
        raise BuildError("Atomic no-replace directory rename requires POSIX.")
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        renameat2 = libc.renameat2
    except (AttributeError, OSError) as exc:
        raise BuildError("renameat2(RENAME_NOREPLACE) is unavailable; recovery refused.") from exc

    renameat2.argtypes = (
        ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        -100, os.fsencode(source), -100, os.fsencode(destination), 1
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), str(destination))


def recover_failed_build(
    config: AdapterConfig,
    project_root: str | Path,
) -> Path:
    """Atomically archive a verified failed/interrupted build without deleting it.

    Only terminal build metadata schema 2 with status ``failed`` or
    ``interrupted`` is eligible. Completed, running, missing, malformed,
    mismatched, or symlinked build paths are refused.
    """
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise BuildError("Refusing failed-build recovery as root.")
    if config.build is None:
        raise BuildError("Adapter has no build configuration.")

    configured = config.build.build_dir
    if configured.is_symlink():
        raise BuildError("Configured build directory is a symlink; recovery refused.")
    try:
        root = Path(project_root).expanduser().resolve(strict=True)
        build_dir = configured.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise BuildError(f"Cannot resolve failed build directory: {exc}") from exc
    if not root.is_dir() or not build_dir.is_dir():
        raise BuildError("Repository or failed build directory is missing.")
    protected_paths = (
        ("repository", root),
        ("target source", config.target.source_dir.resolve(strict=False)),
        ("campaign output", config.target.output_parent.resolve(strict=False)),
    )
    for label, protected in protected_paths:
        if (
            build_dir == protected
            or build_dir in protected.parents
            or protected in build_dir.parents
        ):
            raise BuildError(f"Build directory overlaps the {label}; recovery refused.")
    if build_dir.is_symlink():
        raise BuildError("Build directory became a symlink; recovery refused.")

    metadata_path = build_dir / "build.json"
    try:
        metadata_info = metadata_path.lstat()
        if not stat.S_ISREG(metadata_info.st_mode):
            raise BuildError("Build metadata must be a regular non-symlink file.")
        if metadata_info.st_size <= 0 or metadata_info.st_size > 1024 * 1024:
            raise BuildError("Build metadata is missing, empty, or oversized.")
        raw_metadata = metadata_path.read_bytes()
        metadata = json.loads(raw_metadata.decode("utf-8"))
    except BuildError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BuildError(f"Cannot safely read build metadata: {exc}") from exc

    if not isinstance(metadata, dict):
        raise BuildError("Build metadata must be a JSON object.")
    if type(metadata.get("schema_version")) is not int or metadata["schema_version"] != 2:
        raise BuildError("Only build metadata schema 2 can be recovered.")
    status = metadata.get("status")
    if type(status) is not str or status not in {
        BuildState.FAILED.value, BuildState.INTERRUPTED.value
    }:
        raise BuildError(
            "Only terminal failed or interrupted builds can be recovered; "
            f"observed status {status!r}."
        )
    expected_fields = {
        "target": config.target.name,
        "target_version": config.target.version,
        "profile": config.build.profile,
        "build_dir": str(build_dir),
    }
    for key, expected in expected_fields.items():
        if metadata.get(key) != expected:
            raise BuildError(f"Build metadata field {key!r} does not match this adapter.")
    if not isinstance(metadata.get("steps"), list):
        raise BuildError("Build metadata has no valid steps list.")
    if not isinstance(metadata.get("artifacts"), dict):
        raise BuildError("Build metadata has no valid artifacts object.")
    if not isinstance(metadata.get("started_at"), str) or not metadata.get("started_at"):
        raise BuildError("Build metadata has no valid start timestamp.")
    if not isinstance(metadata.get("ended_at"), str) or not metadata.get("ended_at"):
        raise BuildError("Build metadata is not marked as terminal.")

    existing_manifest = build_dir / "recovery.json"
    if existing_manifest.exists() or existing_manifest.is_symlink():
        raise BuildError(
            "Build already contains recovery.json; recovery refused to overwrite evidence."
        )

    archive_root = build_dir.parent / "failed-builds"
    for label, protected in protected_paths:
        if (
            archive_root == protected
            or archive_root in protected.parents
            or protected in archive_root.parents
        ):
            raise BuildError(
                f"Failed-build archive directory overlaps the {label}; recovery refused."
            )
    if archive_root.is_symlink():
        raise BuildError("Failed-build archive directory is a symlink; recovery refused.")
    try:
        archive_root.mkdir(mode=0o700, exist_ok=True)
        archive_info = archive_root.lstat()
        if not stat.S_ISDIR(archive_info.st_mode):
            raise BuildError("Failed-build archive path is not a plain directory.")
        if archive_info.st_uid != os.getuid():
            raise BuildError("Failed-build archive directory must be owned by the current user.")
        if stat.S_IMODE(archive_info.st_mode) != 0o700:
            raise BuildError("Failed-build archive directory must have mode 0700.")
    except BuildError:
        raise
    except OSError as exc:
        raise BuildError(f"Cannot prepare failed-build archive: {exc}") from exc

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    destination = None
    metadata_digest = hashlib.sha256(raw_metadata).hexdigest()
    for _ in range(5):
        candidate = archive_root / f"{build_dir.name}-{timestamp}-{uuid.uuid4().hex[:12]}"
        try:
            _rename_directory_no_replace(build_dir, candidate)
        except OSError as exc:
            if exc.errno == errno.EEXIST:
                continue
            raise BuildError(f"Could not atomically archive failed build: {exc}") from exc
        destination = candidate
        break
    if destination is None:
        raise BuildError("Could not allocate a unique failed-build archive name.")

    manifest = {
        "schema_version": 1,
        "recovered_at": _utc_now(),
        "original_build_dir": str(build_dir),
        "archive_dir": str(destination),
        "original_status": status,
        "build_started_at": metadata["started_at"],
        "build_ended_at": metadata["ended_at"],
        "build_metadata_sha256": metadata_digest,
        "preservation": "Entire build directory moved atomically; logs and partial outputs retained.",
    }
    manifest_path = destination / "recovery.json"
    temporary_path = destination / f".recovery-{uuid.uuid4().hex}.tmp"
    try:
        with temporary_path.open("x", encoding="utf-8") as stream:
            json.dump(manifest, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary_path, manifest_path, follow_symlinks=False)
        temporary_path.unlink()
        directory_fd = os.open(destination, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise BuildError(
            f"Build was preserved at {destination}, but its recovery manifest could not be completed: {exc}"
        ) from exc
    finally:
        try:
            temporary_path.unlink()
        except FileNotFoundError:
            pass

    return destination


@process_groups_guarded
def run_libpng_build(
    config: AdapterConfig,
    project_root: str | Path,
    *,
    _process_registry: ProcessGroupRegistry,
) -> BuildResult:
    """Run the fixed clean build with bounded resources and persistent logs."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise BuildError("Refusing to run the adapter build as root.")
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
        "schema_version": 2,
        "status": BuildState.RUNNING.value,
        "target": config.target.name,
        "target_version": config.target.version,
        "profile": config.build.profile,
        "build_dir": str(build_dir),
        "adapter_config": str(config.config_path),
        "source_archive_path": (
            str(plan.source_archive_path) if plan.source_archive_path else None
        ),
        "source_archive_sha256": plan.source_archive_sha256,
        "source_tree_sha256": plan.source_tree_sha256,
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

        _process_registry.register(process.pid, process=process)

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

        # The build tool may exit while descendants remain in its session.
        if _group_exists(process.pid):
            _stop_group(process)
        _process_registry.unregister(process.pid)

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

        if _process_registry.interrupted:
            step_record["status"] = "interrupted"
            step_record["message"] = (
                "Build interrupted by SIGTERM; child process groups were stopped."
            )
            status = BuildState.INTERRUPTED
            message = "Build interrupted by SIGTERM; child process groups were stopped."

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

    if _process_registry.interrupted:
        status = BuildState.INTERRUPTED
        message = "Build interrupted by SIGTERM; child process groups were stopped."

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
