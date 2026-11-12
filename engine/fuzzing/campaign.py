"""Bounded single-worker AFL++ campaign orchestration."""

from __future__ import annotations

import json
import os
import signal
import shutil
import subprocess
import threading
import time
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from engine.adapters.config import AdapterConfig
from engine.build.libpng import BuildError
from engine.build.runner import BuildState, run_libpng_build
from engine.fuzzing.coverage import validate_coverage
from engine.fuzzing.preflight import validate_adapter
from engine.fuzzing.provenance import verify_build_provenance
from engine.fuzzing.smoke import run_harness_smoke

_AFL_MAX_GENERATED_INPUT_BYTES = 1024 * 1024


class CampaignError(RuntimeError):
    """Raised when a campaign cannot be safely initialized."""


class CampaignState(str, Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    INTERRUPTED = "interrupted"


@dataclass(frozen=True)
class CampaignResult:
    campaign_id: str
    status: CampaignState
    campaign_dir: Path
    afl_output_dir: Path
    command: tuple[str, ...]
    started_at: str
    ended_at: str
    exit_code: int | None
    message: str


def build_campaign_command(
    config: AdapterConfig,
    afl_fuzz_path: str | Path,
    afl_output_dir: str | Path,
) -> list[str]:
    """Build the fixed, non-shell AFL++ command for the libpng harness."""
    if config.target.name.casefold() != "libpng":
        raise CampaignError(
            "Campaign execution is currently implemented only for libpng."
        )

    try:
        fuzzer = Path(afl_fuzz_path).resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise CampaignError(
            f"Cannot resolve AFL++ executable: {exc}"
        ) from exc

    if not fuzzer.is_file() or not os.access(fuzzer, os.X_OK):
        raise CampaignError(
            f"AFL++ executable is missing or not executable: {fuzzer}"
        )

    raw_output = Path(afl_output_dir).expanduser()
    if not raw_output.is_absolute():
        raise CampaignError("AFL++ output directory must be absolute.")

    if raw_output.exists() or raw_output.is_symlink():
        raise CampaignError(
            f"AFL++ output directory must not already exist: {raw_output}"
        )

    try:
        output_parent = config.target.output_parent.resolve(strict=True)
        output = raw_output.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise CampaignError(f"Cannot resolve campaign output path: {exc}") from exc

    if not output_parent.is_dir():
        raise CampaignError("Configured output parent is not a directory.")

    if output == output_parent or output_parent not in output.parents:
        raise CampaignError(
            "AFL++ output directory must remain inside the configured output parent."
        )

    if not output.parent.is_dir():
        raise CampaignError(
            f"AFL++ output parent does not exist: {output.parent}"
        )

    limits = config.limits

    return [
        str(fuzzer),
        "-i", str(config.target.seed_dir),
        "-o", str(output),
        "-V", str(limits.duration_seconds),
        "-m", str(limits.memory_mib),
        "-t", str(limits.timeout_ms),
        "-G", str(
            min(limits.max_input_bytes, _AFL_MAX_GENERATED_INPUT_BYTES)
        ),
        "--",
        str(config.target.harness_binary),
        "@@",
    ]


_MAX_CAMPAIGN_LOG_BYTES = 8 * 1024 * 1024
_EXTERNAL_TIMEOUT_GRACE_SECONDS = 30
_INTERRUPT_GRACE_SECONDS = 10
_TERMINATE_GRACE_SECONDS = 5


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _write_metadata(campaign_dir: Path, metadata: dict) -> None:
    """Atomically replace the campaign metadata document."""
    temporary = campaign_dir / f".campaign-{uuid.uuid4().hex}.tmp"
    destination = campaign_dir / "campaign.json"

    try:
        with temporary.open("x", encoding="utf-8") as stream:
            json.dump(metadata, stream, indent=2, sort_keys=True)
            stream.write("\n")
        os.replace(temporary, destination)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _drain_stream_to_log(stream, log_path: Path, errors: list[str]) -> None:
    """Drain a child pipe while retaining no more than the log size limit."""
    marker = b"\n[KEKKAI: output truncated at configured log limit]\n"
    payload_limit = _MAX_CAMPAIGN_LOG_BYTES - len(marker)
    retained = 0
    total = 0

    try:
        with log_path.open("xb") as log:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break

                total += len(chunk)
                available = payload_limit - retained
                if available > 0:
                    part = chunk[:available]
                    log.write(part)
                    retained += len(part)

            if total > retained:
                log.write(marker)
    except OSError as exc:
        errors.append(f"{log_path.name}: {exc}")
        # Continue draining so the child cannot block on a full pipe.
        while stream.read(65536):
            pass


def _signal_campaign_group(process, requested_signal: int) -> None:
    try:
        os.killpg(process.pid, requested_signal)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.send_signal(requested_signal)
        except ProcessLookupError:
            pass


def _campaign_group_exists(process_id: int) -> bool:
    """Check whether any process remains in the campaign process group."""
    try:
        os.killpg(process_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _stop_campaign_group(process) -> int | None:
    """Stop the entire campaign process group, even if its leader exits."""
    escalation = (
        (signal.SIGINT, _INTERRUPT_GRACE_SECONDS),
        (signal.SIGTERM, _TERMINATE_GRACE_SECONDS),
        (signal.SIGKILL, _TERMINATE_GRACE_SECONDS),
    )

    group_alive = _campaign_group_exists(process.pid)

    for requested_signal, grace in escalation:
        if not group_alive:
            break

        _signal_campaign_group(process, requested_signal)
        deadline = time.monotonic() + grace

        while group_alive and time.monotonic() < deadline:
            process.poll()
            remaining = deadline - time.monotonic()
            time.sleep(min(0.05, max(0.0, remaining)))
            group_alive = _campaign_group_exists(process.pid)

    return process.poll()


def _paths_overlap(first: Path, second: Path) -> bool:
    return (
        first == second
        or first in second.parents
        or second in first.parents
    )


def _execute_campaign(
    config: AdapterConfig,
    project_root: Path,
    afl_fuzz_path: str | Path,
    validation_evidence: dict[str, object],
) -> CampaignResult:
    """Execute one bounded AFL++ worker and preserve its campaign record."""
    try:
        root = project_root.resolve(strict=True)
        output_parent = config.target.output_parent.resolve(strict=True)
        source_dir = config.target.source_dir.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise CampaignError(f"Cannot resolve campaign paths: {exc}") from exc

    if not root.is_dir() or not output_parent.is_dir():
        raise CampaignError("Repository or campaign output parent is invalid.")

    if _paths_overlap(output_parent, root):
        raise CampaignError("Campaign output must be outside the repository.")

    if _paths_overlap(output_parent, source_dir):
        raise CampaignError("Campaign output must be outside target source.")

    if not os.access(output_parent, os.W_OK | os.X_OK):
        raise CampaignError("Campaign output parent is not writable.")

    campaign_id = (
        "campaign-"
        + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        + "-"
        + uuid.uuid4().hex[:12]
    )
    campaign_dir = output_parent / campaign_id
    afl_output_dir = campaign_dir / "afl-output"

    try:
        campaign_dir.mkdir(mode=0o700)
    except OSError as exc:
        raise CampaignError(f"Cannot create campaign directory: {exc}") from exc

    command = build_campaign_command(
        config,
        afl_fuzz_path,
        afl_output_dir,
    )
    started_at = _utc_now()
    log_errors: list[str] = []

    metadata = {
        "schema_version": 1,
        "campaign_id": campaign_id,
        "status": CampaignState.RUNNING.value,
        "target": {
            "name": config.target.name,
            "version": config.target.version,
            "source_dir": str(source_dir),
            "harness_binary": str(config.target.harness_binary),
            "seed_dir": str(config.target.seed_dir),
        },
        "fuzzer": {
            "executable": str(Path(afl_fuzz_path).resolve()),
            "expected_version": config.fuzzer.expected_version,
        },
        "limits": {
            "duration_seconds": config.limits.duration_seconds,
            "memory_mib": config.limits.memory_mib,
            "timeout_ms": config.limits.timeout_ms,
            "max_input_bytes": config.limits.max_input_bytes,
        },
        "command": command,
        "adapter_config": str(config.config_path),
        "validation": validation_evidence,
        "started_at": started_at,
        "ended_at": None,
        "pid": None,
        "exit_code": None,
        "message": "Campaign initialized.",
    }
    _write_metadata(campaign_dir, metadata)

    child_environment = {
        "PATH": os.defpath,
        "LC_ALL": "C",
        "AFL_NO_UI": "1",
        "ASAN_OPTIONS": "detect_leaks=0:abort_on_error=1:symbolize=0",
    }

    try:
        process = subprocess.Popen(
            command,
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=child_environment,
            close_fds=True,
            start_new_session=True,
            bufsize=0,
        )
    except OSError as exc:
        message = f"Could not start AFL++: {exc}"
        for filename in ("stdout.log", "stderr.log"):
            (campaign_dir / filename).touch(mode=0o600, exist_ok=False)

        status = CampaignState.FAILED
        exit_code = None
    else:
        metadata["pid"] = process.pid

        assert process.stdout is not None
        assert process.stderr is not None

        stdout_thread = threading.Thread(
            target=_drain_stream_to_log,
            args=(process.stdout, campaign_dir / "stdout.log", log_errors),
            name=f"kekkai-{campaign_id}-stdout",
            daemon=True,
        )
        stderr_thread = threading.Thread(
            target=_drain_stream_to_log,
            args=(process.stderr, campaign_dir / "stderr.log", log_errors),
            name=f"kekkai-{campaign_id}-stderr",
            daemon=True,
        )
        stdout_thread.start()
        stderr_thread.start()

        try:
            _write_metadata(campaign_dir, metadata)
        except OSError as exc:
            exit_code = _stop_campaign_group(process)
            status = CampaignState.FAILED
            message = (
                "Could not persist campaign PID metadata; "
                f"the process group was stopped: {exc}"
            )
        else:
            try:
                exit_code = process.wait(
                    timeout=(
                        config.limits.duration_seconds
                        + _EXTERNAL_TIMEOUT_GRACE_SECONDS
                    )
                )
                if exit_code == 0:
                    status = CampaignState.COMPLETED
                    message = "AFL++ exited successfully."
                else:
                    status = CampaignState.FAILED
                    message = f"AFL++ exited with status {exit_code}."
            except subprocess.TimeoutExpired:
                exit_code = _stop_campaign_group(process)
                status = CampaignState.FAILED
                message = (
                    "AFL++ exceeded the external campaign watchdog; "
                    "its process group was stopped."
                )
            except KeyboardInterrupt:
                exit_code = _stop_campaign_group(process)
                status = CampaignState.INTERRUPTED
                message = "Campaign interrupted by the operator."
            except OSError as exc:
                exit_code = _stop_campaign_group(process)
                status = CampaignState.FAILED
                message = f"Error while waiting for AFL++: {exc}"
        if process.poll() is None:
            _stop_campaign_group(process)

        stdout_thread.join(timeout=10)
        stderr_thread.join(timeout=10)

        if stdout_thread.is_alive() or stderr_thread.is_alive():
            _signal_campaign_group(process, signal.SIGKILL)
            stdout_thread.join(timeout=5)
            stderr_thread.join(timeout=5)
            log_errors.append("Campaign output streams did not close cleanly.")

        if process.stdout:
            process.stdout.close()
        if process.stderr:
            process.stderr.close()

        if log_errors and status == CampaignState.COMPLETED:
            status = CampaignState.FAILED
            message = "AFL++ exited, but campaign log capture failed."

    ended_at = _utc_now()
    metadata.update({
        "status": status.value,
        "ended_at": ended_at,
        "exit_code": exit_code,
        "message": message,
        "log_errors": log_errors,
    })
    _write_metadata(campaign_dir, metadata)

    return CampaignResult(
        campaign_id=campaign_id,
        status=status,
        campaign_dir=campaign_dir,
        afl_output_dir=afl_output_dir,
        command=tuple(command),
        started_at=started_at,
        ended_at=ended_at,
        exit_code=exit_code,
        message=message,
    )


def run_campaign(
    config: AdapterConfig,
    project_root: str | Path,
    *,
    smoke_timeout_seconds: float = 5.0,
) -> CampaignResult:
    """Run all required validation gates before starting one AFL++ worker."""
    try:
        root = Path(project_root).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise CampaignError(f"Invalid project root: {exc}") from exc

    if not root.is_dir():
        raise CampaignError("Project root must be a directory.")

    clean_build_evidence = None
    existing_build_metadata = None

    if config.build is not None:
        build_dir = config.build.build_dir

        if build_dir.is_symlink():
            raise CampaignError(
                "Configured build directory is a symlink; campaign was not started."
            )

        if build_dir.exists():
            if not build_dir.is_dir():
                raise CampaignError(
                    "Configured build path is not a directory; campaign was not started."
                )
            existing_build_metadata = build_dir / "build.json"
        else:
            try:
                build_result = run_libpng_build(config, root)
            except (BuildError, OSError, RuntimeError, ValueError) as exc:
                raise CampaignError(
                    "Adapter-driven clean build failed; campaign was not started.\\n"
                    + str(exc)
                ) from exc

            if build_result.status is not BuildState.COMPLETED:
                state = getattr(
                    build_result.status, "value", str(build_result.status)
                )
                raise CampaignError(
                    f"Adapter-driven clean build {state}; campaign was not started.\\n"
                    f"{build_result.message}\\n"
                    f"Build metadata: {build_result.metadata_path}"
                )

            clean_build_evidence = {
                "status": "passed",
                "profile": config.build.profile,
                "build_dir": str(build_result.build_dir),
                "metadata_path": str(build_result.metadata_path),
                "started_at": build_result.started_at,
                "ended_at": build_result.ended_at,
                "message": build_result.message,
                "artifacts": dict(build_result.artifacts),
            }

    preflight = validate_adapter(config, root)
    if not preflight.passed:
        raise CampaignError(
            "Adapter preflight failed; campaign was not started.\n"
            + preflight.format()
        )

    provenance = verify_build_provenance(config, root)
    if not provenance.passed:
        raise CampaignError(
            "Build provenance failed; campaign was not started.\n"
            + provenance.format()
        )

    if existing_build_metadata is not None:
        try:
            if (
                existing_build_metadata.is_symlink()
                or not existing_build_metadata.is_file()
                or existing_build_metadata.stat().st_size > 1024 * 1024
            ):
                raise ValueError("Build metadata is missing, unsafe or oversized.")

            build_metadata = json.loads(
                existing_build_metadata.read_text(encoding="utf-8")
            )
            if (
                not isinstance(build_metadata, dict)
                or not isinstance(build_metadata.get("artifacts"), dict)
            ):
                raise ValueError("Build metadata has an invalid structure.")

            clean_build_evidence = {
                "status": "passed",
                "profile": config.build.profile,
                "build_dir": str(config.build.build_dir),
                "metadata_path": str(existing_build_metadata),
                "started_at": build_metadata.get("started_at"),
                "ended_at": build_metadata.get("ended_at"),
                "message": build_metadata.get("message"),
                "artifacts": build_metadata["artifacts"],
                "reused_verified_build": True,
            }
        except (OSError, UnicodeError, ValueError) as exc:
            raise CampaignError(
                "Completed build metadata could not be read after provenance "
                "validation; campaign was not started.\\n" + str(exc)
            ) from exc

    smoke = run_harness_smoke(
        config,
        root,
        timeout_seconds=smoke_timeout_seconds,
    )
    if not smoke.passed:
        raise CampaignError(
            "Harness smoke validation failed; campaign was not started.\n"
            + smoke.format()
        )

    coverage = validate_coverage(config, root)
    if not coverage.passed:
        raise CampaignError(
            "Coverage validation failed; campaign was not started.\n"
            + coverage.format()
        )

    fuzzer_path = shutil.which("afl-fuzz")
    if fuzzer_path is None:
        raise CampaignError(
            "Cannot resolve afl-fuzz after validation; campaign was not started."
        )

    validation_evidence = {
        "preflight": {
            "status": "passed",
            "report": preflight.format(),
        },
        "build_provenance": {
            "status": "passed",
            "report": provenance.format(),
        },
        "harness_smoke": {
            "status": "passed",
            "report": smoke.format(),
        },
        "coverage": {
            "status": "passed",
            "report": coverage.format(),
            "tool_version": coverage.tool_version,
            "distinct_map_count": coverage.distinct_map_count,
            "repeatability_status": coverage.repeatability_status,
        },
    }

    if clean_build_evidence is not None:
        validation_evidence["clean_build"] = clean_build_evidence

    return _execute_campaign(
        config,
        root,
        Path(fuzzer_path).resolve(strict=True),
        validation_evidence,
    )
