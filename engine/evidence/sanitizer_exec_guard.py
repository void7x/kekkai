"""Trusted pre-exec guard for the fixed P3-03 systemd service.

This program runs inside a DynamicUser system service. It verifies the resource
boundary before starting the repository-owned harness and captures raw output
into the service's private RuntimeDirectory.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import resource
import signal
import stat
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_OUTPUT_BYTES = 8 * 1024 * 1024
READ_CHUNK = 64 * 1024
HARNESS_PATH = "/run/kekkai-harness/kekkai_png_harness"
RUNTIME_FILES = ("status.json", "status.tmp", "stdout.bin", "stderr.bin")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def hash_regular_file(path: str, maximum: int) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(path, flags)
    digest = hashlib.sha256()
    total = 0
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("expected a regular file")
        while True:
            block = os.read(fd, READ_CHUNK)
            if not block:
                break
            total += len(block)
            if total > maximum:
                raise ValueError("file exceeds its configured size limit")
            digest.update(block)
        after = os.fstat(fd)
        identity = lambda item: (
            item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns
        )
        if identity(before) != identity(after) or total != before.st_size:
            raise ValueError("file changed while it was being read")
    finally:
        os.close(fd)
    return digest.hexdigest(), total


def write_all(fd: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short output write")
        view = view[written:]


def write_status(runtime: Path, value: dict[str, Any]) -> None:
    path_tmp = runtime / "status.tmp"
    path_status = runtime / "status.json"
    raw = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path_tmp, flags, 0o600)
    try:
        write_all(fd, raw)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(path_tmp, path_status)
    directory_fd = os.open(runtime, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def read_proc_status() -> dict[str, str]:
    result: dict[str, str] = {}
    for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            result[key] = value.strip()
    return result


def read_cgroup_mount() -> tuple[str, ...]:
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) > 6 and fields[4] == "/sys/fs/cgroup":
            options = fields[5].split(",")
            if "-" not in fields:
                raise ValueError("Malformed cgroup mount record")
            separator = fields.index("-")
            if len(fields) <= separator + 2 or fields[separator + 1] != "cgroup2":
                raise ValueError("The visible cgroup mount is not cgroup v2")
            return tuple(options)
    raise ValueError("No cgroup-v2 mount is visible at /sys/fs/cgroup")


def parse_cgroup() -> str:
    rows = [
        line.split("::", 1)[1]
        for line in Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines()
        if line.startswith("0::")
    ]
    if len(rows) != 1:
        raise ValueError("Expected exactly one unified cgroup membership")
    if rows[0] != "/":
        raise ValueError("The cgroup namespace is not isolated at its root")
    return rows[0]


def read_text(path: Path) -> str:
    return path.read_text(encoding="ascii").strip()


def read_cgroup_counters(path: Path) -> dict[str, int] | dict[str, Any]:
    try:
        if path.stat(follow_symlinks=False).st_size > 16384:
            return {"available": False, "detail": "counter file exceeds the 16 KiB read limit"}
        values: dict[str, int] = {}
        for line in read_text(path).splitlines():
            fields = line.split()
            if len(fields) != 2 or not fields[1].isdecimal():
                return {"available": False, "detail": "counter file has an unexpected format"}
            values[fields[0]] = int(fields[1])
        return values
    except OSError as exc:
        return {"available": False, "detail": f"{type(exc).__name__}: {exc}"[:256]}


def verify_limits() -> dict[str, Any]:
    if os.getuid() == 0 or os.geteuid() == 0:
        raise ValueError("The guard must never run as root")
    proc_status = read_proc_status()
    capability_fields = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")
    for field in capability_fields:
        if int(proc_status.get(field, "1"), 16) != 0:
            raise ValueError(f"Dynamic workload identity has non-zero {field}")
    if proc_status.get("NoNewPrivs") != "1":
        raise ValueError("NoNewPrivs is not active")

    mount_options = read_cgroup_mount()
    if "ro" not in mount_options:
        raise ValueError("The cgroup filesystem is not mounted read-only")
    cgroup = parse_cgroup()
    base = Path("/sys/fs/cgroup")

    for name in ("cgroup.procs", "cgroup.threads", "cgroup.subtree_control"):
        control = base / name
        if os.access(control, os.W_OK):
            raise ValueError(f"The workload identity can write {name}")

    memory_max = int(read_text(base / "memory.max"))
    memory_swap_max = int(read_text(base / "memory.swap.max"))
    pids_max = int(read_text(base / "pids.max"))
    cpu_parts = read_text(base / "cpu.max").split()
    if len(cpu_parts) != 2:
        raise ValueError("cpu.max has an unexpected format")
    cpu_quota, cpu_period = map(int, cpu_parts)
    if memory_max <= 0 or memory_max > 1024 * 1024 * 1024:
        raise ValueError("memory.max does not enforce the requested 1 GiB ceiling")
    if memory_swap_max != 0:
        raise ValueError("memory.swap.max is not zero")
    if pids_max <= 0 or pids_max > 32:
        raise ValueError("pids.max does not enforce the requested process ceiling")
    if (
        cpu_quota <= 0 or cpu_period != 100000
        or cpu_quota * 100 > cpu_period * 60
    ):
        raise ValueError("cpu.max does not enforce the approved 60% quota with a 100 ms period")

    address_limit = resource.getrlimit(resource.RLIMIT_AS)
    core_limit = resource.getrlimit(resource.RLIMIT_CORE)
    if address_limit != (resource.RLIM_INFINITY, resource.RLIM_INFINITY):
        raise ValueError("A finite RLIMIT_AS was inherited; ASan execution is refused")
    if core_limit != (0, 0):
        raise ValueError("RLIMIT_CORE is not disabled")

    return {
        "uid": os.getuid(),
        "gid": os.getgid(),
        "cap_eff": proc_status.get("CapEff"),
        "cap_bnd": proc_status.get("CapBnd"),
        "no_new_privs": proc_status.get("NoNewPrivs"),
        "cgroup": cgroup,
        "cgroup_mount_options": list(mount_options),
        "memory_max": memory_max,
        "memory_swap_max": memory_swap_max,
        "pids_max": pids_max,
        "cpu_quota": cpu_quota,
        "cpu_period": cpu_period,
        "memory_current": read_text(base / "memory.current"),
        "memory_events": read_cgroup_counters(base / "memory.events"),
        "memory_events_local": read_cgroup_counters(base / "memory.events.local"),
        "cpu_stat": read_cgroup_counters(base / "cpu.stat"),
        "pids_current": read_text(base / "pids.current"),
        "rlimit_as": list(address_limit),
        "rlimit_core": list(core_limit),
    }


def open_output(path: Path) -> int:
    return os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )


def drain_stream(pipe, output_fd: int, result: dict[str, Any], key: str) -> None:
    retained = 0
    truncated = False
    error: str | None = None
    try:
        while True:
            block = pipe.read(READ_CHUNK)
            if not block:
                break
            remaining = max(0, MAX_OUTPUT_BYTES - retained)
            if remaining:
                piece = block[:remaining]
                write_all(output_fd, piece)
                retained += len(piece)
            if len(block) > remaining:
                truncated = True
        os.fsync(output_fd)
    except OSError as exc:
        error = f"{type(exc).__name__}: {exc}"[:512]
    finally:
        try:
            pipe.close()
        except OSError:
            pass
        result[key] = {
            "capture_state": "complete" if error is None else "read_failed",
            "truncated": truncated,
            "retained_bytes": retained,
            "detail": error,
        }
        try:
            os.close(output_fd)
        except OSError:
            pass


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-input-sha256", required=True)
    parser.add_argument("--expected-input-size", required=True, type=int)
    parser.add_argument("--expected-harness-sha256", required=True)
    parser.add_argument("--harness-path", required=True)
    parser.add_argument("--input-path", required=True)
    args = parser.parse_args()

    runtime_raw = os.environ.get("RUNTIME_DIRECTORY")
    runtime = Path(runtime_raw) if runtime_raw else None
    if runtime is None:
        return 70
    runtime_link_info = runtime.lstat()
    if stat.S_ISLNK(runtime_link_info.st_mode):
        resolved_runtime = runtime.resolve(strict=True)
        expected_runtime = Path("/run/private") / runtime.name
        if resolved_runtime != expected_runtime:
            return 70
        if runtime_link_info.st_uid != 0:
            return 70
        runtime_info = resolved_runtime.stat(follow_symlinks=False)
    else:
        resolved_runtime = runtime
        runtime_info = runtime_link_info
    if (
        not stat.S_ISDIR(runtime_info.st_mode)
        or runtime_info.st_uid != os.getuid()
        or stat.S_IMODE(runtime_info.st_mode) != 0o700
    ):
        return 70

    status: dict[str, Any] = {
        "schema_version": 1,
        "guard_state": "starting",
        "harness_exec_succeeded": False,
        "execution_started_at": None,
        "execution_finished_at": None,
        "execution_status": "blocked_preflight",
        "exit_code": None,
        "signal_number": None,
        "stdout": {"capture_state": "not_started", "truncated": False, "retained_bytes": 0, "detail": None},
        "stderr": {"capture_state": "not_started", "truncated": False, "retained_bytes": 0, "detail": None},
        "resource_observation": {},
        "harness_argv": None,
        "harness_environment": None,
        "detail": None,
    }
    process: subprocess.Popen | None = None
    interrupted = False

    def handle_signal(signum, frame):
        nonlocal interrupted
        interrupted = True
        if process is not None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    try:
        resource_observation = verify_limits()
        status["resource_observation"] = resource_observation

        harness_path = Path(args.harness_path)
        if harness_path != runtime / "kekkai_png_harness":
            raise ValueError("Harness path is not the fixed file inside this attempt's RuntimeDirectory")
        harness_hash, harness_size = hash_regular_file(str(harness_path), 32 * 1024 * 1024)
        if harness_hash != args.expected_harness_sha256:
            raise ValueError("The read-only harness binary digest does not match the registered build")
        harness_info = os.stat(harness_path, follow_symlinks=False)
        if not (harness_info.st_mode & stat.S_IXUSR or harness_info.st_mode & stat.S_IXOTH):
            raise ValueError("The harness binary is not executable")

        input_path = Path(args.input_path)
        if input_path != runtime / "input.bin":
            raise ValueError("Input path is not the fixed file inside this attempt's RuntimeDirectory")
        input_hash, input_size = hash_regular_file(str(input_path), MAX_INPUT_BYTES)
        if input_hash != args.expected_input_sha256 or input_size != args.expected_input_size:
            raise ValueError("The bound testcase does not match the immutable artifact")

        status["guard_state"] = "awaiting_manager_authorization"
        status["execution_status"] = "blocked_preflight"
        status["manager_authorization_received"] = False
        write_status(runtime, status)
        authorization = sys.stdin.buffer.read(1)
        if authorization != b"\x01":
            status["detail"] = "System-manager authorization was not received; harness was not executed."
            status["guard_state"] = "manager_authorization_refused"
            write_status(runtime, status)
            return 0

        status["manager_authorization_received"] = True
        status["guard_state"] = "manager_authorized"
        status["execution_status"] = "launch_failed"
        write_status(runtime, status)

        stdout_fd = open_output(runtime / "stdout.bin")
        try:
            stderr_fd = open_output(runtime / "stderr.bin")
        except BaseException:
            os.close(stdout_fd)
            raise

        child_env = {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1:symbolize=0",
            "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
        }
        child_argv = [str(harness_path), str(input_path)]
        status["harness_argv"] = child_argv
        status["harness_environment"] = child_env
        write_status(runtime, status)
        try:
            process = subprocess.Popen(
                child_argv,
                cwd=str(runtime),
                env=child_env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                start_new_session=True,
                bufsize=0,
            )
        except OSError as exc:
            os.close(stdout_fd)
            os.close(stderr_fd)
            status["detail"] = f"Harness exec failed: {type(exc).__name__}: {exc}"[:1024]
            status["execution_status"] = "launch_failed"
            status["guard_state"] = "launch_failed"
            write_status(runtime, status)
            return 0

        status["harness_exec_succeeded"] = True
        status["execution_status"] = "exited"
        status["guard_state"] = "harness_running"
        status["execution_started_at"] = utc_now()
        write_status(runtime, status)

        streams: dict[str, Any] = {}
        readers = [
            threading.Thread(target=drain_stream, args=(process.stdout, stdout_fd, streams, "stdout"), daemon=True),
            threading.Thread(target=drain_stream, args=(process.stderr, stderr_fd, streams, "stderr"), daemon=True),
        ]
        for reader in readers:
            reader.start()

        try:
            return_code = process.wait(timeout=3.7)
        except subprocess.TimeoutExpired:
            status["execution_status"] = "timed_out"
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=0.25)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    pass
            return_code = process.returncode
        except BaseException:
            status["execution_status"] = "interrupted"
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=0.25)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    pass
            return_code = process.returncode

        for reader in readers:
            reader.join(timeout=0.6)
        if any(reader.is_alive() for reader in readers):
            for key in ("stdout", "stderr"):
                streams.setdefault(key, {
                    "capture_state": "read_failed",
                    "truncated": False,
                    "retained_bytes": None,
                    "detail": "Output stream did not reach EOF within the bounded drain interval.",
                })

        if interrupted:
            status["execution_status"] = "interrupted"
        elif status["execution_status"] != "timed_out":
            if return_code is not None and return_code < 0:
                status["execution_status"] = "signaled"
                status["signal_number"] = -return_code
            else:
                status["execution_status"] = "exited"
                status["exit_code"] = return_code

        status["execution_finished_at"] = utc_now()
        status["guard_state"] = "finished"
        status["stdout"] = streams.get("stdout", {
            "capture_state": "read_failed", "truncated": False,
            "retained_bytes": None, "detail": "No final stdout capture state was available.",
        })
        status["stderr"] = streams.get("stderr", {
            "capture_state": "read_failed", "truncated": False,
            "retained_bytes": None, "detail": "No final stderr capture state was available.",
        })
        write_status(runtime, status)
        return 0
    except BaseException as exc:
        status["detail"] = f"Guard failure: {type(exc).__name__}: {exc}"[:1024]
        if status["harness_exec_succeeded"]:
            # Never rewrite a post-exec failure as a preflight refusal.
            status["guard_state"] = "post_exec_failure"
            status["execution_status"] = "interrupted"
            status["execution_started_at"] = status["execution_started_at"] or utc_now()
            status["execution_finished_at"] = utc_now()
            for key in ("stdout", "stderr"):
                current = status.get(key, {})
                if current.get("capture_state") == "not_started":
                    current["capture_state"] = "read_failed"
                    current["detail"] = "Guard failed after harness exec; final capture state unavailable."
                status[key] = current
            if process is not None and process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=1)
                except BaseException:
                    pass
        else:
            status["guard_state"] = "preflight_blocked"
            status["execution_status"] = "blocked_preflight"
            status["execution_started_at"] = None
            status["execution_finished_at"] = None
        try:
            write_status(runtime, status)
        except OSError:
            pass
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
