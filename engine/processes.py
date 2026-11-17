"""Process-group lifecycle controls for KEKKAI's POSIX tool execution."""

from __future__ import annotations

import functools
import os
import signal
import subprocess
import threading
import time
from collections.abc import Callable
from typing import Any


def process_group_has_live_members(process_group_id: int) -> bool:
    """Return whether a process group contains a non-zombie process."""
    proc_root = "/proc"
    try:
        entries = os.listdir(proc_root)
    except OSError:
        try:
            os.killpg(process_group_id, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        return True

    for entry in entries:
        if not entry.isdecimal():
            continue
        try:
            with open(f"{proc_root}/{entry}/stat", "r", encoding="ascii") as stream:
                raw = stream.read()
            # comm is parenthesized and may itself contain spaces or ')'.
            fields = raw[raw.rfind(")") + 2 :].split()
            if len(fields) < 3:
                continue
            state = fields[0]
            group_id = int(fields[2])
            if group_id == process_group_id and state not in {"Z", "X"}:
                return True
        except (OSError, ValueError, IndexError):
            continue
    return False


def signal_process_group(process_group_id: int, requested_signal: int) -> None:
    try:
        os.killpg(process_group_id, requested_signal)
    except ProcessLookupError:
        pass


def stop_process_group(
    process_group_id: int,
    *,
    process: subprocess.Popen | None = None,
    graces: tuple[float, float, float] = (0.5, 0.5, 1.0),
) -> int | None:
    """Stop every live process in a session using INT, TERM, then KILL."""
    escalation = (signal.SIGINT, signal.SIGTERM, signal.SIGKILL)
    for requested_signal, grace in zip(escalation, graces):
        if not process_group_has_live_members(process_group_id):
            break
        signal_process_group(process_group_id, requested_signal)
        deadline = time.monotonic() + max(0.0, grace)
        while process_group_has_live_members(process_group_id) and time.monotonic() < deadline:
            if process is not None:
                process.poll()
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
    if process is not None:
        return process.poll()
    return None


class ProcessInterruptedError(subprocess.SubprocessError):
    """Raised when SIGTERM interrupts a managed KEKKAI subprocess."""


class ProcessGroupRegistry:
    """Temporarily translate SIGTERM into bounded cleanup of child groups."""

    def __init__(self) -> None:
        self._groups: dict[
            int,
            tuple[
                subprocess.Popen | None,
                tuple[float, float, float],
            ],
        ] = {}
        self._previous_handler: Any = None
        self._installed = False
        self._in_handler = False
        self.interrupted = False

    def __enter__(self) -> "ProcessGroupRegistry":
        if threading.current_thread() is not threading.main_thread():
            raise RuntimeError(
                "KEKKAI process-group execution must run on the main thread for SIGTERM cleanup."
            )
        self._previous_handler = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, self._handle_sigterm)
        self._installed = True
        return self

    def _handle_sigterm(self, signum: int, frame: object) -> None:
        self.interrupted = True
        if self._in_handler:
            return
        self._in_handler = True
        try:
            for process_group_id, (process, graces) in tuple(self._groups.items()):
                stop_process_group(
                    process_group_id,
                    process=process,
                    graces=graces,
                )
        finally:
            self._in_handler = False

    def raise_if_interrupted(self) -> None:
        if self.interrupted:
            raise ProcessInterruptedError(
                "Process operation interrupted by SIGTERM."
            )

    def register(
        self,
        process_group_id: int,
        process: subprocess.Popen | None = None,
        *,
        graces: tuple[float, float, float] = (0.5, 0.5, 1.0),
    ) -> None:
        self._groups[process_group_id] = (process, graces)
        # SIGTERM may arrive between Popen and registration. Registration
        # observes the flag and immediately applies this process's policy.
        if self.interrupted:
            stop_process_group(
                process_group_id,
                process=process,
                graces=graces,
            )

    def unregister(self, process_group_id: int) -> None:
        self._groups.pop(process_group_id, None)

    def stop_all(self) -> None:
        for process_group_id, (process, graces) in tuple(self._groups.items()):
            stop_process_group(
                process_group_id,
                process=process,
                graces=graces,
            )
            self.unregister(process_group_id)

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        self.stop_all()
        if self._installed:
            signal.signal(signal.SIGTERM, self._previous_handler)
        return False


def process_groups_guarded(function: Callable[..., Any]) -> Callable[..., Any]:
    """Run a build/campaign entry point with temporary SIGTERM group cleanup."""
    @functools.wraps(function)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        with ProcessGroupRegistry() as registry:
            if "_process_registry" in kwargs:
                raise TypeError("_process_registry is an internal argument")
            kwargs["_process_registry"] = registry
            return function(*args, **kwargs)
    return wrapped


def run_process_group(
    command: list[str] | tuple[str, ...],
    *,
    timeout: float | None = None,
    check: bool = False,
    **popen_kwargs: Any,
) -> subprocess.CompletedProcess:
    """Run one validator in its own session and always clean surviving children."""
    with ProcessGroupRegistry() as registry:
        registry.raise_if_interrupted()
        process = subprocess.Popen(
            command,
            start_new_session=True,
            close_fds=True,
            **popen_kwargs,
        )
        registry.register(process.pid, process=process)
        try:
            return_code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            stop_process_group(process.pid, process=process)
            raise
        except KeyboardInterrupt:
            stop_process_group(process.pid, process=process)
            raise
        finally:
            if process_group_has_live_members(process.pid):
                stop_process_group(process.pid, process=process)
            try:
                process.wait(timeout=0)
            except subprocess.TimeoutExpired:
                stop_process_group(process.pid, process=process)
            registry.unregister(process.pid)

    if registry.interrupted:
        raise ProcessInterruptedError(
            "Managed subprocess was interrupted by SIGTERM."
        )

    completed = subprocess.CompletedProcess(command, return_code)
    if check and return_code != 0:
        raise subprocess.CalledProcessError(return_code, command)
    return completed
