"""Integration tests for POSIX process-group lifecycle handling."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from engine.processes import (
    ProcessGroupRegistry,
    ProcessInterruptedError,
    run_process_group,
)


class ProcessGroupTests(unittest.TestCase):
    def test_stops_descendant_after_leader_exits_normally(self):
        with tempfile.TemporaryDirectory() as temporary:
            pid_file = Path(temporary) / "descendant.pid"
            command = [
                "/bin/sh", "-c",
                f"sleep 30 </dev/null >/dev/null 2>&1 & echo $! > {pid_file}; exit 0",
            ]
            completed = run_process_group(
                command,
                timeout=3,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
            )
            self.assertEqual(completed.returncode, 0)
            descendant_pid = int(pid_file.read_text().strip())
            deadline = time.monotonic() + 3.0
            while _pid_is_live(descendant_pid) and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertFalse(_pid_is_live(descendant_pid))

    def test_timeout_stops_descendants(self):
        with tempfile.TemporaryDirectory() as temporary:
            pid_file = Path(temporary) / "descendant.pid"
            command = [
                "/bin/sh", "-c",
                f"sleep 30 </dev/null >/dev/null 2>&1 & echo $! > {pid_file}; wait",
            ]
            with self.assertRaises(subprocess.TimeoutExpired):
                run_process_group(
                    command,
                    timeout=0.2,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    shell=False,
                )
            descendant_pid = int(pid_file.read_text().strip())
            self.assertFalse(_pid_is_live(descendant_pid))

    def test_sigterm_before_registration_escalates_to_kill(self):
        with tempfile.TemporaryDirectory() as temporary:
            ready_file = Path(temporary) / "ready"
            child_code = (
                "import signal, time\n"
                "from pathlib import Path\n"
                "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
                "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
                f"Path({str(ready_file)!r}).write_text('ready')\n"
                "time.sleep(30)\n"
            )
            with ProcessGroupRegistry() as registry:
                process = subprocess.Popen(
                    [sys.executable, "-c", child_code],
                    start_new_session=True,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                deadline = time.monotonic() + 3.0
                while not ready_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready_file.exists(), "child did not become ready")

                # Simulate SIGTERM after Popen succeeds but before register().
                registry._handle_sigterm(signal.SIGTERM, None)
                registry.register(process.pid, process=process)
                process.wait(timeout=2.0)

                self.assertEqual(process.returncode, -signal.SIGKILL)
                self.assertFalse(_pid_is_live(process.pid))

    def test_run_process_group_raises_when_sigterm_interrupts_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            ready_file = Path(temporary) / "ready"
            child_code = (
                "import time\n"
                "from pathlib import Path\n"
                f"Path({str(ready_file)!r}).write_text('ready')\n"
                "time.sleep(30)\n"
            )

            def send_sigterm():
                deadline = time.monotonic() + 5.0
                while not ready_file.exists() and time.monotonic() < deadline:
                    time.sleep(0.01)
                if ready_file.exists():
                    os.kill(os.getpid(), signal.SIGTERM)

            sender = threading.Thread(target=send_sigterm, daemon=True)
            sender.start()
            with self.assertRaises(ProcessInterruptedError):
                run_process_group(
                    [sys.executable, "-c", child_code],
                    timeout=8,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    shell=False,
                )
            sender.join(timeout=2.0)
            self.assertFalse(sender.is_alive())

    def test_interrupted_registry_refuses_to_start_child(self):
        enter = ProcessGroupRegistry.__enter__

        def enter_interrupted(registry):
            enter(registry)
            registry.interrupted = True
            return registry

        with (
            patch.object(ProcessGroupRegistry, "__enter__", enter_interrupted),
            patch("engine.processes.subprocess.Popen") as popen,
            self.assertRaises(ProcessInterruptedError),
        ):
            run_process_group(
                [sys.executable, "-c", "pass"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

        popen.assert_not_called()

    def test_sigterm_uses_registered_grace_periods(self):
        with ProcessGroupRegistry() as registry:
            registry.register(12345, graces=(5.0, 3.0, 2.0))
            with patch("engine.processes.stop_process_group") as stop:
                registry._handle_sigterm(signal.SIGTERM, None)
                stop.assert_called_once_with(
                    12345,
                    process=None,
                    graces=(5.0, 3.0, 2.0),
                )
            registry.unregister(12345)

    def test_check_flag_matches_subprocess_run_semantics(self):
        success = run_process_group(
            ["/bin/sh", "-c", "exit 0"],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=False,
        )
        self.assertEqual(success.returncode, 0)

        with self.assertRaises(subprocess.CalledProcessError) as caught:
            run_process_group(
                ["/bin/sh", "-c", "exit 7"],
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
            )
        self.assertEqual(caught.exception.returncode, 7)

    def test_sigterm_guard_stops_registered_process_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            pid_file = Path(temporary) / "child.pid"
            child_code = (
                "import os, signal, subprocess\n"
                "from pathlib import Path\n"
                "from engine.processes import ProcessGroupRegistry\n"
                "with ProcessGroupRegistry() as registry:\n"
                "    process=subprocess.Popen(['/bin/sh','-c','sleep 30'], start_new_session=True)\n"
                "    registry.register(process.pid)\n"
                f"    Path({str(pid_file)!r}).write_text(str(process.pid))\n"
                "    os.kill(os.getpid(), signal.SIGTERM)\n"
            )
            completed = subprocess.run(
                [sys.executable, "-c", child_code],
                cwd=Path(__file__).resolve().parents[1],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=5,
                check=False,
            )
            self.assertEqual(completed.returncode, 0)
            child_pid = int(pid_file.read_text().strip())
            self.assertFalse(_pid_is_live(child_pid))


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def _pid_is_live(pid: int) -> bool:
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="ascii")
    except FileNotFoundError:
        return False
    fields = raw[raw.rfind(")") + 2 :].split()
    return bool(fields) and fields[0] not in {"Z", "X"}


if __name__ == "__main__":
    unittest.main()
