from __future__ import annotations

import io
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from engine.build.diagnostic import (
    DiagnosticBuildError,
    EXPECTED_SOURCES,
    FRAME_POINTERS,
    SANITIZER,
    _validate_flags,
    _verify_final_build_inputs,
    _verify_compile_commands,
)
from engine.evidence.database import open_database
from engine.evidence import migrations as evidence_migrations
from engine.evidence.migrations import run_migrations
from engine.evidence.repository import EvidenceRepository, SANITIZER_RUN_COLUMNS
from engine.evidence.sanitizer import (
    STAGING_AUTHORIZATION_TOKEN,
    MANAGER_AUTHORIZATION_TOKEN,
    SanitizerCollectionError,
    _GuardEventChannel,
    _deliver_manager_authorization,
    _classify_output,
    _close_process_stdin,
    _execution_outcome_unknown,
    _staged_permissions,
    _stop_and_verify_service,
    _wait_for_guard_ready,
    _wait_for_guard_completion,
    _parse_properties,
    _resource_policy,
    _systemd_run_argv,
    _verify_systemd_properties,
)
from engine.evidence import sanitizer_exec_guard
from engine.evidence.sanitizer_exec_guard import (
    STAGING_AUTHORIZATION_TOKEN as GUARD_STAGING_AUTHORIZATION_TOKEN,
    MANAGER_AUTHORIZATION_TOKEN as GUARD_MANAGER_AUTHORIZATION_TOKEN,
    verify_readonly_bind,
)
from engine.evidence.store import EvidenceStore



class _CaptureStdout:
    def __init__(self):
        self.buffer = io.BytesIO()


def _guard_frames(raw: bytes) -> list[tuple[bytes, bytes]]:
    frames: list[tuple[bytes, bytes]] = []
    offset = 0
    while offset < len(raw):
        header = raw[offset:offset + 9]
        if len(header) != 9 or header[:4] != b"K3E1":
            raise AssertionError("invalid guard event frame in test output")
        kind = header[4:5]
        size = int.from_bytes(header[5:9], "big")
        payload = raw[offset + 9:offset + 9 + size]
        if len(payload) != size:
            raise AssertionError("truncated guard event frame in test output")
        frames.append((kind, payload))
        offset += 9 + size
    return frames


def _last_guard_status(raw: bytes) -> dict:
    statuses = [json.loads(payload) for kind, payload in _guard_frames(raw) if kind == b"S"]
    if not statuses:
        raise AssertionError("guard emitted no status frames")
    return statuses[-1]


def _encode_guard_frame(kind: bytes, payload: bytes) -> bytes:
    return b"K3E1" + kind + len(payload).to_bytes(4, "big") + payload



class SanitizerProtocolRegressionTests(unittest.TestCase):
    def test_role_specific_staging_permissions_match_runtime_needs(self):
        self.assertEqual(_staged_permissions("input"), (0o400, 0o400))
        self.assertEqual(_staged_permissions("harness"), (0o500, 0o500))
        self.assertEqual(_staged_permissions("guard"), (0o444, 0o400))
        with self.assertRaises(SanitizerCollectionError):
            _staged_permissions("unexpected")

    def test_final_authorization_without_durable_exec_ack_is_uncertain(self):
        self.assertFalse(_execution_outcome_unknown(False, None))
        self.assertTrue(_execution_outcome_unknown(True, None))
        self.assertTrue(_execution_outcome_unknown(True, {
            "guard_state": "manager_authorized",
            "harness_exec_succeeded": False,
        }))
        self.assertTrue(_execution_outcome_unknown(True, {
            "guard_state": "launch_failed",
            "harness_exec_succeeded": False,
            "launch_failure_confirmed": False,
        }))
        self.assertFalse(_execution_outcome_unknown(True, {
            "guard_state": "launch_failed",
            "harness_exec_succeeded": False,
            "launch_failure_confirmed": True,
        }))
        self.assertFalse(_execution_outcome_unknown(True, {
            "guard_state": "manager_authorization_refused",
            "manager_authorization_received": False,
            "harness_exec_succeeded": False,
        }))
        self.assertFalse(_execution_outcome_unknown(True, {
            "guard_state": "harness_running",
            "harness_exec_succeeded": True,
        }))


    def test_manager_authorization_interruption_after_pipe_acceptance_is_marked_uncertain(self):
        accepted = []
        possible_delivery = {"value": False}

        class AcceptThenInterrupt:
            def write(self, content):
                accepted.append(content)
                raise KeyboardInterrupt("signal after kernel accepted authorization")

        process = SimpleNamespace(stdin=AcceptThenInterrupt())

        def mark_possible_delivery():
            possible_delivery["value"] = True

        with self.assertRaises(KeyboardInterrupt):
            _deliver_manager_authorization(process, mark_possible_delivery)
        self.assertEqual(accepted, [MANAGER_AUTHORIZATION_TOKEN])
        self.assertTrue(possible_delivery["value"])

    def test_guard_event_channel_uses_collector_owned_status_and_stream_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            attempt = root / "attempt"
            runtime.mkdir(mode=0o700)
            attempt.mkdir(mode=0o700)

            # These are workload-writable decoys. The collector must ignore them.
            (runtime / "status.json").write_text(
                json.dumps({"schema_version": 1, "guard_state": "finished", "harness_exec_succeeded": False}),
                encoding="utf-8",
            )
            (runtime / "stdout.bin").write_bytes(b"forged stdout")
            (runtime / "stderr.bin").write_bytes(b"forged stderr")

            ready = {
                "schema_version": 1,
                "guard_state": "awaiting_manager_authorization",
                "harness_exec_succeeded": False,
                "manager_authorization_received": False,
            }
            finished = {
                "schema_version": 1,
                "guard_state": "finished",
                "harness_exec_succeeded": True,
                "execution_status": "exited",
                "exit_code": 0,
                "stdout": {"capture_state": "complete", "truncated": False},
                "stderr": {"capture_state": "complete", "truncated": False},
            }
            frames = b"".join((
                _encode_guard_frame(b"S", json.dumps(ready).encode()),
                _encode_guard_frame(b"O", b"trusted stdout"),
                _encode_guard_frame(b"E", b"trusted stderr"),
                _encode_guard_frame(b"S", json.dumps(finished).encode()),
            ))
            process = SimpleNamespace(stdout=io.BytesIO(frames))
            channel = _GuardEventChannel(attempt)
            channel.start(process)
            channel.join()

            self.assertIsNone(process.stdout)
            self.assertEqual(channel.snapshot()["guard_state"], "finished")
            stdout, stdout_path, stdout_error = channel.stream_result(b"O")
            stderr, stderr_path, stderr_error = channel.stream_result(b"E")
            self.assertEqual(stdout, b"trusted stdout")
            self.assertEqual(stderr, b"trusted stderr")
            self.assertEqual(stdout_path, attempt / "stdout.bin")
            self.assertEqual(stderr_path, attempt / "stderr.bin")
            self.assertIsNone(stdout_error)
            self.assertIsNone(stderr_error)
            persisted = json.loads((attempt / "guard_status.json").read_text(encoding="utf-8"))
            self.assertEqual(persisted["guard_state"], "finished")
            self.assertEqual((runtime / "stdout.bin").read_bytes(), b"forged stdout")
            self.assertEqual((runtime / "stderr.bin").read_bytes(), b"forged stderr")

    def test_missing_execution_identity_does_not_accept_marker(self):
        families, assessment = _classify_output(
            b"ERROR: AddressSanitizer: heap-use-after-free",
            b"",
            {"harness_exec_succeeded": True, "execution_status": "exited", "exit_code": 0},
        )
        self.assertEqual(families, [])
        self.assertEqual(assessment, "inconclusive")

    def test_close_stdin_detaches_closed_pipe_before_communicate(self):
        process = subprocess.Popen(
            [sys.executable, "-c", "import sys; sys.stdin.read(); print('pipe-closed')"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertIsNotNone(process.stdin)
        process.stdin.write(b"authorization")
        _close_process_stdin(process)
        self.assertIsNone(process.stdin)
        stdout, stderr = process.communicate(timeout=3)
        self.assertEqual(stdout.strip(), b"pipe-closed")
        self.assertEqual(stderr, b"")


class DiagnosticFlagVerificationTests(unittest.TestCase):
    def _valid_flags(self) -> list[str]:
        return ["/usr/bin/clang", SANITIZER, FRAME_POINTERS, "-g", "-c"]

    def test_accepts_required_effective_instrumentation(self):
        _validate_flags(self._valid_flags())

    def test_rejects_sanitizer_disabling_and_trap_overrides(self):
        for override in (
            "-fno-sanitize=address,undefined",
            "-fsanitize-trap=undefined",
            "-fsanitize-minimal-runtime",
            "-fsanitize-recover=undefined",
            "-fsanitize-ignorelist=/tmp/ignore.txt",
            "-fsanitize-blacklist=/tmp/blacklist.txt",
        ):
            with self.subTest(override=override), self.assertRaises(DiagnosticBuildError):
                _validate_flags(self._valid_flags() + [override])

    def test_rejects_debug_and_frame_pointer_overrides(self):
        for override in ("-g0", "-gline-tables-only", "-fomit-frame-pointer"):
            with self.subTest(override=override), self.assertRaises(DiagnosticBuildError):
                _validate_flags(self._valid_flags() + [override])

    def test_rejects_response_files_compiler_plugins_and_linker_pass_through(self):
        for override in (
            "@untrusted.rsp", "-Xclang", "-mllvm", "-fplugin=plugin.so",
            "--config=untrusted.cfg", "-Wl,--wrap=malloc",
        ):
            with self.subTest(override=override), self.assertRaises(DiagnosticBuildError):
                _validate_flags(self._valid_flags() + [override])

    def _make_compile_db(self, root: Path) -> tuple[Path, Path, Path]:
        source = root / "source"
        build = root / "build"
        source.mkdir()
        build.mkdir()
        compiler = root / "clang"
        compiler.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        compiler.chmod(0o700)
        rows = []
        for index, rel in enumerate(sorted(EXPECTED_SOURCES)):
            source_file = source / rel
            source_file.parent.mkdir(parents=True, exist_ok=True)
            source_file.write_text("int p3_test;\n", encoding="utf-8")
            output = build / "objects" / f"unit-{index}.o"
            rows.append({
                "directory": str(build),
                "file": str(source_file),
                "arguments": [
                    str(compiler), SANITIZER, FRAME_POINTERS, "-g",
                    "-c", str(source_file), "-o", str(output),
                ],
            })
        compile_db = build / "compile_commands.json"
        compile_db.write_text(json.dumps(rows), encoding="utf-8")
        return source, build, compiler

    def test_accepts_exact_seventeen_translation_units_and_unique_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, build, compiler = self._make_compile_db(Path(temporary))
            verified = _verify_compile_commands(
                source.resolve(), build / "compile_commands.json",
                compiler.resolve(), build.resolve(),
            )
            self.assertEqual(len(verified), 17)
            self.assertEqual({item["source"] for item in verified}, EXPECTED_SOURCES)
            self.assertEqual(len({item["object_path"] for item in verified}), 17)

    def test_rejects_duplicate_translation_unit(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, build, compiler = self._make_compile_db(Path(temporary))
            path = build / "compile_commands.json"
            rows = json.loads(path.read_text(encoding="utf-8"))
            rows[-1]["file"] = rows[0]["file"]
            path.write_text(json.dumps(rows), encoding="utf-8")
            with self.assertRaises(DiagnosticBuildError):
                _verify_compile_commands(source.resolve(), path, compiler.resolve(), build.resolve())

    def test_rejects_object_output_outside_build_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            source, build, compiler = self._make_compile_db(Path(temporary))
            path = build / "compile_commands.json"
            rows = json.loads(path.read_text(encoding="utf-8"))
            rows[0]["arguments"][-1] = str(Path(temporary) / "escape.o")
            path.write_text(json.dumps(rows), encoding="utf-8")
            with self.assertRaisesRegex(DiagnosticBuildError, "escapes"):
                _verify_compile_commands(source.resolve(), path, compiler.resolve(), build.resolve())

    def test_final_build_input_identity_is_rechecked_before_registration(self):
        from engine.build import diagnostic

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            archive = root / "source.tar.xz"
            harness = root / "harness.c"
            source.mkdir()
            archive.write_bytes(b"source archive")
            harness.write_text("int main(void){return 0;}\\n", encoding="utf-8")
            expected_harness = diagnostic.HARNESS_SHA256
            identity = SimpleNamespace(
                archive_sha256="a" * 64,
                tree_sha256="b" * 64,
            )
            with patch.object(diagnostic, "verify_libpng_source_identity", return_value=identity), patch.object(
                diagnostic, "_hash_file", return_value=(expected_harness, harness.stat().st_size)
            ):
                verified = _verify_final_build_inputs(
                    source, archive, harness, "a" * 64, "b" * 64, expected_harness
                )
            self.assertEqual(verified["source_archive_sha256"], "a" * 64)
            self.assertEqual(verified["source_tree_sha256"], "b" * 64)

            changed = SimpleNamespace(archive_sha256="a" * 64, tree_sha256="c" * 64)
            with patch.object(diagnostic, "verify_libpng_source_identity", return_value=changed), patch.object(
                diagnostic, "_hash_file", return_value=(expected_harness, harness.stat().st_size)
            ):
                with self.assertRaisesRegex(DiagnosticBuildError, "source identity changed"):
                    _verify_final_build_inputs(
                        source, archive, harness, "a" * 64, "b" * 64, expected_harness
                    )


class SanitizerClassificationTests(unittest.TestCase):
    def test_report_signature_takes_precedence_over_timeout_and_truncation(self):
        families, assessment = _classify_output(
            b"",
            b"ERROR: AddressSanitizer: heap-use-after-free",
            {
                "harness_exec_succeeded": True,
                "execution_identity_verified": True,
                "execution_status": "timed_out",
                "stdout_capture_state": "read_failed",
                "stderr_capture_state": "complete",
                "stdout_truncated": True,
                "stderr_truncated": False,
                "stdout_publication_state": "pending_recovery",
                "stderr_publication_state": "published",
            },
        )
        self.assertEqual(families, ["address"])
        self.assertEqual(assessment, "report_signature_observed")

    def test_no_signature_requires_successful_complete_published_capture(self):
        good = {
            "harness_exec_succeeded": True,
            "execution_identity_verified": True,
            "execution_status": "exited",
            "exit_code": 0,
            "stdout_capture_state": "complete",
            "stderr_capture_state": "complete",
            "stdout_truncated": False,
            "stderr_truncated": False,
            "stdout_publication_state": "published",
            "stderr_publication_state": "published",
            "systemd_policy_verified": True,
        }
        self.assertEqual(
            _classify_output(b"ordinary stdout", b"ordinary stderr", good),
            ([], "no_signature_observed"),
        )
        for key, value in (
            ("exit_code", 1),
            ("stdout_capture_state", "read_failed"),
            ("stderr_truncated", True),
            ("stderr_publication_state", "pending_recovery"),
            ("execution_status", "signaled"),
        ):
            changed = dict(good)
            changed[key] = value
            with self.subTest(key=key):
                self.assertEqual(
                    _classify_output(b"ordinary", b"ordinary", changed)[1],
                    "inconclusive",
                )

    def test_markers_are_not_joined_across_independent_streams(self):
        marker = b"ERROR: AddressSanitizer:"
        families, assessment = _classify_output(
            marker[:-1], marker[-1:],
            {"harness_exec_succeeded": True, "execution_status": "exited", "exit_code": 0},
        )
        self.assertEqual(families, [])
        self.assertEqual(assessment, "inconclusive")

    def test_systemd_property_verification_requires_the_exact_unit_policy(self):
        properties = {
            "LoadState": "loaded",
            "ActiveState": "active",
            "SubState": "running",
            "MainPID": "4321",
            "ControlGroup": "/system.slice/kekkai-p3-03-test.service",
            "Type": "exec",
            "DynamicUser": "yes",
            "NoNewPrivileges": "yes",
            "CapabilityBoundingSet": "",
            "Delegate": "no",
            "ProtectControlGroups": "strict",
            "ProtectSystem": "strict",
            "ProtectHome": "yes",
            "PrivateTmp": "yes",
            "MemoryAccounting": "yes",
            "CPUAccounting": "yes",
            "MemoryMax": "1073741824",
            "MemorySwapMax": "0",
            "CPUQuotaPerSecUSec": "600ms",
            "CPUQuotaPeriodUSec": "100ms",
            "TasksMax": "32",
            "KillMode": "control-group",
            "LimitCORE": "0",
            "SendSIGKILL": "yes",
            "RuntimeDirectoryPreserve": "yes",
            "RemainAfterExit": "yes",
            "RuntimeMaxUSec": "5s",
            "TimeoutStopUSec": "1s",
        }
        self.assertEqual(_verify_systemd_properties(properties), {"passed": True, "issues": []})
        properties["MemoryMax"] = "infinity"
        self.assertFalse(_verify_systemd_properties(properties)["passed"])

    def test_runtime_policy_is_fixed(self):
        self.assertEqual(_resource_policy()["memory_max_bytes"], 1024 * 1024 * 1024)
        self.assertEqual(_resource_policy()["memory_swap_max_bytes"], 0)
        self.assertEqual(_resource_policy()["cpu_quota_percent"], 60)
        self.assertEqual(_resource_policy()["tasks_max"], 32)
        self.assertEqual(_resource_policy()["kill_mode"], "control-group")

    def test_systemd_command_uses_read_only_staging_paths_and_service_pipe(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            testcase = root / "input.bin"
            testcase.write_bytes(b"input")
            harness = root / "harness"
            harness.write_bytes(b"executable")
            guard = root / "guard.py"
            guard.write_text("# guard\n", encoding="utf-8")
            argv = _systemd_run_argv(
                "kekkai-p3-03-test",
                "kekkai-p3-03-test",
                testcase,
                harness,
                guard,
                "a" * 64,
                5,
                "b" * 64,
            )
            self.assertIn("--pipe", argv)
            self.assertIn("--remain-after-exit", argv)
            self.assertNotIn("--wait", argv)
            self.assertTrue(any(item.startswith("--property=BindReadOnlyPaths=") and ":/run/" in item for item in argv))
            self.assertIn("--input-path", argv)
            self.assertNotIn("LoadCredential=input:", " ".join(argv))
            self.assertIn("--property=MemoryMax=1G", argv)
            self.assertIn("--property=MemorySwapMax=0", argv)
            self.assertIn("--property=CPUQuota=60%", argv)
            self.assertIn("--property=ProtectControlGroups=strict", argv)
            self.assertIn("--property=KillMode=control-group", argv)
            harness_arg = argv.index("--harness-path")
            input_arg = argv.index("--input-path")
            self.assertEqual(argv[harness_arg + 1], "/run/kekkai-p3-03-test/kekkai_png_harness")
            self.assertEqual(argv[input_arg + 1], "/run/kekkai-p3-03-test/input.bin")
            self.assertEqual(STAGING_AUTHORIZATION_TOKEN, bytes([1]))
            self.assertEqual(MANAGER_AUTHORIZATION_TOKEN, bytes([2]))
            self.assertEqual(GUARD_STAGING_AUTHORIZATION_TOKEN, bytes([1]))
            self.assertEqual(GUARD_MANAGER_AUTHORIZATION_TOKEN, bytes([2]))


class SanitizerGuardHandshakeTests(unittest.TestCase):
    def test_harness_is_not_executed_without_second_authorization_token(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "runtime"
            runtime.mkdir(mode=0o700)
            input_path = runtime / "input.bin"
            input_path.write_bytes(b"testcase")
            harness_path = runtime / "kekkai_png_harness"
            harness_path.write_bytes(b"registered harness image")
            harness_path.chmod(0o500)
            input_digest = __import__("hashlib").sha256(b"testcase").hexdigest()
            harness_digest = __import__("hashlib").sha256(b"registered harness image").hexdigest()
            argv = [
                "sanitizer_exec_guard.py",
                "--expected-input-sha256", input_digest,
                "--expected-input-size", str(len(b"testcase")),
                "--expected-harness-sha256", harness_digest,
                "--harness-path", str(harness_path),
                "--input-path", str(input_path),
            ]
            fake_stdin = SimpleNamespace(buffer=io.BytesIO(bytes([1])))
            fake_stdout = _CaptureStdout()
            with patch.object(sanitizer_exec_guard.sys, "argv", argv), patch.object(
                sanitizer_exec_guard.sys, "stdin", fake_stdin
            ), patch.object(sanitizer_exec_guard.sys, "stdout", fake_stdout), patch.dict(
                os.environ, {"RUNTIME_DIRECTORY": str(runtime)}, clear=False
            ), patch.object(
                sanitizer_exec_guard, "prevent_ptrace_access", return_value=None
            ), patch.object(
                sanitizer_exec_guard, "verify_limits", return_value={"cpu_quota": 60000}
            ), patch.object(
                sanitizer_exec_guard, "verify_readonly_bind", return_value={"read_only": "true"}
            ), patch.object(sanitizer_exec_guard.subprocess, "Popen") as popen:
                self.assertEqual(sanitizer_exec_guard.main(), 0)
            popen.assert_not_called()
            status = _last_guard_status(fake_stdout.buffer.getvalue())
            self.assertEqual(status["guard_state"], "manager_authorization_refused")
            self.assertFalse(status["harness_exec_succeeded"])
            self.assertFalse(status["manager_authorization_received"])
            self.assertFalse((runtime / "status.json").exists())
            self.assertFalse((runtime / "stdout.bin").exists())
            self.assertFalse((runtime / "stderr.bin").exists())

    def test_popen_failure_is_explicitly_confirmed_as_non_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "runtime"
            runtime.mkdir(mode=0o700)
            input_path = runtime / "input.bin"
            input_path.write_bytes(b"testcase")
            harness_path = runtime / "kekkai_png_harness"
            harness_path.write_bytes(b"registered harness image")
            harness_path.chmod(0o500)
            import hashlib
            argv = [
                "sanitizer_exec_guard.py",
                "--expected-input-sha256", hashlib.sha256(b"testcase").hexdigest(),
                "--expected-input-size", str(len(b"testcase")),
                "--expected-harness-sha256", hashlib.sha256(b"registered harness image").hexdigest(),
                "--harness-path", str(harness_path),
                "--input-path", str(input_path),
            ]
            fake_stdin = SimpleNamespace(buffer=io.BytesIO(bytes([1, 2])))
            fake_stdout = _CaptureStdout()
            with patch.object(sanitizer_exec_guard.sys, "argv", argv), patch.object(
                sanitizer_exec_guard.sys, "stdin", fake_stdin
            ), patch.object(sanitizer_exec_guard.sys, "stdout", fake_stdout), patch.dict(
                os.environ, {"RUNTIME_DIRECTORY": str(runtime)}, clear=False
            ), patch.object(
                sanitizer_exec_guard, "prevent_ptrace_access", return_value=None
            ), patch.object(
                sanitizer_exec_guard, "verify_limits", return_value={"cpu_quota": 60000}
            ), patch.object(
                sanitizer_exec_guard, "verify_readonly_bind", return_value={"read_only": "true"}
            ), patch.object(
                sanitizer_exec_guard.subprocess, "Popen", side_effect=OSError("exec denied")
            ):
                self.assertEqual(sanitizer_exec_guard.main(), 0)
            status = _last_guard_status(fake_stdout.buffer.getvalue())
            self.assertFalse(status["harness_exec_succeeded"])
            self.assertTrue(status["launch_failure_confirmed"])
            self.assertEqual(status["guard_state"], "launch_failed")
            self.assertFalse((runtime / "status.json").exists())


class SanitizerGuardMountTests(unittest.TestCase):
    def test_readonly_bind_requires_exact_read_only_mount(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "bound-input"
            path.write_bytes(b"data")
            mountpoint = str(path.resolve())
            readonly = (
                "36 25 0:32 / " + mountpoint
                + " ro,nosuid,nodev - ext4 /dev/root ro\\n"
            )
            result = verify_readonly_bind(path, readonly)
            self.assertEqual(result["read_only"], "true")
            writable = readonly.replace(" ro,nosuid", " rw,nosuid")
            with self.assertRaisesRegex(ValueError, "not read-only"):
                verify_readonly_bind(path, writable)


class SanitizerMigrationTests(unittest.TestCase):
    @staticmethod
    def _insert_parent_evidence(connection, root: Path) -> tuple[EvidenceRepository, dict[str, int]]:
        repo = EvidenceRepository(connection)
        timestamp = "2026-11-19T10:00:00.000000Z"
        target_id = repo.insert_target({
            "name": "libpng", "description": "P3 test target", "created_at": timestamp,
        })
        version_id = repo.insert_target_version({
            "target_id": target_id,
            "version": "1.6.59",
            "source_archive_sha256": "a" * 64,
            "source_tree_sha256": "b" * 64,
            "source_dir_recorded": str(root / "source"),
            "source_archive_path": str(root / "libpng.tar.xz"),
            "created_at": timestamp,
        })

        build_ids = {}
        for index, role in enumerate(("fuzz", "diagnostic_replay"), start=1):
            label = str(index)
            build_ids[role] = repo.insert_build({
                "target_id": target_id,
                "target_version_id": version_id,
                "profile": "afl-clang-fast" if role == "fuzz" else "libpng-asan-ubsan",
                "build_role": role,
                "build_dir": str(root / f"build-{role}"),
                "build_metadata_sha256": label * 64,
                "harness_source_path": str(root / "harness.c"),
                "harness_binary_path": str(root / f"harness-{role}"),
                "harness_source_sha256": "c" * 64,
                "harness_binary_sha256": ("d" if role == "fuzz" else "e") * 64,
                "library_archive_sha256": "f" * 64,
                "cmake_cache_sha256": "1" * 64,
                "compile_database_sha256": "2" * 64,
                "generated_header_sha256": "3" * 64,
                "compiler_path": "/usr/bin/clang",
                "compiler_version": "test compiler version",
                "cmake_build_type": "RelWithDebInfo",
                "aflpp_version": "4.33c" if role == "fuzz" else None,
                "afl_instrumented_locations": 1 if role == "fuzz" else None,
                "sanitizer_config_json": {"profile": role},
                "environment_json": {},
                "build_status": "completed",
                "started_at": timestamp,
                "ended_at": timestamp,
                "recorded_at": timestamp,
            })

        campaign_id = repo.insert_campaign({
            "campaign_uid": "campaign-20261119T100000Z-0123456789ab",
            "target_id": target_id,
            "target_version_id": version_id,
            "build_id": build_ids["fuzz"],
            "adapter_config_path": str(root / "adapter.json"),
            "adapter_config_sha256": "4" * 64,
            "campaign_dir": str(root / "campaign"),
            "afl_output_dir": str(root / "campaign" / "out"),
            "campaign_metadata_sha256": "5" * 64,
            "seed_dir": str(root / "seeds"),
            "seed_manifest_sha256": "6" * 64,
            "seed_count": 1,
            "fuzzer_executable": "/usr/bin/afl-fuzz",
            "fuzzer_version": "AFL++ 4.33c",
            "command_json": ["/usr/bin/afl-fuzz"],
            "duration_seconds": 1,
            "memory_mib": 512,
            "timeout_ms": 1000,
            "effective_timeout_ms": 1000,
            "max_input_bytes": 8 * 1024 * 1024,
            "afl_max_generated_bytes": 8 * 1024 * 1024,
            "status": "completed",
            "exit_code": 0,
            "total_execs": 1,
            "saved_crashes_reported": 1,
            "saved_hangs_reported": 0,
            "started_at": timestamp,
            "ended_at": timestamp,
            "recorded_at": timestamp,
        })
        original_sha = "7" * 64
        artifact_id = repo.insert_artifact({
            "sha256": original_sha,
            "size_bytes": 1,
            "storage_relpath": "objects/sha256/77/77/" + original_sha + ".bin",
            "first_ingested_at": timestamp,
            "last_verified_at": timestamp,
        })
        observation_id = repo.insert_observation({
            "observation_uid": "obs-" + ("8" * 64),
            "target_id": target_id,
            "target_version_id": version_id,
            "build_id": build_ids["fuzz"],
            "campaign_id": campaign_id,
            "original_artifact_id": artifact_id,
            "observation_kind": "crash",
            "afl_worker_name": "default",
            "afl_source_filename": "id:000001,sig:06,src:000000,time:0,execs:1",
            "afl_input_id": None,
            "observed_signal": 11,
            "observed_exit_code": None,
            "afl_discovery_time_ms": 100,
            "afl_discovery_execs": 1,
            "source_file_mtime_utc": timestamp,
            "ingested_at": timestamp,
        })
        return repo, {
            "target_id": target_id,
            "target_version_id": version_id,
            "source_build_id": build_ids["fuzz"],
            "diagnostic_build_id": build_ids["diagnostic_replay"],
            "campaign_id": campaign_id,
            "artifact_id": artifact_id,
            "observation_id": observation_id,
        }

    @staticmethod
    def _blocked_run_record(ids: dict[str, int]) -> dict[str, object]:
        started = "2026-11-19T10:00:01.000000Z"
        finished = "2026-11-19T10:00:02.000000Z"
        return {
            "run_uid": str(uuid.uuid4()),
            "target_id": ids["target_id"],
            "target_version_id": ids["target_version_id"],
            "source_build_id": ids["source_build_id"],
            "campaign_id": ids["campaign_id"],
            "observation_id": ids["observation_id"],
            "diagnostic_build_id": ids["diagnostic_build_id"],
            "original_artifact_id": ids["artifact_id"],
            "policy_id": "p3-03-test-policy",
            "argv_json": [],
            "environment_json": {},
            "resource_policy_json": {},
            "runtime_observation_json": {},
            "attempt_started_at": started,
            "attempt_finished_at": finished,
            "execution_started_at": None,
            "execution_finished_at": None,
            "execution_status": "blocked_preflight",
            "harness_exec_succeeded": 0,
            "exit_code": None,
            "signal_number": None,
            "sanitizer_families_json": [],
            "assessment": "inconclusive",
            "cleanup_status": "not_required",
            "cleanup_detail": None,
            "recovery_path": None,
            "systemd_unit_name": None,
            "kernel_version": "test-kernel",
            "wsl_version": None,
            "systemd_version": None,
            "stdout_artifact_id": None,
            "stdout_capture_state": "not_started",
            "stdout_truncated": 0,
            "stdout_publication_state": "not_started",
            "stdout_detail": None,
            "stderr_artifact_id": None,
            "stderr_capture_state": "not_started",
            "stderr_truncated": 0,
            "stderr_publication_state": "not_started",
            "stderr_detail": None,
            "recorded_at": finished,
        }

    def test_fresh_database_applies_immutable_sanitizer_schema(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            with EvidenceStore(root):
                pass
            run_migrations(root)
            import sqlite3
            connection = open_database(root / "db" / "kekkai.db")
            try:
                tables = {
                    row[1]: row for row in connection.execute("PRAGMA table_list").fetchall()
                }
                self.assertIn("sanitizer_runs", tables)
                self.assertEqual(tables["sanitizer_runs"][5], 1)
                trigger_names = {
                    row[0] for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type = 'trigger'"
                    )
                }
                self.assertIn("prevent_sanitizer_run_mutation", trigger_names)
                self.assertIn("prevent_sanitizer_run_deletion", trigger_names)
                self.assertEqual(
                    connection.execute("PRAGMA foreign_keys").fetchone()[0],
                    1,
                )
            finally:
                connection.close()

    def test_wait_for_guard_ready_requires_the_preexec_barrier(self):
        process = SimpleNamespace(poll=lambda: None)
        ready = {
            "schema_version": 1,
            "guard_state": "awaiting_manager_authorization",
            "harness_exec_succeeded": False,
        }
        channel = SimpleNamespace(
            wait_for_state=lambda expected, timeout: (ready, None)
        )
        status, error = _wait_for_guard_ready(
            process, channel, "awaiting_manager_authorization", timeout=0.1
        )
        self.assertEqual(status, ready)
        self.assertIsNone(error)

    def test_wait_for_guard_ready_does_not_authorize_on_a_guard_refusal(self):
        process = SimpleNamespace(poll=lambda: None)
        refused = {
            "schema_version": 1,
            "guard_state": "preflight_blocked",
            "detail": "effective CPU quota missing",
        }
        channel = SimpleNamespace(
            wait_for_state=lambda expected, timeout: (
                refused, str(refused.get("detail"))
            )
        )
        status, error = _wait_for_guard_ready(
            process, channel, "awaiting_private_staging", timeout=0.1
        )
        self.assertEqual(status, refused)
        self.assertIn("effective CPU quota missing", error)

    def test_guard_completion_waits_for_terminal_status_before_unit_stop(self):
        process = SimpleNamespace(poll=lambda: None)
        finished = {
            "schema_version": 1,
            "guard_state": "finished",
            "harness_exec_succeeded": True,
            "execution_status": "exited",
            "exit_code": 0,
        }
        channel = SimpleNamespace(
            wait_for_terminal=lambda timeout: (finished, None)
        )
        status, error = _wait_for_guard_completion(process, channel, timeout=0.1)
        self.assertEqual(status, finished)
        self.assertIsNone(error)

    def test_guard_completion_refuses_to_guess_if_runtime_is_unreadable(self):
        process = SimpleNamespace(poll=lambda: None)
        channel = SimpleNamespace(
            wait_for_terminal=lambda timeout: (None, "Guard event channel ended before a terminal state was received.")
        )
        status, error = _wait_for_guard_completion(process, channel, timeout=0.1)
        self.assertIsNone(status)
        self.assertIn("terminal state", error)

    def test_final_systemd_inspection_failure_is_not_cleanup_success(self):
        with patch(
            "engine.evidence.sanitizer._sudo",
            return_value=subprocess.CompletedProcess([], 0, b"", b""),
        ), patch(
            "engine.evidence.sanitizer._systemd_show",
            return_value={"show_error": "permission denied"},
        ):
            okay, detail, final = _stop_and_verify_service("kekkai-p3-03-test", {})
        self.assertFalse(okay)
        self.assertIn("unverified", detail)
        self.assertIn("show_error", final)

    def test_positive_systemd_not_found_is_the_only_absence_shortcut(self):
        with patch(
            "engine.evidence.sanitizer._sudo",
            return_value=subprocess.CompletedProcess([], 5, b"", b"unit not loaded"),
        ), patch(
            "engine.evidence.sanitizer._systemd_show",
            return_value={"LoadState": "not-found"},
        ):
            okay, detail, final = _stop_and_verify_service("kekkai-p3-03-test", {})
        self.assertTrue(okay)
        self.assertIsNone(detail)
        self.assertEqual(final["cgroup_populated"], "not-found")

    def test_identity_mismatch_prevents_positive_assessment(self):
        families, assessment = _classify_output(
            b"",
            b"ERROR: AddressSanitizer: heap-use-after-free",
            {
                "harness_exec_succeeded": True,
                "execution_status": "exited",
                "exit_code": 0,
                "execution_identity_verified": False,
            },
        )
        self.assertEqual(families, [])
        self.assertEqual(assessment, "inconclusive")

    def test_sanitizer_table_enforces_truth_table_uuid_time_and_immutability(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            with EvidenceStore(root):
                pass
            run_migrations(root)
            connection = open_database(root / "db" / "kekkai.db")
            try:
                repo, ids = self._insert_parent_evidence(connection, root)
                record = self._blocked_run_record(ids)
                row_id = repo.insert_sanitizer_run(record)

                with self.assertRaisesRegex(sqlite3.IntegrityError, "immutable"):
                    connection.execute(
                        "UPDATE sanitizer_runs SET assessment='inconclusive' WHERE id=?",
                        (row_id,),
                    )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "cannot be deleted"):
                    connection.execute("DELETE FROM sanitizer_runs WHERE id=?", (row_id,))

                cases = [
                    ("inconclusive_nonempty_families", {
                        "sanitizer_families_json": ["address"],
                    }),
                    ("blocked_truncated_output", {
                        "stdout_truncated": 1,
                    }),
                    ("invalid_calendar_timestamp", {
                        "attempt_started_at": "2026-02-30T10:00:01.000000Z",
                    }),
                    ("invalid_clock_timestamp", {
                        "attempt_started_at": "2026-11-19T24:00:01.000000Z",
                    }),
                    ("extra_uuid_hyphen", {
                        "run_uid": "-" + str(uuid.uuid4())[1:],
                    }),
                ]
                normalized_base = EvidenceRepository._normalize_record(
                    SANITIZER_RUN_COLUMNS, self._blocked_run_record(ids)
                )
                for name, changes in cases:
                    values = dict(normalized_base)
                    for column, value in changes.items():
                        if column == "sanitizer_families_json":
                            value = '["address"]'
                        values[column] = value
                    columns = ", ".join(SANITIZER_RUN_COLUMNS)
                    placeholders = ", ".join("?" for _ in SANITIZER_RUN_COLUMNS)
                    with self.subTest(name=name), self.assertRaises(sqlite3.IntegrityError):
                        connection.execute(
                            f"INSERT INTO sanitizer_runs ({columns}) VALUES ({placeholders})",
                            tuple(values[column] for column in SANITIZER_RUN_COLUMNS),
                        )
            finally:
                connection.close()

    def test_populated_v1_database_migrates_to_v2_without_losing_rows(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "evidence"
            with EvidenceStore(root):
                pass
            with patch("os.geteuid", return_value=1000), patch.object(
                evidence_migrations, "MIGRATIONS", evidence_migrations.MIGRATIONS[:1]
            ):
                self.assertEqual(run_migrations(root), 1)
            connection = open_database(root / "db" / "kekkai.db")
            try:
                self._insert_parent_evidence(connection, root)
                before = {
                    table: connection.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                    for table in (
                        "targets", "target_versions", "builds", "campaigns",
                        "artifacts", "observations",
                    )
                }
            finally:
                connection.close()
            with patch("os.geteuid", return_value=1000):
                self.assertEqual(run_migrations(root), 2)
            migrated = open_database(root / "db" / "kekkai.db")
            try:
                self.assertEqual(migrated.execute("PRAGMA user_version").fetchone()[0], 2)
                after = {
                    table: migrated.execute(f"SELECT count(*) FROM {table}").fetchone()[0]
                    for table in before
                }
                self.assertEqual(after, before)
                self.assertEqual(migrated.execute("PRAGMA foreign_key_check").fetchall(), [])
                self.assertEqual(
                    migrated.execute("SELECT count(*) FROM schema_migrations").fetchone()[0],
                    2,
                )
            finally:
                migrated.close()
            backups = list((root / "backups").glob("kekkai-pre-migration-*.db"))
            self.assertGreaterEqual(len(backups), 1)

    def test_systemd_properties_parse_without_truncating_values(self):
        parsed = _parse_properties(
            b"ActiveState=inactive\nMemoryMax=1073741824\nControlGroup=/system.slice/unit.service\n"
        )
        self.assertEqual(parsed["MemoryMax"], "1073741824")
        self.assertEqual(parsed["ControlGroup"], "/system.slice/unit.service")


if __name__ == "__main__":
    unittest.main()
