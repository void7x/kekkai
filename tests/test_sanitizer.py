from __future__ import annotations

import json
import os
import sqlite3
import subprocess
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
    _verify_compile_commands,
)
from engine.evidence.database import open_database
from engine.evidence import migrations as evidence_migrations
from engine.evidence.migrations import run_migrations
from engine.evidence.repository import EvidenceRepository, SANITIZER_RUN_COLUMNS
from engine.evidence.sanitizer import (
    MANAGER_AUTHORIZATION_TOKEN,
    SanitizerCollectionError,
    _classify_output,
    _copy_service_streams,
    _stop_and_verify_service,
    _wait_for_guard_ready,
    _parse_properties,
    _resource_policy,
    _systemd_run_argv,
    _verify_systemd_properties,
)
from engine.evidence.sanitizer_exec_guard import MANAGER_AUTHORIZATION_TOKEN as GUARD_AUTHORIZATION_TOKEN
from engine.evidence.store import EvidenceStore


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


class SanitizerClassificationTests(unittest.TestCase):
    def test_report_signature_takes_precedence_over_timeout_and_truncation(self):
        families, assessment = _classify_output(
            b"",
            b"ERROR: AddressSanitizer: heap-use-after-free",
            {
                "harness_exec_succeeded": True,
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
            self.assertEqual(MANAGER_AUTHORIZATION_TOKEN, b"\\x01")
            self.assertEqual(GUARD_AUTHORIZATION_TOKEN, b"\\x01")


class SanitizerMigrationTests(unittest.TestCase):
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

    def test_stream_copy_failure_does_not_skip_the_other_stream(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            runtime = root / "runtime"
            attempt = root / "attempt"
            runtime.mkdir()
            attempt.mkdir()
            from engine.evidence import sanitizer
            with patch.object(
                sanitizer,
                "_copy_service_stream",
                side_effect=[
                    SanitizerCollectionError("stdout read failed"),
                    (b"stderr", attempt / "stderr.bin"),
                ],
            ) as copy:
                stdout, stderr = _copy_service_streams(runtime, attempt)
            self.assertEqual(copy.call_count, 2)
            self.assertEqual(stdout, (None, None, "stdout read failed"))
            self.assertEqual(stderr, (b"stderr", attempt / "stderr.bin", None))

    def test_wait_for_guard_ready_requires_the_preexec_barrier(self):
        process = SimpleNamespace(poll=lambda: None)
        ready = {
            "schema_version": 1,
            "guard_state": "awaiting_manager_authorization",
            "harness_exec_succeeded": False,
        }
        with patch("engine.evidence.sanitizer._sudo", return_value=subprocess.CompletedProcess([], 0, b"", b"")), patch(
            "engine.evidence.sanitizer._read_guard_status", return_value=ready
        ):
            status, error = _wait_for_guard_ready(process, Path("/run/p3-ready"), timeout=0.1)
        self.assertEqual(status, ready)
        self.assertIsNone(error)

    def test_wait_for_guard_ready_does_not_authorize_on_a_guard_refusal(self):
        process = SimpleNamespace(poll=lambda: None)
        refused = {
            "schema_version": 1,
            "guard_state": "preflight_blocked",
            "detail": "effective CPU quota missing",
        }
        with patch("engine.evidence.sanitizer._sudo", return_value=subprocess.CompletedProcess([], 0, b"", b"")), patch(
            "engine.evidence.sanitizer._read_guard_status", return_value=refused
        ):
            status, error = _wait_for_guard_ready(process, Path("/run/p3-refused"), timeout=0.1)
        self.assertEqual(status, refused)
        self.assertIn("effective CPU quota missing", error)

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

    def test_systemd_properties_parse_without_truncating_values(self):
        parsed = _parse_properties(
            b"ActiveState=inactive\nMemoryMax=1073741824\nControlGroup=/system.slice/unit.service\n"
        )
        self.assertEqual(parsed["MemoryMax"], "1073741824")
        self.assertEqual(parsed["ControlGroup"], "/system.slice/unit.service")


if __name__ == "__main__":
    unittest.main()
