"""Tests for AFL++ coverage-feedback validation."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from engine.adapters.config import (
    AdapterConfig,
    FuzzerConfig,
    ResourceLimits,
    TargetConfig,
)
from engine.fuzzing.coverage import (
    CoverageValidationError,
    _run_bounded_process,
    validate_coverage,
)
from engine.fuzzing.smoke import LIBPNG_SEED_CASES


class CoverageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)

        self.root = self.base / "repository"
        self.root.mkdir()

        self.workspace = self.base / "workspace"
        self.workspace.mkdir()

        source_dir = self.workspace / "libpng"
        source_dir.mkdir()

        harness_source_dir = self.root / "targets" / "libpng"
        harness_source_dir.mkdir(parents=True)
        harness_source = harness_source_dir / "png_read_harness.c"
        harness_source.write_text("/* test source */\n", encoding="utf-8")

        binary_dir = self.workspace / "build"
        binary_dir.mkdir()
        self.binary = binary_dir / "kekkai_png_harness"
        self.binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        self.binary.chmod(0o755)

        self.seed_dir = self.workspace / "seeds"
        self.seed_dir.mkdir()

        for _, filename in LIBPNG_SEED_CASES:
            (self.seed_dir / filename).write_bytes(b"test-seed")

        output_parent = self.workspace / "output"
        output_parent.mkdir(parents=True)

        tool_dir = self.workspace / "bin"
        tool_dir.mkdir()
        self.showmap = tool_dir / "afl-showmap"
        self.showmap.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        self.showmap.chmod(0o755)

        self.config = AdapterConfig(
            schema_version=1,
            target=TargetConfig(
                name="libpng",
                version="1.6.59",
                source_dir=source_dir,
                harness_source=harness_source,
                harness_binary=self.binary,
                seed_dir=self.seed_dir,
                output_parent=output_parent,
            ),
            fuzzer=FuzzerConfig(
                executable="afl-fuzz",
                expected_version="4.33c",
            ),
            limits=ResourceLimits(
                duration_seconds=300,
                memory_mib=512,
                timeout_ms=1000,
                max_input_bytes=8 * 1024 * 1024,
            ),
            config_path=self.root / "adapter.toml",
        )

        self.adam7_calls = 0

    def tearDown(self) -> None:
        self.temp.cleanup()

    def fake_run(
        self,
        argv,
        *,
        all_maps_same=False,
        empty_first_map=False,
        oversized_first_map=False,
        unstable_adam7=False,
        wrong_exit_first_map=False,
        timeout_first_map=False,
        wrong_version=False,
        repeat_stable_but_initial_differs=False,
    ):
        if argv[1] == "-h":
            version = "4.34c" if wrong_version else "4.33c"
            stdout = f"afl-showmap++{version} by test\n"
            return 1, len(stdout.encode("utf-8")), stdout, 0, ""

        input_path = Path(argv[-1])
        map_path = Path(argv[argv.index("-o") + 1])

        if timeout_first_map:
            raise subprocess.TimeoutExpired(argv, timeout=6.0)

        if wrong_exit_first_map and input_path.name == "valid.png":
            error = "simulated showmap failure"
            return 1, 0, "", len(error.encode("utf-8")), error

        if empty_first_map and input_path.name == "valid.png":
            map_path.write_bytes(b"")
            return 0, 0, "", 0, ""

        if oversized_first_map and input_path.name == "valid.png":
            with map_path.open("wb") as output:
                output.truncate(8 * 1024 * 1024 + 1)
            return 0, 0, "", 0, ""

        if all_maps_same:
            content = b"000001:1\n"
        elif input_path.name == "adam7.png":
            self.adam7_calls += 1
            if unstable_adam7:
                content = f"000001:{self.adam7_calls}\n".encode("ascii")
            elif (
                repeat_stable_but_initial_differs
                and self.adam7_calls == 1
            ):
                content = b"000009:1\n"
            else:
                content = b"000001:1\n000003:4\n"
        else:
            seed_index = next(
                index
                for index, (_, filename) in enumerate(LIBPNG_SEED_CASES)
                if filename == input_path.name
            )
            content = (
                f"{seed_index + 1:06x}:1\n000100:2\n"
            ).encode("ascii")

        map_path.write_bytes(content)

        stdout = "coverage captured"
        return 0, len(stdout.encode("utf-8")), stdout, 0, ""

    def run_coverage(
        self,
        *,
        which_result=None,
        **fake_options,
    ):
        selected_tool = (
            str(self.showmap)
            if which_result == "default" or which_result is None
            else which_result
        )

        def side_effect(argv, **kwargs):
            return self.fake_run(argv, **fake_options)

        with (
            patch(
                "engine.fuzzing.coverage.os.geteuid",
                return_value=1000,
            ),
            patch(
                "engine.fuzzing.coverage.shutil.which",
                return_value=selected_tool,
            ),
            patch(
                "engine.fuzzing.coverage._run_bounded_process",
                side_effect=side_effect,
            ) as mocked_run,
        ):
            report = validate_coverage(self.config, self.root)

        return report, mocked_run

    def test_bounded_process_uses_safe_subprocess_options(self) -> None:
        def fake_subprocess_run(argv, **kwargs):
            kwargs["stdout"].write(b"bounded stdout")
            kwargs["stderr"].write(b"bounded stderr")
            return SimpleNamespace(returncode=0)

        with patch(
            "engine.fuzzing.coverage.subprocess.run",
            side_effect=fake_subprocess_run,
        ) as process:
            result = _run_bounded_process(
                ["fake-tool"],
                cwd=self.root,
                timeout=3,
                env={},
            )

        self.assertEqual(
            result,
            (
                0,
                len(b"bounded stdout"),
                "bounded stdout",
                len(b"bounded stderr"),
                "bounded stderr",
            ),
        )

        options = process.call_args.kwargs
        self.assertIs(options["stdin"], subprocess.DEVNULL)
        self.assertFalse(options["shell"])
        self.assertNotIn("capture_output", options)
        self.assertTrue(callable(options["preexec_fn"]))

    def test_valid_coverage_and_repeatability(self) -> None:
        report, mocked_run = self.run_coverage()

        self.assertTrue(report.passed, report.format())
        self.assertEqual(len(report.cases), 10)
        self.assertEqual(len(report.repeat_runs), 2)
        self.assertEqual(report.distinct_map_count, 10)
        self.assertEqual(report.diversity_status, "passed")
        self.assertEqual(report.repeatability_status, "passed")
        self.assertEqual(mocked_run.call_count, 13)

        for call in mocked_run.call_args_list:
            argv = call.args[0]
            options = call.kwargs

            if argv[1] == "-h":
                continue

            self.assertIsInstance(argv, list)
            self.assertIn("--", argv)
            self.assertEqual(argv[1], "-e")
            self.assertEqual(argv[2], "-o")
            self.assertIn("-m", argv)
            self.assertIn("512", argv)
            self.assertIn("-t", argv)
            self.assertIn("1000", argv)
            self.assertNotIn("-i", argv)
            self.assertNotIn("@@", argv)
            self.assertEqual(options["cwd"], self.root)
            self.assertIn("timeout", options)
            self.assertIn("env", options)

    def test_rejects_empty_coverage_map(self) -> None:
        report, _ = self.run_coverage(empty_first_map=True)

        self.assertFalse(report.passed)
        self.assertEqual(report.cases[0].status, "failed")
        self.assertIn("empty", report.cases[0].message.lower())

    def test_rejects_oversized_coverage_map(self) -> None:
        report, _ = self.run_coverage(oversized_first_map=True)

        self.assertFalse(report.passed)
        self.assertEqual(report.cases[0].status, "failed")
        self.assertIn("exceeds", report.cases[0].message.lower())
        self.assertIn("limit", report.cases[0].message.lower())

    def test_rejects_no_coverage_diversity(self) -> None:
        report, _ = self.run_coverage(all_maps_same=True)

        self.assertFalse(report.passed)
        self.assertEqual(report.distinct_map_count, 1)
        self.assertEqual(report.diversity_status, "failed")

    def test_rejects_non_repeatable_adam7_map(self) -> None:
        report, _ = self.run_coverage(unstable_adam7=True)

        self.assertFalse(report.passed)
        self.assertEqual(report.repeatability_status, "failed")
        self.assertNotEqual(
            report.repeat_runs[0].sha256,
            report.repeat_runs[1].sha256,
        )

    def test_rejects_repeat_maps_that_differ_from_initial_adam7(self) -> None:
        report, _ = self.run_coverage(
            repeat_stable_but_initial_differs=True,
        )

        self.assertFalse(report.passed)
        self.assertEqual(
            report.repeat_runs[0].sha256,
            report.repeat_runs[1].sha256,
        )

        initial_adam7 = next(
            case for case in report.cases if case.name == "adam7_png"
        )
        self.assertNotEqual(
            initial_adam7.sha256,
            report.repeat_runs[0].sha256,
        )
        self.assertEqual(report.repeatability_status, "failed")

    def test_rejects_wrong_showmap_version(self) -> None:
        report, mocked_run = self.run_coverage(wrong_version=True)

        self.assertFalse(report.passed)
        self.assertEqual(report.tool_status, "failed")
        self.assertEqual(report.tool_version, "4.34c")
        self.assertEqual(mocked_run.call_count, 1)

    def test_rejects_missing_showmap(self) -> None:
        with (
            patch(
                "engine.fuzzing.coverage.os.geteuid",
                return_value=1000,
            ),
            patch(
                "engine.fuzzing.coverage.shutil.which",
                return_value=None,
            ),
            patch("engine.fuzzing.coverage.subprocess.run") as process,
        ):
            report = validate_coverage(self.config, self.root)

        self.assertFalse(report.passed)
        self.assertEqual(report.tool_status, "failed")
        process.assert_not_called()

    def test_missing_seed_fails_validation(self) -> None:
        (self.seed_dir / "adam7.png").unlink()

        report, _ = self.run_coverage()

        self.assertFalse(report.passed)
        adam7 = next(case for case in report.cases if case.name == "adam7_png")
        self.assertEqual(adam7.status, "failed")
        self.assertEqual(report.repeatability_status, "failed")

    def test_timeout_fails_coverage_case(self) -> None:
        report, _ = self.run_coverage(timeout_first_map=True)

        self.assertFalse(report.passed)
        self.assertEqual(report.cases[0].status, "failed")
        self.assertIn("timed out", report.cases[0].message.lower())

    def test_nonzero_showmap_exit_fails_case(self) -> None:
        report, _ = self.run_coverage(wrong_exit_first_map=True)

        self.assertFalse(report.passed)
        self.assertEqual(report.cases[0].status, "failed")
        self.assertIn("status 1", report.cases[0].message)

    def test_refuses_to_run_as_root(self) -> None:
        with (
            patch(
                "engine.fuzzing.coverage.os.geteuid",
                return_value=0,
            ),
            patch("engine.fuzzing.coverage.subprocess.run") as process,
        ):
            with self.assertRaises(CoverageValidationError):
                validate_coverage(self.config, self.root)

        process.assert_not_called()

    def test_rejects_unsupported_target(self) -> None:
        config = replace(
            self.config,
            target=replace(self.config.target, name="other-target"),
        )

        with patch(
            "engine.fuzzing.coverage.os.geteuid",
            return_value=1000,
        ):
            with self.assertRaises(CoverageValidationError):
                validate_coverage(config, self.root)


if __name__ == "__main__":
    unittest.main()
