"""Tests for bounded libpng build execution."""

import io
import json
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import Mock, patch

from engine.adapters.config import (
    AdapterConfig,
    BuildConfig,
    FuzzerConfig,
    ResourceLimits,
    TargetConfig,
)
from engine.build.libpng import BuildPlan, BuildStep
from engine.build.runner import (
    BuildState,
    _drain_to_log,
    run_libpng_build,
)


class BuildRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "repository"
        self.root.mkdir()

        self.build_parent = self.base / "work" / "builds"
        self.build_parent.mkdir(parents=True)
        self.build_dir = self.build_parent / "clean"

        self.source = self.base / "source"
        self.source.mkdir()
        self.harness = self.root / "harness.c"
        self.harness.write_text("/* test */\n")

        self.config = AdapterConfig(
            schema_version=2,
            target=TargetConfig(
                name="libpng",
                version="1.6.59",
                source_dir=self.source,
                harness_source=self.harness,
                harness_binary=self.build_dir / "kekkai_png_harness",
                seed_dir=self.base / "seeds",
                output_parent=self.base / "fuzzing",
            ),
            fuzzer=FuzzerConfig("afl-fuzz", "4.33c"),
            limits=ResourceLimits(300, 512, 1000, 8388608),
            config_path=self.root / "adapter.toml",
            build=BuildConfig(
                profile="libpng-afl-ubsan",
                build_dir=self.build_dir,
                jobs=2,
                timeout_seconds=10,
                memory_mib=4096,
                log_limit_bytes=1024 * 1024,
            ),
        )

        self.plan = BuildPlan(
            build_dir=self.build_dir,
            steps=(
                BuildStep(
                    "configure",
                    (sys.executable, "-c", "print('configure passed')"),
                ),
                BuildStep(
                    "library",
                    (sys.executable, "-c", "print('library passed')"),
                ),
                BuildStep(
                    "harness",
                    (sys.executable, "-c", "print('harness passed')"),
                ),
            ),
            environment=(("PATH", "/bin:/usr/bin"), ("LC_ALL", "C")),
        )

    def tearDown(self):
        self.temp.cleanup()

    def run_plan(self, plan=None, config=None):
        with (
            patch(
                "engine.build.runner.build_command_plan",
                return_value=plan or self.plan,
            ),
            patch(
                "engine.build.runner.verify_build_outputs",
                return_value={"harness_binary_sha256": "test-hash"},
            ) as verify,
        ):
            result = run_libpng_build(
                config or self.config,
                self.root,
            )
        return result, verify

    def test_success_records_each_step_and_artifacts(self):
        result, verify = self.run_plan()

        self.assertEqual(result.status, BuildState.COMPLETED)
        self.assertEqual(result.artifacts[0], ("harness_binary_sha256", "test-hash"))
        verify.assert_called_once_with(self.build_dir)

        metadata = json.loads(result.metadata_path.read_text())
        self.assertEqual(metadata["status"], "completed")
        self.assertEqual(
            [step["status"] for step in metadata["steps"]],
            ["completed", "completed", "completed"],
        )
        self.assertIn(
            "configure passed",
            (self.build_dir / "stdout.log").read_text(),
        )
        self.assertTrue((self.build_dir / "stderr.log").is_file())

    def test_nonzero_build_step_records_failure(self):
        failed_plan = replace(
            self.plan,
            steps=(
                self.plan.steps[0],
                BuildStep(
                    "library",
                    (sys.executable, "-c", "raise SystemExit(7)"),
                ),
                self.plan.steps[2],
            ),
        )

        result, verify = self.run_plan(failed_plan)

        self.assertEqual(result.status, BuildState.FAILED)
        metadata = json.loads(result.metadata_path.read_text())
        self.assertEqual(metadata["status"], "failed")
        self.assertEqual(metadata["steps"][0]["status"], "completed")
        self.assertEqual(metadata["steps"][1]["status"], "failed")
        self.assertEqual(metadata["steps"][1]["exit_code"], 7)
        self.assertEqual(metadata["steps"][2]["status"], "pending")
        verify.assert_not_called()

    def test_watchdog_stops_overlong_build_step(self):
        slow_plan = replace(
            self.plan,
            steps=(
                BuildStep(
                    "configure",
                    (sys.executable, "-c", "import time; time.sleep(20)"),
                ),
            ),
        )
        config = replace(
            self.config,
            build=replace(self.config.build, timeout_seconds=1),
        )

        result, verify = self.run_plan(slow_plan, config)

        self.assertEqual(result.status, BuildState.FAILED)
        self.assertIn("watchdog", result.message)
        metadata = json.loads(result.metadata_path.read_text())
        self.assertEqual(metadata["status"], "failed")
        self.assertEqual(metadata["steps"][0]["status"], "failed")
        verify.assert_not_called()

    def test_keyboard_interrupt_records_interrupted_state(self):
        fake_process = Mock()
        fake_process.pid = 2_000_000_000
        fake_process.stdout = io.BytesIO()
        fake_process.stderr = io.BytesIO()
        fake_process.wait.side_effect = KeyboardInterrupt()
        fake_process.poll.return_value = -2

        one_step = replace(
            self.plan,
            steps=(self.plan.steps[0],),
        )

        with (
            patch(
                "engine.build.runner.build_command_plan",
                return_value=one_step,
            ),
            patch(
                "engine.build.runner.subprocess.Popen",
                return_value=fake_process,
            ),
            patch("engine.build.runner.verify_build_outputs") as verify,
        ):
            result = run_libpng_build(self.config, self.root)

        self.assertEqual(result.status, BuildState.INTERRUPTED)
        metadata = json.loads(result.metadata_path.read_text())
        self.assertEqual(metadata["status"], "interrupted")
        self.assertEqual(metadata["steps"][0]["status"], "interrupted")
        verify.assert_not_called()

    def test_build_log_output_is_bounded(self):
        log_path = self.base / "bounded.log"
        errors = []
        counter = [0, False]

        _drain_to_log(
            io.BytesIO(b"x" * 4096),
            log_path,
            128,
            counter,
            errors,
        )

        self.assertLessEqual(log_path.stat().st_size, 128)
        self.assertIn(b"output truncated", log_path.read_bytes())
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
