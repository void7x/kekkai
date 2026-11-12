"""Tests for safe AFL++ campaign command construction."""

import io
import json
import os
import subprocess
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from engine.adapters.config import (
    AdapterConfig,
    BuildConfig,
    FuzzerConfig,
    ResourceLimits,
    TargetConfig,
)
from engine.build.runner import BuildState
from engine.fuzzing.campaign import (
    CampaignError,
    CampaignState,
    _campaign_group_exists,
    _execute_campaign,
    _stop_campaign_group,
    build_campaign_command,
    run_campaign,
)


class CampaignCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)

        self.output_parent = self.base / "output"
        self.output_parent.mkdir()

        self.seed_dir = self.base / "seeds"
        self.seed_dir.mkdir()

        self.binary = self.base / "harness"
        self.binary.write_text("#!/bin/sh\nexit 0\n")
        self.binary.chmod(0o755)

        self.fuzzer = self.base / "afl-fuzz"
        self.fuzzer.write_text("#!/bin/sh\nexit 0\n")
        self.fuzzer.chmod(0o755)

        self.config = AdapterConfig(
            schema_version=1,
            target=TargetConfig(
                name="libpng",
                version="1.6.59",
                source_dir=self.base,
                harness_source=self.base / "harness.c",
                harness_binary=self.binary,
                seed_dir=self.seed_dir,
                output_parent=self.output_parent,
            ),
            fuzzer=FuzzerConfig("afl-fuzz", "4.33c"),
            limits=ResourceLimits(300, 512, 1000, 8388608),
            config_path=self.base / "adapter.toml",
        )

    def tearDown(self):
        self.temp.cleanup()

    def run_fake_campaign(self, script_body):
        self.fuzzer.write_text(
            "#!/bin/sh\n" + script_body,
            encoding="utf-8",
        )
        self.fuzzer.chmod(0o755)

        repository = self.base / "repository"
        repository.mkdir(exist_ok=True)

        source_dir = self.base / "source"
        source_dir.mkdir(exist_ok=True)

        config = replace(
            self.config,
            target=replace(
                self.config.target,
                source_dir=source_dir,
            ),
        )

        return _execute_campaign(
            config,
            repository,
            self.fuzzer,
            {
                "preflight": "passed",
                "smoke": "passed",
                "coverage": "passed",
                "build_provenance": "passed",
            },
        )

    def test_fake_campaign_records_success_and_logs(self):
        script = (
            "printf 'fake stdout\\\\n'\n"
            "printf 'fake stderr\\\\n' >&2\n"
            "exit 0\n"
        )
        result = self.run_fake_campaign(script)

        self.assertEqual(result.status, CampaignState.COMPLETED)
        self.assertEqual(result.exit_code, 0)
        self.assertTrue((result.campaign_dir / "campaign.json").is_file())
        self.assertIn(
            "fake stdout",
            (result.campaign_dir / "stdout.log").read_text(),
        )
        self.assertIn(
            "fake stderr",
            (result.campaign_dir / "stderr.log").read_text(),
        )

        metadata = json.loads(
            (result.campaign_dir / "campaign.json").read_text()
        )
        self.assertEqual(metadata["status"], "completed")
        self.assertEqual(metadata["exit_code"], 0)
        self.assertIsNotNone(metadata["started_at"])
        self.assertIsNotNone(metadata["ended_at"])

    def test_campaign_uses_documented_fuzzer_environment(self):
        result = self.run_fake_campaign(
            "printf 'PATH=%s\\nLC_ALL=%s\\nAFL_NO_UI=%s\\nASAN_OPTIONS=%s\\n' \"$PATH\" \"$LC_ALL\" \"$AFL_NO_UI\" \"$ASAN_OPTIONS\"\n"
            "exit 0\n"
        )

        output = (result.campaign_dir / "stdout.log").read_text()
        self.assertIn(f"PATH={os.defpath}", output)
        self.assertIn("LC_ALL=C", output)
        self.assertIn("AFL_NO_UI=1", output)
        self.assertIn(
            "ASAN_OPTIONS=detect_leaks=0:abort_on_error=1:symbolize=0",
            output,
        )

    def test_fake_campaign_records_nonzero_exit_as_failed(self):
        result = self.run_fake_campaign("exit 7\n")

        self.assertEqual(result.status, CampaignState.FAILED)
        self.assertEqual(result.exit_code, 7)

        metadata = json.loads(
            (result.campaign_dir / "campaign.json").read_text()
        )
        self.assertEqual(metadata["status"], "failed")
        self.assertEqual(metadata["exit_code"], 7)

    def test_each_failed_validation_gate_blocks_campaign(self):
        repository = self.base / "repository"
        repository.mkdir(exist_ok=True)

        gate_names = (
            "preflight",
            "provenance",
            "smoke",
            "coverage",
        )

        for failed_gate in gate_names:
            with self.subTest(failed_gate=failed_gate):
                reports = {
                    name: SimpleNamespace(
                        passed=name != failed_gate,
                        format=lambda name=name: f"{name} simulated failure",
                    )
                    for name in gate_names
                }

                with (
                    patch(
                        "engine.fuzzing.campaign.validate_adapter",
                        return_value=reports["preflight"],
                    ),
                    patch(
                        "engine.fuzzing.campaign.verify_build_provenance",
                        return_value=reports["provenance"],
                    ),
                    patch(
                        "engine.fuzzing.campaign.run_harness_smoke",
                        return_value=reports["smoke"],
                    ),
                    patch(
                        "engine.fuzzing.campaign.validate_coverage",
                        return_value=reports["coverage"],
                    ),
                    patch(
                        "engine.fuzzing.campaign._execute_campaign",
                    ) as execute,
                ):
                    with self.assertRaises(CampaignError):
                        run_campaign(self.config, repository)

                execute.assert_not_called()

    def test_public_campaign_runs_validation_gates_in_order(self):
        repository = self.base / "repository"
        repository.mkdir(exist_ok=True)
        events = []

        def successful_gate(name):
            def call(*args, **kwargs):
                events.append(name)
                return SimpleNamespace(
                    passed=True,
                    format=lambda: f"{name} passed",
                    tool_version="4.33c",
                    distinct_map_count=10,
                    repeatability_status="passed",
                )
            return call

        expected_result = object()

        with (
            patch(
                "engine.fuzzing.campaign.validate_adapter",
                side_effect=successful_gate("preflight"),
            ),
            patch(
                "engine.fuzzing.campaign.verify_build_provenance",
                side_effect=successful_gate("provenance"),
            ),
            patch(
                "engine.fuzzing.campaign.run_harness_smoke",
                side_effect=successful_gate("smoke"),
            ),
            patch(
                "engine.fuzzing.campaign.validate_coverage",
                side_effect=successful_gate("coverage"),
            ),
            patch(
                "engine.fuzzing.campaign.shutil.which",
                return_value=str(self.fuzzer),
            ),
            patch(
                "engine.fuzzing.campaign._execute_campaign",
                return_value=expected_result,
            ) as execute,
        ):
            result = run_campaign(self.config, repository)

        self.assertIs(result, expected_result)
        self.assertEqual(
            events,
            ["preflight", "provenance", "smoke", "coverage"],
        )
        execute.assert_called_once()
        evidence = execute.call_args.args[3]
        self.assertEqual(evidence["preflight"]["status"], "passed")
        self.assertEqual(evidence["build_provenance"]["status"], "passed")
        self.assertEqual(evidence["harness_smoke"]["status"], "passed")
        self.assertEqual(evidence["coverage"]["status"], "passed")
        self.assertEqual(evidence["coverage"]["tool_version"], "4.33c")
        self.assertEqual(evidence["coverage"]["distinct_map_count"], 10)
        self.assertEqual(
            evidence["coverage"]["repeatability_status"], "passed"
        )

    def test_schema_v2_build_runs_before_validation(self):
        repository = self.base / "repository"
        repository.mkdir(exist_ok=True)
        events = []
        build_dir = self.base / "clean-build"

        config = replace(
            self.config,
            schema_version=2,
            target=replace(
                self.config.target,
                harness_binary=build_dir / "kekkai_png_harness",
            ),
            build=BuildConfig(
                profile="libpng-afl-ubsan",
                build_dir=build_dir,
                jobs=2,
                timeout_seconds=900,
                memory_mib=4096,
                log_limit_bytes=16777216,
            ),
        )

        build_result = SimpleNamespace(
            status=BuildState.COMPLETED,
            build_dir=build_dir,
            metadata_path=build_dir / "build.json",
            started_at="2026-11-11T00:00:00Z",
            ended_at="2026-11-11T00:01:00Z",
            message="Build completed.",
            artifacts=(("harness_binary_sha256", "abc123"),),
        )

        def successful_build(*args, **kwargs):
            events.append("build")
            return build_result

        def successful_gate(name):
            def call(*args, **kwargs):
                events.append(name)
                return SimpleNamespace(
                    passed=True,
                    format=lambda: f"{name} passed",
                    tool_version="4.33c",
                    distinct_map_count=10,
                    repeatability_status="passed",
                )
            return call

        with (
            patch(
                "engine.fuzzing.campaign.run_libpng_build",
                side_effect=successful_build,
            ) as build,
            patch(
                "engine.fuzzing.campaign.validate_adapter",
                side_effect=successful_gate("preflight"),
            ),
            patch(
                "engine.fuzzing.campaign.verify_build_provenance",
                side_effect=successful_gate("provenance"),
            ),
            patch(
                "engine.fuzzing.campaign.run_harness_smoke",
                side_effect=successful_gate("smoke"),
            ),
            patch(
                "engine.fuzzing.campaign.validate_coverage",
                side_effect=successful_gate("coverage"),
            ),
            patch(
                "engine.fuzzing.campaign.shutil.which",
                return_value=str(self.fuzzer),
            ),
            patch(
                "engine.fuzzing.campaign._execute_campaign",
                return_value="campaign-result",
            ) as execute,
        ):
            result = run_campaign(config, repository)

        self.assertEqual(result, "campaign-result")
        build.assert_called_once_with(config, repository.resolve())
        self.assertEqual(
            events,
            ["build", "preflight", "provenance", "smoke", "coverage"],
        )
        evidence = execute.call_args.args[3]
        self.assertEqual(evidence["clean_build"]["status"], "passed")
        self.assertEqual(
            evidence["clean_build"]["artifacts"]["harness_binary_sha256"],
            "abc123",
        )

    def test_schema_v2_reuses_existing_verified_build(self):
        repository = self.base / "repository"
        repository.mkdir(exist_ok=True)
        build_dir = self.base / "clean-build"
        build_dir.mkdir()

        metadata_path = build_dir / "build.json"
        metadata_path.write_text(json.dumps({
            "status": "completed",
            "profile": "libpng-afl-ubsan",
            "build_dir": str(build_dir),
            "started_at": "2026-11-11T00:00:00Z",
            "ended_at": "2026-11-11T00:01:00Z",
            "message": "Build completed.",
            "artifacts": {"harness_binary_sha256": "abc123"},
        }))

        config = replace(
            self.config,
            schema_version=2,
            target=replace(
                self.config.target,
                harness_binary=build_dir / "kekkai_png_harness",
            ),
            build=BuildConfig(
                profile="libpng-afl-ubsan",
                build_dir=build_dir,
                jobs=2,
                timeout_seconds=900,
                memory_mib=4096,
                log_limit_bytes=16777216,
            ),
        )

        events = []

        def successful_gate(name):
            def call(*args, **kwargs):
                events.append(name)
                return SimpleNamespace(
                    passed=True,
                    format=lambda: f"{name} passed",
                    tool_version="4.33c",
                    distinct_map_count=10,
                    repeatability_status="passed",
                )
            return call

        with (
            patch(
                "engine.fuzzing.campaign.run_libpng_build"
            ) as build,
            patch(
                "engine.fuzzing.campaign.validate_adapter",
                side_effect=successful_gate("preflight"),
            ),
            patch(
                "engine.fuzzing.campaign.verify_build_provenance",
                side_effect=successful_gate("provenance"),
            ),
            patch(
                "engine.fuzzing.campaign.run_harness_smoke",
                side_effect=successful_gate("smoke"),
            ),
            patch(
                "engine.fuzzing.campaign.validate_coverage",
                side_effect=successful_gate("coverage"),
            ),
            patch(
                "engine.fuzzing.campaign.shutil.which",
                return_value=str(self.fuzzer),
            ),
            patch(
                "engine.fuzzing.campaign._execute_campaign",
                return_value="campaign-result",
            ) as execute,
        ):
            result = run_campaign(config, repository)

        self.assertEqual(result, "campaign-result")
        build.assert_not_called()
        self.assertEqual(
            events, ["preflight", "provenance", "smoke", "coverage"]
        )

        evidence = execute.call_args.args[3]
        self.assertTrue(evidence["clean_build"]["reused_verified_build"])
        self.assertEqual(
            evidence["clean_build"]["artifacts"]["harness_binary_sha256"],
            "abc123",
        )

    def test_failed_schema_v2_build_blocks_all_validation(self):
        repository = self.base / "repository"
        repository.mkdir(exist_ok=True)
        build_dir = self.base / "clean-build"

        config = replace(
            self.config,
            schema_version=2,
            target=replace(
                self.config.target,
                harness_binary=build_dir / "kekkai_png_harness",
            ),
            build=BuildConfig(
                profile="libpng-afl-ubsan",
                build_dir=build_dir,
                jobs=2,
                timeout_seconds=900,
                memory_mib=4096,
                log_limit_bytes=16777216,
            ),
        )

        failed_build = SimpleNamespace(
            status=BuildState.FAILED,
            build_dir=build_dir,
            metadata_path=build_dir / "build.json",
            message="Ninja exited with status 1.",
        )

        with (
            patch(
                "engine.fuzzing.campaign.run_libpng_build",
                return_value=failed_build,
            ) as build,
            patch(
                "engine.fuzzing.campaign.validate_adapter"
            ) as preflight,
            patch(
                "engine.fuzzing.campaign._execute_campaign"
            ) as execute,
        ):
            with self.assertRaisesRegex(CampaignError, "clean build failed"):
                run_campaign(config, repository)

        build.assert_called_once()
        preflight.assert_not_called()
        execute.assert_not_called()

    def test_campaign_logs_are_bounded(self):
        with patch(
            "engine.fuzzing.campaign._MAX_CAMPAIGN_LOG_BYTES",
            128,
        ):
            result = self.run_fake_campaign(
                "head -c 256 /dev/zero\nexit 0\n"
            )

        log = (result.campaign_dir / "stdout.log").read_bytes()
        self.assertLessEqual(len(log), 128)
        self.assertIn(b"output truncated", log)

    def test_pid_metadata_failure_stops_campaign_and_records_failure(self):
        from engine.fuzzing import campaign as campaign_module

        original_write = campaign_module._write_metadata
        write_calls = 0

        def fail_second_metadata_write(campaign_dir, metadata):
            nonlocal write_calls
            write_calls += 1
            if write_calls == 2:
                raise OSError("simulated PID metadata failure")
            original_write(campaign_dir, metadata)

        with patch(
            "engine.fuzzing.campaign._write_metadata",
            side_effect=fail_second_metadata_write,
        ):
            result = self.run_fake_campaign("exec sleep 30\\n")

        self.assertEqual(result.status, CampaignState.FAILED)
        self.assertIn("Could not persist campaign PID metadata", result.message)
        self.assertEqual(write_calls, 3)

        metadata = json.loads(
            (result.campaign_dir / "campaign.json").read_text()
        )
        self.assertEqual(metadata["status"], "failed")
        self.assertIsNotNone(metadata["pid"])
        self.assertFalse(_campaign_group_exists(metadata["pid"]))
        self.assertTrue((result.campaign_dir / "stdout.log").is_file())
        self.assertTrue((result.campaign_dir / "stderr.log").is_file())

    def test_campaign_start_failure_is_recorded(self):
        with patch(
            "engine.fuzzing.campaign.subprocess.Popen",
            side_effect=OSError("simulated launch failure"),
        ):
            result = self.run_fake_campaign("exit 0\\n")

        self.assertEqual(result.status, CampaignState.FAILED)
        self.assertIsNone(result.exit_code)
        self.assertIn("Could not start AFL++", result.message)
        self.assertTrue((result.campaign_dir / "stdout.log").is_file())
        self.assertTrue((result.campaign_dir / "stderr.log").is_file())

    def test_stop_campaign_group_cleans_descendant_after_leader_exits(self):
        process = subprocess.Popen(
            [
                "/bin/sh",
                "-c",
                'sh -c \'trap "" INT; exec sleep 30\' & sleep 0.1; exit 0',
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        process.wait(timeout=2)

        self.assertEqual(process.returncode, 0)
        self.assertTrue(_campaign_group_exists(process.pid))

        with (
            patch("engine.fuzzing.campaign._INTERRUPT_GRACE_SECONDS", 0.2),
            patch("engine.fuzzing.campaign._TERMINATE_GRACE_SECONDS", 0.5),
        ):
            exit_code = _stop_campaign_group(process)

        self.assertEqual(exit_code, 0)
        self.assertFalse(_campaign_group_exists(process.pid))

    def test_campaign_watchdog_stops_overlong_process(self):
        self.config = replace(
            self.config,
            limits=replace(self.config.limits, duration_seconds=1),
        )

        with patch(
            "engine.fuzzing.campaign._EXTERNAL_TIMEOUT_GRACE_SECONDS",
            0.1,
        ):
            result = self.run_fake_campaign("sleep 5\n")

        self.assertEqual(result.status, CampaignState.FAILED)
        self.assertIn("watchdog", result.message.lower())
        self.assertIsNotNone(result.exit_code)

    def test_keyboard_interrupt_records_interrupted_state(self):
        repository = self.base / "repository"
        repository.mkdir(exist_ok=True)
        source_dir = self.base / "source"
        source_dir.mkdir(exist_ok=True)

        config = replace(
            self.config,
            target=replace(self.config.target, source_dir=source_dir),
        )

        process = SimpleNamespace(
            pid=12345,
            stdout=io.BytesIO(),
            stderr=io.BytesIO(),
            wait=Mock(side_effect=KeyboardInterrupt),
            poll=Mock(return_value=-2),
        )

        with (
            patch(
                "engine.fuzzing.campaign.subprocess.Popen",
                return_value=process,
            ),
            patch(
                "engine.fuzzing.campaign._stop_campaign_group",
                return_value=-2,
            ) as stop,
        ):
            result = _execute_campaign(
                config,
                repository,
                self.fuzzer,
                {"validation": "passed"},
            )

        self.assertEqual(result.status, CampaignState.INTERRUPTED)
        self.assertEqual(result.exit_code, -2)
        self.assertIn("interrupted", result.message.lower())
        stop.assert_called_once()

    def test_builds_fixed_single_worker_command(self):
        output = self.output_parent / "campaign-001"

        command = build_campaign_command(
            self.config, self.fuzzer, output
        )

        self.assertEqual(command[0], str(self.fuzzer))
        self.assertEqual(command[1:3], ["-i", str(self.seed_dir)])
        self.assertEqual(command[3:5], ["-o", str(output)])
        self.assertIn("-V", command)
        self.assertIn("300", command)
        self.assertIn("-m", command)
        self.assertIn("512", command)
        self.assertIn("-t", command)
        self.assertIn("1000", command)
        self.assertIn("-G", command)
        self.assertEqual(
            command[command.index("-G") + 1],
            "1048576",
        )
        self.assertEqual(self.config.limits.max_input_bytes, 8388608)
        self.assertEqual(command[-2:], [str(self.binary), "@@"])
        self.assertFalse(output.exists())

    def test_rejects_unsupported_target(self):
        config = replace(
            self.config,
            target=replace(self.config.target, name="other"),
        )
        with self.assertRaises(CampaignError):
            build_campaign_command(
                config, self.fuzzer, self.output_parent / "run"
            )

    def test_rejects_non_executable_fuzzer(self):
        self.fuzzer.chmod(0o644)
        with self.assertRaises(CampaignError):
            build_campaign_command(
                self.config, self.fuzzer, self.output_parent / "run"
            )

    def test_rejects_relative_output_path(self):
        with self.assertRaises(CampaignError):
            build_campaign_command(self.config, self.fuzzer, "relative/run")

    def test_rejects_output_outside_configured_parent(self):
        outside = self.base / "outside" / "run"
        with self.assertRaises(CampaignError):
            build_campaign_command(self.config, self.fuzzer, outside)

    def test_rejects_existing_output_directory(self):
        existing = self.output_parent / "existing"
        existing.mkdir()
        with self.assertRaises(CampaignError):
            build_campaign_command(self.config, self.fuzzer, existing)


if __name__ == "__main__":
    unittest.main()
