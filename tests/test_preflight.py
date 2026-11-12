"""Tests for read-only adapter preflight validation."""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from engine.adapters.config import (
    AdapterConfig,
    FuzzerConfig,
    ResourceLimits,
    TargetConfig,
)
from engine.fuzzing.preflight import validate_adapter


class PreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)

        self.root = self.base / "repository"
        self.root.mkdir()

        self.work = self.base / "workspace"
        self.work.mkdir()

        self.source_dir = self.work / "libpng"
        self.source_dir.mkdir()
        (self.source_dir / "png.h").write_text(
            '#define PNG_LIBPNG_VER_STRING "1.6.59"\n',
            encoding="utf-8",
        )

        harness_dir = self.root / "targets" / "libpng"
        harness_dir.mkdir(parents=True)
        self.harness_source = harness_dir / "png_read_harness.c"
        self.write_harness_limit(8 * 1024 * 1024)

        build_dir = self.work / "build"
        build_dir.mkdir()
        self.harness_binary = build_dir / "kekkai_png_harness"
        self.harness_binary.write_text(
            "#!/bin/sh\nexit 0\n",
            encoding="utf-8",
        )
        self.harness_binary.chmod(0o755)

        self.output_parent = self.work / "fuzzing" / "libpng"
        self.output_parent.mkdir(parents=True)

        self.seed_dir = self.output_parent / "seeds"
        self.seed_dir.mkdir()
        (self.seed_dir / "valid.png").write_bytes(b"valid-seed")
        (self.seed_dir / "malformed.png").write_bytes(b"bad")

        bin_dir = self.work / "bin"
        bin_dir.mkdir()
        self.fuzzer = bin_dir / "afl-fuzz"
        self.fuzzer.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' 'afl-fuzz++4.33c'\n",
            encoding="utf-8",
        )
        self.fuzzer.chmod(0o755)

        self.config = AdapterConfig(
            schema_version=1,
            target=TargetConfig(
                name="libpng",
                version="1.6.59",
                source_dir=self.source_dir,
                harness_source=self.harness_source,
                harness_binary=self.harness_binary,
                seed_dir=self.seed_dir,
                output_parent=self.output_parent,
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
            config_path=self.root / "targets" / "libpng" / "adapter.toml",
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_harness_limit(self, value: int) -> None:
        self.harness_source.write_text(
            f"#define MAX_INPUT_BYTES ({value}U)\n",
            encoding="utf-8",
        )

    def run_preflight(
        self,
        config: AdapterConfig | None = None,
        *,
        fuzzer_available: bool = True,
    ):
        resolved = str(self.fuzzer) if fuzzer_available else None

        with patch(
            "engine.fuzzing.preflight.shutil.which",
            return_value=resolved,
        ):
            return validate_adapter(config or self.config, self.root)

    def check(self, report, name: str):
        return next(item for item in report.checks if item.name == name)

    def test_valid_configuration_passes_required_checks(self) -> None:
        before = sorted(path.name for path in self.output_parent.iterdir())

        report = self.run_preflight()

        self.assertTrue(report.passed, report.format())
        self.assertEqual(self.check(report, "target_version").status, "passed")
        self.assertEqual(self.check(report, "harness_input_limit").status, "passed")
        self.assertEqual(self.check(report, "seed_corpus").status, "passed")
        self.assertEqual(self.check(report, "fuzzer_version").status, "passed")
        self.assertEqual(
            self.check(report, "harness_smoke_validation").status,
            "not_run",
        )
        self.assertEqual(
            self.check(report, "coverage_diversity").status,
            "not_run",
        )

        # Preflight must not create campaign output.
        after = sorted(path.name for path in self.output_parent.iterdir())
        self.assertEqual(before, after)

    def test_rejects_wrong_source_version(self) -> None:
        (self.source_dir / "png.h").write_text(
            '#define PNG_LIBPNG_VER_STRING "1.6.58"\n',
            encoding="utf-8",
        )

        report = self.run_preflight()

        self.assertFalse(report.passed)
        self.assertEqual(self.check(report, "target_version").status, "failed")

    def test_rejects_harness_input_limit_mismatch(self) -> None:
        self.write_harness_limit(4 * 1024 * 1024)

        report = self.run_preflight()

        self.assertFalse(report.passed)
        self.assertEqual(
            self.check(report, "harness_input_limit").status,
            "failed",
        )

    def test_rejects_oversized_seed(self) -> None:
        self.write_harness_limit(16)
        (self.seed_dir / "oversized.bin").write_bytes(b"x" * 17)

        limits = replace(self.config.limits, max_input_bytes=16)
        config = replace(self.config, limits=limits)

        report = self.run_preflight(config)

        self.assertFalse(report.passed)
        self.assertEqual(self.check(report, "seed_corpus").status, "failed")

    def test_rejects_output_parent_inside_repository(self) -> None:
        unsafe_output = self.root / "campaign-output"
        unsafe_output.mkdir()
        target = replace(self.config.target, output_parent=unsafe_output)
        config = replace(self.config, target=target)

        report = self.run_preflight(config)

        self.assertFalse(report.passed)
        self.assertEqual(self.check(report, "output_parent").status, "failed")

    def test_rejects_output_parent_overlapping_target_source(self) -> None:
        target = replace(
            self.config.target,
            output_parent=self.source_dir,
        )
        config = replace(self.config, target=target)

        report = self.run_preflight(config)

        self.assertFalse(report.passed)
        self.assertEqual(self.check(report, "output_parent").status, "failed")

    def test_rejects_non_executable_harness_binary(self) -> None:
        self.harness_binary.chmod(0o644)

        report = self.run_preflight()

        self.assertFalse(report.passed)
        self.assertEqual(self.check(report, "harness_binary").status, "failed")

    def test_rejects_missing_fuzzer(self) -> None:
        report = self.run_preflight(fuzzer_available=False)

        self.assertFalse(report.passed)
        self.assertEqual(
            self.check(report, "fuzzer_executable").status,
            "failed",
        )

    def test_rejects_custom_fuzzer_command(self) -> None:
        fuzzer = replace(
            self.config.fuzzer,
            executable="afl-fuzz --version; echo unsafe",
        )
        config = replace(self.config, fuzzer=fuzzer)

        report = self.run_preflight(config)

        self.assertFalse(report.passed)
        self.assertEqual(
            self.check(report, "fuzzer_executable").status,
            "failed",
        )
        self.assertEqual(
            self.check(report, "fuzzer_version").status,
            "not_run",
        )

    def test_rejects_excessive_fuzzer_version_output(self) -> None:
        self.fuzzer.write_text(
            "#!/bin/sh\n"
            "head -c 20000 /dev/zero\n",
            encoding="utf-8",
        )
        self.fuzzer.chmod(0o755)

        report = self.run_preflight()

        self.assertFalse(report.passed)
        check = self.check(report, "fuzzer_version")
        self.assertEqual(check.status, "failed")
        self.assertIn("bounded output limit", check.message)

    def test_rejects_wrong_fuzzer_version(self) -> None:
        fuzzer = replace(
            self.config.fuzzer,
            expected_version="4.32c",
        )
        config = replace(self.config, fuzzer=fuzzer)

        report = self.run_preflight(config)

        self.assertFalse(report.passed)
        self.assertEqual(self.check(report, "fuzzer_version").status, "failed")

    def test_rejects_corpus_with_only_empty_seed_files(self) -> None:
        for seed in self.seed_dir.iterdir():
            seed.write_bytes(b"")

        report = self.run_preflight()

        self.assertFalse(report.passed)
        self.assertEqual(self.check(report, "seed_corpus").status, "failed")

    def test_allows_empty_seed_when_nonempty_seed_exists(self) -> None:
        (self.seed_dir / "empty.png").write_bytes(b"")

        report = self.run_preflight()

        self.assertTrue(report.passed, report.format())
        self.assertEqual(self.check(report, "seed_corpus").status, "passed")

    def test_rejects_missing_seed_files(self) -> None:
        for seed in self.seed_dir.iterdir():
            seed.unlink()

        report = self.run_preflight()

        self.assertFalse(report.passed)
        self.assertEqual(self.check(report, "seed_corpus").status, "failed")

    def test_rejects_symlink_seed(self) -> None:
        outside_seed = self.work / "outside-seed"
        outside_seed.write_bytes(b"outside")
        (self.seed_dir / "linked.png").symlink_to(outside_seed)

        report = self.run_preflight()

        self.assertFalse(report.passed)
        self.assertEqual(self.check(report, "seed_corpus").status, "failed")

    def test_rejects_seed_directory_entry_limit(self) -> None:
        (self.seed_dir / "extra.png").write_bytes(b"extra")

        with patch(
            "engine.fuzzing.preflight._MAX_SEED_ENTRIES",
            2,
        ):
            report = self.run_preflight()

        self.assertFalse(report.passed)
        self.assertIn(
            "entry inspection limit",
            self.check(report, "seed_corpus").message,
        )

    def test_rejects_total_seed_corpus_size_limit(self) -> None:
        with patch(
            "engine.fuzzing.preflight._MAX_SEED_TOTAL_BYTES",
            8,
        ):
            report = self.run_preflight()

        self.assertFalse(report.passed)
        self.assertIn(
            "total inspection limit",
            self.check(report, "seed_corpus").message,
        )

    def test_rejects_unsupported_target(self) -> None:
        target = replace(self.config.target, name="unknown-target")
        config = replace(self.config, target=target)

        report = self.run_preflight(config)

        self.assertFalse(report.passed)
        self.assertEqual(
            self.check(report, "supported_target").status,
            "failed",
        )


if __name__ == "__main__":
    unittest.main()
