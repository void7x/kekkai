"""Tests for strict KEKKAI adapter TOML configuration loading."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from engine.adapters.config import (
    AdapterConfigError,
    load_adapter_config,
)


VALID_TOML = """\
schema_version = 2

[target]
name = "libpng"
version = "1.6.59"
source_dir = "../kekkai-work/downloads/libpng-1.6.59"
harness_source = "targets/libpng/png_read_harness.c"
harness_binary = "../kekkai-work/builds/libpng-1.6.59-afl-ubsan-phase2-clean/kekkai_png_harness"
seed_dir = "../kekkai-work/seeds"
output_parent = "../kekkai-work/output"

[fuzzer]
executable = "afl-fuzz"
expected_version = "4.33c"

[limits]
duration_seconds = 300
memory_mib = 512
timeout_ms = 1000
max_input_bytes = 8388608

[build]
profile = "libpng-afl-ubsan"
build_dir = "../kekkai-work/builds/libpng-1.6.59-afl-ubsan-phase2-clean"
jobs = 2
timeout_seconds = 900
memory_mib = 4096
log_limit_bytes = 16777216
"""


class AdapterConfigTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)
        self.config_path = self.root / "adapter.toml"
        self.config_path.write_text(VALID_TOML, encoding="utf-8")

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def load(self, content: str | None = None):
        if content is not None:
            self.config_path.write_text(content, encoding="utf-8")
        return load_adapter_config(self.config_path, self.root)

    def test_loads_valid_configuration(self) -> None:
        config = self.load()

        self.assertEqual(config.schema_version, 2)
        self.assertEqual(config.build.profile, "libpng-afl-ubsan")
        self.assertEqual(config.build.jobs, 2)
        self.assertEqual(config.build.timeout_seconds, 900)
        self.assertEqual(config.build.memory_mib, 4096)
        self.assertEqual(config.build.log_limit_bytes, 16777216)
        self.assertEqual(config.target.name, "libpng")
        self.assertEqual(config.target.version, "1.6.59")
        self.assertEqual(
            config.target.harness_source,
            (self.root / "targets/libpng/png_read_harness.c").resolve(),
        )
        self.assertEqual(config.fuzzer.executable, "afl-fuzz")
        self.assertEqual(config.fuzzer.expected_version, "4.33c")
        self.assertEqual(config.limits.duration_seconds, 300)
        self.assertEqual(config.limits.memory_mib, 512)
        self.assertEqual(config.limits.timeout_ms, 1000)
        self.assertEqual(config.limits.max_input_bytes, 8388608)

    def test_resolves_relative_paths_against_project_root(self) -> None:
        config = self.load()

        self.assertEqual(
            config.target.source_dir,
            (self.root / "../kekkai-work/downloads/libpng-1.6.59").resolve(),
        )
        self.assertEqual(
            config.target.output_parent,
            (self.root / "../kekkai-work/output").resolve(),
        )

    def test_rejects_unsupported_schema_version(self) -> None:
        content = VALID_TOML.replace(
            "schema_version = 2", "schema_version = 3"
        )
        with self.assertRaisesRegex(AdapterConfigError, "schema_version"):
            self.load(content)

    def test_rejects_boolean_schema_version(self) -> None:
        content = VALID_TOML.replace(
            "schema_version = 2", "schema_version = true"
        )
        with self.assertRaisesRegex(AdapterConfigError, "schema_version"):
            self.load(content)

    def test_rejects_unknown_root_key(self) -> None:
        content = VALID_TOML.replace(
            "[target]", 'unexpected = "value"\n\n[target]'
        )
        with self.assertRaisesRegex(AdapterConfigError, "unknown keys"):
            self.load(content)

    def test_rejects_unknown_target_key(self) -> None:
        content = VALID_TOML.replace(
            '[fuzzer]', 'unexpected = "value"\n\n[fuzzer]'
        )
        with self.assertRaisesRegex(AdapterConfigError, "unknown keys"):
            self.load(content)

    def test_rejects_missing_required_key(self) -> None:
        content = VALID_TOML.replace(
            'version = "1.6.59"\n', ""
        )
        with self.assertRaisesRegex(AdapterConfigError, "missing required"):
            self.load(content)

    def test_rejects_boolean_as_integer(self) -> None:
        content = VALID_TOML.replace(
            "timeout_ms = 1000", "timeout_ms = true"
        )
        with self.assertRaisesRegex(AdapterConfigError, "must be an integer"):
            self.load(content)

    def test_rejects_out_of_range_timeout(self) -> None:
        content = VALID_TOML.replace(
            "timeout_ms = 1000", "timeout_ms = 4"
        )
        with self.assertRaisesRegex(AdapterConfigError, "between 5 and 60000"):
            self.load(content)

    def test_rejects_out_of_range_duration(self) -> None:
        content = VALID_TOML.replace(
            "duration_seconds = 300", "duration_seconds = 0"
        )
        with self.assertRaisesRegex(AdapterConfigError, "duration_seconds"):
            self.load(content)

    def test_rejects_blank_required_string(self) -> None:
        content = VALID_TOML.replace(
            'name = "libpng"', 'name = "   "'
        )
        with self.assertRaisesRegex(AdapterConfigError, "non-empty string"):
            self.load(content)

    def test_rejects_unknown_build_key(self) -> None:
        content = VALID_TOML + 'unexpected = "value"\n'
        with self.assertRaisesRegex(AdapterConfigError, "unknown keys"):
            self.load(content)

    def test_rejects_boolean_build_jobs(self) -> None:
        content = VALID_TOML.replace("jobs = 2", "jobs = true")
        with self.assertRaisesRegex(AdapterConfigError, "must be an integer"):
            self.load(content)

    def test_rejects_build_directory_inside_repository(self) -> None:
        content = VALID_TOML.replace(
            "../kekkai-work/builds/libpng-1.6.59-afl-ubsan-phase2-clean",
            "builds/inside-repository",
        )
        with self.assertRaisesRegex(AdapterConfigError, "overlap"):
            self.load(content)

    def test_rejects_malformed_toml(self) -> None:
        with self.assertRaisesRegex(AdapterConfigError, "valid TOML"):
            self.load("schema_version = [\n")

    def test_rejects_missing_config_file(self) -> None:
        with self.assertRaisesRegex(AdapterConfigError, "Cannot resolve"):
            load_adapter_config(self.root / "missing.toml", self.root)

    def test_rejects_non_directory_project_root(self) -> None:
        with self.assertRaisesRegex(AdapterConfigError, "directory"):
            load_adapter_config(self.config_path, self.config_path)


if __name__ == "__main__":
    unittest.main()
