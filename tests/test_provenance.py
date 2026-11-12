"""Tests for pinned libpng build provenance verification."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from engine.adapters.config import (
    AdapterConfig,
    FuzzerConfig,
    ResourceLimits,
    TargetConfig,
)
from engine.fuzzing.provenance import verify_build_provenance


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)

        self.root = self.base / "repository"
        self.target_dir = self.root / "targets" / "libpng"
        self.build_dir = self.base / "build"
        self.output_dir = self.base / "output"
        self.seed_dir = self.base / "seeds"

        for directory in (
            self.target_dir, self.build_dir,
            self.output_dir, self.seed_dir,
        ):
            directory.mkdir(parents=True)

        self.source = self.target_dir / "png_read_harness.c"
        self.source.write_text("/* pinned harness */\n")

        self.binary = self.build_dir / "harness"
        self.binary.write_text("#!/bin/sh\nexit 0\n")
        self.binary.chmod(0o755)

        self.archive = self.build_dir / "libpng16.a"
        self.archive.write_bytes(b"test static archive")

        self.compiler = self.build_dir / "afl-clang-fast"
        self.compiler.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' 'Ubuntu clang version test'\n"
        )
        self.compiler.chmod(0o755)

        self.afl = self.build_dir / "afl-fuzz"
        self.afl.write_text(
            "#!/bin/sh\n"
            "printf '%s\\n' 'afl-fuzz++4.33c'\n"
        )
        self.afl.chmod(0o755)

        self.other_compiler = self.build_dir / "other-compiler"
        self.other_compiler.write_text("#!/bin/sh\nexit 0\n")
        self.other_compiler.chmod(0o755)

        cache = {
            "CMAKE_BUILD_TYPE": "RelWithDebInfo",
            "CMAKE_C_COMPILER": str(self.compiler),
            "CMAKE_POSITION_INDEPENDENT_CODE": "ON",
            "PNG_STATIC": "ON",
            "PNG_SHARED": "OFF",
            "PNG_TESTS": "OFF",
            "PNG_TOOLS": "OFF",
            "PNG_FRAMEWORK": "OFF",
        }

        (self.build_dir / "CMakeCache.txt").write_text(
            "".join(
                f"{key}:STRING={value}\n"
                for key, value in cache.items()
            )
        )

        entries = [
            {
                "directory": str(self.build_dir),
                "file": f"source-{index}.c",
                "arguments": [str(self.compiler), "-c", f"source-{index}.c"],
            }
            for index in range(17)
        ]

        (self.build_dir / "compile_commands.json").write_text(
            json.dumps(entries)
        )

        evidence = self.root / "docs" / "tasks"
        evidence.mkdir(parents=True)
        self.evidence = evidence / "LIBPNG_AFL_BUILD_VERIFICATION.md"
        self.evidence.write_text(
            "1,987 locations instrumented\n"
            "AFL++ reported UBSAN mode\n"
            "UBSAN trap mode\n"
        )

        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()

        manifest = f'''schema_version = 1
target_name = "libpng"
target_version = "1.6.59"
harness_source = "targets/libpng/png_read_harness.c"
harness_source_sha256 = "{digest(self.source)}"
harness_binary_sha256 = "{digest(self.binary)}"
library_archive = "libpng16.a"
library_archive_sha256 = "{digest(self.archive)}"
cmake_cache = "CMakeCache.txt"
compile_database = "compile_commands.json"
expected_translation_units = 17
compiler_path = "{self.compiler}"
compiler_version = "Ubuntu clang version test"
cmake_build_type = "RelWithDebInfo"
position_independent_code = true
png_static = true
png_shared = false
png_tests = false
png_tools = false
png_framework = false
aflpp_version = "4.33c"
afl_instrumented_locations = 1987
ubsan_mode = "trap"
evidence_document = "docs/tasks/LIBPNG_AFL_BUILD_VERIFICATION.md"
'''

        (self.target_dir / "build-provenance.toml").write_text(manifest)

        self.config = AdapterConfig(
            schema_version=1,
            target=TargetConfig(
                name="libpng",
                version="1.6.59",
                source_dir=self.target_dir,
                harness_source=self.source,
                harness_binary=self.binary,
                seed_dir=self.seed_dir,
                output_parent=self.output_dir,
            ),
            fuzzer=FuzzerConfig("afl-fuzz", "4.33c"),
            limits=ResourceLimits(300, 512, 1000, 8388608),
            config_path=self.target_dir / "adapter.toml",
        )

    def tearDown(self):
        self.temp.cleanup()

    def verify(self):
        with patch(
            "engine.fuzzing.provenance.shutil.which",
            return_value=str(self.afl),
        ):
            return verify_build_provenance(self.config, self.root)

    def test_accepts_matching_build_artifacts(self):
        report = self.verify()
        self.assertTrue(report.passed, report.format())

    def test_rejects_modified_harness_binary(self):
        self.binary.write_bytes(b"changed binary")

        report = self.verify()

        self.assertFalse(report.passed)
        check = next(
            item for item in report.checks
            if item.name == "harness_binary"
        )
        self.assertEqual(check.status, "failed")

    def test_rejects_unexpected_compile_database_compiler(self):
        database_path = self.build_dir / "compile_commands.json"
        entries = json.loads(database_path.read_text())
        entries[-1]["arguments"][0] = str(self.other_compiler)
        database_path.write_text(json.dumps(entries))

        report = self.verify()

        self.assertFalse(report.passed)
        check = next(
            item for item in report.checks
            if item.name == "compile_database_compiler"
        )
        self.assertEqual(check.status, "failed")


if __name__ == "__main__":
    unittest.main()
