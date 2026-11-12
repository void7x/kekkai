"""Tests for the fixed libpng build command planner."""

import hashlib
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from engine.adapters.config import (
    AdapterConfig,
    BuildConfig,
    FuzzerConfig,
    ResourceLimits,
    TargetConfig,
)
from engine.build.libpng import BuildError, build_command_plan


class LibpngBuildPlanTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)

        self.root = self.base / "repository"
        self.harness_dir = self.root / "targets" / "libpng"
        self.harness_dir.mkdir(parents=True)

        self.source = self.base / "work" / "source"
        self.source.mkdir(parents=True)
        (self.source / "png.h").write_text(
            '#define PNG_LIBPNG_VER_STRING "1.6.59"\n'
        )

        self.harness = self.harness_dir / "png_read_harness.c"
        self.harness.write_text("/* test harness */\n")

        self.work = self.base / "work"
        self.build_parent = self.work / "builds"
        self.build_parent.mkdir()
        self.build_dir = self.build_parent / "clean"

        self.output = self.work / "fuzzing"
        self.output.mkdir()

        self.tools = self.base / "tools"
        self.tools.mkdir()
        self.tool_paths = {}
        for name in ("cmake", "ninja", "afl-clang-fast", "gawk"):
            executable = self.tools / name
            executable.write_text("#!/bin/sh\nexit 0\n")
            executable.chmod(0o755)
            self.tool_paths[name] = executable

        self.zlib_include = self.base / "zlib" / "include"
        self.zlib_include.mkdir(parents=True)
        (self.zlib_include / "zlib.h").write_text(
            '#define ZLIB_VERSION "1.3.1"\n'
        )

        self.zlib_library = self.base / "zlib" / "libz.so"
        self.zlib_library.write_bytes(b"fake zlib library")

        self.config = AdapterConfig(
            schema_version=2,
            target=TargetConfig(
                name="libpng",
                version="1.6.59",
                source_dir=self.source,
                harness_source=self.harness,
                harness_binary=self.build_dir / "kekkai_png_harness",
                seed_dir=self.base / "seeds",
                output_parent=self.output,
            ),
            fuzzer=FuzzerConfig("afl-fuzz", "4.33c"),
            limits=ResourceLimits(300, 512, 1000, 8388608),
            config_path=self.root / "targets/libpng/adapter.toml",
            build=BuildConfig(
                profile="libpng-afl-ubsan",
                build_dir=self.build_dir,
                jobs=2,
                timeout_seconds=900,
                memory_mib=4096,
                log_limit_bytes=16777216,
            ),
        )

        self.patches = patch.multiple(
            "engine.build.libpng",
            _CMAKE=self.tool_paths["cmake"],
            _NINJA=self.tool_paths["ninja"],
            _COMPILER=self.tool_paths["afl-clang-fast"],
            _AWK=self.tool_paths["gawk"],
            _ZLIB_INCLUDE=self.zlib_include,
            _ZLIB_LIBRARY=self.zlib_library,
            _HARNESS_SHA256=hashlib.sha256(
                self.harness.read_bytes()
            ).hexdigest(),
        )
        self.patches.start()

    def tearDown(self):
        self.patches.stop()
        self.temp.cleanup()

    def test_build_plan_contains_only_fixed_steps(self):
        plan = build_command_plan(self.config, self.root)

        self.assertEqual(plan.build_dir, self.build_dir)
        self.assertEqual(
            [step.name for step in plan.steps],
            ["configure", "library", "harness"],
        )

        configure, library, harness = [
            list(step.command) for step in plan.steps
        ]

        self.assertEqual(configure[0], str(self.tool_paths["cmake"]))
        self.assertIn("-G", configure)
        self.assertIn("Ninja", configure)
        self.assertIn(
            "-DCMAKE_BUILD_TYPE=RelWithDebInfo", configure
        )
        self.assertIn(
            "-DCMAKE_C_COMPILER=" + str(self.tool_paths["afl-clang-fast"]),
            configure,
        )
        self.assertIn("-DPNG_STATIC=ON", configure)
        self.assertIn("-DPNG_SHARED=OFF", configure)

        self.assertEqual(library[0], str(self.tool_paths["ninja"]))
        self.assertIn("png_static", library)
        self.assertIn("-j", library)
        self.assertIn("2", library)

        self.assertEqual(harness[0], str(self.tool_paths["afl-clang-fast"]))
        self.assertIn(str(self.source), harness)
        self.assertIn(str(self.build_dir / "libpng16.a"), harness)
        self.assertIn(str(self.zlib_library), harness)
        self.assertIn("-lm", harness)
        self.assertFalse(self.build_dir.exists())

        self.assertEqual(
            dict(plan.environment)["AFL_USE_UBSAN"], "1"
        )

    def test_rejects_wrong_source_version(self):
        (self.source / "png.h").write_text(
            '#define PNG_LIBPNG_VER_STRING "1.6.58"\n'
        )
        with self.assertRaisesRegex(BuildError, "Source version mismatch"):
            build_command_plan(self.config, self.root)

    def test_rejects_modified_harness(self):
        self.harness.write_text("/* changed harness */\n")
        with self.assertRaisesRegex(BuildError, "source hash"):
            build_command_plan(self.config, self.root)

    def test_rejects_wrong_profile(self):
        config = replace(
            self.config,
            build=replace(self.config.build, profile="arbitrary"),
        )
        with self.assertRaisesRegex(BuildError, "Unsupported build profile"):
            build_command_plan(config, self.root)

    def test_rejects_existing_build_directory(self):
        self.build_dir.mkdir()
        with self.assertRaisesRegex(BuildError, "already exists"):
            build_command_plan(self.config, self.root)

    def test_rejects_zlib_version_mismatch(self):
        (self.zlib_include / "zlib.h").write_text(
            '#define ZLIB_VERSION "1.2.13"\n'
        )
        with self.assertRaisesRegex(BuildError, "requires system zlib"):
            build_command_plan(self.config, self.root)

    def test_rejects_tool_symlink_outside_pinned_directory(self):
        escape = self.tools / "afl-clang-fast"
        escape.unlink()
        escape.symlink_to("/bin/true")

        with self.assertRaisesRegex(BuildError, "missing or unsafe"):
            build_command_plan(self.config, self.root)

    def test_rejects_build_directory_inside_repository(self):
        unsafe_dir = self.root / "build"
        config = replace(
            self.config,
            target=replace(
                self.config.target,
                harness_binary=unsafe_dir / "kekkai_png_harness",
            ),
            build=replace(self.config.build, build_dir=unsafe_dir),
        )
        with self.assertRaisesRegex(BuildError, "outside the repository"):
            build_command_plan(config, self.root)


if __name__ == "__main__":
    unittest.main()
