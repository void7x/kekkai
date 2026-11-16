"""Tests for non-destructive failed-build recovery."""
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import datetime as RealDateTime, timezone
from pathlib import Path
from unittest.mock import patch

from engine.adapters.config import (
    AdapterConfig,
    BuildConfig,
    FuzzerConfig,
    ResourceLimits,
    TargetConfig,
)
from engine.build.libpng import BuildError
from engine.build.runner import recover_failed_build


class FailedBuildRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "repository"
        self.root.mkdir()
        self.work = Path(self.temp.name) / "work"
        self.build_dir = self.work / "builds" / "libpng-build"
        self.build_dir.mkdir(parents=True)
        self.source = Path(self.temp.name) / "source"
        self.source.mkdir()
        self.harness = self.root / "harness.c"
        self.harness.write_text("/* harness */\n", encoding="utf-8")
        self.build_dir_value = str(self.build_dir.resolve())
        self.config = AdapterConfig(
            schema_version=3,
            target=TargetConfig(
                name="libpng",
                version="1.6.59",
                source_dir=self.source,
                harness_source=self.harness,
                harness_binary=self.build_dir / "kekkai_png_harness",
                seed_dir=self.work / "seeds",
                output_parent=self.work / "output",
            ),
            fuzzer=FuzzerConfig("afl-fuzz", "4.33c"),
            limits=ResourceLimits(300, 512, 1000, 8388608),
            config_path=self.root / "adapter.toml",
            build=BuildConfig(
                profile="libpng-afl-ubsan",
                build_dir=self.build_dir,
                jobs=2,
                timeout_seconds=900,
                memory_mib=4096,
                log_limit_bytes=16777216,
            ),
        )
        self.metadata = {
            "schema_version": 2,
            "status": "failed",
            "target": "libpng",
            "target_version": "1.6.59",
            "profile": "libpng-afl-ubsan",
            "build_dir": self.build_dir_value,
            "started_at": "2026-11-14T10:00:00Z",
            "ended_at": "2026-11-14T10:01:00Z",
            "steps": [{"name": "configure", "status": "failed"}],
            "artifacts": {},
            "message": "test failure",
        }
        (self.build_dir / "stdout.log").write_text("partial compiler output\n")
        (self.build_dir / "stderr.log").write_text("compiler error\n")
        self.write_metadata()

    def tearDown(self):
        self.temp.cleanup()

    def write_metadata(self):
        (self.build_dir / "build.json").write_text(
            json.dumps(self.metadata, sort_keys=True), encoding="utf-8"
        )

    def test_archives_failed_build_and_preserves_logs(self):
        raw_metadata = (self.build_dir / "build.json").read_bytes()
        archive = recover_failed_build(self.config, self.root)
        self.assertFalse(self.build_dir.exists())
        self.assertIn("failed-builds", archive.parts)
        self.assertEqual((archive / "stdout.log").read_text(), "partial compiler output\n")
        self.assertEqual((archive / "stderr.log").read_text(), "compiler error\n")
        self.assertTrue((archive / "build.json").is_file())
        manifest = json.loads((archive / "recovery.json").read_text())
        self.assertEqual(manifest["original_status"], "failed")
        self.assertEqual(manifest["build_metadata_sha256"], hashlib.sha256(raw_metadata).hexdigest())

    def test_archives_interrupted_build(self):
        self.metadata["status"] = "interrupted"
        self.write_metadata()
        archive = recover_failed_build(self.config, self.root)
        manifest = json.loads((archive / "recovery.json").read_text())
        self.assertEqual(manifest["original_status"], "interrupted")

    def test_refuses_running_or_completed_builds(self):
        for status in ("running", "completed"):
            with self.subTest(status=status):
                self.metadata["status"] = status
                self.write_metadata()
                with self.assertRaisesRegex(BuildError, "Only terminal failed or interrupted"):
                    recover_failed_build(self.config, self.root)
                self.assertTrue(self.build_dir.is_dir())

    def test_refuses_metadata_for_another_build_directory(self):
        self.metadata["build_dir"] = str(self.work / "other-build")
        self.write_metadata()
        with self.assertRaisesRegex(BuildError, "does not match"):
            recover_failed_build(self.config, self.root)
        self.assertTrue(self.build_dir.is_dir())

    def test_refuses_non_string_status_metadata(self):
        self.metadata["status"] = ["failed"]
        self.write_metadata()
        with self.assertRaisesRegex(BuildError, "terminal failed or interrupted"):
            recover_failed_build(self.config, self.root)
        self.assertTrue(self.build_dir.is_dir())

    def test_refuses_existing_recovery_manifest_without_overwriting_it(self):
        manifest = self.build_dir / "recovery.json"
        manifest.write_text("original evidence\n", encoding="utf-8")
        with self.assertRaisesRegex(BuildError, "already contains recovery.json"):
            recover_failed_build(self.config, self.root)
        self.assertTrue(self.build_dir.is_dir())
        self.assertEqual(manifest.read_text(encoding="utf-8"), "original evidence\n")

    def test_refuses_manifest_created_during_publication_without_overwriting_it(self):
        real_link = __import__("os").link
        racing_content = "created by competing writer\n"

        def racing_link(source, destination, *, follow_symlinks=True):
            Path(destination).write_text(racing_content, encoding="utf-8")
            return real_link(source, destination, follow_symlinks=follow_symlinks)

        with patch("engine.build.runner.os.link", side_effect=racing_link):
            with self.assertRaisesRegex(
                BuildError, "recovery manifest could not be completed"
            ):
                recover_failed_build(self.config, self.root)

        archive_root = self.build_dir.parent / "failed-builds"
        archives = list(archive_root.iterdir())
        self.assertEqual(len(archives), 1)

        archived = archives[0]
        manifest = archived / "recovery.json"

        self.assertTrue((archived / "build.json").is_file())
        self.assertEqual(manifest.read_text(encoding="utf-8"), racing_content)
        self.assertEqual(list(archived.glob(".recovery-*.tmp")), [])
        self.assertFalse(self.build_dir.exists())

    def test_retries_archive_name_collision_without_overwriting_existing_archive(self):
        class FixedDateTime:
            @staticmethod
            def now(tz=None):
                return RealDateTime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)

        archive_root = self.build_dir.parent / "failed-builds"
        archive_root.mkdir(mode=0o700)
        collision = archive_root / f"{self.build_dir.name}-20261114T120000Z-{'a' * 12}"
        collision.mkdir(mode=0o700)
        sentinel = collision / "keep.txt"
        sentinel.write_text("prior archive\n", encoding="utf-8")
        identifiers = iter(("a" * 32, "b" * 32, "c" * 32))

        class FixedUUID:
            def __init__(self, value):
                self.hex = value

        with (
            patch("engine.build.runner.datetime", FixedDateTime),
            patch(
                "engine.build.runner.uuid.uuid4",
                side_effect=lambda: FixedUUID(next(identifiers)),
            ),
        ):
            archived = recover_failed_build(self.config, self.root)

        self.assertTrue(sentinel.is_file())
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "prior archive\n")
        self.assertTrue((archived / "build.json").is_file())
        self.assertIn("-bbbbbbbbbbbb", archived.name)
        self.assertFalse(self.build_dir.exists())

    def test_refuses_archive_name_collisions_when_no_unique_name_is_available(self):
        class FixedDateTime:
            @staticmethod
            def now(tz=None):
                return RealDateTime(2026, 11, 14, 12, 0, 0, tzinfo=timezone.utc)

        archive_root = self.build_dir.parent / "failed-builds"
        archive_root.mkdir(mode=0o700)
        collision = archive_root / f"{self.build_dir.name}-20261114T120000Z-{'a' * 12}"
        collision.mkdir(mode=0o700)
        sentinel = collision / "keep.txt"
        sentinel.write_text("prior archive\n", encoding="utf-8")

        class FixedUUID:
            hex = "a" * 32

        with (
            patch("engine.build.runner.datetime", FixedDateTime),
            patch("engine.build.runner.uuid.uuid4", return_value=FixedUUID()),
        ):
            with self.assertRaisesRegex(BuildError, "unique failed-build archive"):
                recover_failed_build(self.config, self.root)

        self.assertTrue(self.build_dir.is_dir())
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "prior archive\n")

    def test_refuses_symlinked_metadata(self):
        metadata = self.build_dir / "build.json"
        real_metadata = self.build_dir / "build-real.json"
        metadata.rename(real_metadata)
        metadata.symlink_to(real_metadata)
        with self.assertRaisesRegex(BuildError, "regular non-symlink"):
            recover_failed_build(self.config, self.root)
        self.assertTrue(self.build_dir.is_dir())

    def test_refuses_symlinked_build_directory(self):
        real = self.build_dir.with_name("real-build")
        self.build_dir.rename(real)
        self.build_dir.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(BuildError, "symlink"):
            recover_failed_build(self.config, self.root)
        self.assertTrue(real.is_dir())


if __name__ == "__main__":
    unittest.main()
