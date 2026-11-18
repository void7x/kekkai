from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from engine.adapters.config import (
    AdapterConfig,
    BuildConfig,
    FuzzerConfig,
    ResourceLimits,
    TargetConfig,
)
from engine.evidence.afl_ingest import (
    AflIngestError,
    _mtime_to_utc,
    _parse_afl_filename,
    _parse_fuzzer_stats,
    ingest_afl_campaign,
)


TS_START = "2026-11-18T12:00:00.000000Z"
TS_END = "2026-11-18T12:05:00.000000Z"
SOURCE_ARCHIVE_SHA256 = "a" * 64
SOURCE_TREE_SHA256 = "b" * 64
CAMPAIGN_UID = "campaign-20261118T120000Z-abcdef123456"


class AflFilenameTests(unittest.TestCase):
    def test_parses_crash_filename(self):
        self.assertEqual(
            _parse_afl_filename(
                "id:000012,sig:11,src:000003,time:12345,execs:67890,op:havoc,rep:2",
                "crash",
            ),
            ("000012", 11, 12345, 67890),
        )

    def test_parses_hang_filename_without_signal(self):
        self.assertEqual(
            _parse_afl_filename("id:000013,src:000004,time:9,execs:10,op:havoc", "hang"),
            ("000013", None, 9, 10),
        )

    def test_optional_time_and_execs_are_unknown_when_absent(self):
        self.assertEqual(
            _parse_afl_filename("id:000014,sig:06", "crash"),
            ("000014", 6, None, None),
        )

    def test_rejects_missing_or_misplaced_id(self):
        for name in ("sig:11,id:000001", "README.txt", "not-an-afl-name"):
            with self.subTest(name=name), self.assertRaises(AflIngestError):
                _parse_afl_filename(name, "crash")

    def test_rejects_duplicate_known_tokens(self):
        for name in (
            "id:000001,id:000002,sig:11",
            "id:000001,sig:11,sig:06",
            "id:000001,sig:11,time:1,time:2",
            "id:000001,sig:11,execs:1,execs:2",
        ):
            with self.subTest(name=name), self.assertRaisesRegex(AflIngestError, "repeats"):
                _parse_afl_filename(name, "crash")

    def test_rejects_invalid_crash_signal_bounds(self):
        for signal in ("0", "00", "256", "999", "x"):
            with self.subTest(signal=signal), self.assertRaises(AflIngestError):
                _parse_afl_filename(f"id:000001,sig:{signal}", "crash")

    def test_rejects_missing_crash_signal_and_signal_on_hang(self):
        with self.assertRaises(AflIngestError):
            _parse_afl_filename("id:000001,time:1", "crash")
        with self.assertRaisesRegex(AflIngestError, "must not contain a sig"):
            _parse_afl_filename("id:000001,sig:11,time:1", "hang")

    def test_rejects_non_decimal_or_sqlite_overflow_discovery_values(self):
        for token in ("time:-1", "execs:1.5", "time:9223372036854775808"):
            with self.subTest(token=token), self.assertRaises(AflIngestError):
                _parse_afl_filename(f"id:000001,sig:11,{token}", "crash")

    def test_source_mtime_uses_integer_nanoseconds(self):
        seconds = 1_795_000_000
        expected = "2026-11-18T"  # Assert fractional precision independently of float conversion.
        actual = _mtime_to_utc(seconds * 1_000_000_000 + 123_456_789)
        self.assertTrue(actual.startswith(expected))
        self.assertTrue(actual.endswith(".123456Z"))


class FuzzerStatsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.worker = self.root / "default"
        self.worker.mkdir(mode=0o700)

    def tearDown(self):
        self.temp.cleanup()

    def _parse(self):
        from engine.evidence.afl_ingest import _open_directory
        descriptor = _open_directory(self.worker)
        try:
            return _parse_fuzzer_stats(self.worker, descriptor, os.fstat(descriptor).st_dev)
        finally:
            os.close(descriptor)

    def test_parses_supported_optional_statistics(self):
        (self.worker / "fuzzer_stats").write_text(
            "execs_done : 123\nsaved_crashes : 4\nsaved_hangs : 2\nexec_timeout : 1000\n",
            encoding="utf-8",
        )
        self.assertEqual(self._parse(), {
            "execs_done": 123,
            "saved_crashes": 4,
            "saved_hangs": 2,
            "exec_timeout": 1000,
        })

    def test_missing_stats_means_unknown_not_zero(self):
        self.assertEqual(self._parse(), {
            "execs_done": None,
            "saved_crashes": None,
            "saved_hangs": None,
            "exec_timeout": None,
        })

    def test_rejects_duplicate_or_malformed_statistics(self):
        (self.worker / "fuzzer_stats").write_text(
            "execs_done : 1\nexecs_done : 2\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(AflIngestError, "duplicate"):
            self._parse()
        (self.worker / "fuzzer_stats").write_text("exec_timeout : 0\n", encoding="utf-8")
        with self.assertRaisesRegex(AflIngestError, "must be positive"):
            self._parse()

    def test_rejects_symlinked_stats(self):
        other = self.root / "outside"
        other.write_text("execs_done : 1\n", encoding="utf-8")
        (self.worker / "fuzzer_stats").symlink_to(other)
        with self.assertRaises(AflIngestError):
            self._parse()


class AflIngestIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.repository = self.base / "repository"
        self.repository.mkdir()
        self.source_dir = self.base / "libpng-source"
        self.source_dir.mkdir()
        self.source_archive = self.base / "libpng.tar.xz"
        self.source_archive.write_bytes(b"pinned archive")
        self.harness_source = self.repository / "png_read_harness.c"
        self.harness_source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
        self.output_parent = self.base / "campaign-output"
        self.output_parent.mkdir(mode=0o700)
        self.seed_dir = self.base / "seeds"
        self.seed_dir.mkdir(mode=0o700)
        (self.seed_dir / "seed.png").write_bytes(b"valid seed")
        self.build_dir = self.base / "build"
        self.build_dir.mkdir(mode=0o700)
        self.harness_binary = self.build_dir / "kekkai_png_harness"
        self.harness_binary.write_bytes(b"fake harness binary")
        self.config_path = self.repository / "adapter.toml"
        self.config_path.write_text("schema_version = 4\n", encoding="utf-8")
        self.fuzzer_path = self.base / "afl-fuzz"
        self.campaign_dir = self.output_parent / CAMPAIGN_UID
        self.worker_root = self.campaign_dir / "afl-output" / "default"
        self.crash_dir = self.worker_root / "crashes"
        self.hang_dir = self.worker_root / "hangs"
        self.crash_dir.mkdir(parents=True, mode=0o700)
        self.hang_dir.mkdir(mode=0o700)
        self.worker_root.mkdir(mode=0o700)
        self.campaign_dir.mkdir(mode=0o700)
        self.evidence_root = self.base / "evidence-store"
        self.config = AdapterConfig(
            schema_version=4,
            target=TargetConfig(
                name="libpng",
                version="1.6.59",
                source_dir=self.source_dir,
                harness_source=self.harness_source,
                harness_binary=self.harness_binary,
                seed_dir=self.seed_dir,
                output_parent=self.output_parent,
                source_archive=self.source_archive,
                campaign_storage_image=self.base / "campaign.ext4",
                campaign_storage_uuid="e8657221-eb6f-41ca-b087-76912b527e4b",
            ),
            fuzzer=FuzzerConfig("afl-fuzz", "4.33c"),
            limits=ResourceLimits(300, 512, 1000, 8 * 1024 * 1024),
            config_path=self.config_path,
            build=BuildConfig(
                profile="libpng-afl-ubsan",
                build_dir=self.build_dir,
                jobs=2,
                timeout_seconds=900,
                memory_mib=4096,
                log_limit_bytes=16 * 1024 * 1024,
            ),
        )
        self._write_build_metadata()
        self._write_campaign_metadata()

    def tearDown(self):
        self.temp.cleanup()

    @staticmethod
    def _sha(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def _write_build_metadata(self):
        files = {
            "harness_source_sha256": self.harness_source,
            "harness_binary_sha256": self.harness_binary,
        }
        generated = {
            "library_archive_sha256": self.build_dir / "libpng16.a",
            "cmake_cache_sha256": self.build_dir / "CMakeCache.txt",
            "compile_database_sha256": self.build_dir / "compile_commands.json",
            "generated_header_sha256": self.build_dir / "pnglibconf.h",
        }
        generated["library_archive_sha256"].write_bytes(b"library")
        generated["cmake_cache_sha256"].write_text(
            "CMAKE_BUILD_TYPE:STRING=RelWithDebInfo\n"
            "CMAKE_C_COMPILER:FILEPATH=/usr/bin/afl-clang-fast\n",
            encoding="utf-8",
        )
        generated["compile_database_sha256"].write_text("[]", encoding="utf-8")
        generated["generated_header_sha256"].write_text("#define PNG_READ_SUPPORTED\n", encoding="utf-8")
        files.update(generated)
        self.build_artifacts = {key: self._sha(path) for key, path in files.items()}
        steps = [
            {
                "name": "configure",
                "status": "completed",
                "exit_code": 0,
                "command": ["/usr/bin/cmake", "-DCMAKE_C_COMPILER=/usr/bin/afl-clang-fast"],
            },
            {
                "name": "library",
                "status": "completed",
                "exit_code": 0,
                "command": ["/usr/bin/ninja", "-C", str(self.build_dir)],
            },
            {
                "name": "harness",
                "status": "completed",
                "exit_code": 0,
                "command": ["/usr/bin/afl-clang-fast", "-o", str(self.harness_binary)],
            },
        ]
        self.build_metadata = {
            "schema_version": 2,
            "status": "completed",
            "target": "libpng",
            "target_version": "1.6.59",
            "profile": "libpng-afl-ubsan",
            "build_dir": str(self.build_dir),
            "adapter_config": str(self.config_path),
            "source_archive_path": str(self.source_archive),
            "source_archive_sha256": SOURCE_ARCHIVE_SHA256,
            "source_tree_sha256": SOURCE_TREE_SHA256,
            "environment": {
                "PATH": os.defpath,
                "LC_ALL": "C",
                "AFL_USE_UBSAN": "1",
                "AFL_DEBUG": "1",
            },
            "steps": steps,
            "started_at": TS_START,
            "ended_at": TS_END,
            "artifacts": self.build_artifacts,
        }
        self.build_metadata_path = self.build_dir / "build.json"
        self.build_metadata_raw = json.dumps(
            self.build_metadata, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        self.build_metadata_path.write_bytes(self.build_metadata_raw)

    def _write_campaign_metadata(self):
        crash = self.crash_dir / "id:000001,sig:11,src:000000,time:12345,execs:987,op:havoc"
        hang = self.hang_dir / "id:000002,src:000001,time:999,execs:1000,op:havoc"
        crash.write_bytes(b"original crash testcase")
        hang.write_bytes(b"original hang testcase")
        self.original_bytes = {crash: crash.read_bytes(), hang: hang.read_bytes()}
        (self.worker_root / "fuzzer_stats").write_text(
            "execs_done : 1234\nsaved_crashes : 1\nsaved_hangs : 1\nexec_timeout : 1000\n",
            encoding="utf-8",
        )

        from engine.evidence.seed_manifest import build_seed_manifest, hash_stable_file
        seed_manifest = build_seed_manifest(self.seed_dir, max_file_bytes=self.config.limits.max_input_bytes)
        identity = {
            "adapter_config_path": str(self.config_path),
            "adapter_config_sha256": hash_stable_file(self.config_path).sha256,
            "seed_dir": str(self.seed_dir),
            "seed_manifest_sha256": seed_manifest.sha256,
            "seed_count": seed_manifest.seed_count,
            "build_metadata_path": str(self.build_metadata_path),
            "build_metadata_sha256": self._sha(self.build_metadata_path),
        }
        toolchain = {
            "compiler_path": "/usr/bin/afl-clang-fast",
            "compiler_version": "Ubuntu clang version 21.1.8 (6ubuntu1)",
            "aflpp_version": "4.33c",
            "afl_showmap_version": "4.33c",
        }
        afl_output = self.campaign_dir / "afl-output"
        command = [
            str(self.fuzzer_path),
            "-i", str(self.seed_dir),
            "-o", str(afl_output),
            "-V", "300",
            "-m", "512",
            "-t", "1000",
            "-G", str(1024 * 1024),
            "--",
            str(self.harness_binary),
            "@@",
        ]
        self.metadata = {
            "schema_version": 2,
            "campaign_id": CAMPAIGN_UID,
            "status": "completed",
            "target": {
                "name": "libpng",
                "version": "1.6.59",
                "source_dir": str(self.source_dir),
                "harness_binary": str(self.harness_binary),
                "seed_dir": str(self.seed_dir),
            },
            "fuzzer": {
                "executable": str(self.fuzzer_path),
                "expected_version": "4.33c",
            },
            "limits": {
                "duration_seconds": 300,
                "memory_mib": 512,
                "timeout_ms": 1000,
                "max_input_bytes": 8 * 1024 * 1024,
            },
            "command": command,
            "adapter_config": str(self.config_path),
            "validation": {
                "preflight": {"status": "passed", "report": "passed"},
                "build_provenance": {"status": "passed", "report": "passed"},
                "harness_smoke": {"status": "passed", "report": "passed"},
                "coverage": {
                    "status": "passed",
                    "report": "passed",
                    "tool_version": "4.33c",
                },
            },
            "started_at": TS_START,
            "ended_at": TS_END,
            "exit_code": 0,
            "identity": identity,
            "toolchain": toolchain,
        }
        self.campaign_metadata_raw = json.dumps(
            self.metadata, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        (self.campaign_dir / "campaign.json").write_bytes(self.campaign_metadata_raw)

    def _ingest(self):
        with (
            patch("os.geteuid", return_value=1000),
            patch("engine.evidence.afl_ingest.load_adapter_config", return_value=self.config),
            patch("engine.evidence.afl_ingest.verify_campaign_storage"),
            patch(
                "engine.evidence.afl_ingest.verify_libpng_source_identity",
                return_value=SimpleNamespace(
                    archive_sha256=SOURCE_ARCHIVE_SHA256,
                    tree_sha256=SOURCE_TREE_SHA256,
                ),
            ),
        ):
            return ingest_afl_campaign(
                self.campaign_dir,
                self.config_path,
                self.evidence_root,
            )

    def test_imports_crashes_and_hangs_into_linked_immutable_records(self):
        result = self._ingest()
        self.assertEqual((result.crash_count, result.hang_count), (1, 1))
        self.assertEqual(result.artifact_count, 2)
        self.assertTrue(self.evidence_root.is_dir())
        for path, expected in self.original_bytes.items():
            self.assertEqual(path.read_bytes(), expected)

        connection = sqlite3.connect(self.evidence_root / "db" / "kekkai.db")
        try:
            self.assertEqual(connection.execute("SELECT count(*) FROM targets").fetchone(), (1,))
            self.assertEqual(connection.execute("SELECT count(*) FROM target_versions").fetchone(), (1,))
            self.assertEqual(connection.execute("SELECT count(*) FROM builds").fetchone(), (1,))
            self.assertEqual(connection.execute("SELECT count(*) FROM campaigns").fetchone(), (1,))
            self.assertEqual(connection.execute("SELECT count(*) FROM artifacts").fetchone(), (2,))
            self.assertEqual(connection.execute("SELECT count(*) FROM observations").fetchone(), (2,))
            rows = connection.execute(
                "SELECT observation_kind, observed_signal, afl_input_id, afl_discovery_time_ms, afl_discovery_execs "
                "FROM observations ORDER BY observation_kind"
            ).fetchall()
            self.assertEqual(rows, [
                ("crash", 11, "000001", 12345, 987),
                ("hang", None, "000002", 999, 1000),
            ])
            campaign_row = connection.execute(
                "SELECT campaign_metadata_sha256, afl_max_generated_bytes, total_execs, "
                "saved_crashes_reported, saved_hangs_reported FROM campaigns"
            ).fetchone()
            self.assertEqual(campaign_row, (
                hashlib.sha256(self.campaign_metadata_raw).hexdigest(),
                1024 * 1024,
                1234,
                1,
                1,
            ))
            build_row = connection.execute(
                "SELECT build_role, compiler_path, compiler_version, cmake_build_type, "
                "afl_instrumented_locations, sanitizer_config_json FROM builds"
            ).fetchone()
            self.assertEqual(build_row[:5], (
                "fuzz",
                "/usr/bin/afl-clang-fast",
                "Ubuntu clang version 21.1.8 (6ubuntu1)",
                "RelWithDebInfo",
                None,
            ))
            self.assertIn('"afl_use_ubsan":"1"', build_row[5])
        finally:
            connection.close()

    def test_identical_import_is_idempotent(self):
        first = self._ingest()
        second = self._ingest()
        self.assertEqual(
            (first.target_id, first.target_version_id, first.build_id, first.campaign_row_id),
            (second.target_id, second.target_version_id, second.build_id, second.campaign_row_id),
        )
        connection = sqlite3.connect(self.evidence_root / "db" / "kekkai.db")
        try:
            self.assertEqual(connection.execute("SELECT count(*) FROM observations").fetchone(), (2,))
            self.assertEqual(connection.execute("SELECT count(*) FROM artifacts").fetchone(), (2,))
        finally:
            connection.close()

    def test_invalid_signal_is_rejected_before_evidence_store_creation(self):
        original = next(iter(self.crash_dir.iterdir()))
        invalid = self.crash_dir / "id:000001,sig:00,src:000000"
        original.rename(invalid)
        self.original_bytes.pop(original)
        with patch("os.geteuid", return_value=1000), patch(
            "engine.evidence.afl_ingest.load_adapter_config", return_value=self.config
        ), patch("engine.evidence.afl_ingest.verify_campaign_storage"), patch(
            "engine.evidence.afl_ingest.verify_libpng_source_identity",
            return_value=SimpleNamespace(archive_sha256=SOURCE_ARCHIVE_SHA256, tree_sha256=SOURCE_TREE_SHA256),
        ):
            with self.assertRaisesRegex(AflIngestError, "signal"):
                ingest_afl_campaign(self.campaign_dir, self.config_path, self.evidence_root)
        self.assertFalse(self.evidence_root.exists())


if __name__ == "__main__":
    unittest.main()
