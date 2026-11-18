from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from engine.evidence import EvidenceRepository, EvidenceStore
from engine.evidence.repository import EvidenceConflictError
from engine.evidence.migrations import run_migrations

TS = "2026-11-18T10:20:30.000000Z"


class EvidenceSchemaTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "evidence"
        with patch("os.geteuid", return_value=1000):
            self.store = EvidenceStore(self.root)
        with patch("os.geteuid", return_value=1000):
            run_migrations(self.root)
        self.connection = sqlite3.connect(self.store.database_path, isolation_level=None)
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.repo = EvidenceRepository(self.connection)
        self.target_id = self.repo.insert_target({"name": "libpng", "created_at": TS})
        self.version_id = self.repo.insert_target_version({
            "target_id": self.target_id,
            "version": "1.6.59",
            "source_archive_sha256": "a" * 64,
            "source_tree_sha256": "b" * 64,
            "source_dir_recorded": "/work/libpng-1.6.59",
            "created_at": TS,
        })
        self.build_id = self.repo.insert_build(self.build_record())
        self.campaign_uid = "campaign-20261118T102030Z-" + "c" * 12
        self.campaign_id = self.repo.insert_campaign(self.campaign_record())
        stored = self.store.publish_bytes(b"original crash bytes")
        self.artifact_id = self.repo.insert_artifact({
            "sha256": stored.sha256,
            "size_bytes": stored.size_bytes,
            "storage_relpath": stored.storage_relpath,
            "first_ingested_at": TS,
            "last_verified_at": TS,
        })

    def tearDown(self):
        self.connection.close()
        self.store.close()
        self.temp.cleanup()

    def build_record(self, **overrides):
        record = {
            "target_id": self.target_id,
            "target_version_id": self.version_id,
            "profile": "libpng-afl-ubsan",
            "build_role": "fuzz",
            "build_dir": "/work/build/libpng-afl-ubsan",
            "build_metadata_sha256": "d" * 64,
            "harness_source_path": "/repo/targets/libpng/png_read_harness.c",
            "harness_binary_path": "/work/build/libpng-afl-ubsan/kekkai_png_harness",
            "harness_source_sha256": "1" * 64,
            "harness_binary_sha256": "2" * 64,
            "library_archive_sha256": "3" * 64,
            "cmake_cache_sha256": "4" * 64,
            "compile_database_sha256": "5" * 64,
            "generated_header_sha256": "6" * 64,
            "compiler_path": "/usr/bin/afl-clang-fast",
            "compiler_version": "clang version 21.1.8",
            "cmake_build_type": "RelWithDebInfo",
            "aflpp_version": "4.33c",
            "afl_instrumented_locations": 12000,
            "sanitizer_config_json": {"undefined": "trap"},
            "environment_json": {"AFL_DEBUG": "1"},
            "build_status": "completed",
            "started_at": TS,
            "ended_at": TS,
            "recorded_at": TS,
        }
        record.update(overrides)
        return record

    def campaign_record(self, **overrides):
        record = {
            "campaign_uid": self.campaign_uid,
            "target_id": self.target_id,
            "target_version_id": self.version_id,
            "build_id": self.build_id,
            "adapter_config_path": "/repo/targets/libpng/adapter.toml",
            "adapter_config_sha256": "7" * 64,
            "campaign_dir": "/work/campaign-storage/" + self.campaign_uid,
            "afl_output_dir": "/work/campaign-storage/" + self.campaign_uid + "/afl-output",
            "campaign_metadata_sha256": "8" * 64,
            "seed_dir": "/repo/targets/libpng/seeds",
            "seed_manifest_sha256": "9" * 64,
            "seed_count": 10,
            "fuzzer_executable": "/usr/bin/afl-fuzz",
            "fuzzer_version": "4.33c",
            "command_json": ["/usr/bin/afl-fuzz", "-i", "seeds"],
            "duration_seconds": 300,
            "memory_mib": 512,
            "timeout_ms": 1000,
            "effective_timeout_ms": 1000,
            "max_input_bytes": 8388608,
            "afl_max_generated_bytes": 1048576,
            "status": "completed",
            "exit_code": 0,
            "total_execs": 1000,
            "saved_crashes_reported": 2,
            "saved_hangs_reported": 0,
            "started_at": TS,
            "ended_at": TS,
            "recorded_at": TS,
        }
        record.update(overrides)
        return record

    def observation_record(self, filename="id:000001,sig:04", **overrides):
        record = {
            "campaign_uid": self.campaign_uid,
            "target_id": self.target_id,
            "target_version_id": self.version_id,
            "build_id": self.build_id,
            "campaign_id": self.campaign_id,
            "original_artifact_id": self.artifact_id,
            "observation_kind": "crash",
            "afl_worker_name": "default",
            "afl_source_filename": filename,
            "observed_signal": 4,
            "source_file_mtime_utc": TS,
            "ingested_at": TS,
        }
        record.update(overrides)
        return record

    def test_later_registration_timestamps_are_idempotent(self):
        later = "2026-11-18T10:20:31.000000Z"
        self.assertEqual(
            self.repo.insert_target({"name": "libpng", "created_at": later}),
            self.target_id,
        )
        self.assertEqual(
            self.repo.insert_target_version({
                "target_id": self.target_id,
                "version": "1.6.59",
                "source_archive_sha256": "a" * 64,
                "source_tree_sha256": "b" * 64,
                "source_dir_recorded": "/work/libpng-1.6.59",
                "created_at": later,
            }),
            self.version_id,
        )
        self.assertEqual(self.repo.insert_build(self.build_record(recorded_at=later)), self.build_id)
        self.assertEqual(self.repo.insert_campaign(self.campaign_record(recorded_at=later)), self.campaign_id)
        artifact_row = self.connection.execute(
            "SELECT sha256, size_bytes, storage_relpath FROM artifacts WHERE id=?",
            (self.artifact_id,),
        ).fetchone()
        self.assertEqual(
            self.repo.insert_artifact({
                "sha256": artifact_row[0],
                "size_bytes": artifact_row[1],
                "storage_relpath": artifact_row[2],
                "first_ingested_at": later,
                "last_verified_at": later,
            }),
            self.artifact_id,
        )
        original_observation_id = self.repo.insert_observation(self.observation_record())
        self.assertEqual(
            self.repo.insert_observation(self.observation_record(ingested_at=later)),
            original_observation_id,
        )
        self.assertEqual(
            self.connection.execute("SELECT created_at FROM targets WHERE id=?", (self.target_id,)).fetchone()[0],
            TS,
        )
        self.assertEqual(
            self.connection.execute("SELECT created_at FROM target_versions WHERE id=?", (self.version_id,)).fetchone()[0],
            TS,
        )
        self.assertEqual(
            self.connection.execute("SELECT recorded_at FROM builds WHERE id=?", (self.build_id,)).fetchone()[0],
            TS,
        )
        self.assertEqual(
            self.connection.execute("SELECT recorded_at FROM campaigns WHERE id=?", (self.campaign_id,)).fetchone()[0],
            TS,
        )
        self.assertEqual(
            self.connection.execute(
                "SELECT first_ingested_at, last_verified_at FROM artifacts WHERE id=?",
                (self.artifact_id,),
            ).fetchone(),
            (TS, later),
        )
        self.assertEqual(
            self.connection.execute("SELECT ingested_at FROM observations WHERE id=?", (original_observation_id,)).fetchone()[0],
            TS,
        )

    def test_campaign_all_unique_identities_are_checked(self):
        with self.assertRaises(EvidenceConflictError):
            self.repo.insert_campaign(self.campaign_record(
                campaign_uid="campaign-20261118T102031Z-" + "d" * 12,
                campaign_dir="/work/campaign-storage/" + self.campaign_uid,
                afl_output_dir="/work/campaign-storage/other/afl-output",
            ))
        with self.assertRaises(EvidenceConflictError):
            self.repo.insert_campaign(self.campaign_record(
                campaign_uid="campaign-20261118T102032Z-" + "e" * 12,
                campaign_dir="/work/campaign-storage/other",
                afl_output_dir="/work/campaign-storage/" + self.campaign_uid + "/afl-output",
            ))

    def test_repository_rejects_nul_strings_and_boolean_integer_values(self):
        with self.assertRaises(ValueError):
            self.repo.insert_target({"name": "bad\x00target", "created_at": TS})
        with self.assertRaises(ValueError):
            self.repo.insert_campaign(self.campaign_record(seed_count=True))
        artifact_row = self.connection.execute(
            "SELECT sha256, storage_relpath FROM artifacts WHERE id=?", (self.artifact_id,)
        ).fetchone()
        with self.assertRaises(ValueError):
            self.repo.insert_artifact({
                "sha256": artifact_row[0],
                "size_bytes": True,
                "storage_relpath": artifact_row[1],
                "first_ingested_at": TS,
                "last_verified_at": TS,
            })

    def test_sql_schema_rejects_embedded_nul_text(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "INSERT INTO targets(name, created_at) VALUES(?, ?)",
                ("bad\x00target", TS),
            )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "INSERT INTO schema_migrations(version, name, checksum_sha256, applied_at) VALUES(2, ?, ?, ?)",
                ("safe_name\x00../../evil", "a" * 64, TS),
            )

    def test_actual_campaign_uid_format_is_accepted(self):
        self.assertEqual(len(self.campaign_uid), 38)
        self.assertEqual(
            self.connection.execute("SELECT campaign_uid FROM campaigns WHERE id=?", (self.campaign_id,)).fetchone()[0],
            self.campaign_uid,
        )

    def test_bad_hash_is_rejected_even_when_bad_character_is_late(self):
        digest = "a" + "Z" * 63
        path = f"objects/sha256/{digest[:2]}/{digest[2:4]}/{digest}.bin"
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "INSERT INTO artifacts(sha256,size_bytes,storage_relpath,first_ingested_at,last_verified_at) VALUES(?,?,?,?,?)",
                (digest, 1, path, TS, TS),
            )

    def test_invalid_calendar_timestamp_is_rejected(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "INSERT INTO targets(name,created_at) VALUES(?,?)",
                ("invalid-date", "2026-02-30T10:20:30.000000Z"),
            )

    def test_sha256_rejects_embedded_nul_bytes(self):
        digest = ("a" * 64) + "\x00"
        path = f"objects/sha256/{digest[:2]}/{digest[2:4]}/{digest}.bin"
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "INSERT INTO artifacts(sha256,size_bytes,storage_relpath,first_ingested_at,last_verified_at) VALUES(?,?,?,?,?)",
                (digest, 1, path, TS, TS),
            )

    def test_fixed_width_timestamp_sort_is_chronological(self):
        self.connection.execute("INSERT INTO targets(name,created_at) VALUES(?,?)", ("later", "2026-11-18T10:20:30.000001Z"))
        values = [row[0] for row in self.connection.execute("SELECT created_at FROM targets ORDER BY created_at")]
        self.assertLess(values.index(TS), values.index("2026-11-18T10:20:30.000001Z"))

    def test_failed_build_can_have_no_output_hashes(self):
        failed = self.build_record(
            build_dir="/work/build/failed",
            build_metadata_sha256="e" * 64,
            build_status="failed",
            harness_source_sha256=None,
            harness_binary_sha256=None,
            library_archive_sha256=None,
            cmake_cache_sha256=None,
            compile_database_sha256=None,
            generated_header_sha256=None,
        )
        row_id = self.repo.insert_build(failed)
        self.assertIsInstance(row_id, int)

    def test_completed_build_requires_all_output_hashes(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "INSERT INTO builds(target_id,target_version_id,profile,build_role,build_dir,build_metadata_sha256,harness_source_path,harness_binary_path,compiler_path,compiler_version,cmake_build_type,sanitizer_config_json,environment_json,build_status,started_at,ended_at,recorded_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (self.target_id, self.version_id, "p", "fuzz", "/b/other", "f"*64, "/h.c", "/h", "/clang", "v", "RelWithDebInfo", "{}", "{}", "completed", TS, TS, TS),
            )

    def test_composite_build_foreign_key_rejects_mismatched_target(self):
        other_target = self.repo.insert_target({"name": "other", "created_at": TS})
        with self.assertRaises(sqlite3.IntegrityError):
            self.repo.insert_build(self.build_record(
                target_id=other_target,
                build_dir="/work/build/wrong-parent",
                build_metadata_sha256="f" * 64,
            ))

    def test_composite_campaign_foreign_key_rejects_wrong_build(self):
        other_target = self.repo.insert_target({"name": "other", "created_at": TS})
        other_version = self.repo.insert_target_version({
            "target_id": other_target, "version": "1.0", "source_archive_sha256": "a"*64,
            "source_tree_sha256": "b"*64, "source_dir_recorded": "/tmp/other", "created_at": TS,
        })
        other_build = self.repo.insert_build(self.build_record(
            target_id=other_target, target_version_id=other_version,
            build_dir="/work/build/other", build_metadata_sha256="c"*64,
        ))
        with self.assertRaises(sqlite3.IntegrityError):
            self.repo.insert_campaign(self.campaign_record(
                campaign_uid="campaign-20261118T102031Z-" + "d"*12,
                build_id=other_build,
                campaign_dir="/work/campaign-storage/wrong",
                afl_output_dir="/work/campaign-storage/wrong/afl-output",
            ))

    def test_observation_must_match_campaign_build_identity(self):
        other_build = self.repo.insert_build(self.build_record(
            build_dir="/work/build/other-profile", build_metadata_sha256="f"*64,
        ))
        with self.assertRaises(sqlite3.IntegrityError):
            self.repo.insert_observation(self.observation_record(
                filename="id:000002,sig:04", build_id=other_build,
            ))

    def test_same_content_can_be_referenced_by_multiple_observations(self):
        first = self.repo.insert_observation(self.observation_record())
        second = self.repo.insert_observation(self.observation_record(filename="id:000002,sig:04"))
        self.assertNotEqual(first, second)
        self.assertEqual(
            self.connection.execute(
                "SELECT count(*) FROM observations WHERE original_artifact_id=?", (self.artifact_id,)
            ).fetchone(),
            (2,),
        )

    def test_observation_is_immutable(self):
        observation_id = self.repo.insert_observation(self.observation_record())
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("UPDATE observations SET observed_signal=11 WHERE id=?", (observation_id,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("DELETE FROM observations WHERE id=?", (observation_id,))

    def test_artifact_is_immutable_but_verification_timestamp_can_advance(self):
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("DELETE FROM artifacts WHERE id=?", (self.artifact_id,))
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute("UPDATE artifacts SET size_bytes=0 WHERE id=?", (self.artifact_id,))
        self.connection.execute(
            "UPDATE artifacts SET last_verified_at=? WHERE id=?",
            ("2026-11-18T10:20:31.000000Z", self.artifact_id),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            self.connection.execute(
                "UPDATE artifacts SET last_verified_at=? WHERE id=?", (TS, self.artifact_id)
            )

    def test_observation_uid_is_deterministic(self):
        one = self.repo.insert_observation(self.observation_record(filename="id:000009,sig:04"))
        two = self.repo.insert_observation(self.observation_record(filename="id:000009,sig:04"))
        self.assertEqual(one, two)


if __name__ == "__main__":
    unittest.main()
