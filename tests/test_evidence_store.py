from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from engine.evidence import EvidenceRepository, EvidenceStore, EvidenceIntegrityError, EvidenceStoreError
from engine.evidence.migrations import run_migrations

TS = "2026-11-18T10:20:30.000000Z"


class EvidenceStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.root = self.base / "evidence"
        with patch("os.geteuid", return_value=1000):
            self.store = EvidenceStore(self.root, min_free_reserve_bytes=0)
            run_migrations(self.root)
        self.connection = sqlite3.connect(self.store.database_path, isolation_level=None)
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.repo = EvidenceRepository(self.connection)

    def tearDown(self):
        self.connection.close()
        self.store.close()
        self.temp.cleanup()

    def register(self, artifact):
        return self.repo.insert_artifact({
            "sha256": artifact.sha256,
            "size_bytes": artifact.size_bytes,
            "storage_relpath": artifact.storage_relpath,
            "first_ingested_at": TS,
            "last_verified_at": TS,
        })

    def test_store_layout_permissions_and_database_mode(self):
        for name in ("db", "backups", "staging", "objects", "objects/sha256"):
            self.assertEqual((self.root / name).stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.root / "STORE_VERSION").stat().st_mode & 0o777, 0o400)
        self.assertEqual((self.root / "db/kekkai.db").stat().st_mode & 0o777, 0o600)

    def test_publish_empty_and_regular_bytes(self):
        empty = self.store.publish_bytes(b"")
        self.assertEqual(empty.sha256, hashlib.sha256(b"").hexdigest())
        self.assertEqual(empty.size_bytes, 0)
        self.assertEqual(empty.path.stat().st_mode & 0o777, 0o400)
        regular = self.store.publish_bytes(b"testcase")
        self.assertEqual(self.store.read_verified_artifact(regular.sha256), b"testcase")
        self.assertEqual(regular.path.stat().st_nlink, 1)

    def test_duplicate_publication_reuses_object_inode(self):
        one = self.store.publish_bytes(b"same bytes")
        first_inode = one.path.stat().st_ino
        two = self.store.publish_bytes(b"same bytes")
        self.assertEqual(one.sha256, two.sha256)
        self.assertEqual(two.path.stat().st_ino, first_inode)
        self.assertEqual(two.path.stat().st_nlink, 1)

    def test_publish_file_copies_stable_regular_file(self):
        source = self.base / "crash-input"
        source.write_bytes(b"saved crash input")
        result = self.store.publish_file(source)
        self.assertEqual(result.sha256, hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertEqual(result.path.read_bytes(), source.read_bytes())

    def test_source_parent_does_not_need_private_mode(self):
        source_dir = self.base / "shared-inputs"
        source_dir.mkdir(mode=0o755)
        source_dir.chmod(0o755)
        source = source_dir / "testcase"
        source.write_bytes(b"read-only source parent")
        result = self.store.publish_file(source)
        self.assertEqual(result.path.read_bytes(), source.read_bytes())

    def test_rejects_symlink_source(self):
        source = self.base / "real-input"
        source.write_bytes(b"x")
        alias = self.base / "alias-input"
        alias.symlink_to(source)
        with self.assertRaises(EvidenceStoreError):
            self.store.publish_file(alias)

    def test_rejects_fifo_source_without_blocking(self):
        fifo = self.base / "named-pipe"
        os.mkfifo(fifo)
        with self.assertRaises(EvidenceStoreError):
            self.store.publish_file(fifo)

    def test_rejects_oversized_artifact(self):
        small_store_root = self.base / "small-store"
        with patch("os.geteuid", return_value=1000):
            small_store = EvidenceStore(small_store_root, max_artifact_bytes=8, min_free_reserve_bytes=0)
        try:
            with self.assertRaises(EvidenceStoreError):
                small_store.publish_bytes(b"123456789")
        finally:
            small_store.close()

    def test_corrupt_object_is_refused_on_read(self):
        artifact = self.store.publish_bytes(b"do not trust modified bytes")
        artifact.path.chmod(0o600)
        artifact.path.write_bytes(b"modified")
        with self.assertRaises(EvidenceIntegrityError):
            self.store.read_verified_artifact(artifact.sha256)

    def test_stale_staging_hardlink_is_removed_before_future_validation(self):
        artifact = self.store.publish_bytes(b"recover link count")
        staging_link = self.root / "staging/.ingest-stale.tmp"
        os.link(artifact.path, staging_link)
        self.assertEqual(artifact.path.stat().st_nlink, 2)
        self.store.close()
        with patch("os.geteuid", return_value=1000):
            replacement = EvidenceStore(self.root, min_free_reserve_bytes=0)
        try:
            self.assertFalse(staging_link.exists())
            self.assertEqual(artifact.path.stat().st_nlink, 1)
            self.assertEqual(replacement.read_verified_artifact(artifact.sha256), b"recover link count")
        finally:
            replacement.close()

    def test_verify_store_reports_registered_and_orphan_objects(self):
        artifact = self.store.publish_bytes(b"registered")
        self.register(artifact)
        report = self.store.verify_evidence_store(self.connection)
        self.assertTrue(report.passed)
        self.assertEqual(report.verified_count, 1)
        orphan = self.store.publish_bytes(b"orphan without row")
        report = self.store.verify_evidence_store(self.connection)
        self.assertIn(orphan.storage_relpath.split("objects/sha256/", 1)[1], " ".join(report.unreferenced))

    def test_verifier_flags_all_unexpected_staging_entries(self):
        ordinary = self.root / "staging" / "unexpected.tmp"
        ordinary.write_bytes(b"leftover")
        symlink = self.root / "staging" / "foreign-link"
        symlink.symlink_to(ordinary)
        report = self.store.verify_evidence_store(self.connection)
        self.assertFalse(report.passed)
        self.assertEqual(set(report.stale_staging), {"unexpected.tmp", "foreign-link"})

    def test_verifier_rejects_invalid_shard_names_and_permissions(self):
        invalid_name = self.root / "objects/sha256/ZZ"
        invalid_name.mkdir(mode=0o700)
        invalid_mode = self.root / "objects/sha256/aa"
        invalid_mode.mkdir(mode=0o700)
        invalid_mode.chmod(0o777)
        report = self.store.verify_evidence_store(self.connection)
        self.assertIn("ZZ", report.corrupt)
        self.assertIn("aa", report.corrupt)

    def test_symlink_component_in_store_root_is_rejected(self):
        actual = self.base / "real-parent"
        actual.mkdir()
        alias = self.base / "linked-parent"
        alias.symlink_to(actual, target_is_directory=True)
        with patch("os.geteuid", return_value=1000):
            with self.assertRaises(EvidenceStoreError):
                EvidenceStore(alias / "store", min_free_reserve_bytes=0)

    def test_capacity_check_uses_operation_size_and_reserve(self):
        class FakeStatVfs:
            f_bavail = 1
            f_frsize = 4096
            f_favail = 100
            f_files = 1000
        with patch("engine.evidence.store.os.fstatvfs", return_value=FakeStatVfs()):
            with self.assertRaises(EvidenceStoreError):
                self.store.publish_bytes(b"x")


if __name__ == "__main__":
    unittest.main()
