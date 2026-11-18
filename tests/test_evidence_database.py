from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from engine.evidence.database import (
    EvidenceDatabaseError,
    immediate_transaction,
    normalize_utc_timestamp,
    open_database,
    utc_now_iso,
)


class EvidenceDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "evidence"
        self.db_dir = self.root / "db"
        self.db_dir.mkdir(parents=True, mode=0o700)
        self.db_path = self.db_dir / "kekkai.db"

    def tearDown(self):
        self.temp.cleanup()

    def open_nonroot(self):
        with patch("os.geteuid", return_value=1000):
            return open_database(self.db_path)

    def test_connection_pragmas_are_enforced(self):
        connection = self.open_nonroot()
        try:
            self.assertEqual(connection.execute("PRAGMA trusted_schema").fetchone(), (0,))
            self.assertEqual(connection.execute("PRAGMA cell_size_check").fetchone(), (1,))
            self.assertEqual(connection.execute("PRAGMA busy_timeout").fetchone(), (5000,))
            self.assertEqual(connection.execute("PRAGMA foreign_keys").fetchone(), (1,))
            self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone(), ("wal",))
            self.assertEqual(connection.execute("PRAGMA synchronous").fetchone(), (2,))
        finally:
            connection.close()
        self.assertEqual(self.db_path.stat().st_mode & 0o777, 0o600)

    def test_refuses_root_execution(self):
        with patch("os.geteuid", return_value=0):
            with self.assertRaises(EvidenceDatabaseError):
                open_database(self.db_path)

    def test_rejects_symlinked_database(self):
        target = self.db_dir / "real.db"
        target.touch(mode=0o600)
        self.db_path.symlink_to(target)
        with patch("os.geteuid", return_value=1000):
            with self.assertRaises(EvidenceDatabaseError):
                open_database(self.db_path)

    def test_rejects_unsafe_database_mode(self):
        self.db_path.touch(mode=0o644)
        self.db_path.chmod(0o644)
        with patch("os.geteuid", return_value=1000):
            with self.assertRaises(EvidenceDatabaseError):
                open_database(self.db_path)

    def test_immediate_transaction_rolls_back_dml_and_ddl(self):
        connection = self.open_nonroot()
        try:
            with self.assertRaises(RuntimeError):
                with immediate_transaction(connection):
                    connection.execute("CREATE TABLE should_rollback(value INTEGER)")
                    connection.execute("INSERT INTO should_rollback VALUES (1)")
                    raise RuntimeError("injected failure")
            self.assertIsNone(connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='should_rollback'"
            ).fetchone())
            with immediate_transaction(connection):
                connection.execute("CREATE TABLE should_commit(value INTEGER)")
            self.assertIsNotNone(connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='should_commit'"
            ).fetchone())
        finally:
            connection.close()

    def test_nested_transaction_is_rejected(self):
        connection = self.open_nonroot()
        try:
            connection.execute("BEGIN IMMEDIATE")
            with self.assertRaises(EvidenceDatabaseError):
                with immediate_transaction(connection):
                    pass
            connection.execute("ROLLBACK")
        finally:
            connection.close()

    def test_timestamp_normalization_is_fixed_width_utc(self):
        normalized = normalize_utc_timestamp("2026-11-18T10:20:30Z")
        self.assertEqual(normalized, "2026-11-18T10:20:30.000000Z")
        self.assertEqual(len(utc_now_iso()), 27)
        with self.assertRaises(ValueError):
            normalize_utc_timestamp("2026-11-18T10:20:30+05:30")

    def test_normalizer_rejects_invalid_calendar_date(self):
        with self.assertRaises(ValueError):
            normalize_utc_timestamp("2026-02-30T10:20:30Z")


if __name__ == "__main__":
    unittest.main()
