from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from engine.evidence import EvidenceStore
from engine.evidence import migrations
from engine.evidence.migrations import Migration, MigrationError, run_migrations, split_sql_statements


class EvidenceMigrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "evidence"
        with patch("os.geteuid", return_value=1000):
            self.store = EvidenceStore(self.root)

    def tearDown(self):
        self.store.close()
        self.temp.cleanup()

    def test_initial_migration_and_idempotent_rerun(self):
        with patch("os.geteuid", return_value=1000):
            self.assertEqual(run_migrations(self.root), 1)
            self.assertEqual(run_migrations(self.root), 1)
        connection = sqlite3.connect(self.store.database_path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (1,))
            tables = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            self.assertEqual(
                tables,
                {"schema_migrations", "targets", "target_versions", "builds", "campaigns", "artifacts", "observations"},
            )
            self.assertEqual(connection.execute("PRAGMA integrity_check").fetchall(), [("ok",)])
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
            self.assertEqual(connection.execute("SELECT count(*) FROM schema_migrations").fetchone(), (1,))
        finally:
            connection.close()

    def test_sql_splitter_preserves_trigger_body(self):
        statements = split_sql_statements(
            "CREATE TABLE t(x);\nCREATE TRIGGER tr AFTER INSERT ON t BEGIN\n"
            "UPDATE t SET x=x+1;\nUPDATE t SET x=x+1;\nEND;\n"
        )
        self.assertEqual(len(statements), 2)
        self.assertIn("UPDATE t SET x=x+1;", statements[1])

    def test_sql_splitter_rejects_embedded_transaction_control(self):
        with self.assertRaises(MigrationError):
            split_sql_statements("PRAGMA foreign_keys=OFF;\n")
        with self.assertRaises(MigrationError):
            split_sql_statements("BEGIN;\n")

    def test_migration_failure_rolls_back_ddl_and_creates_backup(self):
        with patch("os.geteuid", return_value=1000):
            run_migrations(self.root)
        sql_path = Path(self.temp.name) / "002_failure.sql"
        sql = "CREATE TABLE migration_probe(value INTEGER);\nINSERT INTO missing_table VALUES (1);\n"
        sql_path.write_text(sql, encoding="utf-8")
        migration = Migration(2, "002_failure", sql_path, hashlib.sha256(sql.encode()).hexdigest())
        with patch("os.geteuid", return_value=1000), patch.object(
            migrations, "MIGRATIONS", migrations.MIGRATIONS + (migration,)
        ):
            with self.assertRaises(MigrationError):
                run_migrations(self.root)
        connection = sqlite3.connect(self.store.database_path)
        try:
            self.assertEqual(connection.execute("PRAGMA user_version").fetchone(), (1,))
            self.assertIsNone(connection.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='migration_probe'"
            ).fetchone())
        finally:
            connection.close()
        backups = list((self.root / "backups").glob("kekkai-pre-migration-*.db"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].stat().st_mode & 0o777, 0o400)
        sidecar = Path(str(backups[0]) + ".sha256")
        self.assertTrue(sidecar.is_file())
        actual = hashlib.sha256(backups[0].read_bytes()).hexdigest()
        self.assertTrue(sidecar.read_text().startswith(actual + "  "))

    def test_checksum_mismatch_fails_before_migration(self):
        wrong = Migration(1, "001_initial_evidence_schema", migrations.MIGRATIONS[0].path, "0" * 64)
        with patch("os.geteuid", return_value=1000), patch.object(migrations, "MIGRATIONS", (wrong,)):
            with self.assertRaises(MigrationError):
                run_migrations(self.root)

    def test_applied_migration_file_drift_fails_closed(self):
        with patch("os.geteuid", return_value=1000):
            self.assertEqual(run_migrations(self.root), 1)
        changed_sql = Path(self.temp.name) / "001_changed.sql"
        changed_sql.write_text("CREATE TABLE edited_after_apply(value INTEGER);\n", encoding="utf-8")
        changed = Migration(
            1,
            migrations.MIGRATIONS[0].name,
            changed_sql,
            migrations.MIGRATIONS[0].checksum_sha256,
        )
        with patch("os.geteuid", return_value=1000), patch.object(
            migrations, "MIGRATIONS", (changed,)
        ):
            with self.assertRaisesRegex(MigrationError, "checksum mismatch"):
                run_migrations(self.root)


if __name__ == "__main__":
    unittest.main()
