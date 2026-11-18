"""Bounded extracted-source identity scanning tests."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from engine.build.source_identity import (
    SourceIdentityError,
    _source_entries,
    _sha256_file,
)


class SourceEntryLimitTests(unittest.TestCase):
    def test_rejects_extracted_tree_over_entry_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("one", "two", "three", "four"):
                (root / name).write_text("x", encoding="utf-8")

            with patch("engine.build.source_identity._MAX_ENTRIES", 3):
                with self.assertRaisesRegex(SourceIdentityError, "entry-count limit"):
                    _source_entries(root)

    def test_rejects_oversized_file_before_hashing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "large.c").write_bytes(b"12345")

            with (
                patch("engine.build.source_identity._MAX_TREE_BYTES", 4),
                patch(
                    "engine.build.source_identity._sha256_file",
                    wraps=_sha256_file,
                ) as hash_file,
            ):
                with self.assertRaisesRegex(SourceIdentityError, "size limit"):
                    _source_entries(root)

                hash_file.assert_not_called()


if __name__ == "__main__":
    unittest.main()
