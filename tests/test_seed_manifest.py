from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from engine.evidence.seed_manifest import (
    SeedManifestError,
    build_seed_manifest,
    hash_stable_file,
)


class SeedManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.seeds = self.root / "seeds"
        self.seeds.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def test_manifest_is_deterministic_and_filename_sorted(self):
        (self.seeds / "z.png").write_bytes(b"last")
        (self.seeds / "a.png").write_bytes(b"first")
        first = build_seed_manifest(self.seeds)
        second = build_seed_manifest(self.seeds)
        self.assertEqual(first.sha256, second.sha256)
        self.assertEqual(first.entries, second.entries)
        self.assertEqual([entry[0] for entry in first.entries], ["a.png", "z.png"])
        self.assertEqual(first.seed_count, 2)
        self.assertEqual(first.total_bytes, 9)

    def test_rejects_direct_subdirectories(self):
        (self.seeds / "valid.png").write_bytes(b"input")
        nested = self.seeds / "nested"
        nested.mkdir()
        (nested / "not-a-direct-seed").write_bytes(b"ignored")
        with self.assertRaisesRegex(SeedManifestError, "Subdirectories"):
            build_seed_manifest(self.seeds)

    def test_rejects_symlink_entries(self):
        target = self.root / "outside"
        target.write_bytes(b"input")
        (self.seeds / "alias.png").symlink_to(target)
        with self.assertRaisesRegex(SeedManifestError, "Symlink"):
            build_seed_manifest(self.seeds)

    def test_rejects_special_entries(self):
        fifo = self.seeds / "pipe"
        os.mkfifo(fifo)
        with self.assertRaisesRegex(SeedManifestError, "regular user-owned"):
            build_seed_manifest(self.seeds)

    def test_enforces_entry_count_limit_including_subdirectories(self):
        (self.seeds / "one.png").write_bytes(b"1")
        (self.seeds / "two.png").write_bytes(b"2")
        with self.assertRaisesRegex(SeedManifestError, "entry limit"):
            build_seed_manifest(self.seeds, max_entries=1)

    def test_enforces_total_size_limit(self):
        (self.seeds / "one.png").write_bytes(b"1234")
        (self.seeds / "two.png").write_bytes(b"5678")
        with self.assertRaisesRegex(SeedManifestError, "total limit"):
            build_seed_manifest(self.seeds, max_total_bytes=7)

    def test_enforces_per_file_size_limit(self):
        (self.seeds / "too-large.png").write_bytes(b"12345")
        with self.assertRaisesRegex(SeedManifestError, "input limit"):
            build_seed_manifest(self.seeds, max_file_bytes=4)

    def test_requires_at_least_one_non_empty_regular_seed(self):
        (self.seeds / "empty.png").write_bytes(b"")
        with self.assertRaisesRegex(SeedManifestError, "non-empty"):
            build_seed_manifest(self.seeds)

    def test_hash_stable_file_returns_sha_and_exact_size(self):
        source = self.root / "identity.json"
        source.write_bytes(b'{"schema":2}')
        result = hash_stable_file(source)
        self.assertEqual(result.size_bytes, len(b'{"schema":2}'))
        self.assertEqual(len(result.sha256), 64)

    def test_hash_stable_file_rejects_symlinks_and_oversized_inputs(self):
        actual = self.root / "actual.json"
        actual.write_bytes(b"content")
        alias = self.root / "alias.json"
        alias.symlink_to(actual)
        with self.assertRaises(SeedManifestError):
            hash_stable_file(alias)
        with self.assertRaisesRegex(SeedManifestError, "limit"):
            hash_stable_file(actual, max_bytes=2)


if __name__ == "__main__":
    unittest.main()
