from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from engine.evidence.seed_manifest import build_seed_manifest
from engine.fuzzing.libpng_seed_corpus import (
    LIBPNG_ADDITIONAL_SEED_CASES,
    LIBPNG_BASE_SEED_FILES,
    SeedCorpusError,
    generate_additional_seed_bytes,
    prepare_libpng_seed_corpus,
)
from engine.fuzzing.smoke import _validate_seed_fixture


class LibpngSeedCorpusTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.workspace = self.base / "workspace"
        self.workspace.mkdir()

        self.repository = self.workspace / "repository"
        self.repository.mkdir()
        self.target_source = self.workspace / "target-source"
        self.target_source.mkdir()
        self.campaign_output = self.workspace / "campaign-output"
        self.campaign_output.mkdir()

        self.source = self.workspace / "original-seeds"
        self.source.mkdir()
        self.original_bytes = {}
        for name in sorted(LIBPNG_BASE_SEED_FILES):
            data = b"existing-pilot-seed:" + name.encode("ascii")
            (self.source / name).write_bytes(data)
            self.original_bytes[name] = data

        self.destination = self.workspace / "expanded-seeds"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def prepare(self, destination: Path | None = None):
        return prepare_libpng_seed_corpus(
            self.source,
            destination or self.destination,
            repository_root=self.repository,
            target_source_root=self.target_source,
            campaign_output_parent=self.campaign_output,
        )

    def test_generated_pngs_are_deterministic_and_semantically_valid(self) -> None:
        first = generate_additional_seed_bytes()
        second = generate_additional_seed_bytes()

        expected = {filename for _, filename in LIBPNG_ADDITIONAL_SEED_CASES}
        self.assertEqual(set(first), expected)
        self.assertEqual(first, second)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for case_name, filename in LIBPNG_ADDITIONAL_SEED_CASES:
                path = root / filename
                path.write_bytes(first[filename])
                _validate_seed_fixture(case_name, path)

    def test_prepares_new_corpus_without_modifying_original(self) -> None:
        original_manifest = build_seed_manifest(self.source)
        result = self.prepare()

        self.assertEqual(result.destination, self.destination)
        self.assertEqual(result.seed_manifest.seed_count, 18)
        self.assertEqual(
            result.added_seed_names,
            tuple(sorted(filename for _, filename in LIBPNG_ADDITIONAL_SEED_CASES)),
        )
        self.assertEqual(build_seed_manifest(self.source), original_manifest)
        self.assertEqual(
            {path.name: path.read_bytes() for path in self.source.iterdir()},
            self.original_bytes,
        )
        self.assertEqual(
            build_seed_manifest(self.destination).sha256,
            result.seed_manifest.sha256,
        )
        self.assertEqual(
            set(path.name for path in self.destination.iterdir()),
            LIBPNG_BASE_SEED_FILES
            | {filename for _, filename in LIBPNG_ADDITIONAL_SEED_CASES},
        )

    def test_refuses_existing_destination_without_modifying_it(self) -> None:
        self.destination.mkdir()
        marker = self.destination / "keep.txt"
        marker.write_text("preserve", encoding="utf-8")

        with self.assertRaisesRegex(SeedCorpusError, "already exists"):
            self.prepare()

        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")

    def test_atomic_publication_does_not_replace_racing_empty_directory(self) -> None:
        from engine.fuzzing import libpng_seed_corpus

        original_publish = libpng_seed_corpus._rename_directory_noreplace
        observed = {}

        def create_racing_destination(parent_fd, source_name, destination_name):
            self.destination.mkdir()
            observed["inode"] = self.destination.stat().st_ino
            return original_publish(parent_fd, source_name, destination_name)

        with patch(
            "engine.fuzzing.libpng_seed_corpus._rename_directory_noreplace",
            side_effect=create_racing_destination,
        ):
            with self.assertRaisesRegex(SeedCorpusError, "Destination appeared"):
                self.prepare()

        self.assertTrue(self.destination.is_dir())
        self.assertEqual(self.destination.stat().st_ino, observed["inode"])
        self.assertEqual(list(self.destination.iterdir()), [])

    def test_refuses_destination_inside_repository(self) -> None:
        destination = self.repository / "generated-seeds"

        with self.assertRaisesRegex(SeedCorpusError, "overlaps the protected repository"):
            self.prepare(destination)

        self.assertFalse(destination.exists())

    def test_refuses_missing_original_pilot_seed(self) -> None:
        (self.source / sorted(LIBPNG_BASE_SEED_FILES)[0]).unlink()

        with self.assertRaisesRegex(SeedCorpusError, "missing required pilot seeds"):
            self.prepare()

        self.assertFalse(self.destination.exists())

    def test_refuses_symlink_in_original_corpus(self) -> None:
        victim = self.workspace / "outside-seed"
        victim.write_bytes(b"not inside corpus")
        (self.source / "unsafe-link.png").symlink_to(victim)

        with self.assertRaisesRegex(SeedCorpusError, "Symlink"):
            self.prepare()

        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
