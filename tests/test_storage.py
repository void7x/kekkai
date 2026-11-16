"""Unit tests for the authenticated campaign storage volume."""
from __future__ import annotations

import os
import tempfile
import uuid
import unittest
from pathlib import Path

from engine.storage import (
    CAMPAIGN_STORAGE_BYTES,
    StorageError,
    _decode_mount_field,
    _parse_mountinfo_text,
    _read_ext4_uuid,
    verify_campaign_storage,
)


class CampaignStorageTests(unittest.TestCase):
    def make_image(self, directory: Path, filesystem_uuid: str | None = None) -> Path:
        image = directory / "campaign.ext4"
        with image.open("wb") as stream:
            stream.truncate(CAMPAIGN_STORAGE_BYTES)
        raw_uuid = uuid.UUID(filesystem_uuid or "e8657221-eb6f-41ca-b087-76912b527e4b").bytes
        descriptor = os.open(image, os.O_RDWR)
        try:
            superblock = bytearray(1024)
            superblock[0x38:0x3A] = b"\x53\xef"
            superblock[0x68:0x78] = raw_uuid
            os.pwrite(descriptor, superblock, 1024)
        finally:
            os.close(descriptor)
        image.chmod(0o600)
        return image

    def test_reads_uuid_from_ext4_superblock(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = self.make_image(Path(temporary))
            self.assertEqual(
                _read_ext4_uuid(image),
                "e8657221-eb6f-41ca-b087-76912b527e4b",
            )

    def test_rejects_non_ext4_image(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = self.make_image(Path(temporary))
            descriptor = os.open(image, os.O_RDWR)
            try:
                os.pwrite(descriptor, b"\x00\x00", 1024 + 0x38)
            finally:
                os.close(descriptor)
            with self.assertRaisesRegex(StorageError, "ext filesystem"):
                _read_ext4_uuid(image)

    def test_rejects_wrong_image_size(self):
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "small.ext4"
            image.write_bytes(b"not a 4 GiB image")
            image.chmod(0o600)
            with self.assertRaisesRegex(StorageError, "exactly"):
                _read_ext4_uuid(image)

    def test_decodes_mountinfo_escape_sequences(self):
        self.assertEqual(_decode_mount_field("/mnt/campaign\\040data"), "/mnt/campaign data")

    def test_parses_mountinfo_device_filesystem_and_flags(self):
        contents = (
            "42 25 7:0 / /home/test/campaign\\040storage rw,nosuid,nodev,noexec,relatime "
            "- ext4 /dev/loop0 rw,data=ordered\n"
        )
        records = _parse_mountinfo_text(contents)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].major_minor, "7:0")
        self.assertEqual(records[0].mountpoint, Path("/home/test/campaign storage"))
        self.assertEqual(records[0].filesystem, "ext4")
        self.assertEqual(records[0].source, "/dev/loop0")
        self.assertTrue({"nodev", "nosuid", "noexec"}.issubset(records[0].options))

    def test_refuses_unmounted_directory_even_when_image_uuid_is_correct(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = self.make_image(root)
            mountpoint = root / "campaign-storage"
            mountpoint.mkdir()
            with self.assertRaisesRegex(StorageError, "not mounted"):
                verify_campaign_storage(
                    image,
                    "e8657221-eb6f-41ca-b087-76912b527e4b",
                    mountpoint,
                )

    def test_rejects_configured_uuid_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = self.make_image(root)
            mountpoint = root / "campaign-storage"
            mountpoint.mkdir()
            with self.assertRaisesRegex(StorageError, "UUID mismatch"):
                verify_campaign_storage(
                    image,
                    "11111111-2222-3333-4444-555555555555",
                    mountpoint,
                )


if __name__ == "__main__":
    unittest.main()
