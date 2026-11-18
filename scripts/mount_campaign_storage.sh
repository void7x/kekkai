#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
IMAGE="${HOME}/kekkai-work/campaign-quota.ext4"
MOUNTPOINT="${HOME}/kekkai-work/campaign-storage"
EXPECTED_UUID="e8657221-eb6f-41ca-b087-76912b527e4b"

verify_image_identity() {
  python3 -I - "${REPO_ROOT}" "${IMAGE}" "${EXPECTED_UUID}" "${MOUNTPOINT}" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from engine.storage import (  # noqa: E402
    StorageError,
    _read_ext4_uuid,
    _reject_symlink_components,
)

image = Path(sys.argv[2]).expanduser()
expected_uuid = sys.argv[3]
mountpoint = Path(sys.argv[4]).expanduser()

_reject_symlink_components(image, "Campaign storage image")
_reject_symlink_components(mountpoint, "Campaign storage mountpoint")
actual_uuid = _read_ext4_uuid(image)
if actual_uuid != expected_uuid:
    raise StorageError(
        f"UUID mismatch: expected {expected_uuid}, found {actual_uuid}"
    )
print(actual_uuid)
PY
}

verify_mounted_storage() {
  python3 -I - "${REPO_ROOT}" "${IMAGE}" "${EXPECTED_UUID}" "${MOUNTPOINT}" <<'PY'
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
from engine.storage import verify_campaign_storage  # noqa: E402

result = verify_campaign_storage(sys.argv[2], sys.argv[3], sys.argv[4])
print(f"Verified {result.filesystem_uuid} on {result.device} at {result.mountpoint}")
print(f"Capacity bytes: {result.capacity_bytes}")
print(f"Available bytes: {result.available_bytes}")
PY
}

# Validate the image and every existing path component before invoking sudo.
actual_uuid="$(verify_image_identity)"
echo "Verified campaign image UUID: ${actual_uuid}"

mkdir -p -- "${MOUNTPOINT}"

if mountpoint -q "${MOUNTPOINT}"; then
  echo "Mountpoint is already mounted; verifying without changing its contents."
  verify_mounted_storage
  exit 0
fi

if find "${MOUNTPOINT}" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  echo "Refusing to mount over a non-empty directory: ${MOUNTPOINT}" >&2
  exit 1
fi
chmod 700 -- "${MOUNTPOINT}"

sudo -v
loop_device="$(sudo losetup -j "${IMAGE}" | cut -d: -f1 | head -n 1 || true)"
created_loop=0
if [[ -z "${loop_device}" ]]; then
  loop_device="$(sudo losetup --find --show "${IMAGE}")"
  created_loop=1
fi

if ! sudo mount -o nodev,nosuid,noexec "${loop_device}" "${MOUNTPOINT}"; then
  if [[ "${created_loop}" == "1" ]]; then
    sudo losetup -d "${loop_device}" || true
  fi
  echo "Mount failed. The image was not formatted or modified by this script." >&2
  exit 1
fi

# The mounted ext4 root has its own inode permissions. Set it explicitly so
# the unprivileged KEKKAI process owns a private 0700 campaign directory.
if ! {
  sudo chown "$(id -u):$(id -g)" -- "${MOUNTPOINT}" &&
  sudo chmod 700 -- "${MOUNTPOINT}" &&
  verify_mounted_storage
}; then
  echo "Storage verification failed. Unmounting the untrusted mount." >&2
  sudo umount "${MOUNTPOINT}" || true
  if [[ "${created_loop}" == "1" ]]; then
    sudo losetup -d "${loop_device}" || true
  fi
  exit 1
fi
