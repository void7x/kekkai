#!/usr/bin/env bash
set -euo pipefail

IMAGE="${HOME}/kekkai-work/campaign-quota.ext4"
MOUNTPOINT="${HOME}/kekkai-work/campaign-storage"
EXPECTED_UUID="e8657221-eb6f-41ca-b087-76912b527e4b"
EXPECTED_SIZE="4294967296"

if [[ ! -f "${IMAGE}" || -L "${IMAGE}" ]]; then
  echo "Refusing: campaign image is missing or is a symlink: ${IMAGE}" >&2
  exit 1
fi
actual_size="$(stat -c '%s' "${IMAGE}")"
if [[ "${actual_size}" != "${EXPECTED_SIZE}" ]]; then
  echo "Refusing: expected ${EXPECTED_SIZE}-byte image, found ${actual_size}." >&2
  exit 1
fi
actual_type="$(sudo blkid -p -s TYPE -o value "${IMAGE}" 2>/dev/null || true)"
actual_uuid="$(sudo blkid -p -s UUID -o value "${IMAGE}" 2>/dev/null || true)"
if [[ "${actual_type}" != "ext4" || "${actual_uuid}" != "${EXPECTED_UUID}" ]]; then
  echo "Refusing: image filesystem identity does not match the pinned ext4 UUID." >&2
  exit 1
fi

mkdir -p "${MOUNTPOINT}"

if mountpoint -q "${MOUNTPOINT}"; then
  echo "Mountpoint already has a filesystem attached; verifying it without changing it."
  python3 - <<PY
from engine.storage import verify_campaign_storage
result = verify_campaign_storage("${IMAGE}", "${EXPECTED_UUID}", "${MOUNTPOINT}")
print(f"Verified {result.filesystem_uuid} on {result.device} at {result.mountpoint}")
print(f"Available bytes: {result.available_bytes}")
PY
  exit 0
fi

if find "${MOUNTPOINT}" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  echo "Refusing to mount over a non-empty directory: ${MOUNTPOINT}" >&2
  exit 1
fi
chmod 700 "${MOUNTPOINT}"

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

if ! python3 - <<PY
from engine.storage import verify_campaign_storage
result = verify_campaign_storage("${IMAGE}", "${EXPECTED_UUID}", "${MOUNTPOINT}")
print(f"Verified {result.filesystem_uuid} on {result.device} at {result.mountpoint}")
print(f"Capacity bytes: {result.capacity_bytes}")
print(f"Available bytes: {result.available_bytes}")
PY
then
  echo "Storage verification failed. Unmounting the untrusted mount." >&2
  sudo umount "${MOUNTPOINT}" || true
  if [[ "${created_loop}" == "1" ]]; then
    sudo losetup -d "${loop_device}" || true
  fi
  exit 1
fi
