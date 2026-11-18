# Campaign storage and failed-build recovery

## Campaign storage (F-07)

The libpng adapter uses schema 4 and pins both the 4 GiB ext4 image and its
filesystem UUID. `target.output_parent` is the mountpoint, not an ordinary
fuzzing directory. The preflight and campaign executor verify all of the
following before campaign output is created:

- The image is a regular, current-user-owned 4 GiB file with private mode
  `0600`, a valid ext4 superblock and the pinned UUID.
- The exact configured mountpoint is an ext4 mount exposing the filesystem
  root, with `nodev,nosuid,noexec` options.
- The mount's device number matches `/proc/self/mountinfo`; its loop device's
  sysfs `backing_file` resolves to the pinned image.
- There are no nested mounts below the campaign mountpoint.

If the volume is absent or any identity check fails, campaign execution stops
before a clean build or campaign directory is created. The image is never
formatted by the mount helper. The image must have private mode `0600`.
For an existing image with broader permissions, verify that it is the expected
user-owned image and run `chmod 600 ~/kekkai-work/campaign-quota.ext4` once.

After WSL restarts, mount the existing image with:

```bash
./scripts/mount_campaign_storage.sh
```

## Failed-build recovery (F-08)

Recovery is explicit and non-destructive. Only a build metadata schema-2
record with terminal status `failed` or `interrupted`, matching the configured
target, version, profile, and build directory, is eligible. Running and
completed builds are refused.

Run:

```bash
python3 scripts/recover_failed_build.py --config targets/libpng/adapter.toml
```

The entire build directory is atomically moved into a sibling `failed-builds/`
folder. Logs and partial outputs are retained. A `recovery.json` manifest
records the original status, timestamps, archive path, and SHA-256 of the
original `build.json`. Recovery does not delete or overwrite a prior archive
and does not automatically run as part of a campaign.
