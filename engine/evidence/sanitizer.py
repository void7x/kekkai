"""Bounded, immutable one-observation ASan/UBSan evidence collection for libpng."""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import sqlite3
import stat
import subprocess
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engine.evidence.database import canonical_json, immediate_transaction, open_database, utc_now_iso
from engine.evidence.migrations import run_migrations
from engine.evidence.repository import EvidenceRepository
from engine.evidence.store import EvidenceIntegrityError, EvidenceStore, EvidenceStoreError


POLICY_ID = "p3-03-libpng-asan-ubsan-v1"
MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_STREAM_BYTES = 8 * 1024 * 1024
MAX_RECOVERY_BYTES = 32 * 1024 * 1024
MAX_SYSTEMD_DIAGNOSTICS = 4096
SERVICE_RUNTIME_SECONDS = 5
SERVICE_RUNTIME_NAME_PREFIX = "kekkai-p3-03-"
SERVICE_UNIT_PREFIX = "kekkai-p3-03-"
GUARD_DEST_NAME = "sanitizer_exec_guard.py"
HARNESS_DEST_NAME = "kekkai_png_harness"
SYSTEMD_RUN = Path("/usr/bin/systemd-run")
SYSTEMCTL = Path("/usr/bin/systemctl")
SUDO = Path("/usr/bin/sudo")
PYTHON = Path("/usr/bin/python3")
GUARD_SOURCE = Path(__file__).with_name("sanitizer_exec_guard.py")
STAGING_AUTHORIZATION_TOKEN = bytes([1])
MANAGER_AUTHORIZATION_TOKEN = bytes([2])


class SanitizerCollectionError(RuntimeError):
    """Raised when a one-observation sanitizer attempt cannot be safely recorded."""


@dataclass(frozen=True)
class SanitizerCollectionResult:
    run_uid: str
    database_row_id: int
    execution_status: str
    assessment: str
    recovery_path: Path | None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _hash_regular_file(path: Path, maximum: int = 256 * 1024 * 1024) -> tuple[str, int]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    total = 0
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SanitizerCollectionError(f"Expected a regular file: {path}")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > maximum:
                raise SanitizerCollectionError(f"File exceeds its size limit: {path}")
            digest.update(block)
        after = os.fstat(descriptor)
        identity = lambda item: (
            item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns
        )
        if identity(before) != identity(after) or total != before.st_size:
            raise SanitizerCollectionError(f"File changed while hashing: {path}")
    finally:
        os.close(descriptor)
    return digest.hexdigest(), total


def _reject_symlink_components(path: Path) -> None:
    absolute = Path(os.path.abspath(os.fspath(path)))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise SanitizerCollectionError(f"Path contains a symlink: {current}")


def _path_overlaps(left: Path, right: Path) -> bool:
    left = Path(os.path.abspath(left))
    right = Path(os.path.abspath(right))
    return left == right or left in right.parents or right in left.parents


def _private_directory(path: Path, *, create: bool) -> Path:
    path = Path(os.path.abspath(path.expanduser()))
    _reject_symlink_components(path)
    if create and not path.exists():
        if not path.parent.is_dir():
            raise SanitizerCollectionError("Recovery directory parent must already exist.")
        os.mkdir(path, 0o700)
        parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    info = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise SanitizerCollectionError(
            f"Recovery directory must be owned by the current user with mode 0700: {path}"
        )
    return path


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        count = os.write(descriptor, view)
        if count <= 0:
            raise OSError("short file write")
        view = view[count:]


def _write_private_file(path: Path, content: bytes, *, exclusive: bool = True) -> None:
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    if exclusive:
        flags |= os.O_EXCL
    else:
        flags |= os.O_TRUNC
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        _write_all(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _write_manifest(attempt_dir: Path, manifest: dict[str, Any]) -> None:
    manifest["updated_at"] = _now()
    payload = (json.dumps(manifest, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    temporary = attempt_dir / f".manifest-{uuid.uuid4().hex}.tmp"
    _write_private_file(temporary, payload)
    os.replace(temporary, attempt_dir / "manifest.json")
    descriptor = os.open(attempt_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _open_recovery_lock(recovery_root: Path) -> int:
    path = recovery_root / "recovery.lock"
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise SanitizerCollectionError("Recovery lock must be a private user-owned regular file.")
    fcntl.flock(descriptor, fcntl.LOCK_EX)
    return descriptor


def _safe_remove_attempt(path: Path) -> None:
    allowed = {"manifest.json", "input.bin", "stdout.bin", "stderr.bin"}
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise SanitizerCollectionError(f"Refusing to remove unsafe recovery directory: {path}")
    for entry in path.iterdir():
        entry_info = entry.lstat()
        if entry.name.startswith(".manifest-") and entry.name.endswith(".tmp"):
            if not stat.S_ISREG(entry_info.st_mode) or entry_info.st_uid != os.getuid():
                raise SanitizerCollectionError(f"Unsafe temporary manifest: {entry}")
        elif entry.name not in allowed or not stat.S_ISREG(entry_info.st_mode) or entry_info.st_uid != os.getuid():
            raise SanitizerCollectionError(f"Unexpected recovery entry; preserving it: {entry}")
        entry.unlink()
    path.rmdir()
    parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _reconcile_recovery(recovery_root: Path, repository: EvidenceRepository) -> None:
    for entry in sorted(recovery_root.iterdir(), key=lambda item: item.name):
        if entry.name == "recovery.lock":
            continue
        info = entry.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise SanitizerCollectionError(f"Unexpected recovery entry; preserving it: {entry}")
        manifest_path = entry / "manifest.json"
        try:
            manifest_info = manifest_path.lstat()
            if not stat.S_ISREG(manifest_info.st_mode) or manifest_info.st_uid != os.getuid():
                raise SanitizerCollectionError(f"Unsafe recovery manifest; preserving {entry}")
            if manifest_info.st_size > 64 * 1024:
                raise SanitizerCollectionError(f"Recovery manifest is oversized; preserving {entry}")
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            run_uid = manifest.get("run_uid")
            if not isinstance(run_uid, str):
                raise SanitizerCollectionError(f"Recovery manifest has no run UID; preserving {entry}")
        except FileNotFoundError as exc:
            raise SanitizerCollectionError(
                f"Unresolved recovery directory has no manifest; preserve and inspect {entry}"
            ) from exc
        if not entry.name == f"run-{run_uid}":
            raise SanitizerCollectionError(f"Recovery directory/manifest identity mismatch: {entry}")
        recorded = repository.get_sanitizer_run(run_uid)
        if recorded is None:
            raise SanitizerCollectionError(
                f"Unresolved prior attempt {run_uid}; preserve and recover it before another run: {entry}"
            )
        if (
            recorded.get("recovery_path") is not None
            or recorded.get("cleanup_status") == "failed"
            or recorded.get("stdout_publication_state") == "pending_recovery"
            or recorded.get("stderr_publication_state") == "pending_recovery"
        ):
            raise SanitizerCollectionError(
                f"Attempt {run_uid} has recorded recovery work; preserve {entry} and resolve it before another run."
            )
        _safe_remove_attempt(entry)


def _load_systemd_version() -> str:
    try:
        result = subprocess.run(
            [str(SYSTEMCTL), "--version"], cwd="/", env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=3, check=False, shell=False, close_fds=True,
        )
        if result.returncode == 0:
            return result.stdout.decode("utf-8", errors="replace").splitlines()[0][:255]
    except (OSError, subprocess.TimeoutExpired, IndexError):
        pass
    return "unavailable"


def _load_wsl_version() -> str | None:
    executable = shutil.which("wsl.exe")
    if executable is None:
        return None
    try:
        result = subprocess.run(
            [executable, "--version"], cwd="/",
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            timeout=3, check=False, shell=False, close_fds=True,
        )
        if result.returncode == 0:
            return result.stdout.decode("utf-8", errors="replace")[:255]
    except (OSError, subprocess.TimeoutExpired):
        pass
    return None


def _parse_properties(output: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in output.decode("utf-8", errors="replace").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def _trusted_system_executable(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat(follow_symlinks=False)
    except OSError as exc:
        raise SanitizerCollectionError(f"Required system executable is unavailable: {path}: {exc}") from exc
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not os.access(resolved, os.X_OK)
        or not resolved.is_relative_to(Path("/usr/bin"))
    ):
        raise SanitizerCollectionError(f"System executable is not a trusted root-owned binary: {path}")
    return resolved


def _sudo(argv: list[str], *, timeout: float = 5, capture: bool = True) -> subprocess.CompletedProcess:
    if any(not isinstance(item, str) or "\x00" in item for item in argv):
        raise SanitizerCollectionError("Invalid privileged command argument.")
    try:
        return subprocess.run(
            [str(SUDO), "-n", *argv],
            cwd="/",
            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
            stderr=subprocess.PIPE if capture else subprocess.DEVNULL,
            timeout=timeout,
            check=False,
            shell=False,
            close_fds=True,
        )
    except subprocess.TimeoutExpired as exc:
        raise SanitizerCollectionError(f"Privileged command timed out: {argv[0]}") from exc
    except OSError as exc:
        raise SanitizerCollectionError(f"Cannot execute privileged command {argv[0]}: {exc}") from exc


def _read_service_file(path: Path, maximum: int) -> bytes | None:
    reader = r'''
import os, stat, sys
path = sys.argv[1]
maximum = int(sys.argv[2])
fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
try:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600:
        raise SystemExit(21)
    if before.st_uid == 0 or before.st_nlink != 1 or before.st_size < 0 or before.st_size > maximum:
        raise SystemExit(22)
    chunks = []
    total = 0
    while True:
        chunk = os.read(fd, 65536)
        if not chunk:
            break
        total += len(chunk)
        if total > maximum:
            raise SystemExit(23)
        chunks.append(chunk)
    after = os.fstat(fd)
    identity = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
    if identity(before) != identity(after) or total != before.st_size:
        raise SystemExit(24)
    sys.stdout.buffer.write(b"".join(chunks))
finally:
    os.close(fd)
'''
    result = _sudo([str(PYTHON), "-c", reader, str(path), str(maximum)], timeout=5)
    if result.returncode == 1:
        return None
    if result.returncode != 0:
        raise SanitizerCollectionError(
            f"Cannot safely read systemd service output {path} (exit {result.returncode})."
        )
    return result.stdout


def _stage_root_file(
    source: Path,
    destination: Path,
    expected_sha256: str,
    maximum: int,
) -> tuple[str, int]:
    """Create a root-owned immutable copy in /run for a read-only system-service bind."""
    if (
        destination.parent != Path("/run")
        or not destination.name.startswith("kekkai-p3-03-stage-")
        or not re.fullmatch(r"kekkai-p3-03-stage-[0-9a-f]{32}-(input|harness|guard)", destination.name)
    ):
        raise SanitizerCollectionError("Invalid private system-service staging destination.")
    helper = r'''
import hashlib, os, stat, sys
source, destination, expected, maximum, owner = sys.argv[1:]
maximum, owner = int(maximum), int(owner)
fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
out = None
created = False
try:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != owner:
        raise RuntimeError("source is not a regular file owned by the invoking user")
    if before.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise RuntimeError("source file is group/world writable")
    if before.st_size < 0 or before.st_size > maximum:
        raise RuntimeError("source exceeds the staging size limit")
    out = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o400)
    created = True
    digest, total = hashlib.sha256(), 0
    while True:
        block = os.read(fd, 65536)
        if not block:
            break
        total += len(block)
        if total > maximum:
            raise RuntimeError("source grew beyond the staging size limit")
        digest.update(block)
        view = memoryview(block)
        while view:
            count = os.write(out, view)
            if count <= 0:
                raise OSError("short root staging write")
            view = view[count:]
    after = os.fstat(fd)
    identity = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
    actual = digest.hexdigest()
    if identity(before) != identity(after) or total != before.st_size:
        raise RuntimeError("source changed during root staging")
    if actual != expected:
        raise RuntimeError("source digest differs from the registered identity")
    os.fchmod(out, 0o400)
    os.fsync(out)
    os.close(out)
    out = None
    directory = os.open("/run", os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(actual + "\\t" + str(total))
except BaseException:
    if out is not None:
        os.close(out)
    if created:
        try:
            os.unlink(destination)
        except FileNotFoundError:
            pass
    raise
finally:
    os.close(fd)
'''
    result = _sudo(
        [str(PYTHON), "-c", helper, str(source), str(destination),
         expected_sha256, str(maximum), str(os.getuid())],
        timeout=10,
    )
    if result.returncode != 0:
        raise SanitizerCollectionError(
            "Cannot create verified root-owned service input: "
            + result.stderr.decode("utf-8", errors="replace")[:1024]
        )
    try:
        digest, size = result.stdout.decode("ascii").strip().split("\\t", 1)
        size_value = int(size)
    except (UnicodeError, ValueError) as exc:
        raise SanitizerCollectionError("Root staging helper returned malformed identity data.") from exc
    if digest != expected_sha256 or size_value < 0 or size_value > maximum:
        raise SanitizerCollectionError("Root staging helper returned an unexpected file identity.")
    return digest, size_value


def _set_root_staged_owner(paths: list[Path], properties: dict[str, str]) -> tuple[int, int]:
    """Transfer read-only staged files to the exact non-root UID running the guard."""
    if not paths:
        raise SanitizerCollectionError("No private staging files were prepared.")
    try:
        main_pid = int(properties.get("MainPID", "0"))
    except ValueError as exc:
        raise SanitizerCollectionError("System manager did not expose a valid service MainPID.") from exc
    control_group = properties.get("ControlGroup", "")
    if main_pid <= 1 or not control_group.startswith("/system.slice/") or ".." in Path(control_group).parts:
        raise SanitizerCollectionError("Cannot establish the transient service process identity.")
    helper = r'''
import os, pathlib, stat, sys
pid, expected_cgroup, *raw_paths = sys.argv[1:]
proc = pathlib.Path("/proc") / pid
status = {}
for line in (proc / "status").read_text(encoding="ascii").splitlines():
    if ":" in line:
        key, value = line.split(":", 1)
        status[key] = value.strip()
cgroups = (proc / "cgroup").read_text(encoding="ascii").splitlines()
rows = [line.split("::", 1)[1] for line in cgroups if line.startswith("0::")]
if rows != [expected_cgroup]:
    raise RuntimeError("MainPID is not in the expected systemd service cgroup")
uids = status.get("Uid", "").split()
gids = status.get("Gid", "").split()
if len(uids) != 4 or len(gids) != 4:
    raise RuntimeError("Cannot read effective service UID/GID")
uid, gid = int(uids[1]), int(gids[1])
if uid <= 0 or gid <= 0:
    raise RuntimeError("Dynamic service identity must be non-root")
paths = [pathlib.Path(raw) for raw in raw_paths]
for path in paths:
    if path.parent != pathlib.Path("/run") or not path.name.startswith("kekkai-p3-03-stage-"):
        raise RuntimeError("staging path is outside the fixed /run namespace")
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o400 or info.st_nlink != 1:
        raise RuntimeError("staging file identity changed before ownership transfer")
changed = []
try:
    for path in paths:
        os.chown(path, uid, gid, follow_symlinks=False)
        os.chmod(path, 0o400, follow_symlinks=False)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        changed.append(path)
except BaseException:
    for path in changed:
        try:
            os.chown(path, 0, 0, follow_symlinks=False)
            os.chmod(path, 0o400, follow_symlinks=False)
        except OSError:
            pass
    raise
directory = os.open("/run", os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
print(str(uid) + "\\t" + str(gid))
'''
    result = _sudo(
        [str(PYTHON), "-c", helper, str(main_pid), control_group, *[str(item) for item in paths]],
        timeout=5,
    )
    if result.returncode != 0:
        raise SanitizerCollectionError(
            "Cannot assign private staging files to the DynamicUser: "
            + result.stderr.decode("utf-8", errors="replace")[:1024]
        )
    try:
        uid, gid = (
            int(item)
            for item in result.stdout.decode("ascii").strip().split("\\t", 1)
        )
    except (UnicodeError, ValueError) as exc:
        raise SanitizerCollectionError("DynamicUser ownership helper returned malformed identity data.") from exc
    return uid, gid


def _root_hash_regular_file(
    path: Path,
    maximum: int,
    expected_uid: int | None,
) -> tuple[str, int]:
    if expected_uid is None or path.parent != Path("/run"):
        raise SanitizerCollectionError("Root-staged file has no verified DynamicUser owner.")
    helper = r'''
import hashlib, os, pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
maximum, expected_uid = int(sys.argv[2]), int(sys.argv[3])
if path.parent != pathlib.Path("/run"):
    raise RuntimeError("staged path is outside /run")
fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
digest, total = hashlib.sha256(), 0
try:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != expected_uid or stat.S_IMODE(before.st_mode) != 0o400 or before.st_nlink != 1:
        raise RuntimeError("staged file ownership or mode differs from the verified DynamicUser identity")
    while True:
        block = os.read(fd, 65536)
        if not block:
            break
        total += len(block)
        if total > maximum:
            raise RuntimeError("staged file exceeds the configured bound")
        digest.update(block)
    after = os.fstat(fd)
    identity = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
    if identity(before) != identity(after) or total != before.st_size:
        raise RuntimeError("staged file changed while hashing")
    print(digest.hexdigest() + chr(9) + str(total))
finally:
    os.close(fd)
'''
    result = _sudo(
        [str(PYTHON), "-c", helper, str(path), str(maximum), str(expected_uid)],
        timeout=5,
    )
    if result.returncode != 0:
        raise SanitizerCollectionError(
            f"Cannot verify private staged file {path.name}: "
            + result.stderr.decode("utf-8", errors="replace")[:1024]
        )
    try:
        digest, size = result.stdout.decode("ascii").strip().split(chr(9), 1)
        return digest, int(size)
    except (UnicodeError, ValueError) as exc:
        raise SanitizerCollectionError("Root hash helper returned malformed identity data.") from exc


def _remove_root_staged_files(
    paths: list[Path],
    expected_uid: int | None = None,
) -> tuple[bool, str | None]:
    if not paths:
        return True, None
    owner_ids = "0" if expected_uid is None else f"0,{expected_uid}"
    helper = r'''
import os, pathlib, re, stat, sys
allowed_owners = {int(item) for item in sys.argv[1].split(",")}
for raw in sys.argv[2:]:
    path = pathlib.Path(raw)
    if path.parent != pathlib.Path("/run") or not re.fullmatch(r"kekkai-p3-03-stage-[0-9a-f]{32}-(input|harness|guard)", path.name):
        raise RuntimeError("refusing to remove a path outside the exact P3-03 staging namespace")
    try:
        info = path.lstat()
    except FileNotFoundError:
        continue
    if not stat.S_ISREG(info.st_mode) or info.st_uid not in allowed_owners or stat.S_IMODE(info.st_mode) != 0o400 or info.st_nlink != 1:
        raise RuntimeError("staging path identity changed; preserving it")
    path.unlink()
directory = os.open("/run", os.O_RDONLY | os.O_DIRECTORY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
'''
    result = _sudo(
        [str(PYTHON), "-c", helper, owner_ids, *[str(item) for item in paths]],
        timeout=5,
    )
    if result.returncode != 0:
        return False, result.stderr.decode("utf-8", errors="replace")[:1024]
    return True, None

def _check_context(
    connection: sqlite3.Connection,
    context: dict[str, object],
) -> None:
    required = {
        "target_version": "1.6.59",
        "source_build_role": "fuzz",
        "source_build_status": "completed",
        "diagnostic_build_role": "diagnostic_replay",
        "diagnostic_build_status": "completed",
        "diagnostic_build_profile": "libpng-asan-ubsan",
        "campaign_status": "completed",
    }
    for key, expected in required.items():
        if context.get(key) != expected:
            raise SanitizerCollectionError(
                f"Evidence preflight rejected {key}: expected {expected!r}, found {context.get(key)!r}."
            )
    target = connection.execute(
        "SELECT name FROM targets WHERE id = ?", (context["target_id"],)
    ).fetchone()
    if target is None or target[0] != "libpng":
        raise SanitizerCollectionError("Selected observation does not belong to the libpng target.")
    if context.get("original_artifact_size") is None:
        raise SanitizerCollectionError("Original observation artifact has no recorded size.")
    maximum = min(int(context["max_input_bytes"]), MAX_INPUT_BYTES)
    if int(context["original_artifact_size"]) > maximum:
        raise SanitizerCollectionError("Original testcase exceeds the P3-03 8 MiB input ceiling.")
    if int(context["original_artifact_size"]) < 0:
        raise SanitizerCollectionError("Original testcase has an invalid recorded size.")
    try:
        source_config = json.loads(str(context["diagnostic_sanitizer_config_json"]))
    except (ValueError, TypeError) as exc:
        raise SanitizerCollectionError("Diagnostic build sanitizer configuration is invalid.") from exc
    if source_config != {
        "address": "enabled",
        "frame_pointers": True,
        "undefined_behavior": "enabled",
    }:
        raise SanitizerCollectionError("Registered diagnostic build does not declare the approved sanitizer profile.")


def _verify_diagnostic_build(context: dict[str, object]) -> tuple[Path, dict[str, Any]]:
    build_dir = Path(str(context["diagnostic_build_dir"]))
    _reject_symlink_components(build_dir)
    build_dir = build_dir.resolve(strict=True)
    build_info = build_dir.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(build_info.st_mode)
        or build_info.st_uid != os.getuid()
        or stat.S_IMODE(build_info.st_mode) != 0o700
    ):
        raise SanitizerCollectionError("Diagnostic build directory must be a private user-owned directory.")
    metadata_path = build_dir / "build.json"
    metadata_info = metadata_path.stat(follow_symlinks=False)
    if (
        not stat.S_ISREG(metadata_info.st_mode)
        or metadata_info.st_uid != os.getuid()
        or stat.S_IMODE(metadata_info.st_mode) != 0o600
    ):
        raise SanitizerCollectionError("Diagnostic build metadata must be a private user-owned regular file.")
    metadata_digest, _ = _hash_regular_file(metadata_path, 4 * 1024 * 1024)
    if metadata_digest != context["diagnostic_build_metadata_sha256"]:
        raise SanitizerCollectionError("Diagnostic build metadata no longer matches the registered digest.")
    try:
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise SanitizerCollectionError(f"Cannot read diagnostic build metadata: {exc}") from exc
    expected = {
        "schema_version": 2,
        "status": "completed",
        "target": "libpng",
        "target_version": "1.6.59",
        "profile": "libpng-asan-ubsan",
        "build_role": "diagnostic_replay",
        "source_archive_sha256": context["source_archive_sha256"],
        "source_tree_sha256": context["source_tree_sha256"],
        "harness_source_sha256": context["diagnostic_harness_source_sha256"],
    }
    for key, value in expected.items():
        if metadata.get(key) != value:
            raise SanitizerCollectionError(f"Diagnostic build metadata mismatch for {key}.")
    compiler = metadata.get("tools", {}).get("clang", {})
    if not str(compiler.get("version", "")).startswith("Ubuntu clang version 21.1.8"):
        raise SanitizerCollectionError("Diagnostic build did not use the approved Clang 21.1.8 toolchain.")
    compiler_path = Path(str(compiler.get("path", "")))
    _reject_symlink_components(compiler_path)
    compiler_path = compiler_path.resolve(strict=True)
    approved_compiler = Path("/usr/bin/clang").resolve(strict=True)
    if compiler_path != approved_compiler:
        raise SanitizerCollectionError("Diagnostic compiler path differs from the approved Clang executable.")
    compiler_info = compiler_path.stat(follow_symlinks=False)
    if compiler_info.st_uid != 0 or compiler_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise SanitizerCollectionError("Diagnostic compiler is not a trusted root-owned system executable.")
    compiler_hash, _ = _hash_regular_file(compiler_path, 128 * 1024 * 1024)
    if compiler_hash != compiler.get("sha256") or not compiler.get("package"):
        raise SanitizerCollectionError("Diagnostic compiler binary/package identity changed since build.")
    runtimes = metadata.get("sanitizer_runtimes")
    expected_runtime_names = {
        "libclang_rt.asan-x86_64.a",
        "libclang_rt.ubsan_standalone-x86_64.a",
    }
    if not isinstance(runtimes, dict) or set(runtimes) != expected_runtime_names:
        raise SanitizerCollectionError("Diagnostic build lacks the exact approved ASan/UBSan runtime set.")
    resource_dir = Path(str(metadata.get("clang_resource_directory", "")))
    _reject_symlink_components(resource_dir)
    resource_dir = resource_dir.resolve(strict=True)
    if not resource_dir.is_relative_to(Path("/usr/lib/llvm-21")):
        raise SanitizerCollectionError("Clang resource directory is outside the approved LLVM 21 installation.")
    for runtime_name, item in runtimes.items():
        runtime_path = Path(str(item.get("path", "")))
        _reject_symlink_components(runtime_path)
        runtime_path = runtime_path.resolve(strict=True)
        runtime_info = runtime_path.stat(follow_symlinks=False)
        if runtime_path.name != runtime_name or not runtime_path.is_relative_to(resource_dir):
            raise SanitizerCollectionError(f"Sanitizer runtime is outside the Clang resource directory: {runtime_name}")
        if runtime_info.st_uid != 0 or runtime_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise SanitizerCollectionError(f"Sanitizer runtime is not a trusted system file: {runtime_name}")
        if _hash_regular_file(runtime_path)[0] != item.get("sha256") or not item.get("package"):
            raise SanitizerCollectionError(f"Sanitizer runtime identity changed: {runtime_name}")
    zlib = metadata.get("zlib", {})
    zlib_path = Path(str(zlib.get("library", "")))
    _reject_symlink_components(zlib_path)
    zlib_path = zlib_path.resolve(strict=True)
    expected_zlib_path = Path("/usr/lib/x86_64-linux-gnu/libz.so").resolve(strict=True)
    zlib_info = zlib_path.stat(follow_symlinks=False)
    if (
        zlib_path != expected_zlib_path
        or zlib.get("version") != "1.3.1"
        or not zlib_info.st_uid == 0
        or zlib_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or _hash_regular_file(zlib_path)[0] != zlib.get("sha256")
    ):
        raise SanitizerCollectionError("The uninstrumented system zlib identity changed since diagnostic build.")
    harness_source = Path(str(metadata.get("harness_source_path", "")))
    expected_harness_source = Path(__file__).resolve().parents[2] / "targets/libpng/png_read_harness.c"
    _reject_symlink_components(harness_source)
    if harness_source.resolve(strict=True) != expected_harness_source.resolve(strict=True):
        raise SanitizerCollectionError("Diagnostic harness source path differs from the repository-owned file.")
    if _hash_regular_file(harness_source, 1024 * 1024)[0] != context["diagnostic_harness_source_sha256"]:
        raise SanitizerCollectionError("Repository harness source changed since diagnostic build.")
    verification = metadata.get("verification", {})
    probes = verification.get("runtime_probes", {})
    if not (
        probes.get("address", {}).get("marker_observed") is True
        and probes.get("undefined_behavior", {}).get("marker_observed") is True
    ):
        raise SanitizerCollectionError("Diagnostic sanitizer runtime self-tests are not recorded as successful.")
    artifacts = metadata.get("artifacts", {})
    db_artifacts = {
        "harness_binary": context["diagnostic_harness_binary_sha256"],
        "library_archive": context["diagnostic_library_archive_sha256"],
    }
    for name, expected_hash in db_artifacts.items():
        item = artifacts.get(name)
        if not isinstance(item, dict) or item.get("sha256") != expected_hash:
            raise SanitizerCollectionError(f"Registered diagnostic {name} hash does not match build metadata.")
    for name, item in artifacts.items():
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            raise SanitizerCollectionError(f"Malformed diagnostic build artifact entry: {name}")
        path = Path(item["path"])
        if not path.is_absolute() or not path.resolve(strict=True).is_relative_to(build_dir):
            raise SanitizerCollectionError(f"Diagnostic build artifact escapes the build directory: {name}")
        digest, size = _hash_regular_file(path, 256 * 1024 * 1024)
        if digest != item.get("sha256") or size != item.get("size_bytes"):
            raise SanitizerCollectionError(f"Diagnostic build artifact changed after registration: {name}")
    harness = Path(str(context["diagnostic_harness_binary_path"]))
    if harness != Path(str(metadata.get("harness_binary_path", ""))):
        raise SanitizerCollectionError("Registered harness path differs from diagnostic build metadata.")
    if not harness.resolve(strict=True).is_relative_to(build_dir):
        raise SanitizerCollectionError("Diagnostic harness is outside the registered build directory.")
    mode = harness.stat(follow_symlinks=False).st_mode
    if not stat.S_ISREG(mode) or not mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH):
        raise SanitizerCollectionError("Diagnostic harness is not a regular executable file.")
    if not _hash_regular_file(harness, 32 * 1024 * 1024)[0] == context["diagnostic_harness_binary_sha256"]:
        raise SanitizerCollectionError("Diagnostic harness digest changed after registration.")
    return harness.resolve(strict=True), metadata


def _resource_policy() -> dict[str, object]:
    return {
        "service_type": "exec",
        "dynamic_user": True,
        "no_new_privileges": True,
        "capability_bounding_set": [],
        "protect_control_groups": "strict",
        "delegate": False,
        "memory_max_bytes": 1024 * 1024 * 1024,
        "memory_swap_max_bytes": 0,
        "memory_accounting": True,
        "cpu_accounting": True,
        "cpu_quota_percent": 60,
        "cpu_quota_period_usec": 100000,
        "runtime_max_usec": 5000000,
        "tasks_max": 32,
        "kill_mode": "control-group",
        "timeout_stop_usec": 1000000,
        "send_sigkill": True,
        "limit_core": 0,
    }


def _parse_systemd_usec(value: str) -> int | None:
    import re
    from decimal import Decimal, InvalidOperation

    match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)(ns|us|µs|ms|s|min|h)?", value.strip())
    if match is None:
        return None
    try:
        number = Decimal(match.group(1))
    except InvalidOperation:
        return None
    multiplier = {
        "ns": Decimal("0.001"),
        "us": Decimal(1),
        "µs": Decimal(1),
        "ms": Decimal(1000),
        "s": Decimal(1000000),
        "min": Decimal(60000000),
        "h": Decimal(3600000000),
        None: Decimal(1),
    }[match.group(2)]
    result = number * multiplier
    if result != result.to_integral_value():
        return None
    return int(result)


def _verify_systemd_properties(properties: dict[str, str]) -> dict[str, Any]:
    expected = {
        "LoadState": "loaded",
        "ActiveState": "active",
        "SubState": "running",
        "Type": "exec",
        "DynamicUser": "yes",
        "NoNewPrivileges": "yes",
        "CapabilityBoundingSet": "",
        "Delegate": "no",
        "ProtectControlGroups": "strict",
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        "PrivateTmp": "yes",
        "MemoryAccounting": "yes",
        "CPUAccounting": "yes",
        "MemorySwapMax": "0",
        "TasksMax": "32",
        "KillMode": "control-group",
        "LimitCORE": "0",
        "SendSIGKILL": "yes",
        "RuntimeDirectoryPreserve": "yes",
        "RemainAfterExit": "yes",
    }
    issues = []
    for key, value in expected.items():
        if properties.get(key) != value:
            issues.append(f"{key}: expected {value!r}, found {properties.get(key)!r}")
    try:
        memory_max = int(properties.get("MemoryMax", ""))
    except ValueError:
        memory_max = -1
    if memory_max != 1024 * 1024 * 1024:
        issues.append(f"MemoryMax: expected 1073741824, found {properties.get('MemoryMax')!r}")
    if _parse_systemd_usec(properties.get("RuntimeMaxUSec", "")) != 5000000:
        issues.append(f"RuntimeMaxUSec: expected 5000000 usec, found {properties.get('RuntimeMaxUSec')!r}")
    if _parse_systemd_usec(properties.get("TimeoutStopUSec", "")) != 1000000:
        issues.append(f"TimeoutStopUSec: expected 1000000 usec, found {properties.get('TimeoutStopUSec')!r}")
    cpu_quota = _parse_systemd_usec(properties.get("CPUQuotaPerSecUSec", ""))
    if cpu_quota != 600000:
        issues.append(f"CPUQuotaPerSecUSec: expected 600000 usec, found {properties.get('CPUQuotaPerSecUSec')!r}")
    cpu_period = _parse_systemd_usec(properties.get("CPUQuotaPeriodUSec", ""))
    if cpu_period != 100000:
        issues.append(f"CPUQuotaPeriodUSec: expected 100000 usec, found {properties.get('CPUQuotaPeriodUSec')!r}")
    try:
        main_pid = int(properties.get("MainPID", "0"))
    except ValueError:
        main_pid = 0
    if main_pid <= 1:
        issues.append(f"MainPID: expected an active guard process, found {properties.get('MainPID')!r}")
    if not properties.get("ControlGroup", "").startswith("/system.slice/"):
        issues.append(f"ControlGroup: expected an attempt-owned system service cgroup, found {properties.get('ControlGroup')!r}")
    return {"passed": not issues, "issues": issues}


def _diagnostic_capture(raw: bytes | None) -> dict[str, Any] | None:
    if raw is None:
        return None
    return {
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size_bytes": len(raw),
        "preview": raw[:512].decode("utf-8", errors="replace"),
    }


def _systemd_show(unit: str) -> dict[str, str]:
    properties = (
        "LoadState", "ActiveState", "SubState", "Result", "MainPID", "ExecMainCode", "ExecMainStatus",
        "ExecMainStartTimestamp", "ExecMainExitTimestamp", "MemoryCurrent",
        "MemoryPeak", "MemorySwapCurrent", "CPUUsageNSec", "TasksCurrent",
        "ControlGroup", "Delegate", "User", "Type", "DynamicUser",
        "NoNewPrivileges", "CapabilityBoundingSet", "MemoryAccounting",
        "CPUAccounting", "MemoryMax", "MemorySwapMax", "CPUQuotaPerSecUSec",
        "CPUQuotaPeriodUSec", "TasksMax", "KillMode", "RuntimeDirectoryPreserve",
        "ProtectControlGroups", "ProtectSystem", "ProtectHome", "PrivateTmp",
        "LimitCORE", "RuntimeMaxUSec", "TimeoutStopUSec", "SendSIGKILL",
        "RemainAfterExit",
    )
    command = [str(SYSTEMCTL), "show", "--no-pager"]
    for name in properties:
        command.append("--property=" + name)
    command.append(unit)
    result = _sudo(command, timeout=5)
    if result.returncode != 0:
        return {"show_error": result.stderr.decode("utf-8", errors="replace")[:2048]}
    return _parse_properties(result.stdout)


def _stop_and_verify_service(unit: str, properties: dict[str, str]) -> tuple[bool, str | None, dict[str, str]]:
    """Stop the attempt unit and require positive evidence that its subtree is empty."""
    stopped = _sudo([str(SYSTEMCTL), "stop", unit], timeout=7)
    final = _systemd_show(unit)
    if final.get("LoadState") == "not-found":
        # A positive manager response that the unit is absent proves there is no live unit.
        final["cgroup_populated"] = "not-found"
        return True, None, final
    if "show_error" in final:
        detail = "Final systemd inspection failed; service cleanup is unverified: " + final["show_error"]
        return False, detail[:1024], final
    if "show_error" in properties and not final.get("ControlGroup"):
        detail = "Initial and final systemd inspection could not establish the unit cgroup."
        return False, detail, final

    detail: str | None = None
    if stopped.returncode != 0:
        detail = stopped.stderr.decode("utf-8", errors="replace")[:1024]
    active = final.get("ActiveState")
    cgroup = properties.get("ControlGroup") or final.get("ControlGroup")
    populated: str | None = None
    if cgroup and cgroup.startswith("/system.slice/") and ".." not in Path(cgroup).parts:
        cgroup_events = Path("/sys/fs/cgroup") / cgroup.lstrip("/") / "cgroup.events"
        event_result = _sudo(
            [str(PYTHON), "-c",
             "import pathlib,sys; print(pathlib.Path(sys.argv[1]).read_text())",
             str(cgroup_events)],
            timeout=3,
        )
        if event_result.returncode == 0:
            for line in event_result.stdout.decode("ascii", errors="replace").splitlines():
                if line.startswith("populated "):
                    populated = line.split()[1]
                    break
    cgroup_path = Path("/sys/fs/cgroup") / str(cgroup or "").lstrip("/")
    cgroup_gone = bool(cgroup) and not cgroup_path.exists()
    okay = stopped.returncode == 0 and active in ("inactive", "failed") and (
        populated == "0" or cgroup_gone
    )
    if not okay and detail is None:
        detail = (
            "Service cleanup not verified "
            f"(ActiveState={active!r}, populated={populated!r}, "
            f"initial_inspection_failed={'show_error' in properties})."
        )
    final["cgroup_populated"] = populated or ("removed" if cgroup_gone else "unknown")
    return okay, detail, final

def _clean_service_runtime(unit: str) -> tuple[bool, str | None]:
    clean = _sudo([str(SYSTEMCTL), "clean", "--what=runtime", unit], timeout=5)
    if clean.returncode != 0:
        return False, clean.stderr.decode("utf-8", errors="replace")[:1024]
    reset = _sudo([str(SYSTEMCTL), "reset-failed", unit], timeout=5)
    if reset.returncode not in (0, 1):
        return False, reset.stderr.decode("utf-8", errors="replace")[:1024]
    return True, None


def _systemd_run_argv(
    unit: str,
    runtime_name: str,
    input_source: Path,
    harness_source: Path,
    guard_source: Path,
    input_sha256: str,
    input_size: int,
    harness_sha256: str,
) -> list[str]:
    runtime_dir = Path("/run") / runtime_name
    guard_dest = runtime_dir / GUARD_DEST_NAME
    harness_dest = runtime_dir / HARNESS_DEST_NAME
    input_dest = runtime_dir / "input.bin"
    properties = [
        "DynamicUser=yes",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=",
        "Delegate=no",
        "ProtectControlGroups=strict",
        "ProtectSystem=strict",
        "ProtectHome=yes",
        "PrivateTmp=yes",
        "MemoryAccounting=yes",
        "CPUAccounting=yes",
        "MemoryMax=1G",
        "MemorySwapMax=0",
        "CPUQuota=60%",
        "CPUQuotaPeriodSec=100ms",
        "TasksMax=32",
        "RuntimeMaxSec=5s",
        "KillMode=control-group",
        "TimeoutStopSec=1s",
        "SendSIGKILL=yes",
        "LimitCORE=0",
        f"RuntimeDirectory={runtime_name}",
        "RuntimeDirectoryMode=0700",
        "RuntimeDirectoryPreserve=yes",
        f"BindReadOnlyPaths={input_source}:{input_dest}",
        f"BindReadOnlyPaths={harness_source}:{harness_dest}",
        f"BindReadOnlyPaths={guard_source}:{guard_dest}",
        f"WorkingDirectory={runtime_dir}",
    ]
    argv = [
        str(SYSTEMD_RUN), "--system", "--quiet", "--pipe", "--remain-after-exit",
        "--unit=" + unit, "--service-type=exec",
    ]
    argv.extend("--property=" + value for value in properties)
    argv.extend([
        str(PYTHON), str(guard_dest),
        "--expected-input-sha256", input_sha256,
        "--expected-input-size", str(input_size),
        "--expected-harness-sha256", harness_sha256,
        "--harness-path", str(harness_dest),
        "--input-path", str(input_dest),
    ])
    for path in (input_source, harness_source, guard_source):
        if ":" in str(path) or "\\n" in str(path):
            raise SanitizerCollectionError("Systemd source paths may not contain ':' or newline characters.")
    return argv

def _classify_output(stdout: bytes, stderr: bytes, status: dict[str, Any]) -> tuple[list[str], str]:
    families: set[str] = set()
    identity_verified = status.get("execution_identity_verified", True) is True
    for stream in (stdout, stderr):
        if b"ERROR: AddressSanitizer:" in stream:
            families.add("address")
        if b"ERROR: LeakSanitizer:" in stream:
            families.add("leak")
        if b"runtime error:" in stream:
            families.add("undefined_behavior")
    ordered = sorted(families)
    if status.get("harness_exec_succeeded") is True and identity_verified and ordered:
        return ordered, "report_signature_observed"
    complete = (
        status.get("systemd_policy_verified") is True
        and status.get("execution_status") == "exited"
        and status.get("exit_code") == 0
        and status.get("harness_exec_succeeded") is True
        and identity_verified
        and status.get("stdout_capture_state") == "complete"
        and status.get("stderr_capture_state") == "complete"
        and status.get("stdout_truncated") is False
        and status.get("stderr_truncated") is False
        and status.get("stdout_publication_state") == "published"
        and status.get("stderr_publication_state") == "published"
        and not ordered
    )
    return ordered, "no_signature_observed" if complete else "inconclusive"


def _read_guard_status(runtime_dir: Path) -> dict[str, Any] | None:
    raw = _read_service_file(runtime_dir / "status.json", 64 * 1024)
    if raw is None:
        return None
    try:
        value = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise SanitizerCollectionError("Guard status file is not valid JSON.") from exc
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        raise SanitizerCollectionError("Guard status file has an unsupported schema.")
    return value


def _wait_for_guard_ready(
    process: subprocess.Popen,
    runtime_dir: Path,
    expected_state: str,
    timeout: float = 3.0,
) -> tuple[dict[str, Any] | None, str | None]:
    deadline = time.monotonic() + timeout
    last_error: str | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            break
        probe = _sudo(["/usr/bin/test", "-d", str(runtime_dir)], timeout=1)
        if probe.returncode == 0:
            try:
                status = _read_guard_status(runtime_dir)
            except SanitizerCollectionError as exc:
                last_error = str(exc)
                status = None
            if status is not None:
                state = status.get("guard_state")
                if state == expected_state:
                    return status, None
                if state in (
                    "preflight_blocked", "staging_authorization_refused",
                    "manager_authorization_refused", "launch_failed", "finished",
                ):
                    return status, str(status.get("detail") or f"Guard stopped in state {state}.")
        elif probe.returncode not in (1,):
            last_error = "Could not inspect the transient service RuntimeDirectory."
        time.sleep(0.1)
    return None, last_error or f"Guard did not reach {expected_state!r} before the deadline."


def _wait_for_guard_completion(
    process: subprocess.Popen,
    runtime_dir: Path,
    timeout: float = SERVICE_RUNTIME_SECONDS + 1.0,
) -> tuple[dict[str, Any] | None, str | None]:
    """Wait for the guard's durable terminal status while the manager retains the unit."""
    terminal_states = {
        "preflight_blocked",
        "staging_authorization_refused",
        "manager_authorization_refused",
        "launch_failed",
        "finished",
        "post_exec_failure",
    }
    deadline = time.monotonic() + timeout
    last_error: str | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            try:
                return _read_guard_status(runtime_dir), None
            except SanitizerCollectionError as exc:
                return None, f"systemd-run exited before a readable terminal guard status: {exc}"
        probe = _sudo(["/usr/bin/test", "-d", str(runtime_dir)], timeout=1)
        if probe.returncode == 0:
            try:
                status = _read_guard_status(runtime_dir)
            except SanitizerCollectionError as exc:
                last_error = str(exc)
                status = None
            if status is not None and status.get("guard_state") in terminal_states:
                return status, None
        elif probe.returncode not in (1,):
            last_error = "Could not inspect the attempt RuntimeDirectory while waiting for guard completion."
        time.sleep(0.05)
    return None, last_error or "Guard did not reach a terminal state before the bounded manager-stop deadline."


def _copy_service_stream(
    runtime_dir: Path,
    name: str,
    attempt_dir: Path,
) -> tuple[bytes | None, Path | None]:
    raw = _read_service_file(runtime_dir / name, MAX_STREAM_BYTES)
    if raw is None:
        return None, None
    stage = attempt_dir / name
    _write_private_file(stage, raw)
    return raw, stage

def _copy_service_streams(
    runtime_dir: Path,
    attempt_dir: Path,
) -> tuple[
    tuple[bytes | None, Path | None, str | None],
    tuple[bytes | None, Path | None, str | None],
]:
    """Attempt both stream copies independently; one failure must not skip the other."""
    results = []
    for name in ("stdout.bin", "stderr.bin"):
        try:
            raw, stage = _copy_service_stream(runtime_dir, name, attempt_dir)
            results.append((raw, stage, None))
        except (SanitizerCollectionError, OSError) as exc:
            results.append((None, None, f"{type(exc).__name__}: {exc}"))
    return results[0], results[1]


def _stream_state(
    guard_status: dict[str, Any] | None,
    key: str,
    stage_path: Path | None,
    execution_started: bool,
) -> tuple[str, int, str, str | None]:
    if not execution_started:
        return "not_started", 0, "not_started", None
    item = guard_status.get(key, {}) if guard_status else {}
    capture = item.get("capture_state")
    if capture not in ("complete", "read_failed"):
        capture = "read_failed"
    truncated = int(bool(item.get("truncated", False)))
    detail = item.get("detail")
    publication = "not_started" if stage_path is None else "pending_recovery"
    return capture, truncated, publication, str(detail)[:1024] if detail else None


def _cleanup_attempt_files(attempt_dir: Path, *, keep: set[str]) -> bool:
    okay = True
    for name in ("input.bin", "stdout.bin", "stderr.bin"):
        if name in keep:
            continue
        path = attempt_dir / name
        try:
            info = path.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid():
            okay = False
            continue
        try:
            path.unlink()
        except OSError:
            okay = False
    try:
        descriptor = os.open(attempt_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError:
        okay = False
    return okay


def _record_blocked(
    repository: EvidenceRepository,
    connection: sqlite3.Connection,
    context: dict[str, object],
    run_uid: str,
    started_at: str,
    manifest: dict[str, Any],
    *,
    detail: str,
    unit: str | None,
    recovery_path: Path,
    runtime_observation: dict[str, Any],
) -> SanitizerCollectionResult:
    finished = _now()
    runtime_observation["refusal_detail"] = detail[:2048]
    record = {
        "run_uid": run_uid,
        "target_id": context["target_id"],
        "target_version_id": context["target_version_id"],
        "source_build_id": context["source_build_id"],
        "campaign_id": context["campaign_id"],
        "observation_id": context["observation_id"],
        "diagnostic_build_id": context["diagnostic_build_id"],
        "original_artifact_id": context["original_artifact_id"],
        "policy_id": POLICY_ID,
        "argv_json": [],
        "environment_json": {},
        "resource_policy_json": _resource_policy(),
        "runtime_observation_json": runtime_observation,
        "attempt_started_at": started_at,
        "attempt_finished_at": finished,
        "execution_started_at": None,
        "execution_finished_at": None,
        "execution_status": "blocked_preflight",
        "harness_exec_succeeded": 0,
        "exit_code": None,
        "signal_number": None,
        "sanitizer_families_json": [],
        "assessment": "inconclusive",
        "cleanup_status": "not_required",
        "cleanup_detail": detail[:1024],
        "recovery_path": None,
        "systemd_unit_name": unit,
        "kernel_version": platform.release()[:255],
        "wsl_version": runtime_observation.get("wsl_version"),
        "systemd_version": runtime_observation.get("systemd_version"),
        "stdout_artifact_id": None,
        "stdout_capture_state": "not_started",
        "stdout_truncated": 0,
        "stdout_publication_state": "not_started",
        "stdout_detail": None,
        "stderr_artifact_id": None,
        "stderr_capture_state": "not_started",
        "stderr_truncated": 0,
        "stderr_publication_state": "not_started",
        "stderr_detail": None,
        "recorded_at": finished,
    }
    manifest.update({
        "state": "blocked_preflight",
        "execution_status": "blocked_preflight",
        "detail": detail[:2048],
    })
    _write_manifest(Path(manifest["attempt_dir"]), manifest)
    with immediate_transaction(connection):
        row_id = repository.insert_sanitizer_run(record)
    manifest.update({"state": "database_committed", "database_row_id": row_id})
    _write_manifest(Path(manifest["attempt_dir"]), manifest)
    _safe_remove_attempt(Path(manifest["attempt_dir"]))
    return SanitizerCollectionResult(run_uid, row_id, "blocked_preflight", "inconclusive", None)


def collect_sanitizer_evidence(
    evidence_root: str | Path,
    diagnostic_build_id: int,
    observation_uid: str,
    recovery_root: str | Path | None = None,
    project_root: str | Path | None = None,
) -> SanitizerCollectionResult:
    """Execute one imported observation once under the fixed systemd resource boundary."""
    if os.geteuid() == 0:
        raise SanitizerCollectionError("Run the collector as your normal user, never as root.")
    if type(diagnostic_build_id) is not int or diagnostic_build_id <= 0:
        raise ValueError("diagnostic_build_id must be a positive integer.")
    if not isinstance(observation_uid, str) or not observation_uid:
        raise ValueError("observation_uid must be non-empty.")
    root = Path(os.path.abspath(Path(evidence_root).expanduser()))
    if not root.is_absolute() or not root.is_dir():
        raise SanitizerCollectionError("Evidence root must be an existing absolute directory.")
    project = Path(project_root).resolve(strict=True) if project_root else Path(__file__).resolve().parents[2]
    recovery = Path(recovery_root).expanduser() if recovery_root else root.with_name(root.name + ".recovery")
    recovery = Path(os.path.abspath(recovery))
    if recovery.parent != root.parent:
        raise SanitizerCollectionError("Recovery directory must be adjacent to, but outside, the evidence root.")
    if any(_path_overlaps(recovery, item) for item in (root, project)):
        raise SanitizerCollectionError("Recovery directory overlaps the evidence store or project checkout.")

    protected = [project]
    recovery_lock_fd: int | None = None
    attempt_dir: Path | None = None
    connection: sqlite3.Connection | None = None
    store: EvidenceStore | None = None
    service_unit: str | None = None
    service_runtime: Path | None = None
    systemd_process: subprocess.Popen | None = None
    launch_requested = False
    service_finalization_attempted = False
    service_cleanup_confirmed = False
    root_staged_files: list[Path] = []
    root_staged_uid: int | None = None
    root_stage_cleanup_finalized = False
    previous_sigterm_handler: Any = None
    attempt_manifest: dict[str, Any] | None = None
    try:
        # Validate stored identities before creating any recovery/staging directories.
        run_migrations(root)
        connection = open_database(root / "db" / "kekkai.db")
        repository = EvidenceRepository(connection)
        context = repository.get_sanitizer_context(observation_uid, diagnostic_build_id)
        if context is None:
            raise SanitizerCollectionError("No matching imported observation and diagnostic build were found.")
        _check_context(connection, context)
        harness, build_metadata = _verify_diagnostic_build(context)
        source_row = connection.execute(
            "SELECT source_dir_recorded FROM target_versions WHERE id = ? AND target_id = ?",
            (context["target_version_id"], context["target_id"]),
        ).fetchone()
        protected_paths = [
            project,
            Path(str(context["campaign_dir"])),
            Path(str(context["source_build_dir"])),
            Path(str(context["diagnostic_build_dir"])),
        ]
        if source_row and source_row[0]:
            protected_paths.append(Path(str(source_row[0])))
        for item in protected_paths:
            if _path_overlaps(recovery, item) or _path_overlaps(root, item):
                raise SanitizerCollectionError(f"Evidence or recovery path overlaps protected project data: {item}")

        store = EvidenceStore(root, protected_paths=tuple(protected_paths))
        verification = store.verify_evidence_store(connection)
        if not verification.passed:
            raise SanitizerCollectionError(
                "Evidence store verification failed; collection refused. "
                f"missing={verification.missing!r}, corrupt={verification.corrupt!r}, "
                f"unreferenced={verification.unreferenced!r}, stale_staging={verification.stale_staging!r}"
            )

        _private_directory(recovery, create=True)
        recovery_lock_fd = _open_recovery_lock(recovery)
        _reconcile_recovery(recovery, repository)
        total_reserved = sum(
            item.stat(follow_symlinks=False).st_size
            for item in recovery.iterdir() if item.is_file() and item.name != "recovery.lock"
        )
        if total_reserved > MAX_RECOVERY_BYTES:
            raise SanitizerCollectionError("Recovery directory exceeds its configured size ceiling.")
        free = os.statvfs(recovery)
        if free.f_bavail * free.f_frsize < MAX_RECOVERY_BYTES + 64 * 1024 * 1024:
            raise SanitizerCollectionError("Recovery filesystem lacks the required 64 MiB reserve.")

        input_bytes = store.read_verified_artifact(str(context["original_artifact_sha256"]))
        if len(input_bytes) != int(context["original_artifact_size"]) or len(input_bytes) > min(
            MAX_INPUT_BYTES, int(context["max_input_bytes"])
        ):
            raise SanitizerCollectionError("Materialized testcase size differs from its immutable artifact record.")

        run_uid = str(uuid.uuid4())
        attempt_dir = recovery / ("run-" + run_uid)
        os.mkdir(attempt_dir, 0o700)
        os.chmod(attempt_dir, 0o700)
        attempt_started = _now()
        manifest: dict[str, Any] = {
            "schema_version": 1,
            "run_uid": run_uid,
            "observation_uid": observation_uid,
            "diagnostic_build_id": diagnostic_build_id,
            "original_artifact_sha256": context["original_artifact_sha256"],
            "policy_id": POLICY_ID,
            "attempt_started_at": attempt_started,
            "state": "allocated",
            "attempt_dir": str(attempt_dir),
            "expected_stage_files": ["input.bin", "stdout.bin", "stderr.bin"],
        }
        _write_manifest(attempt_dir, manifest)
        attempt_manifest = manifest

        input_path = attempt_dir / "input.bin"
        _write_private_file(input_path, input_bytes)
        input_digest, input_size = _hash_regular_file(input_path, MAX_INPUT_BYTES)
        if input_digest != context["original_artifact_sha256"]:
            raise SanitizerCollectionError("Materialized testcase digest differs from original evidence.")

        runtime_observation: dict[str, Any] = {
            "kernel_version": platform.release(),
            "systemd_version": _load_systemd_version(),
            "wsl_version": _load_wsl_version(),
            "build_metadata_sha256": context["diagnostic_build_metadata_sha256"],
            "original_artifact_sha256": context["original_artifact_sha256"],
            "original_artifact_size": input_size,
            "diagnostic_harness_sha256": context["diagnostic_harness_binary_sha256"],
        }
        resource_policy = _resource_policy()
        run_environment = {
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1:symbolize=0",
            "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
        }
        unit = SERVICE_UNIT_PREFIX + run_uid.replace("-", "")
        runtime_name = SERVICE_RUNTIME_NAME_PREFIX + run_uid.replace("-", "")
        runtime_dir = Path("/run") / runtime_name
        service_unit = unit
        service_runtime = runtime_dir
        guard = GUARD_SOURCE.resolve(strict=True)
        if GUARD_SOURCE.is_symlink() or not guard.is_file():
            raise SanitizerCollectionError("Trusted execution guard source is missing or unsafe.")

        # Validate fixed system binaries before authorizing or invoking them.
        try:
            _trusted_system_executable(SYSTEMD_RUN)
            _trusted_system_executable(SYSTEMCTL)
            _trusted_system_executable(PYTHON)
            _trusted_system_executable(SUDO)
        except SanitizerCollectionError as exc:
            return _record_blocked(
                repository, connection, context, run_uid, attempt_started, manifest,
                detail=str(exc), unit=None, recovery_path=attempt_dir,
                runtime_observation=runtime_observation,
            )

        # The caller explicitly authorizes system-manager access before this attempt.
        try:
            authorization = _sudo(["-v"], timeout=3)
        except SanitizerCollectionError as exc:
            return _record_blocked(
                repository, connection, context, run_uid, attempt_started, manifest,
                detail=str(exc), unit=None, recovery_path=attempt_dir,
                runtime_observation=runtime_observation,
            )
        if authorization.returncode != 0:
            return _record_blocked(
                repository, connection, context, run_uid, attempt_started, manifest,
                detail="Non-interactive sudo authorization unavailable; run sudo -v and retry.",
                unit=None, recovery_path=attempt_dir, runtime_observation=runtime_observation,
            )
        runtime_collision = _sudo(["/usr/bin/test", "-e", str(runtime_dir)], timeout=3)
        if runtime_collision.returncode == 0:
            return _record_blocked(
                repository, connection, context, run_uid, attempt_started, manifest,
                detail="The unique systemd RuntimeDirectory already exists; refusing to reuse it.",
                unit=None, recovery_path=attempt_dir, runtime_observation=runtime_observation,
            )
        if runtime_collision.returncode != 1:
            return _record_blocked(
                repository, connection, context, run_uid, attempt_started, manifest,
                detail="Could not prove that the unique systemd RuntimeDirectory is absent.",
                unit=None, recovery_path=attempt_dir, runtime_observation=runtime_observation,
            )

        stage_prefix = "kekkai-p3-03-stage-" + run_uid.replace("-", "")
        root_input = Path("/run") / (stage_prefix + "-input")
        root_harness = Path("/run") / (stage_prefix + "-harness")
        root_guard = Path("/run") / (stage_prefix + "-guard")
        registered_harness_sha256 = str(context["diagnostic_harness_binary_sha256"])
        guard_sha256, _ = _hash_regular_file(guard, 1024 * 1024)
        for source_path, staged_path, digest, maximum in (
            (input_path, root_input, input_digest, MAX_INPUT_BYTES),
            (harness, root_harness, registered_harness_sha256, 32 * 1024 * 1024),
            (guard, root_guard, guard_sha256, 1024 * 1024),
        ):
            _stage_root_file(source_path, staged_path, digest, maximum)
            root_staged_files.append(staged_path)
            manifest["root_staged_files"] = [str(item) for item in root_staged_files]
            _write_manifest(attempt_dir, manifest)

        argv = _systemd_run_argv(
            unit, runtime_name, root_input, root_harness, root_guard,
            input_digest, input_size, registered_harness_sha256,
        )
        manifest.update({
            "state": "service_launch_requested",
            "systemd_unit_name": unit,
            "runtime_directory": str(runtime_dir),
            "command": argv,
            "environment": run_environment,
            "resource_policy": resource_policy,
            "preexec_manager_authorization_required": True,
        })
        _write_manifest(attempt_dir, manifest)

        systemd_result: subprocess.CompletedProcess | None = None
        interrupted = False
        runner_error: str | None = None
        manager_authorized = False
        preexec_properties: dict[str, str] = {}
        staging_properties: dict[str, str] = {}
        preexec_verification: dict[str, Any] = {
            "passed": False,
            "issues": ["Manager properties have not yet been inspected."],
        }

        def _interrupt_service(signum, frame):
            raise KeyboardInterrupt(f"collector interrupted by signal {signum}")

        previous_sigterm_handler = signal.getsignal(signal.SIGTERM)
        signal.signal(signal.SIGTERM, _interrupt_service)
        try:
            launch_requested = True
            systemd_process = subprocess.Popen(
                [str(SUDO), "-n", *argv],
                cwd="/",
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                bufsize=0,
            )
            ready_status, ready_error = _wait_for_guard_ready(
                systemd_process, runtime_dir, "awaiting_private_staging", timeout=3.0
            )
            if ready_status is None or ready_status.get("guard_state") != "awaiting_private_staging":
                runner_error = ready_error or "Guard did not reach the private-staging barrier."
            else:
                staging_properties = _systemd_show(unit)
                staging_verification = _verify_systemd_properties(staging_properties)
                if "show_error" in staging_properties or not staging_verification["passed"]:
                    runner_error = (
                        "System-manager verification failed before private staging access: "
                        + "; ".join(staging_verification["issues"])
                    )
                else:
                    try:
                        root_staged_uid, root_staged_gid = _set_root_staged_owner(
                            root_staged_files, staging_properties
                        )
                        manifest.update({
                            "root_staged_uid": root_staged_uid,
                            "root_staged_gid": root_staged_gid,
                            "dynamic_user_cgroup": staging_properties.get("ControlGroup"),
                            "private_staging_owner_verified": True,
                        })
                        _write_manifest(attempt_dir, manifest)
                        if systemd_process.stdin is None:
                            raise BrokenPipeError("systemd-run stdin pipe is unavailable")
                        systemd_process.stdin.write(STAGING_AUTHORIZATION_TOKEN)
                        systemd_process.stdin.flush()
                    except (SanitizerCollectionError, BrokenPipeError, OSError, ValueError) as exc:
                        runner_error = (
                            f"Private staging authorization failed: {type(exc).__name__}: {exc}"
                        )

                    if runner_error is None:
                        ready_status, ready_error = _wait_for_guard_ready(
                            systemd_process, runtime_dir,
                            "awaiting_manager_authorization", timeout=3.0
                        )
                        if ready_status is None or ready_status.get("guard_state") != "awaiting_manager_authorization":
                            runner_error = ready_error or "Guard did not verify staged identities before the execution barrier."
                        else:
                            preexec_properties = _systemd_show(unit)
                            preexec_verification = _verify_systemd_properties(preexec_properties)
                            if "show_error" in preexec_properties:
                                preexec_verification = {
                                    "passed": False,
                                    "issues": ["System-manager inspection failed before harness authorization."],
                                }
                            stable_manager_identity = (
                                preexec_properties.get("MainPID") == staging_properties.get("MainPID")
                                and preexec_properties.get("ControlGroup") == staging_properties.get("ControlGroup")
                            )
                            if not stable_manager_identity:
                                preexec_verification = {
                                    "passed": False,
                                    "issues": ["Service MainPID or cgroup changed during pre-exec verification."],
                                }
                            if preexec_verification["passed"]:
                                try:
                                    if systemd_process.stdin is None:
                                        raise BrokenPipeError("systemd-run stdin pipe is unavailable")
                                    systemd_process.stdin.write(MANAGER_AUTHORIZATION_TOKEN)
                                    systemd_process.stdin.flush()
                                    systemd_process.stdin.close()
                                    manager_authorized = True
                                except (BrokenPipeError, OSError, ValueError) as exc:
                                    runner_error = (
                                        f"Could not deliver harness authorization: {type(exc).__name__}: {exc}"
                                    )
                            else:
                                runner_error = (
                                    "System-manager property verification failed before harness authorization: "
                                    + "; ".join(preexec_verification["issues"])
                                )

            if not manager_authorized:
                if systemd_process.stdin is not None and not systemd_process.stdin.closed:
                    systemd_process.stdin.close()
            else:
                _, completion_error = _wait_for_guard_completion(
                    systemd_process, runtime_dir, timeout=SERVICE_RUNTIME_SECONDS + 1.0
                )
                if completion_error:
                    runner_error = runner_error or completion_error
            # RemainAfterExit retains the unit for inspection; explicitly stop
            # this attempt-owned unit to release systemd-run --pipe before reading
            # its captured diagnostics and the preserved runtime files.
            _sudo([str(SYSTEMCTL), "stop", unit], timeout=7)
            try:
                out, err = systemd_process.communicate(timeout=7)
            except subprocess.TimeoutExpired:
                runner_error = runner_error or "systemd-run did not finish within the bounded service wait."
                _sudo([str(SYSTEMCTL), "stop", unit], timeout=7)
                try:
                    out, err = systemd_process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    systemd_process.kill()
                    out, err = systemd_process.communicate(timeout=2)
            systemd_result = subprocess.CompletedProcess(
                [str(SUDO), "-n", *argv], systemd_process.returncode, out, err
            )
            if systemd_result.returncode != 0 and runner_error is None:
                runner_error = (
                    "systemd-run failed: "
                    + systemd_result.stderr.decode("utf-8", errors="replace")[:1024]
                )
        except KeyboardInterrupt:
            interrupted = True
            runner_error = "Collector received SIGINT/SIGTERM while the system service was active."
            if systemd_process is not None and systemd_process.stdin is not None:
                try:
                    systemd_process.stdin.close()
                except OSError:
                    pass
            _sudo([str(SYSTEMCTL), "stop", unit], timeout=7)
        except subprocess.TimeoutExpired:
            runner_error = "systemd-run did not finish within the bounded service wait."
            _sudo([str(SYSTEMCTL), "stop", unit], timeout=7)
        except OSError as exc:
            runner_error = f"Cannot start or communicate with systemd service: {type(exc).__name__}: {exc}"
        finally:
            if systemd_process is not None and systemd_process.poll() is None:
                if systemd_process.stdin is not None and not systemd_process.stdin.closed:
                    try:
                        systemd_process.stdin.close()
                    except OSError:
                        pass
                try:
                    _sudo([str(SYSTEMCTL), "stop", unit], timeout=7)
                except SanitizerCollectionError:
                    pass
                try:
                    out, err = systemd_process.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    systemd_process.kill()
                    out, err = systemd_process.communicate(timeout=2)
                if systemd_result is None:
                    systemd_result = subprocess.CompletedProcess(
                        [str(SUDO), "-n", *argv], systemd_process.returncode, out, err
                    )

        initial_properties = preexec_properties or _systemd_show(unit)
        systemd_policy_verification = preexec_verification
        cleanup_ok, cleanup_detail, final_properties = _stop_and_verify_service(unit, initial_properties)
        service_finalization_attempted = True
        service_cleanup_confirmed = cleanup_ok
        runtime_probe = _sudo(["/usr/bin/test", "-d", str(runtime_dir)], timeout=3)
        runtime_exists = runtime_probe.returncode == 0
        runtime_probe_failed = runtime_probe.returncode not in (0, 1)
        if runtime_probe_failed:
            runner_error = runner_error or "Could not establish whether the attempt RuntimeDirectory exists."
        guard_status: dict[str, Any] | None = None
        if runtime_exists:
            try:
                guard_status = _read_guard_status(runtime_dir)
            except SanitizerCollectionError as exc:
                runner_error = runner_error or str(exc)

        stdout_bytes: bytes | None = None
        stderr_bytes: bytes | None = None
        stdout_stage: Path | None = None
        stderr_stage: Path | None = None
        stdout_copy_error: str | None = None
        stderr_copy_error: str | None = None
        if runtime_exists:
            (
                (stdout_bytes, stdout_stage, stdout_copy_error),
                (stderr_bytes, stderr_stage, stderr_copy_error),
            ) = _copy_service_streams(runtime_dir, attempt_dir)
        guard_exec_succeeded = bool(
            guard_status and guard_status.get("harness_exec_succeeded") is True
        )
        runtime_copy_complete = (
            guard_status is not None
            and (not guard_exec_succeeded or (stdout_stage is not None and stderr_stage is not None))
        )
        if not runtime_exists and not runtime_probe_failed:
            runtime_cleanup_ok, runtime_cleanup_detail = True, None
        elif cleanup_ok and runtime_copy_complete:
            runtime_cleanup_ok, runtime_cleanup_detail = _clean_service_runtime(unit)
        else:
            runtime_cleanup_ok = False
            runtime_cleanup_detail = (
                "RuntimeDirectory retained because stream copies or whole-service cleanup "
                "could not be verified."
            )
        root_stage_cleanup_ok = False
        root_stage_cleanup_detail: str | None = "Root-owned staged files retained until final identity checks complete."
        cleanup_ok = cleanup_ok and runtime_cleanup_ok
        cleanup_detail = cleanup_detail or runtime_cleanup_detail
        if stdout_copy_error:
            runner_error = runner_error or "stdout recovery copy failed: " + stdout_copy_error
        if stderr_copy_error:
            runner_error = runner_error or "stderr recovery copy failed: " + stderr_copy_error

        if guard_status is None:
            result_status = "blocked_preflight"
            exec_succeeded = False
            exec_started = None
            exec_finished = None
            exit_code = None
            signal_number = None
            stdout_capture = stderr_capture = "not_started"
            stdout_truncated = stderr_truncated = 0
            stdout_detail = stderr_detail = None
        else:
            exec_succeeded = guard_status.get("harness_exec_succeeded") is True
            exec_started = guard_status.get("execution_started_at")
            exec_finished = guard_status.get("execution_finished_at")
            exit_code = guard_status.get("exit_code")
            signal_number = guard_status.get("signal_number")
            result_status = guard_status.get("execution_status")
            if result_status not in (
                "blocked_preflight", "launch_failed", "exited",
                "signaled", "timed_out", "interrupted",
            ):
                result_status = "interrupted" if exec_succeeded else "blocked_preflight"
            # systemd's own RuntimeMaxSec watchdog can stop the complete service
            # before the guard gets a chance to persist its final status file.
            if exec_succeeded and initial_properties.get("Result") == "timeout":
                result_status = "timed_out"
            if interrupted and exec_succeeded:
                result_status = "interrupted"
            if runner_error and exec_succeeded and not exec_finished:
                result_status = "timed_out" if "bounded service wait" in runner_error else "interrupted"
            if exec_succeeded and result_status in ("exited", "signaled", "timed_out", "interrupted"):
                exec_started = exec_started or attempt_started
                exec_finished = exec_finished or _now()
            if result_status == "exited" and (type(exit_code) is not int or not 0 <= exit_code <= 255):
                result_status = "interrupted"
                exit_code = None
            if result_status == "signaled" and (type(signal_number) is not int or not 1 <= signal_number <= 64):
                result_status = "interrupted"
                signal_number = None
            stdout_capture = guard_status.get("stdout", {}).get("capture_state", "read_failed")
            stderr_capture = guard_status.get("stderr", {}).get("capture_state", "read_failed")
            if stdout_capture not in ("complete", "read_failed"):
                stdout_capture = "read_failed" if exec_succeeded else "not_started"
            if stderr_capture not in ("complete", "read_failed"):
                stderr_capture = "read_failed" if exec_succeeded else "not_started"
            stdout_truncated = int(bool(guard_status.get("stdout", {}).get("truncated", False)))
            stderr_truncated = int(bool(guard_status.get("stderr", {}).get("truncated", False)))
            stdout_detail = guard_status.get("stdout", {}).get("detail")
            stderr_detail = guard_status.get("stderr", {}).get("detail")

        # A stream advertised as captured must have a safely copied regular file.
        if exec_succeeded and stdout_stage is None:
            stdout_capture = "read_failed"
            stdout_detail = (stdout_detail or "Captured stdout file was unavailable.")
        if exec_succeeded and stderr_stage is None:
            stderr_capture = "read_failed"
            stderr_detail = (stderr_detail or "Captured stderr file was unavailable.")
        if not exec_succeeded:
            stdout_capture = stderr_capture = "not_started"
            stdout_truncated = stderr_truncated = 0
            stdout_stage = stderr_stage = None

        stdout_publication = "not_started"
        stderr_publication = "not_started"
        published_stdout = None
        published_stderr = None
        publication_errors: list[str] = []
        for label, stage, capture in (
            ("stdout", stdout_stage, stdout_capture),
            ("stderr", stderr_stage, stderr_capture),
        ):
            if stage is None or capture == "not_started":
                continue
            try:
                stored = store.publish_file(stage)
                if stored.size_bytes > MAX_STREAM_BYTES:
                    raise SanitizerCollectionError(f"{label} artifact exceeded the 8 MiB P3-03 limit.")
                if label == "stdout":
                    published_stdout = stored
                    stdout_publication = "published"
                else:
                    published_stderr = stored
                    stderr_publication = "published"
            except (OSError, EvidenceStoreError, SanitizerCollectionError) as exc:
                publication_errors.append(f"{label}: {type(exc).__name__}: {exc}")
                if label == "stdout":
                    stdout_publication = "pending_recovery"
                else:
                    stderr_publication = "pending_recovery"

        if stdout_publication == "published" and published_stdout is not None:
            stdout_capture = stdout_capture if stdout_capture in ("complete", "read_failed") else "read_failed"
        if stderr_publication == "published" and published_stderr is not None:
            stderr_capture = stderr_capture if stderr_capture in ("complete", "read_failed") else "read_failed"

        if runner_error and not exec_succeeded and result_status != "launch_failed":
            result_status = "blocked_preflight"
        if result_status in ("blocked_preflight", "launch_failed"):
            stdout_capture = stderr_capture = "not_started"
            stdout_truncated = stderr_truncated = 0
            stdout_publication = stderr_publication = "not_started"
            published_stdout = published_stderr = None
            stdout_stage = stderr_stage = None

        identity_verification: dict[str, Any] = {
            "passed": False,
            "issues": [],
        }
        try:
            current_harness, _ = _verify_diagnostic_build(context)
            checks = {
                "registered_harness_path_unchanged": current_harness == harness,
                "registered_harness_digest_unchanged": _hash_regular_file(
                    current_harness, 32 * 1024 * 1024
                )[0] == registered_harness_sha256,
                "staged_harness_digest_unchanged": _root_hash_regular_file(
                    root_harness, 32 * 1024 * 1024, root_staged_uid
                )[0] == registered_harness_sha256,
                "staged_input_digest_unchanged": _root_hash_regular_file(
                    root_input, MAX_INPUT_BYTES, root_staged_uid
                ) == (input_digest, input_size),
                "attempt_input_digest_unchanged": _hash_regular_file(
                    input_path, MAX_INPUT_BYTES
                ) == (input_digest, input_size),
                "stored_original_digest_unchanged": hashlib.sha256(
                    store.read_verified_artifact(str(context["original_artifact_sha256"]))
                ).hexdigest() == str(context["original_artifact_sha256"]),
                "staged_guard_digest_unchanged": _root_hash_regular_file(
                    root_guard, 1024 * 1024, root_staged_uid
                )[0] == guard_sha256,
            }
            for label, staged_path in (
                ("input", root_input),
                ("harness", root_harness),
                ("guard", root_guard),
            ):
                info = staged_path.stat(follow_symlinks=False)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_uid != root_staged_uid
                    or stat.S_IMODE(info.st_mode) != 0o400
                    or info.st_nlink != 1
                ):
                    checks[f"staged_{label}_permissions"] = False
            identity_verification = {
                "passed": all(checks.values()),
                "checks": checks,
                "issues": [name for name, passed in checks.items() if not passed],
            }
        except Exception as exc:
            identity_verification = {
                "passed": False,
                "issues": [f"{type(exc).__name__}: {exc}"[:512]],
            }
        if not identity_verification["passed"]:
            runner_error = runner_error or (
                "Final execution identity verification failed: "
                + "; ".join(identity_verification["issues"])
            )
        if cleanup_ok and runtime_cleanup_ok and not runtime_probe_failed and identity_verification["passed"]:
            root_stage_cleanup_ok, root_stage_cleanup_detail = _remove_root_staged_files(
                root_staged_files, expected_uid=root_staged_uid
            )
        else:
            root_stage_cleanup_ok = False
            root_stage_cleanup_detail = "Root-owned staged files retained because service or identity verification was incomplete."
        root_stage_cleanup_finalized = True
        if root_stage_cleanup_ok:
            manifest.update({"root_staged_files": [], "root_stage_cleanup_state": "complete"})
        else:
            manifest.update({
                "root_stage_cleanup_state": "failed",
                "root_stage_cleanup_detail": root_stage_cleanup_detail,
            })
        cleanup_ok = cleanup_ok and root_stage_cleanup_ok
        cleanup_detail = cleanup_detail or root_stage_cleanup_detail

        stdout_raw = stdout_bytes or b""
        stderr_raw = stderr_bytes or b""
        classification_status = {
            "harness_exec_succeeded": exec_succeeded,
            "execution_status": result_status,
            "exit_code": exit_code,
            "stdout_capture_state": stdout_capture,
            "stderr_capture_state": stderr_capture,
            "stdout_truncated": bool(stdout_truncated),
            "stderr_truncated": bool(stderr_truncated),
            "stdout_publication_state": stdout_publication,
            "stderr_publication_state": stderr_publication,
            "systemd_policy_verified": systemd_policy_verification["passed"],
            "execution_identity_verified": identity_verification["passed"],
        }
        families, assessment = _classify_output(stdout_raw, stderr_raw, classification_status)
        if not identity_verification["passed"]:
            families = []
            assessment = "inconclusive"
        if result_status in ("blocked_preflight", "launch_failed"):
            assessment = "inconclusive"
            families = []

        unresolved_publication = (
            stdout_publication == "pending_recovery" or stderr_publication == "pending_recovery"
        )
        cleanup_status = "failed"
        cleanup_detail = cleanup_detail or "Attempt stage cleanup has not yet been verified."
        recovery_path_value = str(attempt_dir)

        attempt_finished = _now()
        runtime_observation.update({
            "systemd_initial_properties": initial_properties,
            "systemd_final_properties": final_properties,
            "systemd_policy_verification": systemd_policy_verification,
            "systemd_run_return_code": systemd_result.returncode if systemd_result else None,
            "systemd_run_stdout": _diagnostic_capture(systemd_result.stdout) if systemd_result else None,
            "systemd_run_stderr": _diagnostic_capture(systemd_result.stderr) if systemd_result else None,
            "guard_status": guard_status,
            "execution_identity_verification": identity_verification,
            "service_cleanup_verified": cleanup_ok,
            "service_cleanup_detail": cleanup_detail,
            "runtime_directory_removed": runtime_cleanup_ok,
            "publication_errors": publication_errors,
            "collector_error": runner_error,
        })
        serialized_runtime = canonical_json(runtime_observation)
        if len(serialized_runtime) > 16384:
            raise SanitizerCollectionError(
                "Runtime observations exceed the immutable database field limit; attempt files were preserved."
            )
        record = {
            "run_uid": run_uid,
            "target_id": context["target_id"],
            "target_version_id": context["target_version_id"],
            "source_build_id": context["source_build_id"],
            "campaign_id": context["campaign_id"],
            "observation_id": context["observation_id"],
            "diagnostic_build_id": context["diagnostic_build_id"],
            "original_artifact_id": context["original_artifact_id"],
            "policy_id": POLICY_ID,
            "argv_json": (
                guard_status.get("harness_argv")
                if guard_status and isinstance(guard_status.get("harness_argv"), list)
                else [str(PYTHON), str(runtime_dir / GUARD_DEST_NAME)]
            ),
            "environment_json": (
                guard_status.get("harness_environment")
                if guard_status and isinstance(guard_status.get("harness_environment"), dict)
                else {}
            ),
            "resource_policy_json": resource_policy,
            "runtime_observation_json": runtime_observation,
            "attempt_started_at": attempt_started,
            "attempt_finished_at": attempt_finished,
            "execution_started_at": exec_started,
            "execution_finished_at": exec_finished,
            "execution_status": result_status,
            "harness_exec_succeeded": int(exec_succeeded),
            "exit_code": exit_code,
            "signal_number": signal_number,
            "sanitizer_families_json": families,
            "assessment": assessment,
            "cleanup_status": cleanup_status,
            "cleanup_detail": cleanup_detail[:1024] if cleanup_detail else None,
            "recovery_path": recovery_path_value,
            "systemd_unit_name": unit,
            "kernel_version": platform.release()[:255],
            "wsl_version": runtime_observation.get("wsl_version"),
            "systemd_version": runtime_observation.get("systemd_version"),
            "stdout_artifact_id": None,
            "stdout_capture_state": stdout_capture,
            "stdout_truncated": stdout_truncated,
            "stdout_publication_state": stdout_publication,
            "stdout_detail": str(stdout_detail)[:1024] if stdout_detail else None,
            "stderr_artifact_id": None,
            "stderr_capture_state": stderr_capture,
            "stderr_truncated": stderr_truncated,
            "stderr_publication_state": stderr_publication,
            "stderr_detail": str(stderr_detail)[:1024] if stderr_detail else None,
            "recorded_at": _now(),
        }

        # Persist the complete proposed record and CAS associations before removing
        # any staging copy. A failed DB transaction can then be recovered exactly.
        published_artifacts = {}
        if published_stdout is not None:
            published_artifacts["stdout"] = {
                "sha256": published_stdout.sha256,
                "size_bytes": published_stdout.size_bytes,
                "storage_relpath": published_stdout.storage_relpath,
            }
        if published_stderr is not None:
            published_artifacts["stderr"] = {
                "sha256": published_stderr.sha256,
                "size_bytes": published_stderr.size_bytes,
                "storage_relpath": published_stderr.storage_relpath,
            }
        manifest.update({
            "state": "record_prepared",
            "execution_status": result_status,
            "harness_exec_succeeded": exec_succeeded,
            "stdout_publication_state": stdout_publication,
            "stderr_publication_state": stderr_publication,
            "published_artifacts": published_artifacts,
            "proposed_record": record,
            "stage_cleanup_state": "pending",
            "recovery_path": str(attempt_dir),
        })
        _write_manifest(attempt_dir, manifest)

        keep_files = set()
        if stdout_publication == "pending_recovery":
            keep_files.add("stdout.bin")
        if stderr_publication == "pending_recovery":
            keep_files.add("stderr.bin")
        stage_cleanup_ok = _cleanup_attempt_files(attempt_dir, keep=keep_files)
        unresolved_publication = (
            stdout_publication == "pending_recovery" or stderr_publication == "pending_recovery"
        )
        cleanup_complete = cleanup_ok and stage_cleanup_ok and not unresolved_publication
        if cleanup_complete:
            cleanup_status = "complete"
            cleanup_detail = None
            recovery_path_value = None
        else:
            cleanup_status = "failed"
            cleanup_detail = cleanup_detail or (
                "Attempt files or service resources remain pending verified recovery."
            )
            recovery_path_value = str(attempt_dir)
        record.update({
            "cleanup_status": cleanup_status,
            "cleanup_detail": cleanup_detail[:1024] if cleanup_detail else None,
            "recovery_path": recovery_path_value,
        })
        manifest.update({
            "state": "ready_to_commit",
            "cleanup_status": cleanup_status,
            "cleanup_detail": cleanup_detail,
            "recovery_path": recovery_path_value,
            "stage_cleanup_state": "complete" if stage_cleanup_ok else "failed",
            "proposed_record": record,
        })
        _write_manifest(attempt_dir, manifest)

        with immediate_transaction(connection):
            if published_stdout is not None:
                record["stdout_artifact_id"] = repository.insert_artifact({
                    "sha256": published_stdout.sha256,
                    "size_bytes": published_stdout.size_bytes,
                    "storage_relpath": published_stdout.storage_relpath,
                    "first_ingested_at": record["recorded_at"],
                    "last_verified_at": record["recorded_at"],
                })
            if published_stderr is not None:
                record["stderr_artifact_id"] = repository.insert_artifact({
                    "sha256": published_stderr.sha256,
                    "size_bytes": published_stderr.size_bytes,
                    "storage_relpath": published_stderr.storage_relpath,
                    "first_ingested_at": record["recorded_at"],
                    "last_verified_at": record["recorded_at"],
                })
            row_id = repository.insert_sanitizer_run(record)

        manifest.update({"state": "database_committed", "database_row_id": row_id})
        _write_manifest(attempt_dir, manifest)
        if not unresolved_publication and cleanup_ok and stage_cleanup_ok:
            _safe_remove_attempt(attempt_dir)
            return SanitizerCollectionResult(run_uid, row_id, result_status, assessment, None)
        return SanitizerCollectionResult(run_uid, row_id, result_status, assessment, attempt_dir)
    except KeyboardInterrupt as exc:
        if attempt_dir is not None and attempt_dir.exists() and attempt_manifest is not None:
            attempt_manifest.update({
                "state": "collector_interrupted_recovery",
                "systemd_unit_name": service_unit,
                "runtime_directory": str(service_runtime) if service_runtime else None,
                "root_staged_files": [str(item) for item in root_staged_files],
                "detail": f"Collector interrupted: {type(exc).__name__}: {exc}",
            })
            try:
                _write_manifest(attempt_dir, attempt_manifest)
            except OSError:
                pass
        raise SanitizerCollectionError(
            "Collector was interrupted. Any attempt manifest and service runtime data were retained for recovery."
        ) from exc
    except Exception as exc:
        # An incomplete manifest/stage directory is intentionally retained for manual recovery.
        if attempt_dir is not None and attempt_dir.exists():
            raise SanitizerCollectionError(
                f"Attempt {attempt_dir.name.removeprefix('run-')} is incomplete; "
                f"recovery data was preserved at {attempt_dir}: {type(exc).__name__}: {exc}"
            ) from exc
        raise
    finally:
        # A launch request always has a final stop/verification path, including
        # exceptions raised after systemd-run returns but before evidence commit.
        if launch_requested and service_unit is not None and not service_finalization_attempted:
            try:
                if systemd_process is not None and systemd_process.poll() is None:
                    if systemd_process.stdin is not None and not systemd_process.stdin.closed:
                        systemd_process.stdin.close()
                    _sudo([str(SYSTEMCTL), "stop", service_unit], timeout=7)
                    try:
                        systemd_process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        systemd_process.kill()
                        systemd_process.communicate(timeout=2)
                current = _systemd_show(service_unit)
                final_ok, final_detail, _ = _stop_and_verify_service(service_unit, current)
                service_finalization_attempted = True
                service_cleanup_confirmed = final_ok
                if attempt_manifest is not None and attempt_dir is not None and attempt_dir.exists():
                    attempt_manifest.update({
                        "state": "exception_cleanup_verified" if final_ok else "exception_cleanup_unverified",
                        "exception_cleanup_detail": final_detail,
                    })
                    _write_manifest(attempt_dir, attempt_manifest)
            except Exception as cleanup_exc:
                if attempt_manifest is not None and attempt_dir is not None and attempt_dir.exists():
                    attempt_manifest.update({
                        "state": "exception_cleanup_unverified",
                        "exception_cleanup_detail": f"{type(cleanup_exc).__name__}: {cleanup_exc}"[:1024],
                    })
                    try:
                        _write_manifest(attempt_dir, attempt_manifest)
                    except OSError:
                        pass
        # Root-owned staged files are removed only after the attempt service is
        # positively absent or its complete cgroup is known empty.
        if root_staged_files and not root_stage_cleanup_finalized and (not launch_requested or service_cleanup_confirmed):
            try:
                removed, removal_detail = _remove_root_staged_files(
                    root_staged_files, expected_uid=root_staged_uid
                )
                if not removed and attempt_manifest is not None and attempt_dir is not None and attempt_dir.exists():
                    attempt_manifest.update({
                        "state": "root_stage_cleanup_unverified",
                        "root_stage_cleanup_detail": removal_detail,
                    })
                    _write_manifest(attempt_dir, attempt_manifest)
            except Exception as cleanup_exc:
                if attempt_manifest is not None and attempt_dir is not None and attempt_dir.exists():
                    attempt_manifest.update({
                        "state": "root_stage_cleanup_unverified",
                        "root_stage_cleanup_detail": f"{type(cleanup_exc).__name__}: {cleanup_exc}"[:1024],
                    })
                    try:
                        _write_manifest(attempt_dir, attempt_manifest)
                    except OSError:
                        pass
        if previous_sigterm_handler is not None:
            try:
                signal.signal(signal.SIGTERM, previous_sigterm_handler)
            except ValueError:
                pass
        if connection is not None:
            connection.close()
        if store is not None:
            store.close()
        if recovery_lock_fd is not None:
            try:
                fcntl.flock(recovery_lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(recovery_lock_fd)
