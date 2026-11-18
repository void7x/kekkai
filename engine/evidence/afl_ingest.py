"""Offline, evidence-preserving ingestion of AFL++ crash and hang testcases."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import stat
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from engine.adapters.config import AdapterConfig, load_adapter_config
from engine.build.source_identity import verify_libpng_source_identity
from engine.evidence.database import immediate_transaction, open_database, utc_now_iso
from engine.evidence.migrations import run_migrations
from engine.evidence.repository import EvidenceRepository
from engine.evidence.seed_manifest import (
    MAX_IDENTITY_FILE_BYTES,
    SeedManifestError,
    build_seed_manifest,
    hash_stable_file,
)
from engine.evidence.store import EvidenceStore, EvidenceStoreError, MAX_ARTIFACT_BYTES
from engine.storage import StorageError, verify_campaign_storage


MAX_CAMPAIGN_METADATA_BYTES = 1024 * 1024
MAX_FUZZER_STATS_BYTES = 64 * 1024
MAX_IMPORT_OBSERVATIONS = 4096
MAX_IMPORT_TOTAL_BYTES = 512 * 1024 * 1024
MAX_SQLITE_INTEGER = (1 << 63) - 1
EXPECTED_COMPILER_PATH = "/usr/bin/afl-clang-fast"
EXPECTED_COMPILER_VERSION = "Ubuntu clang version 21.1.8 (6ubuntu1)"
EXPECTED_CMAKE_BUILD_TYPE = "RelWithDebInfo"
SANITIZER_CONFIG = {
    "afl_debug": "1",
    "afl_use_ubsan": "1",
    "profile": "libpng-afl-ubsan",
}
_CAMPAIGN_UID = re.compile(r"^campaign-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DECIMAL = re.compile(r"^[0-9]{1,20}$")
_ALLOWED_STAT_KEYS = {
    "execs_done",
    "saved_crashes",
    "saved_hangs",
    "exec_timeout",
}


class AflIngestError(RuntimeError):
    """Raised when an AFL++ campaign cannot be safely ingested."""


@dataclass(frozen=True)
class IngestResult:
    campaign_uid: str
    campaign_id: str
    crash_count: int
    hang_count: int
    artifact_count: int
    total_bytes: int
    target_id: int
    target_version_id: int
    build_id: int
    campaign_row_id: int


@dataclass(frozen=True)
class _FileSnapshot:
    name: str
    kind: str
    size_bytes: int
    mtime_ns: int
    snapshot: tuple[int, int, int, int, int]
    source_path: Path
    input_id: str | None = None
    signal: int | None = None
    discovery_time_ms: int | None = None
    discovery_execs: int | None = None


@dataclass(frozen=True)
class _DirectorySnapshot:
    path: Path
    directory_snapshot: tuple[int, int, int, int, int]
    entries: tuple[tuple[str, tuple[int, int, int, int, int]], ...]
    candidates: tuple[_FileSnapshot, ...]


@dataclass(frozen=True)
class _CampaignContext:
    config: AdapterConfig
    campaign_dir: Path
    campaign_uid: str
    afl_output_dir: Path
    worker_root: Path
    worker_name: str
    metadata: dict[str, Any]
    metadata_sha256: str
    metadata_snapshot: tuple[int, int, int, int, int]
    campaign_directory_snapshot: tuple[int, int, int, int, int]
    afl_output_directory_snapshot: tuple[int, int, int, int, int]
    worker_directory_snapshot: tuple[int, int, int, int, int]
    build_metadata: dict[str, Any]
    build_metadata_path: Path
    build_metadata_snapshot: tuple[int, int, int, int, int]
    build_metadata_sha256: str
    identity: dict[str, Any]
    toolchain: dict[str, str]
    command: tuple[str, ...]
    afl_max_generated_bytes: int
    stats: dict[str, int | None]
    crash_directory: _DirectorySnapshot
    hang_directory: _DirectorySnapshot
    candidates: tuple[_FileSnapshot, ...]
    total_bytes: int


def _snapshot(info: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _open_directory(path: str | Path, *, expected_device: int | None = None) -> int:
    """Open an absolute directory by components without following symlinks."""
    absolute = Path(os.path.abspath(os.fspath(Path(path).expanduser())))
    if not absolute.is_absolute():
        raise AflIngestError("Directory path must be absolute.")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = os.open(absolute.anchor, flags)
    try:
        for part in absolute.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            info = os.fstat(child)
            if not stat.S_ISDIR(info.st_mode):
                os.close(child)
                raise AflIngestError(f"Path component is not a directory: {part}")
            os.close(descriptor)
            descriptor = child
        info = os.fstat(descriptor)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise AflIngestError("Directory must be a plain directory owned by the current user.")
        if expected_device is not None and info.st_dev != expected_device:
            raise AflIngestError("Directory is not on the authenticated campaign filesystem.")
        return descriptor
    except OSError as exc:
        os.close(descriptor)
        raise AflIngestError(f"Cannot safely open directory {absolute}: {exc}") from exc
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise


def _read_file_at(
    directory_fd: int,
    name: str,
    *,
    maximum: int,
    expected_device: int | None = None,
) -> tuple[bytes, tuple[int, int, int, int, int]]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    descriptor = None
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid():
            raise AflIngestError(f"{name} must be a regular file owned by the current user.")
        if expected_device is not None and before.st_dev != expected_device:
            raise AflIngestError(f"{name} is not on the authenticated campaign filesystem.")
        if before.st_size < 0 or before.st_size > maximum:
            raise AflIngestError(f"{name} exceeds the {maximum}-byte limit.")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise AflIngestError(f"{name} grew beyond the {maximum}-byte limit.")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        named = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            total != before.st_size
            or _snapshot(before) != _snapshot(after)
            or _snapshot(named) != _snapshot(after)
        ):
            raise AflIngestError(f"{name} changed while it was being read.")
        return b"".join(chunks), _snapshot(after)
    except OSError as exc:
        raise AflIngestError(f"Cannot safely read {name}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
            parse_constant=lambda item: (_ for _ in ()).throw(ValueError(f"Invalid JSON constant: {item}")),
        )
    except (UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise AflIngestError(f"{label} is not valid duplicate-free UTF-8 JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise AflIngestError(f"{label} must contain a JSON object.")
    return value


def _require_string(mapping: dict[str, Any], key: str, label: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip() or "\x00" in value:
        raise AflIngestError(f"{label}.{key} must be a non-empty NUL-free string.")
    return value


def _require_int(mapping: dict[str, Any], key: str, label: str, *, minimum: int = 0) -> int:
    value = mapping.get(key)
    if type(value) is not int or not minimum <= value <= MAX_SQLITE_INTEGER:
        raise AflIngestError(f"{label}.{key} must be an integer >= {minimum}.")
    return value


def _parse_campaign_uid(value: str) -> None:
    if _CAMPAIGN_UID.fullmatch(value) is None:
        raise AflIngestError("Campaign ID does not match the 38-character KEKKAI campaign identity.")
    try:
        datetime.strptime(value[9:25], "%Y%m%dT%H%M%SZ")
    except ValueError as exc:
        raise AflIngestError("Campaign ID contains an invalid calendar timestamp.") from exc


def _normalize_time(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise AflIngestError(f"{label} must be a UTC timestamp.")
    try:
        from engine.evidence.database import normalize_utc_timestamp
        return normalize_utc_timestamp(value, label)
    except ValueError as exc:
        raise AflIngestError(f"{label} is invalid: {exc}") from exc


def _mtime_to_utc(mtime_ns: int) -> str:
    seconds, remainder = divmod(mtime_ns, 1_000_000_000)
    microseconds = remainder // 1_000
    try:
        base = datetime.fromtimestamp(seconds, tz=timezone.utc)
    except (OverflowError, OSError, ValueError) as exc:
        raise AflIngestError("Source testcase has an unsupported modification timestamp.") from exc
    return base.strftime("%Y-%m-%dT%H:%M:%S") + f".{microseconds:06d}Z"


def _parse_afl_filename(name: str, kind: str) -> tuple[str, int | None, int | None, int | None]:
    if not isinstance(name, str) or not name or len(name.encode("utf-8")) > 255:
        raise AflIngestError("AFL testcase filename is empty or too long.")
    if "/" in name or "\\" in name or "\x00" in name or name in {".", "..", "README.txt"}:
        raise AflIngestError("AFL testcase filename is not a safe direct directory entry.")
    tokens = name.split(",")
    if not tokens or not tokens[0].startswith("id:"):
        raise AflIngestError(f"AFL testcase filename must begin with id:<decimal>: {name!r}")
    values: dict[str, str] = {}
    known = {"id", "sig", "time", "execs"}
    for index, token in enumerate(tokens):
        if ":" not in token:
            if index == 0:
                raise AflIngestError(f"AFL testcase has a malformed ID token: {name!r}")
            continue
        key, value = token.split(":", 1)
        if key in known:
            if key in values:
                raise AflIngestError(f"AFL testcase filename repeats the {key!r} token: {name!r}")
            values[key] = value
    if "id" not in values or _DECIMAL.fullmatch(values["id"]) is None:
        raise AflIngestError(f"AFL testcase has an invalid ID token: {name!r}")
    input_id = values["id"]
    signal_value = None
    if kind == "crash":
        if "sig" not in values or _DECIMAL.fullmatch(values["sig"]) is None:
            raise AflIngestError(f"Crash testcase requires a decimal sig token: {name!r}")
        signal_value = int(values["sig"])
        if not 1 <= signal_value <= 255:
            raise AflIngestError(f"Crash testcase signal must be between 1 and 255: {name!r}")
    elif "sig" in values:
        raise AflIngestError(f"Hang testcase must not contain a sig token: {name!r}")

    parsed: dict[str, int | None] = {"time": None, "execs": None}
    for key in ("time", "execs"):
        if key in values:
            if _DECIMAL.fullmatch(values[key]) is None:
                raise AflIngestError(f"AFL testcase {key} token must be a non-negative decimal integer: {name!r}")
            number = int(values[key])
            if number > MAX_SQLITE_INTEGER:
                raise AflIngestError(f"AFL testcase {key} token exceeds the SQLite integer range: {name!r}")
            parsed[key] = number
    return input_id, signal_value, parsed["time"], parsed["execs"]


def _parse_fuzzer_stats(worker_root: Path, worker_fd: int, expected_device: int) -> dict[str, int | None]:
    try:
        raw, _ = _read_file_at(
            worker_fd,
            "fuzzer_stats",
            maximum=MAX_FUZZER_STATS_BYTES,
            expected_device=expected_device,
        )
    except AflIngestError as exc:
        if isinstance(exc.__cause__, FileNotFoundError):
            return {key: None for key in _ALLOWED_STAT_KEYS}
        if "Cannot safely read fuzzer_stats" in str(exc) and isinstance(exc.__cause__, FileNotFoundError):
            return {key: None for key in _ALLOWED_STAT_KEYS}
        raise
    values: dict[str, str] = {}
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise AflIngestError("AFL++ fuzzer_stats is not UTF-8.") from exc
    for number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        if ":" not in line:
            raise AflIngestError(f"Malformed fuzzer_stats line {number}.")
        key, value = line.split(":", 1)
        key = key.strip()
        value = value.strip()
        if not key or key in values:
            raise AflIngestError(f"Empty or duplicate fuzzer_stats key on line {number}.")
        values[key] = value
    parsed: dict[str, int | None] = {key: None for key in _ALLOWED_STAT_KEYS}
    for key in _ALLOWED_STAT_KEYS:
        if key not in values:
            continue
        value = values[key]
        if _DECIMAL.fullmatch(value) is None:
            raise AflIngestError(f"AFL++ fuzzer_stats field {key!r} is not a non-negative integer.")
        integer = int(value)
        if integer > MAX_SQLITE_INTEGER:
            raise AflIngestError(f"AFL++ fuzzer_stats field {key!r} exceeds the SQLite integer range.")
        if key == "exec_timeout" and integer == 0:
            raise AflIngestError("AFL++ fuzzer_stats exec_timeout must be positive.")
        parsed[key] = integer
    return parsed


def _open_child_directory(parent_fd: int, name: str, expected_device: int) -> tuple[int, os.stat_result]:
    try:
        descriptor = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
    except OSError as exc:
        raise AflIngestError(f"Expected AFL++ directory {name!r} is missing or unsafe: {exc}") from exc
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_dev != expected_device
    ):
        os.close(descriptor)
        raise AflIngestError(f"AFL++ directory {name!r} must be user-owned on the campaign filesystem.")
    return descriptor, info


def _scan_observation_directory(
    directory_path: Path,
    kind: str,
    expected_device: int,
) -> _DirectorySnapshot:
    parent_fd = _open_directory(directory_path.parent, expected_device=expected_device)
    directory_fd = None
    try:
        directory_fd, directory_info = _open_child_directory(parent_fd, directory_path.name, expected_device)
        names = sorted(os.listdir(directory_fd))
        candidates: list[_FileSnapshot] = []
        snapshots: list[tuple[str, tuple[int, int, int, int, int]]] = []
        for name in names:
            info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode):
                raise AflIngestError(f"Symlink is not allowed in AFL++ {kind}/: {name}")
            if name == "README.txt":
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_dev != expected_device:
                    raise AflIngestError(f"AFL++ {kind}/README.txt must be a regular user-owned file.")
                snapshots.append((name, _snapshot(info)))
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_dev != expected_device:
                raise AflIngestError(f"AFL++ {kind} entry is not a regular user-owned file: {name}")
            if info.st_size < 0 or info.st_size > MAX_ARTIFACT_BYTES:
                raise AflIngestError(f"AFL++ testcase exceeds the {MAX_ARTIFACT_BYTES}-byte artifact limit: {name}")
            input_id, signal_value, time_ms, execs = _parse_afl_filename(name, kind)
            snapshot = _snapshot(info)
            snapshots.append((name, snapshot))
            candidates.append(
                _FileSnapshot(
                    name=name,
                    kind=kind,
                    size_bytes=info.st_size,
                    mtime_ns=info.st_mtime_ns,
                    snapshot=snapshot,
                    source_path=directory_path / name,
                    input_id=input_id,
                    signal=signal_value,
                    discovery_time_ms=time_ms,
                    discovery_execs=execs,
                )
            )
        return _DirectorySnapshot(
            path=directory_path,
            directory_snapshot=_snapshot(directory_info),
            entries=tuple(snapshots),
            candidates=tuple(candidates),
        )
    except OSError as exc:
        raise AflIngestError(f"Cannot inspect AFL++ {kind}/: {exc}") from exc
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
        os.close(parent_fd)


def _verify_directory_snapshot(snapshot: _DirectorySnapshot, expected_device: int) -> None:
    parent_fd = _open_directory(snapshot.path.parent, expected_device=expected_device)
    directory_fd = None
    try:
        directory_fd, directory_info = _open_child_directory(
            parent_fd, snapshot.path.name, expected_device
        )
        if _snapshot(directory_info) != snapshot.directory_snapshot:
            raise AflIngestError(f"AFL++ directory changed during ingestion: {snapshot.path}")
        current_names = sorted(os.listdir(directory_fd))
        expected_names = [name for name, _ in snapshot.entries]
        if current_names != expected_names:
            raise AflIngestError(f"AFL++ directory entries changed during ingestion: {snapshot.path}")
        for name, expected in snapshot.entries:
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if stat.S_ISLNK(current.st_mode) or _snapshot(current) != expected:
                raise AflIngestError(f"AFL++ source entry changed during ingestion: {snapshot.path / name}")
    except OSError as exc:
        raise AflIngestError(f"Cannot re-verify AFL++ directory {snapshot.path}: {exc}") from exc
    finally:
        if directory_fd is not None:
            os.close(directory_fd)
        os.close(parent_fd)


def _detect_worker_root(afl_output_dir: Path, expected_device: int) -> tuple[Path, str, int]:
    root_fd = _open_directory(afl_output_dir, expected_device=expected_device)
    try:
        names = sorted(os.listdir(root_fd))
        entries = {}
        for name in names:
            info = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise AflIngestError(f"Unexpected special or symlink entry in AFL output root: {name}")
            entries[name] = info
        has_default = "default" in entries
        has_flat = "crashes" in entries or "hangs" in entries
        if has_default and has_flat:
            raise AflIngestError("AFL output contains both default/ and flat crash/hang directories; layout is ambiguous.")
        if has_default:
            if not stat.S_ISDIR(entries["default"].st_mode):
                raise AflIngestError("AFL output default entry is not a directory.")
            extra_directories = [
                name for name, info in entries.items()
                if stat.S_ISDIR(info.st_mode) and name != "default"
            ]
            if extra_directories:
                raise AflIngestError("Multi-worker or unexpected AFL output directories are not supported.")
            worker_root = afl_output_dir / "default"
            worker_fd, worker_info = _open_child_directory(root_fd, "default", expected_device)
            os.close(worker_fd)
            return worker_root, "default", worker_info.st_dev
        if not {"crashes", "hangs"}.issubset(entries):
            raise AflIngestError(
                "AFL++ did not create both crashes/ and hangs/; the campaign may have ended before fuzzer startup."
            )
        extra_directories = [
            name for name, info in entries.items()
            if stat.S_ISDIR(info.st_mode) and name not in {"crashes", "hangs", "queue"}
        ]
        if extra_directories:
            raise AflIngestError("Multi-worker or unexpected AFL output directories are not supported.")
        return afl_output_dir, "default", expected_device
    finally:
        os.close(root_fd)


def _validate_command(metadata: dict[str, Any], config: AdapterConfig, afl_output_dir: Path) -> tuple[tuple[str, ...], int]:
    raw_command = metadata.get("command")
    if not isinstance(raw_command, list) or not raw_command or any(not isinstance(item, str) or "\x00" in item for item in raw_command):
        raise AflIngestError("Campaign command must be an array of NUL-free strings.")
    fuzzer = metadata.get("fuzzer")
    if not isinstance(fuzzer, dict):
        raise AflIngestError("Campaign fuzzer metadata is missing.")
    executable = _require_string(fuzzer, "executable", "fuzzer")
    if not Path(executable).is_absolute():
        raise AflIngestError("Recorded AFL++ executable path must be absolute.")
    expected = [
        executable,
        "-i", str(config.target.seed_dir),
        "-o", str(afl_output_dir),
        "-V", str(config.limits.duration_seconds),
        "-m", str(config.limits.memory_mib),
        "-t", str(config.limits.timeout_ms),
        "-G", str(min(config.limits.max_input_bytes, 1024 * 1024)),
        "--",
        str(config.target.harness_binary),
        "@@",
    ]
    if raw_command != expected:
        raise AflIngestError("Recorded AFL++ command differs from the fixed validated adapter command.")
    positions = [index for index, value in enumerate(raw_command) if value == "-G"]
    if len(positions) != 1 or positions[0] + 1 >= len(raw_command):
        raise AflIngestError("Recorded AFL++ command must contain exactly one -G argument.")
    max_generated = raw_command[positions[0] + 1]
    if not max_generated.isascii() or not max_generated.isdecimal() or int(max_generated) <= 0:
        raise AflIngestError("Recorded -G maximum generated size must be a positive decimal integer.")
    return tuple(raw_command), int(max_generated)


def _verify_build_metadata(
    config: AdapterConfig,
    metadata: dict[str, Any],
    toolchain: dict[str, str],
    identity: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    if config.build is None:
        raise AflIngestError("P3-02 requires the schema-4 libpng build profile.")
    required = {
        "schema_version": 2,
        "status": "completed",
        "target": "libpng",
        "target_version": config.target.version,
        "profile": config.build.profile,
        "build_dir": str(config.build.build_dir),
        "adapter_config": str(config.config_path),
    }
    for key, expected in required.items():
        if metadata.get(key) != expected:
            raise AflIngestError(f"build.json field {key!r} does not match the campaign adapter.")
    if config.build.profile != "libpng-afl-ubsan" or config.target.version != "1.6.59":
        raise AflIngestError("Only the validated libpng 1.6.59 AFL++ UBSan build is supported.")
    environment = metadata.get("environment")
    if (
        not isinstance(environment, dict)
        or not isinstance(environment.get("PATH"), str)
        or not environment.get("PATH")
        or environment.get("LC_ALL") != "C"
        or environment.get("AFL_USE_UBSAN") != "1"
        or environment.get("AFL_DEBUG") != "1"
    ):
        raise AflIngestError("build.json environment differs from the verified libpng AFL++ UBSan profile.")
    if metadata.get("source_archive_path") != str(config.target.source_archive):
        raise AflIngestError("build.json source archive path does not match the adapter.")
    for field in ("source_archive_sha256", "source_tree_sha256"):
        if not isinstance(metadata.get(field), str) or _SHA256.fullmatch(metadata[field]) is None:
            raise AflIngestError(f"build.json {field} is not a valid SHA-256 digest.")
    source_identity = verify_libpng_source_identity(
        config.target.source_dir,
        config.target.source_archive,
    )
    if (
        metadata["source_archive_sha256"] != source_identity.archive_sha256
        or metadata["source_tree_sha256"] != source_identity.tree_sha256
    ):
        raise AflIngestError("Current pinned source archive/tree identity differs from the completed build.")
    steps = metadata.get("steps")
    if not isinstance(steps, list) or len(steps) != 3:
        raise AflIngestError("build.json must contain the three fixed completed build steps.")
    if tuple(step.get("name") for step in steps if isinstance(step, dict)) != ("configure", "library", "harness"):
        raise AflIngestError("build.json contains an unexpected build-step sequence.")
    if any(
        not isinstance(step, dict)
        or step.get("status") != "completed"
        or type(step.get("exit_code")) is not int
        or step["exit_code"] != 0
        or not isinstance(step.get("command"), list)
        or not step["command"]
        or any(not isinstance(arg, str) for arg in step["command"])
        for step in steps
    ):
        raise AflIngestError("build.json contains an incomplete or malformed build step.")

    compiler_commands = [
        arg for step in steps for arg in step["command"]
        if arg.startswith("-DCMAKE_C_COMPILER=")
    ]
    if compiler_commands != [f"-DCMAKE_C_COMPILER={EXPECTED_COMPILER_PATH}"]:
        raise AflIngestError("Recorded build command does not use the pinned AFL++ compiler.")
    if steps[2]["command"][0] != EXPECTED_COMPILER_PATH:
        raise AflIngestError("Recorded harness link command does not use the pinned AFL++ compiler.")
    if toolchain.get("compiler_path") != EXPECTED_COMPILER_PATH:
        raise AflIngestError("Campaign toolchain compiler path differs from the pinned build command.")
    if toolchain.get("compiler_version") != EXPECTED_COMPILER_VERSION:
        raise AflIngestError("Campaign toolchain compiler version differs from the verified build contract.")
    if toolchain.get("aflpp_version") != config.fuzzer.expected_version:
        raise AflIngestError("Campaign toolchain AFL++ version differs from the adapter.")

    artifacts = metadata.get("artifacts")
    if not isinstance(artifacts, dict):
        raise AflIngestError("build.json has no valid artifact hash mapping.")
    expected_paths = {
        "harness_source_sha256": config.target.harness_source,
        "harness_binary_sha256": config.target.harness_binary,
        "library_archive_sha256": config.build.build_dir / "libpng16.a",
        "cmake_cache_sha256": config.build.build_dir / "CMakeCache.txt",
        "compile_database_sha256": config.build.build_dir / "compile_commands.json",
        "generated_header_sha256": config.build.build_dir / "pnglibconf.h",
    }
    verified_hashes: dict[str, str] = {}
    for key, path in expected_paths.items():
        expected_hash = artifacts.get(key)
        if not isinstance(expected_hash, str) or _SHA256.fullmatch(expected_hash) is None:
            raise AflIngestError(f"build.json artifact hash {key!r} is missing or invalid.")
        actual_hash = hash_stable_file(path, max_bytes=MAX_ARTIFACT_BYTES)
        if actual_hash.sha256 != expected_hash:
            raise AflIngestError(f"Build artifact hash mismatch for {path.name}.")
        verified_hashes[key] = expected_hash

    cache_path = config.build.build_dir / "CMakeCache.txt"
    cache_fd = _open_directory(cache_path.parent)
    try:
        cache_bytes, _ = _read_file_at(cache_fd, cache_path.name, maximum=MAX_ARTIFACT_BYTES)
    finally:
        os.close(cache_fd)
    try:
        cache_raw = cache_bytes.decode("utf-8")
    except UnicodeError as exc:
        raise AflIngestError("CMakeCache.txt is not UTF-8.") from exc
    build_types = [
        line.split("=", 1)[1]
        for line in cache_raw.splitlines()
        if line.startswith("CMAKE_BUILD_TYPE:")
        and "=" in line
    ]
    compiler_cache = [
        line.split("=", 1)[1]
        for line in cache_raw.splitlines()
        if line.startswith("CMAKE_C_COMPILER:")
        and "=" in line
    ]
    if build_types != [EXPECTED_CMAKE_BUILD_TYPE] or compiler_cache != [EXPECTED_COMPILER_PATH]:
        raise AflIngestError("Verified CMake cache does not match the fixed build profile.")
    return verified_hashes, EXPECTED_CMAKE_BUILD_TYPE


def _validate_campaign(
    campaign_dir: str | Path,
    config_path: str | Path,
) -> tuple[_CampaignContext, tuple[str, ...]]:
    campaign_path = Path(campaign_dir).expanduser()
    config_input = Path(config_path).expanduser()
    if not campaign_path.is_absolute() or not config_input.is_absolute():
        raise AflIngestError("--campaign-dir and --config must be absolute paths.")
    if os.name != "posix":
        raise AflIngestError("P3-02 ingestion requires POSIX no-follow filesystem operations.")
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        raise AflIngestError("Refusing to ingest AFL++ evidence as root.")

    project_root = Path(__file__).resolve().parents[2]
    config = load_adapter_config(config_input, project_root)
    if config.schema_version != 4 or config.build is None or config.target.name != "libpng":
        raise AflIngestError("Only the current schema-4 libpng adapter is supported.")
    if config.target.campaign_storage_image is None or not config.target.campaign_storage_uuid:
        raise AflIngestError("Adapter does not pin the dedicated campaign storage image and UUID.")

    try:
        storage = verify_campaign_storage(
            config.target.campaign_storage_image,
            config.target.campaign_storage_uuid,
            config.target.output_parent,
        )
    except StorageError as exc:
        raise AflIngestError(f"Campaign storage verification failed: {exc}") from exc

    output_parent = config.target.output_parent.resolve(strict=True)
    campaign_absolute = Path(os.path.abspath(campaign_path))
    campaign_name = campaign_absolute.name
    _parse_campaign_uid(campaign_name)
    if campaign_absolute.parent != output_parent:
        raise AflIngestError("Campaign directory must be a direct child of the adapter's authenticated output parent.")
    campaign_fd = _open_directory(campaign_absolute, expected_device=os.stat(output_parent).st_dev)
    try:
        campaign_info = os.fstat(campaign_fd)
        if stat.S_IMODE(campaign_info.st_mode) & 0o077:
            raise AflIngestError("Campaign directory must not be accessible by group or other users.")
        storage_device = campaign_info.st_dev
        raw_metadata, metadata_snapshot = _read_file_at(
            campaign_fd,
            "campaign.json",
            maximum=MAX_CAMPAIGN_METADATA_BYTES,
            expected_device=storage_device,
        )
    finally:
        os.close(campaign_fd)
    metadata_sha256 = hashlib.sha256(raw_metadata).hexdigest()
    metadata = _load_json_bytes(raw_metadata, "campaign.json")
    schema_version = metadata.get("schema_version")
    if type(schema_version) is int and schema_version == 1:
        raise AflIngestError("Campaign metadata schema v1 lacks launch-time provenance identities and cannot be ingested.")
    if type(schema_version) is not int or schema_version != 2:
        raise AflIngestError("Only campaign metadata schema version 2 can be ingested.")
    campaign_uid = _require_string(metadata, "campaign_id", "campaign")
    _parse_campaign_uid(campaign_uid)
    if campaign_uid != campaign_name:
        raise AflIngestError("Campaign directory name and campaign_id do not match.")
    status = _require_string(metadata, "status", "campaign")
    if status not in {"completed", "failed", "interrupted"}:
        raise AflIngestError("Only terminal completed, failed or interrupted campaigns can be ingested.")
    started_at = _normalize_time(metadata.get("started_at"), "campaign.started_at")
    ended_at = _normalize_time(metadata.get("ended_at"), "campaign.ended_at")
    if ended_at < started_at:
        raise AflIngestError("Campaign ended_at precedes started_at.")

    target = metadata.get("target")
    fuzzer = metadata.get("fuzzer")
    limits = metadata.get("limits")
    identity = metadata.get("identity")
    toolchain = metadata.get("toolchain")
    validation = metadata.get("validation")
    if not all(isinstance(item, dict) for item in (target, fuzzer, limits, identity, toolchain, validation)):
        raise AflIngestError("Campaign metadata is missing target, fuzzer, limits, identity, toolchain or validation objects.")
    if target.get("name") != config.target.name or target.get("version") != config.target.version:
        raise AflIngestError("Campaign target identity does not match the adapter.")
    if target.get("source_dir") != str(config.target.source_dir) or target.get("harness_binary") != str(config.target.harness_binary):
        raise AflIngestError("Campaign source or harness path differs from the adapter.")
    if target.get("seed_dir") != str(config.target.seed_dir):
        raise AflIngestError("Campaign seed directory differs from the adapter.")
    if _require_string(metadata, "adapter_config", "campaign") != str(config.config_path):
        raise AflIngestError("Campaign adapter-config path differs from the supplied configuration.")
    if fuzzer.get("expected_version") != config.fuzzer.expected_version:
        raise AflIngestError("Campaign expected AFL++ version differs from the adapter.")
    for key, expected in (
        ("duration_seconds", config.limits.duration_seconds),
        ("memory_mib", config.limits.memory_mib),
        ("timeout_ms", config.limits.timeout_ms),
        ("max_input_bytes", config.limits.max_input_bytes),
    ):
        if type(limits.get(key)) is not int or limits[key] != expected:
            raise AflIngestError(f"Campaign limit {key!r} differs from the adapter.")

    adapter_path = _require_string(identity, "adapter_config_path", "identity")
    adapter_hash = _require_string(identity, "adapter_config_sha256", "identity")
    seed_dir_identity = _require_string(identity, "seed_dir", "identity")
    seed_hash = _require_string(identity, "seed_manifest_sha256", "identity")
    build_metadata_path = _require_string(identity, "build_metadata_path", "identity")
    build_metadata_hash = _require_string(identity, "build_metadata_sha256", "identity")
    if adapter_path != str(config.config_path) or seed_dir_identity != str(config.target.seed_dir):
        raise AflIngestError("Campaign launch identity paths do not match the adapter.")
    if _SHA256.fullmatch(adapter_hash) is None or _SHA256.fullmatch(seed_hash) is None or _SHA256.fullmatch(build_metadata_hash) is None:
        raise AflIngestError("Campaign launch identity contains an invalid SHA-256 value.")
    seed_count = _require_int(identity, "seed_count", "identity", minimum=1)
    actual_adapter_hash = hash_stable_file(config.config_path, max_bytes=MAX_IDENTITY_FILE_BYTES)
    if actual_adapter_hash.sha256 != adapter_hash:
        raise AflIngestError("Adapter TOML changed after the campaign started.")
    manifest = build_seed_manifest(
        config.target.seed_dir,
        max_file_bytes=config.limits.max_input_bytes,
    )
    if manifest.sha256 != seed_hash or manifest.seed_count != seed_count:
        raise AflIngestError("Seed corpus changed after the campaign started.")

    expected_build_metadata = config.build.build_dir / "build.json"
    if Path(build_metadata_path) != expected_build_metadata:
        raise AflIngestError("Campaign build metadata path does not match the configured build directory.")
    try:
        build_hash = hash_stable_file(build_metadata_path, max_bytes=MAX_CAMPAIGN_METADATA_BYTES)
        build_raw_path = Path(build_metadata_path)
        build_fd = _open_directory(build_raw_path.parent)
        try:
            build_raw, build_metadata_snapshot = _read_file_at(
                build_fd, build_raw_path.name, maximum=MAX_CAMPAIGN_METADATA_BYTES
            )
        finally:
            os.close(build_fd)
    except (OSError, SeedManifestError) as exc:
        raise AflIngestError(f"Cannot verify campaign build metadata: {exc}") from exc
    if (
        build_hash.sha256 != build_metadata_hash
        or hashlib.sha256(build_raw).hexdigest() != build_metadata_hash
        or build_metadata_snapshot != build_hash.snapshot
    ):
        raise AflIngestError("build.json changed after the campaign started.")
    build_metadata = _load_json_bytes(build_raw, "build.json")
    toolchain_values = {}
    for key in ("compiler_path", "compiler_version", "aflpp_version", "afl_showmap_version"):
        toolchain_values[key] = _require_string(toolchain, key, "toolchain")
    if toolchain_values["afl_showmap_version"] != config.fuzzer.expected_version:
        raise AflIngestError("Campaign coverage tool version differs from the pinned AFL++ version.")
    build_validation = validation.get("build_provenance")
    coverage_validation = validation.get("coverage")
    if not isinstance(build_validation, dict) or build_validation.get("status") != "passed":
        raise AflIngestError("Campaign did not record successful build provenance.")
    if not isinstance(coverage_validation, dict) or coverage_validation.get("status") != "passed":
        raise AflIngestError("Campaign did not record successful coverage validation.")
    if coverage_validation.get("tool_version") != toolchain_values["afl_showmap_version"]:
        raise AflIngestError("Structured afl-showmap version does not match campaign validation evidence.")
    if any(
        not isinstance(validation.get(key), dict)
        or validation[key].get("status") != "passed"
        for key in ("preflight", "harness_smoke")
    ):
        raise AflIngestError("Campaign did not pass all required validation gates.")

    verified_hashes, cmake_build_type = _verify_build_metadata(
        config,
        build_metadata,
        toolchain_values,
        identity,
    )
    afl_output_dir = campaign_absolute / "afl-output"
    command, afl_max_generated_bytes = _validate_command(metadata, config, afl_output_dir)
    if command[0] != _require_string(fuzzer, "executable", "fuzzer"):
        raise AflIngestError("Recorded command executable differs from campaign fuzzer metadata.")
    expected_device = storage_device
    afl_output_directory_snapshot = _directory_identity(afl_output_dir, expected_device)
    worker_root, worker_name, worker_device = _detect_worker_root(afl_output_dir, expected_device)
    worker_directory_snapshot = _directory_identity(worker_root, worker_device)
    worker_fd = _open_directory(worker_root, expected_device=worker_device)
    try:
        worker_entries = set(os.listdir(worker_fd))
        if not {"crashes", "hangs"}.issubset(worker_entries):
            raise AflIngestError(
                "AFL++ did not create both crashes/ and hangs/; refusing a pre-start or incomplete output tree."
            )
        stats = _parse_fuzzer_stats(worker_root, worker_fd, worker_device)
    finally:
        os.close(worker_fd)

    crash_directory = _scan_observation_directory(worker_root / "crashes", "crash", worker_device)
    hang_directory = _scan_observation_directory(worker_root / "hangs", "hang", worker_device)
    candidates = crash_directory.candidates + hang_directory.candidates
    if len(candidates) > MAX_IMPORT_OBSERVATIONS:
        raise AflIngestError(f"Campaign contains more than {MAX_IMPORT_OBSERVATIONS} crash/hang observations.")
    total_bytes = sum(item.size_bytes for item in candidates)
    if total_bytes > MAX_IMPORT_TOTAL_BYTES:
        raise AflIngestError(f"Campaign crash/hang data exceeds the {MAX_IMPORT_TOTAL_BYTES}-byte import budget.")

    context = _CampaignContext(
        config=config,
        campaign_dir=campaign_absolute,
        campaign_uid=campaign_uid,
        afl_output_dir=afl_output_dir,
        worker_root=worker_root,
        worker_name=worker_name,
        metadata=metadata,
        metadata_sha256=metadata_sha256,
        metadata_snapshot=metadata_snapshot,
        campaign_directory_snapshot=_snapshot(campaign_info),
        afl_output_directory_snapshot=afl_output_directory_snapshot,
        worker_directory_snapshot=worker_directory_snapshot,
        build_metadata=build_metadata,
        build_metadata_path=Path(build_metadata_path),
        build_metadata_snapshot=build_metadata_snapshot,
        build_metadata_sha256=build_hash.sha256,
        identity=identity,
        toolchain=toolchain_values,
        command=command,
        afl_max_generated_bytes=afl_max_generated_bytes,
        stats=stats,
        crash_directory=crash_directory,
        hang_directory=hang_directory,
        candidates=candidates,
        total_bytes=total_bytes,
    )
    return context, (str(config.target.source_dir), str(config.build.build_dir), str(config.target.output_parent))


def _directory_identity(path: Path, expected_device: int) -> tuple[int, int, int, int, int]:
    descriptor = _open_directory(path, expected_device=expected_device)
    try:
        return _snapshot(os.fstat(descriptor))
    finally:
        os.close(descriptor)


def _verify_directory_identity(
    path: Path,
    expected_snapshot: tuple[int, int, int, int, int],
    expected_device: int,
) -> None:
    if _directory_identity(path, expected_device) != expected_snapshot:
        raise AflIngestError(f"Campaign directory structure changed during ingestion: {path}")


def _verify_campaign_metadata_unchanged(context: _CampaignContext) -> None:
    _verify_directory_identity(
        context.campaign_dir, context.campaign_directory_snapshot,
        context.campaign_directory_snapshot[0],
    )
    campaign_fd = _open_directory(context.campaign_dir)
    try:
        raw, snapshot = _read_file_at(
            campaign_fd,
            "campaign.json",
            maximum=MAX_CAMPAIGN_METADATA_BYTES,
        )
    finally:
        os.close(campaign_fd)
    if snapshot != context.metadata_snapshot or hashlib.sha256(raw).hexdigest() != context.metadata_sha256:
        raise AflIngestError("campaign.json changed during ingestion.")


def _verify_source_directories_unchanged(context: _CampaignContext, expected_device: int) -> None:
    _verify_directory_identity(
        context.afl_output_dir, context.afl_output_directory_snapshot, expected_device
    )
    _verify_directory_identity(
        context.worker_root, context.worker_directory_snapshot, expected_device
    )
    _verify_directory_snapshot(context.crash_directory, expected_device)
    _verify_directory_snapshot(context.hang_directory, expected_device)


def _verify_campaign_identity_sources_unchanged(context: _CampaignContext) -> None:
    identity = context.identity
    adapter_hash = hash_stable_file(context.config.config_path, max_bytes=MAX_IDENTITY_FILE_BYTES)
    if adapter_hash.sha256 != identity["adapter_config_sha256"]:
        raise AflIngestError("Adapter TOML changed during evidence ingestion.")
    seed_manifest = build_seed_manifest(
        context.config.target.seed_dir,
        max_file_bytes=context.config.limits.max_input_bytes,
    )
    if (
        seed_manifest.sha256 != identity["seed_manifest_sha256"]
        or seed_manifest.seed_count != identity["seed_count"]
    ):
        raise AflIngestError("Seed corpus changed during evidence ingestion.")
    build_hash = hash_stable_file(
        context.build_metadata_path,
        max_bytes=MAX_CAMPAIGN_METADATA_BYTES,
    )
    parent_fd = _open_directory(context.build_metadata_path.parent)
    try:
        raw, snapshot = _read_file_at(
            parent_fd,
            context.build_metadata_path.name,
            maximum=MAX_CAMPAIGN_METADATA_BYTES,
        )
    finally:
        os.close(parent_fd)
    if (
        build_hash.sha256 != context.build_metadata_sha256
        or hashlib.sha256(raw).hexdigest() != context.build_metadata_sha256
        or snapshot != context.build_metadata_snapshot
        or build_hash.snapshot != context.build_metadata_snapshot
    ):
        raise AflIngestError("build.json changed during evidence ingestion.")
    _verify_build_metadata(
        context.config,
        context.build_metadata,
        context.toolchain,
        context.identity,
    )


def _campaign_record(context: _CampaignContext, ids: dict[str, int], recorded_at: str) -> dict[str, object]:
    metadata = context.metadata
    config = context.config
    return {
        "campaign_uid": context.campaign_uid,
        "target_id": ids["target"],
        "target_version_id": ids["target_version"],
        "build_id": ids["build"],
        "adapter_config_path": metadata["adapter_config"],
        "adapter_config_sha256": metadata["identity"]["adapter_config_sha256"],
        "campaign_dir": str(context.campaign_dir),
        "afl_output_dir": str(context.afl_output_dir),
        "campaign_metadata_sha256": context.metadata_sha256,
        "seed_dir": str(config.target.seed_dir),
        "seed_manifest_sha256": metadata["identity"]["seed_manifest_sha256"],
        "seed_count": metadata["identity"]["seed_count"],
        "fuzzer_executable": metadata["fuzzer"]["executable"],
        "fuzzer_version": context.toolchain["aflpp_version"],
        "command_json": list(context.command),
        "duration_seconds": config.limits.duration_seconds,
        "memory_mib": config.limits.memory_mib,
        "timeout_ms": config.limits.timeout_ms,
        "effective_timeout_ms": context.stats.get("exec_timeout"),
        "max_input_bytes": config.limits.max_input_bytes,
        "afl_max_generated_bytes": context.afl_max_generated_bytes,
        "status": metadata["status"],
        "exit_code": metadata.get("exit_code"),
        "total_execs": context.stats.get("execs_done"),
        "saved_crashes_reported": context.stats.get("saved_crashes"),
        "saved_hangs_reported": context.stats.get("saved_hangs"),
        "started_at": metadata["started_at"],
        "ended_at": metadata["ended_at"],
        "recorded_at": recorded_at,
    }


def _build_record(context: _CampaignContext, ids: dict[str, int], recorded_at: str) -> dict[str, object]:
    metadata = context.build_metadata
    artifacts = metadata["artifacts"]
    return {
        "target_id": ids["target"],
        "target_version_id": ids["target_version"],
        "profile": metadata["profile"],
        "build_role": "fuzz",
        "build_dir": metadata["build_dir"],
        "build_metadata_sha256": context.build_metadata_sha256,
        "harness_source_path": str(context.config.target.harness_source),
        "harness_binary_path": str(context.config.target.harness_binary),
        "harness_source_sha256": artifacts["harness_source_sha256"],
        "harness_binary_sha256": artifacts["harness_binary_sha256"],
        "library_archive_sha256": artifacts["library_archive_sha256"],
        "cmake_cache_sha256": artifacts["cmake_cache_sha256"],
        "compile_database_sha256": artifacts["compile_database_sha256"],
        "generated_header_sha256": artifacts["generated_header_sha256"],
        "compiler_path": context.toolchain["compiler_path"],
        "compiler_version": context.toolchain["compiler_version"],
        "cmake_build_type": EXPECTED_CMAKE_BUILD_TYPE,
        "aflpp_version": context.toolchain["aflpp_version"],
        "afl_instrumented_locations": None,
        "sanitizer_config_json": SANITIZER_CONFIG,
        "environment_json": metadata["environment"],
        "build_status": metadata["status"],
        "started_at": metadata["started_at"],
        "ended_at": metadata["ended_at"],
        "recorded_at": recorded_at,
    }


def _target_records(context: _CampaignContext, recorded_at: str) -> tuple[dict[str, object], dict[str, object]]:
    metadata = context.build_metadata
    source_archive = context.config.target.source_archive
    return (
        {
            "name": context.config.target.name,
            "description": "Portable Network Graphics image decoding library.",
            "created_at": recorded_at,
        },
        {
            "target_id": 0,
            "version": context.config.target.version,
            "source_archive_sha256": metadata["source_archive_sha256"],
            "source_tree_sha256": metadata["source_tree_sha256"],
            "source_dir_recorded": str(context.config.target.source_dir),
            "source_archive_path": str(source_archive),
            "created_at": recorded_at,
        },
    )


def ingest_afl_campaign(
    campaign_dir: str | Path,
    config_path: str | Path,
    evidence_root: str | Path,
) -> IngestResult:
    """Validate one terminal AFL++ campaign, copy original inputs, and register them."""
    context, protected_paths = _validate_campaign(campaign_dir, config_path)
    root = Path(evidence_root).expanduser()
    if not root.is_absolute():
        raise AflIngestError("Evidence root must be an absolute path.")
    extra_protected = (
        context.campaign_dir,
        context.config.target.seed_dir,
        context.config.target.source_archive,
        context.config.target.campaign_storage_image,
    )
    protected = tuple(protected_paths) + tuple(str(item) for item in extra_protected if item is not None)

    try:
        with EvidenceStore(root, protected_paths=protected) as store:
            run_migrations(root)
            connection = open_database(store.database_path)
            try:
                published = []
                for candidate in context.candidates:
                    stored = store.publish_file(candidate.source_path)
                    if stored.size_bytes != candidate.size_bytes:
                        raise AflIngestError(f"Copied artifact size differs from source snapshot: {candidate.name}")
                    published.append((candidate, stored))

                campaign_info = os.stat(context.campaign_dir, follow_symlinks=False)
                expected_device = campaign_info.st_dev
                _verify_source_directories_unchanged(context, expected_device)
                _verify_campaign_metadata_unchanged(context)
                _verify_campaign_identity_sources_unchanged(context)

                recorded_at = utc_now_iso()
                repository = EvidenceRepository(connection)
                target_record, version_record = _target_records(context, recorded_at)
                with immediate_transaction(connection):
                    target_id = repository.insert_target(target_record)
                    version_record["target_id"] = target_id
                    target_version_id = repository.insert_target_version(version_record)
                    ids = {
                        "target": target_id,
                        "target_version": target_version_id,
                    }
                    build_id = repository.insert_build(_build_record(context, ids, recorded_at))
                    ids["build"] = build_id
                    campaign_id = repository.insert_campaign(_campaign_record(context, ids, recorded_at))
                    ids["campaign"] = campaign_id
                    for candidate, stored in published:
                        artifact_id = repository.insert_artifact({
                            "sha256": stored.sha256,
                            "size_bytes": stored.size_bytes,
                            "storage_relpath": stored.storage_relpath,
                            "first_ingested_at": recorded_at,
                            "last_verified_at": recorded_at,
                        })
                        repository.insert_observation({
                            "campaign_uid": context.campaign_uid,
                            "target_id": target_id,
                            "target_version_id": target_version_id,
                            "build_id": build_id,
                            "campaign_id": campaign_id,
                            "original_artifact_id": artifact_id,
                            "observation_kind": candidate.kind,
                            "afl_worker_name": context.worker_name,
                            "afl_source_filename": candidate.name,
                            "afl_input_id": candidate.input_id,
                            "observed_signal": candidate.signal,
                            "observed_exit_code": None,
                            "afl_discovery_time_ms": candidate.discovery_time_ms,
                            "afl_discovery_execs": candidate.discovery_execs,
                            "source_file_mtime_utc": _mtime_to_utc(candidate.mtime_ns),
                            "ingested_at": recorded_at,
                        })
                return IngestResult(
                    campaign_uid=context.campaign_uid,
                    campaign_id=context.campaign_uid,
                    crash_count=sum(1 for item in context.candidates if item.kind == "crash"),
                    hang_count=sum(1 for item in context.candidates if item.kind == "hang"),
                    artifact_count=len(published),
                    total_bytes=context.total_bytes,
                    target_id=target_id,
                    target_version_id=target_version_id,
                    build_id=build_id,
                    campaign_row_id=campaign_id,
                )
            finally:
                connection.close()
    except (EvidenceStoreError, sqlite3.Error, OSError, SeedManifestError, StorageError, ValueError, RuntimeError) as exc:
        if isinstance(exc, AflIngestError):
            raise
        raise AflIngestError(f"AFL++ evidence ingestion failed: {exc}") from exc
