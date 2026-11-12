"""Strict TOML configuration loading for KEKKAI target adapters."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class AdapterConfigError(ValueError):
    """Raised when an adapter configuration is invalid or unreadable."""


@dataclass(frozen=True)
class TargetConfig:
    name: str
    version: str
    source_dir: Path
    harness_source: Path
    harness_binary: Path
    seed_dir: Path
    output_parent: Path


@dataclass(frozen=True)
class FuzzerConfig:
    executable: str
    expected_version: str


@dataclass(frozen=True)
class ResourceLimits:
    duration_seconds: int
    memory_mib: int
    timeout_ms: int
    max_input_bytes: int


@dataclass(frozen=True)
class BuildConfig:
    profile: str
    build_dir: Path
    jobs: int
    timeout_seconds: int
    memory_mib: int
    log_limit_bytes: int


@dataclass(frozen=True)
class AdapterConfig:
    schema_version: int
    target: TargetConfig
    fuzzer: FuzzerConfig
    limits: ResourceLimits
    config_path: Path
    build: BuildConfig | None = None


def _require_table(value: Any, name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdapterConfigError(f"'{name}' must be a TOML table.")
    return value


def _require_exact_keys(
    table: dict[str, Any],
    name: str,
    expected: set[str],
) -> None:
    actual = set(table)
    missing = expected - actual
    unknown = actual - expected

    if missing:
        raise AdapterConfigError(
            f"'{name}' is missing required keys: {', '.join(sorted(missing))}."
        )

    if unknown:
        raise AdapterConfigError(
            f"'{name}' contains unknown keys: {', '.join(sorted(unknown))}."
        )


def _require_string(table: dict[str, Any], key: str, section: str) -> str:
    value = table[key]

    if not isinstance(value, str) or not value.strip():
        raise AdapterConfigError(
            f"'{section}.{key}' must be a non-empty string."
        )

    if "\x00" in value:
        raise AdapterConfigError(
            f"'{section}.{key}' must not contain a null character."
        )

    return value.strip()


def _require_integer(
    table: dict[str, Any],
    key: str,
    section: str,
    minimum: int,
    maximum: int,
) -> int:
    value = table[key]

    # bool is a subclass of int in Python, so use an exact type check.
    if type(value) is not int:
        raise AdapterConfigError(
            f"'{section}.{key}' must be an integer."
        )

    if not minimum <= value <= maximum:
        raise AdapterConfigError(
            f"'{section}.{key}' must be between {minimum} and {maximum}."
        )

    return value


def _resolve_path(value: str, project_root: Path, field: str) -> Path:
    try:
        path = Path(value).expanduser()
        if not path.is_absolute():
            path = project_root / path
        return path.resolve(strict=False)
    except (OSError, RuntimeError, ValueError) as exc:
        raise AdapterConfigError(
            f"Unable to resolve path for '{field}': {exc}"
        ) from exc


def load_adapter_config(
    config_path: str | Path,
    project_root: str | Path,
) -> AdapterConfig:
    """Load and structurally validate one adapter TOML file.

    Relative paths are resolved against project_root.
    This function does not check target files, execute programs,
    create directories or launch campaigns. Those belong to preflight
    and campaign execution.
    """
    try:
        root = Path(project_root).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise AdapterConfigError(
            f"Invalid project root: {exc}"
        ) from exc

    if not root.is_dir():
        raise AdapterConfigError("Project root must be a directory.")

    try:
        config_file = Path(config_path).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise AdapterConfigError(
            f"Cannot resolve adapter configuration: {exc}"
        ) from exc

    if not config_file.is_file():
        raise AdapterConfigError(
            f"Adapter configuration is not a regular file: {config_file}"
        )

    try:
        raw_text = config_file.read_text(encoding="utf-8")
        document = tomllib.loads(raw_text)
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        raise AdapterConfigError(
            f"Cannot read valid TOML from '{config_file}': {exc}"
        ) from exc

    document = _require_table(document, "root")
    _require_exact_keys(
        document,
        "root",
        {"schema_version", "target", "fuzzer", "limits", "build"},
    )

    schema_version = document["schema_version"]
    if type(schema_version) is not int or schema_version != 2:
        raise AdapterConfigError(
            "'schema_version' must be the integer 2."
        )

    target_table = _require_table(document["target"], "target")
    _require_exact_keys(
        target_table,
        "target",
        {
            "name",
            "version",
            "source_dir",
            "harness_source",
            "harness_binary",
            "seed_dir",
            "output_parent",
        },
    )

    target = TargetConfig(
        name=_require_string(target_table, "name", "target"),
        version=_require_string(target_table, "version", "target"),
        source_dir=_resolve_path(
            _require_string(target_table, "source_dir", "target"),
            root,
            "target.source_dir",
        ),
        harness_source=_resolve_path(
            _require_string(target_table, "harness_source", "target"),
            root,
            "target.harness_source",
        ),
        harness_binary=_resolve_path(
            _require_string(target_table, "harness_binary", "target"),
            root,
            "target.harness_binary",
        ),
        seed_dir=_resolve_path(
            _require_string(target_table, "seed_dir", "target"),
            root,
            "target.seed_dir",
        ),
        output_parent=_resolve_path(
            _require_string(target_table, "output_parent", "target"),
            root,
            "target.output_parent",
        ),
    )

    fuzzer_table = _require_table(document["fuzzer"], "fuzzer")
    _require_exact_keys(
        fuzzer_table,
        "fuzzer",
        {"executable", "expected_version"},
    )

    fuzzer = FuzzerConfig(
        executable=_require_string(fuzzer_table, "executable", "fuzzer"),
        expected_version=_require_string(
            fuzzer_table, "expected_version", "fuzzer"
        ),
    )

    limits_table = _require_table(document["limits"], "limits")
    _require_exact_keys(
        limits_table,
        "limits",
        {
            "duration_seconds",
            "memory_mib",
            "timeout_ms",
            "max_input_bytes",
        },
    )

    limits = ResourceLimits(
        duration_seconds=_require_integer(
            limits_table, "duration_seconds", "limits", 1, 86400
        ),
        memory_mib=_require_integer(
            limits_table, "memory_mib", "limits", 1, 4096
        ),
        timeout_ms=_require_integer(
            limits_table, "timeout_ms", "limits", 5, 60000
        ),
        max_input_bytes=_require_integer(
            limits_table, "max_input_bytes", "limits", 1, 1073741824
        ),
    )

    build_table = _require_table(document["build"], "build")
    _require_exact_keys(
        build_table,
        "build",
        {
            "profile",
            "build_dir",
            "jobs",
            "timeout_seconds",
            "memory_mib",
            "log_limit_bytes",
        },
    )

    profile = _require_string(build_table, "profile", "build")
    if profile != "libpng-afl-ubsan":
        raise AdapterConfigError(
            "'build.profile' must be 'libpng-afl-ubsan'."
        )

    build_dir = _resolve_path(
        _require_string(build_table, "build_dir", "build"),
        root,
        "build.build_dir",
    )

    def paths_overlap(first: Path, second: Path) -> bool:
        return (
            first == second
            or first in second.parents
            or second in first.parents
        )

    for label, protected in (
        ("repository", root),
        ("target source", target.source_dir),
        ("campaign output", target.output_parent),
    ):
        if paths_overlap(build_dir, protected):
            raise AdapterConfigError(
                f"'build.build_dir' must not overlap the {label}."
            )

    expected_harness = build_dir / "kekkai_png_harness"
    if target.harness_binary != expected_harness:
        raise AdapterConfigError(
            "'target.harness_binary' must be build.build_dir/"
            "'kekkai_png_harness'."
        )

    build = BuildConfig(
        profile=profile,
        build_dir=build_dir,
        jobs=_require_integer(
            build_table, "jobs", "build", 1, 2
        ),
        timeout_seconds=_require_integer(
            build_table, "timeout_seconds", "build", 60, 1800
        ),
        memory_mib=_require_integer(
            build_table, "memory_mib", "build", 1024, 8192
        ),
        log_limit_bytes=_require_integer(
            build_table, "log_limit_bytes", "build",
            1048576, 33554432
        ),
    )

    return AdapterConfig(
        schema_version=schema_version,
        target=target,
        fuzzer=fuzzer,
        limits=limits,
        config_path=config_file,
        build=build,
    )
