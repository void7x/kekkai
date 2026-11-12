"""Fixed, validated build plan for the libpng 1.6.59 AFL++ profile."""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path

from engine.adapters.config import AdapterConfig


class BuildError(RuntimeError):
    """Raised when a safe libpng build plan cannot be created."""


@dataclass(frozen=True)
class BuildStep:
    name: str
    command: tuple[str, ...]


@dataclass(frozen=True)
class BuildPlan:
    build_dir: Path
    steps: tuple[BuildStep, ...]
    environment: tuple[tuple[str, str], ...]


_PROFILE = "libpng-afl-ubsan"
_TARGET_VERSION = "1.6.59"
_HARNESS_SHA256 = (
    "3f67a53d149535763e6d76e26edc4147"
    "eb31cd2765f838b5317d4065e7fe2bdc"
)

_CMAKE = Path("/usr/bin/cmake")
_NINJA = Path("/usr/bin/ninja")
_COMPILER = Path("/usr/bin/afl-clang-fast")
_AWK = Path("/usr/bin/gawk")
_ZLIB_INCLUDE = Path("/usr/include")
_ZLIB_LIBRARY = Path("/usr/lib/x86_64-linux-gnu/libz.so")


def _overlap(first: Path, second: Path) -> bool:
    return (
        first == second
        or first in second.parents
        or second in first.parents
    )


def _require_executable(path: Path, label: str) -> str:
    """Validate a pinned system executable while preserving wrapper symlinks."""
    try:
        resolved = path.resolve(strict=True)
        trusted_directory = path.parent.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise BuildError(f"Cannot resolve {label}: {exc}") from exc

    if (
        not resolved.is_relative_to(trusted_directory)
        or not resolved.is_file()
        or not os.access(resolved, os.X_OK)
    ):
        raise BuildError(
            f"Required {label} is missing or unsafe: {path}"
        )

    # Keep the original name. AFL++ uses the afl-clang-fast wrapper name.
    return str(path)


def _validate_source(config: AdapterConfig, root: Path) -> Path:
    if config.target.name.casefold() != "libpng":
        raise BuildError("The approved build profile supports only libpng.")
    if config.target.version != _TARGET_VERSION:
        raise BuildError(f"This build profile requires libpng {_TARGET_VERSION}.")

    source = config.target.source_dir.resolve(strict=True)
    if not source.is_dir():
        raise BuildError("libpng source path is not a directory.")

    header = source / "png.h"
    if header.is_symlink() or not header.is_file():
        raise BuildError("Pinned libpng png.h is missing or unsafe.")
    if header.stat().st_size > 1024 * 1024:
        raise BuildError("libpng png.h exceeds the allowed size.")

    header_text = header.read_text(encoding="utf-8")
    match = re.search(
        r'^\s*#\s*define\s+PNG_LIBPNG_VER_STRING\s+"([^"]+)"',
        header_text,
        re.MULTILINE,
    )
    if match is None or match.group(1) != _TARGET_VERSION:
        raise BuildError(
            f"Source version mismatch; expected {_TARGET_VERSION}, "
            f"observed {match.group(1) if match else 'unknown'}."
        )

    harness_path = config.target.harness_source
    if harness_path.is_symlink() or not harness_path.is_file():
        raise BuildError("Harness source is not a regular file.")

    harness = harness_path.resolve(strict=True)
    expected_harness = root / "targets/libpng/png_read_harness.c"
    if harness != expected_harness.resolve(strict=True):
        raise BuildError("Harness source is not the repository-owned libpng harness.")

    digest = hashlib.sha256(harness.read_bytes()).hexdigest()
    if digest != _HARNESS_SHA256:
        raise BuildError(f"Harness source hash differs from the reviewed source: {digest}")

    return source


def build_command_plan(
    config: AdapterConfig,
    project_root: str | Path,
) -> BuildPlan:
    """Create fixed CMake, Ninja and harness-link commands without executing them."""
    if config.build is None:
        raise BuildError("Adapter has no build configuration.")
    if config.build.profile != _PROFILE:
        raise BuildError("Unsupported build profile.")

    try:
        root = Path(project_root).expanduser().resolve(strict=True)
        source = _validate_source(config, root)
        build_dir = config.build.build_dir
        parent = build_dir.parent.resolve(strict=True)
        output_parent = config.target.output_parent.resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise BuildError(f"Cannot validate build paths or source: {exc}") from exc

    if not root.is_dir() or not parent.is_dir() or not output_parent.is_dir():
        raise BuildError("Repository, build parent or output parent is invalid.")

    build_dir = parent / build_dir.name
    if build_dir.exists() or build_dir.is_symlink():
        raise BuildError(f"Clean build directory already exists: {build_dir}")

    for label, protected in (
        ("repository", root),
        ("source tree", source),
        ("campaign output", output_parent),
    ):
        if _overlap(build_dir, protected):
            raise BuildError(f"Build directory must be outside the {label}.")

    if not os.access(parent, os.W_OK | os.X_OK):
        raise BuildError("Clean build directory parent is not writable.")

    if config.target.harness_binary != build_dir / "kekkai_png_harness":
        raise BuildError("Harness binary must be inside the configured clean build directory.")

    cmake = _require_executable(_CMAKE, "CMake")
    ninja = _require_executable(_NINJA, "Ninja")
    compiler = _require_executable(_COMPILER, "AFL++ compiler")
    awk = _require_executable(_AWK, "AWK")
    zlib_header = _ZLIB_INCLUDE / "zlib.h"
    if (
        not _ZLIB_INCLUDE.is_dir()
        or zlib_header.is_symlink()
        or not zlib_header.is_file()
        or zlib_header.stat().st_size > 1024 * 1024
        or not _ZLIB_LIBRARY.is_file()
    ):
        raise BuildError("The approved system zlib headers or library are missing.")

    zlib_text = zlib_header.read_text(encoding="utf-8")
    zlib_match = re.search(
        r'^\s*#\s*define\s+ZLIB_VERSION\s+"([^"]+)"',
        zlib_text,
        re.MULTILINE,
    )
    if zlib_match is None or zlib_match.group(1) != "1.3.1":
        raise BuildError(
            "The fixed build profile requires system zlib 1.3.1; "
            f"observed {zlib_match.group(1) if zlib_match else 'unknown'}."
        )

    cmake_command = (
        cmake,
        "-S", str(source),
        "-B", str(build_dir),
        "-G", "Ninja",
        "-DCMAKE_MAKE_PROGRAM=" + ninja,
        "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
        "-DCMAKE_C_COMPILER=" + compiler,
        "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
        "-DAWK=" + awk,
        "-DPNG_BUILD_ZLIB=OFF",
        "-DPNG_EXECUTABLES=ON",
        "-DPNG_FRAMEWORK=OFF",
        "-DPNG_HARDWARE_OPTIMIZATIONS=ON",
        "-DPNG_INTEL_SSE=on",
        "-DPNG_SHARED=OFF",
        "-DPNG_STATIC=ON",
        "-DPNG_TESTS=OFF",
        "-DPNG_TOOLS=OFF",
        "-DZLIB_INCLUDE_DIR=" + str(_ZLIB_INCLUDE),
        "-DZLIB_LIBRARY_RELEASE=" + str(_ZLIB_LIBRARY),
    )

    ninja_command = (
        ninja,
        "-C", str(build_dir),
        "-j", str(config.build.jobs),
        "-v",
        "png_static",
    )

    harness_command = (
        compiler,
        "-O2",
        "-g",
        "-DNDEBUG",
        "-fPIC",
        "-I", str(source),
        "-I", str(build_dir),
        str(config.target.harness_source),
        str(build_dir / "libpng16.a"),
        str(_ZLIB_LIBRARY),
        "-lm",
        "-o", str(build_dir / "kekkai_png_harness"),
    )

    return BuildPlan(
        build_dir=build_dir,
        steps=(
            BuildStep("configure", cmake_command),
            BuildStep("library", ninja_command),
            BuildStep("harness", harness_command),
        ),
        environment=(
            ("PATH", os.defpath),
            ("LC_ALL", "C"),
            ("AFL_USE_UBSAN", "1"),
            ("AFL_DEBUG", "1"),
        ),
    )
