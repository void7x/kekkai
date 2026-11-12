"""Verification of the pinned libpng AFL++ build identity."""

from __future__ import annotations

import hashlib
import json
import os
import re
import resource
import shlex
import shutil
import subprocess
import tempfile
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProvenanceCheck:
    name: str
    status: str
    message: str


@dataclass(frozen=True)
class ProvenanceReport:
    target_name: str
    target_version: str
    checks: tuple[ProvenanceCheck, ...]

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(
            check.status == "passed" for check in self.checks
        )

    def format(self) -> str:
        result = "PASS" if self.passed else "FAIL"
        lines = [
            f"Build provenance: {result}",
            f"Target: {self.target_name} {self.target_version}",
        ]
        for check in self.checks:
            lines.append(
                f"[{check.status.upper()}] {check.name}: {check.message}"
            )
        return "\n".join(lines)


_MAX_MANIFEST_BYTES = 64 * 1024
_MAX_BUILD_FILE_BYTES = 16 * 1024 * 1024
_MAX_VERSION_OUTPUT_BYTES = 16 * 1024

_REQUIRED_KEYS = {
    "schema_version", "target_name", "target_version",
    "harness_source", "harness_source_sha256",
    "harness_binary_sha256", "library_archive",
    "library_archive_sha256", "cmake_cache",
    "compile_database", "expected_translation_units",
    "compiler_path", "compiler_version", "cmake_build_type",
    "position_independent_code", "png_static", "png_shared",
    "png_tests", "png_tools", "png_framework",
    "aflpp_version", "afl_instrumented_locations",
    "ubsan_mode", "evidence_document",
}


def _read_bounded_file(path: Path, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"Not a regular, non-symlink file: {path}")
    if path.stat().st_size > maximum:
        raise ValueError(f"File exceeds {maximum} bytes: {path}")
    with path.open("rb") as stream:
        content = stream.read(maximum + 1)
    if len(content) > maximum:
        raise ValueError(f"File exceeds {maximum} bytes: {path}")
    return content


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run_bounded_version(command: list[str]) -> tuple[int, str]:
    if os.name != "posix":
        raise OSError("Bounded version verification requires POSIX.")

    def limit_output() -> None:
        for descriptor in (1, 2):
            current_soft, current_hard = resource.getrlimit(
                resource.RLIMIT_FSIZE
            )
            maximum = _MAX_VERSION_OUTPUT_BYTES // 2
            if current_soft != resource.RLIM_INFINITY:
                maximum = min(maximum, current_soft)
            if current_hard != resource.RLIM_INFINITY:
                maximum = min(maximum, current_hard)
            resource.setrlimit(
                resource.RLIMIT_FSIZE, (maximum, maximum)
            )

    with (
        tempfile.TemporaryFile(mode="w+b") as stdout_file,
        tempfile.TemporaryFile(mode="w+b") as stderr_file,
    ):
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=stdout_file,
            stderr=stderr_file,
            timeout=5,
            check=False,
            shell=False,
            preexec_fn=limit_output,
            env={"PATH": os.defpath, "LC_ALL": "C"},
        )

        outputs = []
        for stream in (stdout_file, stderr_file):
            stream.flush()
            size = os.fstat(stream.fileno()).st_size
            if size >= _MAX_VERSION_OUTPUT_BYTES // 2:
                raise ValueError("Version command exceeded output limit.")
            stream.seek(0)
            outputs.append(stream.read(_MAX_VERSION_OUTPUT_BYTES // 2))

    return result.returncode, b"\n".join(outputs).decode(
        "utf-8", errors="replace"
    )



def _verify_adapter_build_provenance(
    config,
    project_root: str | Path,
) -> ProvenanceReport:
    """Verify artifacts produced by the schema-v2 adapter build runner."""
    checks: list[ProvenanceCheck] = []

    def add(name: str, passed: bool, message: str) -> None:
        checks.append(
            ProvenanceCheck(name, "passed" if passed else "failed", message)
        )

    try:
        root = Path(project_root).expanduser().resolve(strict=True)
        build_dir = config.build.build_dir.resolve(strict=True)
        metadata_path = build_dir / "build.json"
        metadata = json.loads(
            _read_bounded_file(metadata_path, 1024 * 1024)
        )

        if not isinstance(metadata, dict):
            raise ValueError("Build metadata must be a JSON object.")

        identity_valid = (
            metadata.get("schema_version") == 1
            and metadata.get("status") == "completed"
            and metadata.get("target") == "libpng"
            and metadata.get("target_version") == config.target.version
            and metadata.get("profile") == config.build.profile
            and Path(metadata.get("build_dir", "")).resolve() == build_dir
            and Path(metadata.get("adapter_config", "")).resolve()
            == config.config_path.resolve()
        )
        add(
            "adapter_build_identity",
            identity_valid,
            "Completed build metadata matches the adapter and target."
            if identity_valid
            else "Build metadata is incomplete or does not match the adapter.",
        )
        if not identity_valid:
            raise ValueError("Clean build identity verification failed.")

        steps = metadata.get("steps")
        expected_steps = ("configure", "library", "harness")
        steps_valid = (
            isinstance(steps, list)
            and tuple(step.get("name") for step in steps if isinstance(step, dict))
            == expected_steps
            and len(steps) == len(expected_steps)
            and all(
                isinstance(step, dict)
                and step.get("status") == "completed"
                and step.get("exit_code") == 0
                for step in steps
            )
        )
        add(
            "build_steps",
            steps_valid,
            "CMake, Ninja library and harness steps completed."
            if steps_valid
            else "One or more required build steps are incomplete.",
        )
        if not steps_valid:
            raise ValueError("Required clean build steps did not all complete.")

        environment = metadata.get("environment")
        environment_valid = (
            isinstance(environment, dict)
            and environment.get("AFL_USE_UBSAN") == "1"
            and environment.get("AFL_DEBUG") == "1"
        )
        add(
            "ubsan_build_environment",
            environment_valid,
            "AFL_USE_UBSAN=1 and AFL_DEBUG=1 were recorded for the build."
            if environment_valid
            else "Required AFL++ UBSan/debug build environment was not recorded.",
        )

        expected_artifacts = {
            "harness_source_sha256": config.target.harness_source,
            "harness_binary_sha256": config.target.harness_binary,
            "library_archive_sha256": build_dir / "libpng16.a",
            "cmake_cache_sha256": build_dir / "CMakeCache.txt",
            "compile_database_sha256": build_dir / "compile_commands.json",
            "generated_header_sha256": build_dir / "pnglibconf.h",
        }
        artifact_hashes = metadata.get("artifacts")
        if not isinstance(artifact_hashes, dict):
            raise ValueError("Build metadata has no artifact hash mapping.")

        for key, artifact_path in expected_artifacts.items():
            expected_hash = artifact_hashes.get(key)
            _read_bounded_file(artifact_path, _MAX_BUILD_FILE_BYTES)
            actual_hash = _sha256(artifact_path)
            valid = (
                isinstance(expected_hash, str)
                and re.fullmatch(r"[0-9a-f]{64}", expected_hash) is not None
                and actual_hash == expected_hash
            )
            add(
                key,
                valid,
                "SHA-256 matches completed build metadata."
                if valid
                else f"SHA-256 mismatch; observed {actual_hash}.",
            )

        cache_text = _read_bounded_file(
            build_dir / "CMakeCache.txt", _MAX_BUILD_FILE_BYTES
        ).decode("utf-8")
        expected_cache = {
            "CMAKE_BUILD_TYPE": "RelWithDebInfo",
            "CMAKE_C_COMPILER": "/usr/bin/afl-clang-fast",
            "CMAKE_GENERATOR": "Ninja",
            "CMAKE_MAKE_PROGRAM": "/usr/bin/ninja",
            "CMAKE_EXPORT_COMPILE_COMMANDS": "ON",
            "CMAKE_POSITION_INDEPENDENT_CODE": "ON",
            "AWK": "/usr/bin/gawk",
            "PNG_BUILD_ZLIB": "OFF",
            "PNG_EXECUTABLES": "ON",
            "PNG_FRAMEWORK": "OFF",
            "PNG_HARDWARE_OPTIMIZATIONS": "ON",
            "PNG_INTEL_SSE": "on",
            "PNG_STATIC": "ON",
            "PNG_SHARED": "OFF",
            "PNG_TESTS": "OFF",
            "PNG_TOOLS": "OFF",
            "ZLIB_INCLUDE_DIR": "/usr/include",
            "ZLIB_LIBRARY_RELEASE": "/usr/lib/x86_64-linux-gnu/libz.so",
        }
        for key, expected in expected_cache.items():
            matches = [
                line.split("=", 1)[1]
                for line in cache_text.splitlines()
                if line.startswith(key + ":") and "=" in line
            ]
            add(
                f"cmake_{key.casefold()}",
                matches == [expected],
                f"Expected {expected}; observed {matches!r}.",
            )

        header_text = _read_bounded_file(
            build_dir / "pnglibconf.h", _MAX_BUILD_FILE_BYTES
        ).decode("utf-8")
        required_features = (
            "PNG_READ_SUPPORTED",
            "PNG_SEQUENTIAL_READ_SUPPORTED",
            "PNG_READ_ANCILLARY_CHUNKS_SUPPORTED",
            "PNG_READ_INTERLACING_SUPPORTED",
            "PNG_SETJMP_SUPPORTED",
            "PNG_SET_USER_LIMITS_SUPPORTED",
        )
        for feature in required_features:
            add(
                f"header_{feature.casefold()}",
                f"#define {feature}" in header_text,
                "Required libpng feature is enabled."
                if f"#define {feature}" in header_text
                else "Required libpng feature is missing.",
            )

        database = json.loads(
            _read_bounded_file(
                build_dir / "compile_commands.json",
                _MAX_BUILD_FILE_BYTES,
            )
        )
        database_valid = isinstance(database, list) and len(database) == 17
        compiler = Path("/usr/bin/afl-clang-fast").resolve(strict=True)
        compiler_matches = database_valid

        if database_valid:
            for entry in database:
                if not isinstance(entry, dict):
                    compiler_matches = False
                    break
                if isinstance(entry.get("arguments"), list):
                    argv = entry["arguments"]
                elif isinstance(entry.get("command"), str):
                    argv = shlex.split(entry["command"])
                else:
                    compiler_matches = False
                    break
                try:
                    observed = Path(argv[0]).resolve(strict=True) if argv else None
                except (OSError, RuntimeError, ValueError):
                    observed = None
                if observed != compiler:
                    compiler_matches = False
                    break

        add(
            "translation_units",
            database_valid,
            f"Expected 17; observed "
            f"{len(database) if isinstance(database, list) else 'invalid'}.",
        )
        add(
            "compile_database_compiler",
            compiler_matches,
            "All translation units use the pinned AFL++ compiler wrapper."
            if compiler_matches
            else "Compile database contains an unexpected compiler.",
        )

        compiler_rc, compiler_output = _run_bounded_version(
            [str(compiler), "--version"]
        )
        compiler_line = (
            compiler_output.splitlines()[0] if compiler_output else ""
        )
        compiler_valid = (
            compiler_rc == 0
            and compiler_line
            == "Ubuntu clang version 21.1.8 (6ubuntu1)"
        )
        add(
            "compiler_version",
            compiler_valid,
            f"Observed {compiler_line!r}.",
        )

        afl_path = shutil.which("afl-fuzz")
        if afl_path is None:
            raise ValueError("Cannot find afl-fuzz on PATH.")
        afl_rc, afl_output = _run_bounded_version(
            [str(Path(afl_path).resolve(strict=True)), "--version"]
        )
        afl_match = re.search(
            r"afl-fuzz\+\+([0-9A-Za-z.+_-]+)", afl_output
        )
        afl_version = afl_match.group(1) if afl_match else None
        add(
            "aflpp_version",
            afl_rc == 0 and afl_version == "4.33c",
            f"Observed AFL++ version {afl_version!r}.",
        )

        zlib_header = Path("/usr/include/zlib.h")
        zlib_text = _read_bounded_file(
            zlib_header, 1024 * 1024
        ).decode("utf-8")
        zlib_match = re.search(
            r'^\s*#\s*define\s+ZLIB_VERSION\s+"([^"]+)"',
            zlib_text,
            re.MULTILINE,
        )
        add(
            "zlib_version",
            zlib_match is not None and zlib_match.group(1) == "1.3.1",
            f"Observed {zlib_match.group(1) if zlib_match else 'unknown'}.",
        )

    except (
        OSError, UnicodeError, ValueError, KeyError, TypeError,
        subprocess.SubprocessError, json.JSONDecodeError,
    ) as exc:
        add("adapter_build_provenance", False, str(exc))

    return ProvenanceReport(
        target_name=config.target.name,
        target_version=config.target.version,
        checks=tuple(checks),
    )


def verify_build_provenance(
    config,
    project_root: str | Path,
) -> ProvenanceReport:
    """Verify pinned artifacts or completed schema-v2 adapter builds."""
    if config.build is not None:
        return _verify_adapter_build_provenance(config, project_root)

    checks: list[ProvenanceCheck] = []

    def add(name: str, passed: bool, message: str) -> None:
        checks.append(
            ProvenanceCheck(name, "passed" if passed else "failed", message)
        )

    target_name = config.target.name
    target_version = config.target.version

    try:
        root = Path(project_root).expanduser().resolve(strict=True)
        manifest_path = root / "targets/libpng/build-provenance.toml"
        raw_manifest = _read_bounded_file(
            manifest_path, _MAX_MANIFEST_BYTES
        )
        manifest = tomllib.loads(raw_manifest.decode("utf-8"))

        if set(manifest) != _REQUIRED_KEYS:
            raise ValueError(
                "Provenance manifest has missing or unknown keys."
            )
        if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
            raise ValueError("Unsupported provenance schema version.")
        if (
            manifest["target_name"] != "libpng"
            or manifest["target_version"] != target_version
            or target_name.casefold() != "libpng"
        ):
            raise ValueError("Manifest target does not match the adapter.")

        add("manifest", True, "Strict schema and target identity verified.")

        source_path = (root / manifest["harness_source"]).resolve(strict=True)
        if source_path != config.target.harness_source.resolve(strict=True):
            raise ValueError("Manifest harness source differs from adapter.")
        binary_path = config.target.harness_binary.resolve(strict=True)

        if not binary_path.is_file() or binary_path.is_symlink():
            raise ValueError("Harness binary is not a regular file.")

        for label, path, expected in (
            ("harness_source", source_path, manifest["harness_source_sha256"]),
            ("harness_binary", binary_path, manifest["harness_binary_sha256"]),
        ):
            actual = _sha256(path)
            add(
                label,
                actual == expected,
                "SHA-256 matches pinned manifest."
                if actual == expected
                else f"SHA-256 mismatch: observed {actual}.",
            )

        archive_name = manifest["library_archive"]
        cache_name = manifest["cmake_cache"]
        database_name = manifest["compile_database"]

        for name, value in (
            ("library_archive", archive_name),
            ("cmake_cache", cache_name),
            ("compile_database", database_name),
        ):
            if not isinstance(value, str) or Path(value).name != value:
                raise ValueError(f"Unsafe manifest filename: {name}.")

        build_dir = binary_path.parent
        archive = build_dir / archive_name
        cache_path = build_dir / cache_name
        database_path = build_dir / database_name

        archive_bytes = _read_bounded_file(
            archive, _MAX_BUILD_FILE_BYTES
        )
        archive_hash = hashlib.sha256(archive_bytes).hexdigest()
        add(
            "library_archive",
            archive_hash == manifest["library_archive_sha256"],
            "Static archive SHA-256 matches."
            if archive_hash == manifest["library_archive_sha256"]
            else f"Static archive SHA-256 mismatch: {archive_hash}.",
        )

        cache_text = _read_bounded_file(
            cache_path, _MAX_BUILD_FILE_BYTES
        ).decode("utf-8")
        expected_cache = {
            "CMAKE_BUILD_TYPE": manifest["cmake_build_type"],
            "CMAKE_C_COMPILER": manifest["compiler_path"],
            "CMAKE_POSITION_INDEPENDENT_CODE": (
                "ON" if manifest["position_independent_code"] else "OFF"
            ),
            "PNG_STATIC": "ON" if manifest["png_static"] else "OFF",
            "PNG_SHARED": "ON" if manifest["png_shared"] else "OFF",
            "PNG_TESTS": "ON" if manifest["png_tests"] else "OFF",
            "PNG_TOOLS": "ON" if manifest["png_tools"] else "OFF",
            "PNG_FRAMEWORK": "ON" if manifest["png_framework"] else "OFF",
        }

        for key, expected in expected_cache.items():
            matches = [
                line.split("=", 1)[1]
                for line in cache_text.splitlines()
                if line.startswith(key + ":") and "=" in line
            ]
            valid = len(matches) == 1 and matches[0] == expected
            add(
                f"cmake_{key.lower()}",
                valid,
                f"Expected {expected}; observed {matches!r}.",
            )

        database_bytes = _read_bounded_file(
            database_path, _MAX_BUILD_FILE_BYTES
        )
        database = json.loads(database_bytes)
        if not isinstance(database, list):
            raise ValueError("Compile database must be a JSON array.")

        expected_units = manifest["expected_translation_units"]
        if type(expected_units) is not int or expected_units < 1:
            raise ValueError("Invalid expected translation-unit count.")

        add(
            "translation_units",
            len(database) == expected_units,
            f"Expected {expected_units}; observed {len(database)}.",
        )

        compiler_value = manifest["compiler_path"]
        if not isinstance(compiler_value, str) or not Path(compiler_value).is_absolute():
            raise ValueError("Compiler path must be absolute.")
        compiler = Path(compiler_value).resolve(strict=True)
        if not compiler.is_file() or not os.access(compiler, os.X_OK):
            raise ValueError("Pinned compiler is not executable.")

        compiler_matches = True
        for entry in database:
            if not isinstance(entry, dict):
                compiler_matches = False
                break
            if isinstance(entry.get("arguments"), list):
                argv = entry["arguments"]
            elif isinstance(entry.get("command"), str):
                argv = shlex.split(entry["command"])
            else:
                compiler_matches = False
                break
            if not argv or Path(argv[0]).resolve(strict=True) != compiler:
                compiler_matches = False
                break

        add(
            "compile_database_compiler",
            compiler_matches,
            "Every translation unit uses the pinned AFL++ compiler wrapper."
            if compiler_matches
            else "Compile database contains an unexpected compiler.",
        )

        compiler_rc, compiler_output = _run_bounded_version(
            [str(compiler), "--version"]
        )
        compiler_line = compiler_output.splitlines()[0] if compiler_output else ""
        compiler_valid = (
            compiler_rc == 0
            and compiler_line == manifest["compiler_version"]
        )
        add(
            "compiler_version",
            compiler_valid,
            f"Observed {compiler_line!r}; expected "
            f"{manifest['compiler_version']!r}.",
        )

        afl_path = shutil.which("afl-fuzz")
        if afl_path is None:
            raise ValueError("Cannot find afl-fuzz on PATH.")
        afl_rc, afl_output = _run_bounded_version(
            [str(Path(afl_path).resolve(strict=True)), "--version"]
        )
        afl_match = re.search(
            r"afl-fuzz\+\+([0-9A-Za-z.+_-]+)", afl_output
        )
        afl_version = afl_match.group(1) if afl_match else None
        afl_valid = (
            afl_rc == 0 and afl_version == manifest["aflpp_version"]
        )
        add(
            "aflpp_version",
            afl_valid,
            f"Observed {afl_version!r}; expected "
            f"{manifest['aflpp_version']!r}.",
        )

        evidence_path = (root / manifest["evidence_document"]).resolve(strict=True)
        if root not in evidence_path.parents:
            raise ValueError("Evidence document resolves outside repository.")
        evidence_text = _read_bounded_file(
            evidence_path, _MAX_BUILD_FILE_BYTES
        ).decode("utf-8")
        evidence_text = evidence_text.replace("**", "").replace("`", "").casefold()

        locations = manifest["afl_instrumented_locations"]
        if type(locations) is not int or locations < 1:
            raise ValueError("Invalid instrumentation location count.")
        instrumentation_recorded = (
            f"{locations:,} locations instrumented".casefold()
            in evidence_text
            and "afl++ reported ubsan mode" in evidence_text
            and manifest["ubsan_mode"].casefold() in evidence_text
        )
        add(
            "instrumentation_evidence",
            instrumentation_recorded,
            "PCGUARD count and UBSan mode are supported by the recorded "
            "build evidence; they are not independently reconstructed "
            "from the binary.",
        )

    except (
        OSError, UnicodeError, ValueError, KeyError, TypeError,
        tomllib.TOMLDecodeError, subprocess.SubprocessError,
    ) as exc:
        add("provenance_validation", False, str(exc))

    return ProvenanceReport(
        target_name=target_name,
        target_version=target_version,
        checks=tuple(checks),
    )
