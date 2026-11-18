"""Fixed and provenance-verified ASan+UBSan build for pinned libpng 1.6.59."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import signal
import stat
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from engine.adapters.config import AdapterConfig
from engine.build.source_identity import verify_libpng_source_identity
from engine.evidence.database import open_database, utc_now_iso
from engine.evidence.migrations import run_migrations
from engine.evidence.repository import EvidenceRepository
from engine.evidence.store import EvidenceStore

CLANG = Path("/usr/bin/clang")
CMAKE = Path("/usr/bin/cmake")
NINJA = Path("/usr/bin/ninja")
LLVM_AR = Path("/usr/bin/llvm-ar")
LLVM_NM = Path("/usr/bin/llvm-nm")
ZLIB_HEADER = Path("/usr/include/zlib.h")
ZLIB_LIBRARY = Path("/usr/lib/x86_64-linux-gnu/libz.so")
CLANG_VERSION = "Ubuntu clang version 21.1.8"
ZLIB_VERSION = "1.3.1"
HARNESS_PATH = Path("targets/libpng/png_read_harness.c")
HARNESS_SHA256 = "3f67a53d149535763e6d76e26edc4147eb31cd2765f838b5317d4065e7fe2bdc"
SANITIZER = "-fsanitize=address,undefined"
FRAME_POINTERS = "-fno-omit-frame-pointer"
PROFILE = "libpng-asan-ubsan"
MAX_LOG = 16 * 1024 * 1024
EXPECTED_SOURCES = frozenset({
    "png.c", "pngerror.c", "pngget.c", "pngmem.c", "pngpread.c",
    "pngread.c", "pngrio.c", "pngrtran.c", "pngrutil.c", "pngset.c",
    "pngtrans.c", "pngwio.c", "pngwrite.c", "pngwtran.c", "pngwutil.c",
    "intel/intel_init.c", "intel/filter_sse2_intrinsics.c",
})


class DiagnosticBuildError(RuntimeError):
    """Raised when the fixed diagnostic build contract is not met."""


@dataclass(frozen=True)
class DiagnosticBuildResult:
    build_id: int
    build_dir: Path
    metadata_path: Path
    metadata_sha256: str
    harness_sha256: str
    archive_sha256: str


def _hash_file(path: Path, maximum: int = 256 * 1024 * 1024) -> tuple[str, int]:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0))
    digest, total = hashlib.sha256(), 0
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise DiagnosticBuildError(f"Not a regular file: {path}")
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > maximum:
                raise DiagnosticBuildError(f"File exceeds size limit: {path}")
            digest.update(block)
        after = os.fstat(fd)
        identity = lambda x: (x.st_dev, x.st_ino, x.st_size, x.st_mtime_ns, x.st_ctime_ns)
        if identity(before) != identity(after) or total != before.st_size:
            raise DiagnosticBuildError(f"File changed while hashing: {path}")
    finally:
        os.close(fd)
    return digest.hexdigest(), total


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    raw = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("short metadata write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, path)
    dfd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def _system_executable(path: Path) -> Path:
    resolved = path.resolve(strict=True)
    info = resolved.stat()
    trusted = (Path("/usr/bin"), Path("/usr/lib/llvm-21/bin"))
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not os.access(resolved, os.X_OK)
            or not any(resolved.is_relative_to(parent) for parent in trusted)):
        raise DiagnosticBuildError(f"Unsafe system tool path: {path}")
    return resolved


def _tool_text(path: Path, *args: str, env: dict[str, str]) -> str:
    result = subprocess.run([str(path), *args], cwd="/", env=env,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        timeout=10, check=False, shell=False, close_fds=True)
    if result.returncode:
        raise DiagnosticBuildError(f"Tool query failed: {path} {' '.join(args)}")
    return result.stdout.decode("utf-8", errors="replace").strip()


def _package(path: Path, env: dict[str, str]) -> str:
    owner = subprocess.run(["/usr/bin/dpkg-query", "-S", str(path)], cwd="/", env=env,
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10, check=False, shell=False, close_fds=True)
    if owner.returncode or not owner.stdout:
        raise DiagnosticBuildError(f"Cannot identify owning package for {path}")
    records = []
    for line in owner.stdout.decode("utf-8", errors="strict").splitlines():
        package = line.split(":", 1)[0].strip()
        query = subprocess.run(["/usr/bin/dpkg-query", "-W",
            "-f=${binary:Package}\t${Version}\t${Architecture}", package], cwd="/", env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, check=False, shell=False, close_fds=True)
        if query.returncode == 0:
            records.append(query.stdout.decode("utf-8", errors="strict").strip())
    if not records:
        raise DiagnosticBuildError(f"Cannot identify installed package version for {path}")
    return ";".join(sorted(set(records)))


def _run_bounded(argv: list[str], cwd: Path, env: dict[str, str], timeout: int,
                 stdout_path: Path, stderr_path: Path) -> dict[str, Any]:
    if not argv or any(not isinstance(x, str) or "\x00" in x for x in argv):
        raise DiagnosticBuildError("Invalid fixed command argv")
    proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
        close_fds=True, start_new_session=True, bufsize=0)
    state = {"stdout_bytes": 0, "stderr_bytes": 0,
             "stdout_truncated": False, "stderr_truncated": False}
    errors: list[str] = []

    def drain(pipe, path: Path, label: str) -> None:
        try:
            with path.open("xb") as out:
                while True:
                    block = pipe.read(65536)
                    if not block:
                        break
                    room = max(0, MAX_LOG - state[label + "_bytes"])
                    kept = block[:room]
                    if kept:
                        out.write(kept)
                        state[label + "_bytes"] += len(kept)
                    if len(kept) < len(block):
                        state[label + "_truncated"] = True
                out.flush()
                os.fsync(out.fileno())
        except OSError as exc:
            errors.append(f"{label} capture failed: {exc}")
        finally:
            pipe.close()
    readers = [threading.Thread(target=drain, args=(proc.stdout, stdout_path, "stdout"), daemon=True),
               threading.Thread(target=drain, args=(proc.stderr, stderr_path, "stderr"), daemon=True)]
    for reader in readers:
        reader.start()
    timed_out = False
    try:
        code = proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=1)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=3)
        code = proc.returncode
    for reader in readers:
        reader.join(timeout=5)
        if reader.is_alive():
            errors.append("output capture reader did not terminate")
    return {"argv": argv, "return_code": code, "timed_out": timed_out,
            **state, "capture_errors": errors}


def _validate_flags(argv: list[str]) -> None:
    sanitizer = [x for x in argv if x.startswith("-fsanitize=")]
    if sanitizer != [SANITIZER]:
        raise DiagnosticBuildError("Compiler command must enable ASan+UBSan exactly once")
    forbidden = ("-fno-sanitize", "-fsanitize-trap", "-fsanitize-minimal-runtime",
        "-fno-sanitize-recover", "-fsanitize-ignorelist", "-fsanitize-blacklist",
        "-fsanitize-link-runtime=false")
    if any(x.startswith(forbidden) for x in argv):
        raise DiagnosticBuildError("Conflicting sanitizer override detected")
    if any(x.startswith("@") or x in {"-Xclang", "-fplugin", "-load", "-plugin"}
           or x.startswith("-fplugin=") or x.startswith("--config") for x in argv):
        raise DiagnosticBuildError("Response files, Clang config and compiler plugins are prohibited")


def _verify_compile_commands(source: Path, path: Path, compiler: Path) -> list[dict[str, Any]]:
    try:
        rows = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise DiagnosticBuildError(f"Cannot read compile database: {exc}") from exc
    if not isinstance(rows, list) or len(rows) != 17:
        raise DiagnosticBuildError("Expected exactly 17 libpng compile database entries")
    seen: dict[str, dict[str, Any]] = {}
    outputs: set[str] = set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get("file"), str) or not isinstance(row.get("directory"), str):
            raise DiagnosticBuildError("Malformed compile database entry")
        file = Path(row["file"])
        if not file.is_absolute():
            file = Path(row["directory"]) / file
        try:
            rel = file.resolve(strict=True).relative_to(source).as_posix()
        except (OSError, ValueError) as exc:
            raise DiagnosticBuildError("Compile source is outside the authenticated libpng tree") from exc
        if rel not in EXPECTED_SOURCES or rel in seen:
            raise DiagnosticBuildError(f"Unexpected or duplicate source: {rel}")
        args = row.get("arguments")
        if args is None and isinstance(row.get("command"), str):
            try:
                args = shlex.split(row["command"], posix=True)
            except ValueError as exc:
                raise DiagnosticBuildError("Unparseable compiler command") from exc
        if not isinstance(args, list) or not args or any(not isinstance(x, str) for x in args):
            raise DiagnosticBuildError("Missing tokenized compiler arguments")
        if Path(args[0]).resolve(strict=True) != compiler:
            raise DiagnosticBuildError("Compile entry does not use the approved Clang binary")
        _validate_flags(args)
        if args.count(FRAME_POINTERS) != 1 or args.count("-g") < 1 or "-c" not in args:
            raise DiagnosticBuildError(f"Missing frame-pointer/debug/compile flags in {rel}")
        if "-o" not in args:
            raise DiagnosticBuildError(f"No object output in compile command {rel}")
        out = str(Path(row["directory"]) / args[args.index("-o") + 1])
        if out in outputs:
            raise DiagnosticBuildError("Duplicate object output path")
        outputs.add(out)
        seen[rel] = {"source": rel, "argv": args, "directory": row["directory"], "object_path": out}
    if set(seen) != EXPECTED_SOURCES:
        raise DiagnosticBuildError(f"Source set mismatch; missing={sorted(EXPECTED_SOURCES-set(seen))}")
    return [seen[name] for name in sorted(seen)]


def _verify_cache(path: Path, compiler: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith(("//", "#")) and "=" in line:
            key, value = line.split("=", 1)
            values[key.split(":", 1)[0]] = value
    expected = {
        "CMAKE_BUILD_TYPE": "RelWithDebInfo", "CMAKE_C_COMPILER": str(compiler),
        "CMAKE_EXPORT_COMPILE_COMMANDS": "ON", "PNG_SHARED": "OFF", "PNG_STATIC": "ON",
        "PNG_HARDWARE_OPTIMIZATIONS": "ON", "PNG_INTEL_SSE": "on",
        "PNG_TESTS": "OFF", "PNG_TOOLS": "OFF",
    }
    for key, value in expected.items():
        if values.get(key) != value:
            raise DiagnosticBuildError(f"CMake cache mismatch for {key}: {values.get(key)!r}")
    if values.get("CMAKE_C_COMPILER_LAUNCHER", "") or values.get("CMAKE_C_COMPILER_ARG1", ""):
        raise DiagnosticBuildError("Compiler launcher or argument override is not permitted")
    flags = values.get("CMAKE_C_FLAGS", "").split()
    _validate_flags(flags)
    if flags.count(FRAME_POINTERS) != 1 or flags.count("-g") != 1:
        raise DiagnosticBuildError("CMake cache lost required frame-pointer/debug flags")
    for key in ("CMAKE_EXE_LINKER_FLAGS", "CMAKE_SHARED_LINKER_FLAGS", "CMAKE_MODULE_LINKER_FLAGS"):
        if values.get(key, "").split() != [SANITIZER]:
            raise DiagnosticBuildError(f"Unexpected linker sanitizer flags: {key}")
    return {key: values[key] for key in expected}


def _probe_runtimes(build: Path, compiler: Path, env: dict[str, str]) -> dict[str, Any]:
    probe = build / ".runtime-probes"
    probe.mkdir(mode=0o700)
    tests = {
        "address": ("a.c", "#include <stdlib.h>\nint main(void){volatile char *p=malloc(1);p[1]=1;free((void*)p);return 0;}\n", "-fsanitize=address", "ERROR: AddressSanitizer:", {"ASAN_OPTIONS":"detect_leaks=1:halt_on_error=1:abort_on_error=1"}),
        "undefined_behavior": ("u.c", "int main(void){volatile int x=2147483647;x+=1;return x==0;}\n", "-fsanitize=undefined", "runtime error:", {"UBSAN_OPTIONS":"halt_on_error=1:print_stacktrace=1"}),
    }
    outcomes: dict[str, Any] = {}
    try:
        for name, (source_name, source_text, flag, marker, overrides) in tests.items():
            src, exe = probe / source_name, probe / name
            src.write_text(source_text, encoding="utf-8")
            src.chmod(0o600)
            compile_result = subprocess.run([str(compiler), "--no-default-config", "-g", "-O1", flag, str(src), "-o", str(exe)],
                cwd=probe, env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=8, check=False, shell=False, close_fds=True)
            if compile_result.returncode:
                raise DiagnosticBuildError(f"Could not compile the {name} sanitizer runtime probe")
            run_env = dict(env); run_env.update(overrides)
            try:
                executed = subprocess.run([str(exe)], cwd=probe, env=run_env, stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8,
                    check=False, shell=False, close_fds=True)
            except subprocess.TimeoutExpired as exc:
                raise DiagnosticBuildError(f"The {name} sanitizer runtime probe timed out") from exc
            combined = executed.stdout + executed.stderr
            if executed.returncode == 0 or marker.encode() not in combined:
                raise DiagnosticBuildError(f"The {name} runtime probe did not observe its expected sanitizer marker")
            outcomes[name] = {"compile_return_code": 0, "execution_return_code": executed.returncode, "marker_observed": True}
    finally:
        for item in probe.iterdir():
            if item.is_file() and not item.is_symlink():
                item.unlink()
        probe.rmdir()
    return outcomes


def _tool_record(path: Path, env: dict[str, str]) -> dict[str, str]:
    digest, _ = _hash_file(path)
    return {"path": str(path), "sha256": digest, "version": _tool_text(path, "--version", env=env).splitlines()[0], "package": _package(path, env)}


def _register_build(evidence_root: Path, root: Path, source: Path, campaign_root: Path,
                    build: Path, metadata: dict[str, Any], metadata_sha256: str) -> int:
    store = EvidenceStore(evidence_root, protected_paths=(root, source, campaign_root, build))
    db = None
    try:
        run_migrations(evidence_root)
        db = open_database(store.database_path)
        target = db.execute("SELECT t.id,tv.id,tv.source_archive_sha256,tv.source_tree_sha256 FROM targets t JOIN target_versions tv ON tv.target_id=t.id WHERE t.name='libpng' AND tv.version='1.6.59'").fetchone()
        if target is None:
            raise DiagnosticBuildError("Import a P3-02 libpng 1.6.59 campaign before registering this diagnostic build")
        target_id, version_id, archive_hash, tree_hash = target
        if archive_hash != metadata["source_archive_sha256"] or tree_hash != metadata["source_tree_sha256"]:
            raise DiagnosticBuildError("Diagnostic source identity differs from the existing evidence target/version")
        repo = EvidenceRepository(db)
        artifacts = metadata["artifacts"]
        record = {
            "target_id": target_id, "target_version_id": version_id,
            "profile": PROFILE, "build_role": "diagnostic_replay", "build_dir": str(build),
            "build_metadata_sha256": metadata_sha256,
            "harness_source_path": metadata["harness_source_path"], "harness_binary_path": metadata["harness_binary_path"],
            "harness_source_sha256": metadata["harness_source_sha256"],
            "harness_binary_sha256": artifacts["harness_binary"]["sha256"],
            "library_archive_sha256": artifacts["library_archive"]["sha256"],
            "cmake_cache_sha256": artifacts["cmake_cache"]["sha256"],
            "compile_database_sha256": artifacts["compile_database"]["sha256"],
            "generated_header_sha256": artifacts["generated_header"]["sha256"],
            "compiler_path": metadata["tools"]["clang"]["path"],
            "compiler_version": metadata["tools"]["clang"]["version"],
            "cmake_build_type": "RelWithDebInfo", "aflpp_version": None,
            "afl_instrumented_locations": None,
            "sanitizer_config_json": {"address":"enabled", "undefined_behavior":"enabled", "frame_pointers":True},
            "environment_json": metadata["environment"], "build_status":"completed",
            "started_at": metadata["started_at"], "ended_at": metadata["ended_at"], "recorded_at": utc_now_iso(),
        }
        return repo.insert_build(record)
    finally:
        if db is not None:
            db.close()
        store.close()


def build_libpng_diagnostic(config: AdapterConfig, project_root: str | Path,
                            build_dir: str | Path, evidence_root: str | Path) -> DiagnosticBuildResult:
    if os.geteuid() == 0:
        raise DiagnosticBuildError("Do not build or register diagnostic evidence as root")
    root = Path(project_root).resolve(strict=True)
    source = config.target.source_dir
    if source.is_symlink() or not source.is_dir():
        raise DiagnosticBuildError("libpng source tree must be a real directory")
    identity = verify_libpng_source_identity(source, config.target.source_archive)
    harness_source = (root / HARNESS_PATH).resolve(strict=True)
    if config.target.harness_source.resolve(strict=True) != harness_source:
        raise DiagnosticBuildError("Configured harness differs from the repository-owned harness path")
    harness_hash, _ = _hash_file(harness_source, 1024 * 1024)
    if harness_hash != HARNESS_SHA256:
        raise DiagnosticBuildError("Repository harness source hash is not the approved hash")
    source = source.resolve(strict=True)
    evidence = Path(os.path.abspath(Path(evidence_root).expanduser()))
    build = Path(os.path.abspath(Path(build_dir).expanduser()))
    if build.exists() or not build.is_absolute():
        raise DiagnosticBuildError("Choose a new absolute diagnostic build directory")
    if not build.parent.is_dir() or build.parent.stat().st_uid != os.getuid():
        raise DiagnosticBuildError("Build parent must exist and be owned by the current user")
    protected = [root, source, config.target.output_parent.resolve(strict=True), evidence]
    if config.build:
        protected.append(config.build.build_dir.resolve(strict=False))
    if any(build == p or build in p.parents or p in build.parents for p in protected):
        raise DiagnosticBuildError("Diagnostic build directory overlaps a protected project/evidence path")
    build.mkdir(mode=0o700)
    home, tmp = build / ".home", build / ".tmp"
    home.mkdir(mode=0o700); tmp.mkdir(mode=0o700)
    env = {"PATH":"/usr/bin:/bin", "LC_ALL":"C", "HOME":str(home), "TMPDIR":str(tmp)}
    compiler = _system_executable(CLANG)
    clang_version = _tool_text(compiler, "--version", env=env)
    if CLANG_VERSION not in clang_version:
        raise DiagnosticBuildError(f"Expected Clang 21.1.8, found {clang_version.splitlines()[0]}")
    tools = {"clang": {"path":str(compiler), "version":clang_version.splitlines()[0],
                       "sha256":_hash_file(compiler)[0], "package":_package(compiler, env)}}
    system_tools = {"cmake":_system_executable(CMAKE), "ninja":_system_executable(NINJA),
                    "llvm_ar":_system_executable(LLVM_AR), "llvm_nm":_system_executable(LLVM_NM)}
    for name, path in system_tools.items():
        tools[name] = _tool_record(path, env)
    resource_dir = Path(_tool_text(compiler, "-print-resource-dir", env=env)).resolve(strict=True)
    runtimes = {}
    for name in ("libclang_rt.asan-x86_64.a", "libclang_rt.ubsan_standalone-x86_64.a"):
        runtime = Path(_tool_text(compiler, f"-print-file-name={name}", env=env)).resolve(strict=True)
        runtimes[name] = {"path":str(runtime), "sha256":_hash_file(runtime)[0]}
    zlib_text = ZLIB_HEADER.read_text(encoding="utf-8")
    zlib_match = re.search(r'^\s*#\s*define\s+ZLIB_VERSION\s+"([^"]+)"', zlib_text, re.M)
    if not zlib_match or zlib_match.group(1) != ZLIB_VERSION:
        raise DiagnosticBuildError("This diagnostic profile requires the pinned system zlib 1.3.1")
    zlib = ZLIB_LIBRARY.resolve(strict=True)
    zlib_hash = _hash_file(zlib)[0]
    started = utc_now_iso()
    metadata_path = build / "build.json"
    metadata: dict[str, Any] = {
        "schema_version":2, "status":"running", "target":"libpng", "target_version":"1.6.59",
        "profile":PROFILE, "build_role":"diagnostic_replay", "build_dir":str(build),
        "source_archive_sha256":identity.archive_sha256, "source_tree_sha256":identity.tree_sha256,
        "harness_source_path":str(harness_source), "harness_source_sha256":harness_hash,
        "started_at":started, "ended_at":None, "environment":env, "tools":tools,
        "clang_resource_directory":str(resource_dir), "sanitizer_runtimes":runtimes,
        "zlib":{"version":ZLIB_VERSION,"library":str(zlib),"sha256":zlib_hash,"instrumented":False},
        "expected_translation_units":sorted(EXPECTED_SOURCES), "steps":[], "verification":{}, "artifacts":{},
    }
    _atomic_json(metadata_path, metadata)
    try:
        cmake, ninja = system_tools["cmake"], system_tools["ninja"]
        configure = [str(cmake), "-S", str(source), "-B", str(build), "-G", "Ninja",
            "-DCMAKE_MAKE_PROGRAM="+str(ninja), "-DCMAKE_BUILD_TYPE=RelWithDebInfo",
            "-DCMAKE_C_COMPILER="+str(compiler), "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
            "-DCMAKE_C_FLAGS=--no-default-config -fsanitize=address,undefined -fno-omit-frame-pointer -g",
            "-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address,undefined",
            "-DCMAKE_SHARED_LINKER_FLAGS=-fsanitize=address,undefined",
            "-DCMAKE_MODULE_LINKER_FLAGS=-fsanitize=address,undefined",
            "-DAWK=/usr/bin/gawk", "-DPNG_BUILD_ZLIB=OFF", "-DPNG_EXECUTABLES=OFF",
            "-DPNG_FRAMEWORK=OFF", "-DPNG_HARDWARE_OPTIMIZATIONS=ON", "-DPNG_INTEL_SSE=on",
            "-DPNG_ARM_NEON=off", "-DPNG_POWERPC_VSX=off", "-DPNG_SHARED=OFF", "-DPNG_STATIC=ON",
            "-DPNG_TESTS=OFF", "-DPNG_TOOLS=OFF", "-DZLIB_INCLUDE_DIR=/usr/include",
            "-DZLIB_LIBRARY_RELEASE="+str(zlib)]
        library = [str(ninja), "-C", str(build), "-j", "2", "-v", "png_static"]
        for label, argv in (("configure", configure), ("library", library)):
            out, err = build/f"{label}.stdout.log", build/f"{label}.stderr.log"
            result = _run_bounded(argv, build, env, 900, out, err)
            result.update({"name":label, "started_at":utc_now_iso(), "ended_at":utc_now_iso()})
            metadata["steps"].append(result); _atomic_json(metadata_path, metadata)
            if result["timed_out"] or result["return_code"] != 0 or result["capture_errors"]:
                raise DiagnosticBuildError(f"{label} step failed: {result}")
        compile_db, cache = build/"compile_commands.json", build/"CMakeCache.txt"
        commands = _verify_compile_commands(source, compile_db, compiler)
        metadata["verification"]["compile_commands"] = commands
        metadata["verification"]["cmake_cache"] = _verify_cache(cache, compiler)
        archive = build/"libpng16.a"
        if not archive.is_file() or archive.is_symlink():
            raise DiagnosticBuildError("The expected libpng16.a archive was not built")
        ar_result = subprocess.run([str(system_tools["llvm_ar"]), "t", str(archive)], cwd=build,
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=15, check=False, shell=False, close_fds=True)
        members = ar_result.stdout.decode("utf-8", errors="strict").splitlines()
        expected_members = sorted(Path(name).name+".o" for name in EXPECTED_SOURCES)
        if ar_result.returncode or sorted(members) != expected_members or len(members) != 17:
            raise DiagnosticBuildError("Static archive member list differs from the exact 17-source build")
        nm = subprocess.run([str(system_tools["llvm_nm"]), "-A", "-u", str(archive)], cwd=build,
            env=env, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=20, check=False, shell=False, close_fds=True)
        undefined = nm.stdout.decode("utf-8", errors="replace")
        symbols = {"asan": "__asan_" in undefined, "ubsan": "__ubsan_" in undefined}
        if nm.returncode or not all(symbols.values()):
            raise DiagnosticBuildError(f"Expected ASan and UBSan references missing from archive: {symbols}")
        metadata["verification"].update({"archive_members":members,"instrumentation_symbols":symbols})
        harness = build/"kekkai_png_harness"
        link_argv = [str(compiler), "--no-default-config", "-O2", "-g", "-DNDEBUG", "-fPIC",
            SANITIZER, "-fno-omit-frame-pointer", "-I", str(source), "-I", str(build),
            str(harness_source), str(archive), str(zlib), "-lm", "-o", str(harness)]
        _validate_flags(link_argv)
        result = _run_bounded(link_argv, build, env, 900,
            build/"harness.stdout.log", build/"harness.stderr.log")
        result.update({"name":"harness", "started_at":utc_now_iso(), "ended_at":utc_now_iso()})
        metadata["steps"].append(result); metadata["verification"]["harness_link_argv"] = link_argv
        _atomic_json(metadata_path, metadata)
        if result["timed_out"] or result["return_code"] != 0 or result["capture_errors"]:
            raise DiagnosticBuildError("Diagnostic harness compilation/link failed")
        metadata["verification"]["runtime_probes"] = _probe_runtimes(build, compiler, env)
        outputs = {"harness_binary":harness,"library_archive":archive,"cmake_cache":cache,
                   "compile_database":compile_db,"generated_header":build/"pnglibconf.h"}
        for name, path in outputs.items():
            if path.is_symlink() or not path.is_file():
                raise DiagnosticBuildError(f"Required output is missing or unsafe: {name}")
            digest, size = _hash_file(path, 16*1024*1024)
            metadata["artifacts"][name] = {"path":str(path),"sha256":digest,"size_bytes":size}
        metadata["harness_binary_path"] = str(harness)
        metadata["status"] = "completed"; metadata["ended_at"] = utc_now_iso()
        _atomic_json(metadata_path, metadata)
        metadata_sha = _hash_file(metadata_path, 4*1024*1024)[0]
        build_id = _register_build(evidence, root, source, config.target.output_parent.resolve(strict=True), build, metadata, metadata_sha)
        return DiagnosticBuildResult(build_id, build, metadata_path, metadata_sha,
            metadata["artifacts"]["harness_binary"]["sha256"], metadata["artifacts"]["library_archive"]["sha256"])
    except BaseException as exc:
        metadata["status"] = "interrupted" if isinstance(exc, KeyboardInterrupt) else "failed"
        metadata["ended_at"] = utc_now_iso()
        metadata["message"] = f"Build not registered: {type(exc).__name__}: {exc}"[:2048]
        try:
            _atomic_json(metadata_path, metadata)
        except OSError:
            pass
        raise
