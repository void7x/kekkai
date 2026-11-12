"""Read-only preflight validation for KEKKAI target adapters."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from engine.adapters.config import AdapterConfig


_MAX_SEED_ENTRIES = 4096
_MAX_SEED_TOTAL_BYTES = 512 * 1024 * 1024


_MAX_FUZZER_VERSION_OUTPUT_BYTES = 16 * 1024
_MAX_FUZZER_VERSION_STREAM_BYTES = _MAX_FUZZER_VERSION_OUTPUT_BYTES // 2


def _fuzzer_output_limit_callback(max_bytes: int):
    """Limit each regular output file written by the version probe."""
    if os.name != "posix":
        raise OSError("Bounded version probing requires POSIX resource limits.")

    try:
        import resource
    except ImportError as exc:
        raise OSError("The resource module is unavailable.") from exc

    if not hasattr(resource, "RLIMIT_FSIZE"):
        raise OSError("RLIMIT_FSIZE is unavailable on this platform.")

    def apply_limit() -> None:
        soft_limit, hard_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
        effective_limit = max_bytes

        if soft_limit != resource.RLIM_INFINITY:
            effective_limit = min(effective_limit, soft_limit)
        if hard_limit != resource.RLIM_INFINITY:
            effective_limit = min(effective_limit, hard_limit)

        resource.setrlimit(
            resource.RLIMIT_FSIZE,
            (effective_limit, effective_limit),
        )

    return apply_limit


def _read_bounded_output_file(stream, maximum: int) -> tuple[int, bytes]:
    """Return file size and at most maximum bytes from a child output file."""
    stream.flush()
    size = os.fstat(stream.fileno()).st_size
    stream.seek(0)
    return size, stream.read(maximum)


@dataclass(frozen=True)
class PreflightCheck:
    name: str
    status: str
    message: str


@dataclass(frozen=True)
class PreflightReport:
    target_name: str
    target_version: str
    checks: tuple[PreflightCheck, ...]

    @property
    def passed(self) -> bool:
        """Return whether the required preflight checks passed.

        Checks marked not_run describe separate validation gates. They
        neither pass nor fail this preflight stage and must be completed
        before a campaign can be accepted.
        """
        return not any(check.status == "failed" for check in self.checks)

    @property
    def failed_checks(self) -> tuple[PreflightCheck, ...]:
        return tuple(
            check for check in self.checks if check.status == "failed"
        )

    def format(self) -> str:
        outcome = "PASS" if self.passed else "FAIL"
        lines = [
            f"Preflight: {outcome}",
            f"Target: {self.target_name} {self.target_version}",
        ]

        for check in self.checks:
            lines.append(
                f"[{check.status.upper()}] {check.name}: {check.message}"
            )

        return "\n".join(lines)


def _is_within(path: Path, parent: Path) -> bool:
    """Return whether path is parent or one of its descendants."""
    return path == parent or parent in path.parents


def _paths_overlap(first: Path, second: Path) -> bool:
    """Return whether either path contains the other."""
    return _is_within(first, second) or _is_within(second, first)


def _parse_c_integer_multiplication(
    source_text: str,
    macro_name: str,
) -> int:
    """Parse a deliberately small C integer-multiplication macro.

    Supported form: (8U * 1024U * 1024U)
    Arbitrary C expressions are intentionally not evaluated.
    """
    pattern = re.compile(
        rf"^\s*#\s*define\s+{re.escape(macro_name)}\s+(.+?)\s*$"
    )
    matches = [
        match.group(1)
        for line in source_text.splitlines()
        if (match := pattern.match(line))
    ]

    if len(matches) != 1:
        raise ValueError(
            f"Expected exactly one definition of {macro_name}; "
            f"found {len(matches)}."
        )

    expression = re.split(r"//|/\*", matches[0], maxsplit=1)[0].strip()

    while expression.startswith("(") and expression.endswith(")"):
        expression = expression[1:-1].strip()

    factors = expression.split("*")
    if not factors:
        raise ValueError(f"Empty expression for {macro_name}.")

    result = 1

    for factor in factors:
        factor = factor.strip()

        while factor.startswith("(") and factor.endswith(")"):
            factor = factor[1:-1].strip()

        match = re.fullmatch(
            r"(0[xX][0-9A-Fa-f]+|[0-9]+)[uUlL]*",
            factor,
        )
        if match is None:
            raise ValueError(
                f"Unsupported integer expression in {macro_name}: "
                f"{matches[0]!r}."
            )

        literal = match.group(1)
        base = 16 if literal.lower().startswith("0x") else 10
        result *= int(literal, base)

    return result


def validate_adapter(
    config: AdapterConfig,
    project_root: str | Path,
) -> PreflightReport:
    """Run read-only checks for the currently supported libpng adapter.

    This function does not build or execute the harness, write files,
    create campaign directories, or start AFL++. It runs only the
    configured fuzzer's --version command.
    """
    try:
        root = Path(project_root).expanduser().resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"Invalid project root: {exc}") from exc

    if not root.is_dir():
        raise ValueError("Project root must be a directory.")

    checks: list[PreflightCheck] = []

    def add(name: str, status: str, message: str) -> None:
        checks.append(PreflightCheck(name, status, message))

    target = config.target
    limits = config.limits
    supported_target = target.name.casefold() == "libpng"

    if supported_target:
        add("supported_target", "passed", "libpng adapter checks are available.")
    else:
        add(
            "supported_target",
            "failed",
            f"No target-specific preflight checks exist for {target.name!r}.",
        )

    # Target source directory and pinned version.
    if target.source_dir.is_dir():
        add(
            "target_source",
            "passed",
            f"Source directory exists: {target.source_dir}",
        )
    else:
        add(
            "target_source",
            "failed",
            f"Source directory is missing: {target.source_dir}",
        )

    if not supported_target or not target.source_dir.is_dir():
        add(
            "target_version",
            "not_run",
            "Source version could not be checked.",
        )
    else:
        header_path = target.source_dir / "png.h"
        try:
            header_text = header_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            add(
                "target_version",
                "failed",
                f"Cannot read libpng version header: {exc}",
            )
        else:
            version_match = re.search(
                r'^\s*#\s*define\s+PNG_LIBPNG_VER_STRING\s+"([^"]+)"',
                header_text,
                re.MULTILINE,
            )
            if version_match is None:
                add(
                    "target_version",
                    "failed",
                    "PNG_LIBPNG_VER_STRING was not found in png.h.",
                )
            elif version_match.group(1) != target.version:
                add(
                    "target_version",
                    "failed",
                    f"Adapter expects {target.version}; "
                    f"source declares {version_match.group(1)}.",
                )
            else:
                add(
                    "target_version",
                    "passed",
                    f"Source declares libpng {target.version}.",
                )

    # Harness source must be a repository-owned file.
    harness_source_valid = (
        _is_within(target.harness_source, root)
        and target.harness_source.is_file()
    )

    if harness_source_valid:
        add(
            "harness_source",
            "passed",
            f"Repository harness source exists: {target.harness_source}",
        )
    elif not _is_within(target.harness_source, root):
        add(
            "harness_source",
            "failed",
            "Harness source resolves outside the project repository.",
        )
    else:
        add(
            "harness_source",
            "failed",
            f"Harness source is missing: {target.harness_source}",
        )

    # Compare the source-level input cap with adapter configuration.
    if not supported_target or not harness_source_valid:
        add(
            "harness_input_limit",
            "not_run",
            "Harness input limit could not be checked.",
        )
    else:
        try:
            harness_text = target.harness_source.read_text(encoding="utf-8")
            harness_limit = _parse_c_integer_multiplication(
                harness_text,
                "MAX_INPUT_BYTES",
            )
        except (OSError, UnicodeError, ValueError) as exc:
            add(
                "harness_input_limit",
                "failed",
                f"Could not verify MAX_INPUT_BYTES: {exc}",
            )
        else:
            if harness_limit != limits.max_input_bytes:
                add(
                    "harness_input_limit",
                    "failed",
                    f"Harness allows {harness_limit} bytes; adapter "
                    f"specifies {limits.max_input_bytes} bytes.",
                )
            else:
                add(
                    "harness_input_limit",
                    "passed",
                    f"Harness and adapter both specify "
                    f"{harness_limit} bytes.",
                )

    # A file check is not proof of build freshness or correct instrumentation.
    if target.harness_binary.is_file() and os.access(
        target.harness_binary, os.X_OK
    ):
        add(
            "harness_binary",
            "passed",
            f"Executable harness binary exists: {target.harness_binary}",
        )
    else:
        add(
            "harness_binary",
            "failed",
            "Harness binary is missing or is not executable: "
            f"{target.harness_binary}",
        )

    # Validate direct seed files. Reject symlinks and special files.
    if not target.seed_dir.is_dir():
        add(
            "seed_corpus",
            "failed",
            f"Seed directory is missing: {target.seed_dir}",
        )
    else:
        try:
            seed_sizes: list[tuple[str, int]] = []
            unsafe_entries: list[str] = []
            entry_count = 0
            too_many_entries = False
            too_large = False
            total_seed_bytes = 0

            with os.scandir(target.seed_dir) as entries:
                for entry in entries:
                    entry_count += 1
                    if entry_count > _MAX_SEED_ENTRIES:
                        too_many_entries = True
                        break

                    if entry.is_symlink():
                        unsafe_entries.append(entry.name)
                    elif entry.is_file(follow_symlinks=False):
                        size = entry.stat(follow_symlinks=False).st_size
                        seed_sizes.append((entry.name, size))
                        total_seed_bytes += size

                        if total_seed_bytes > _MAX_SEED_TOTAL_BYTES:
                            too_large = True
                            break
                    elif entry.is_dir(follow_symlinks=False):
                        # AFL++ seeds are expected as direct files.
                        continue
                    else:
                        unsafe_entries.append(entry.name)

            seed_sizes.sort(key=lambda item: item[0])
        except OSError as exc:
            add(
                "seed_corpus",
                "failed",
                f"Cannot inspect seed directory: {exc}",
            )
        else:
            non_empty_seed_files = [
                (name, size) for name, size in seed_sizes if size > 0
            ]

            if too_many_entries:
                add(
                    "seed_corpus",
                    "failed",
                    f"Seed directory exceeds the {_MAX_SEED_ENTRIES}-entry "
                    "inspection limit.",
                )
            elif too_large:
                add(
                    "seed_corpus",
                    "failed",
                    f"Seed corpus exceeds the {_MAX_SEED_TOTAL_BYTES}-byte "
                    "total inspection limit.",
                )
            elif unsafe_entries:
                unsafe_preview = ", ".join(sorted(unsafe_entries)[:20])
                if len(unsafe_entries) > 20:
                    unsafe_preview += ", ..."
                add(
                    "seed_corpus",
                    "failed",
                    "Symlink or special entries are not allowed: "
                    + unsafe_preview,
                )
            elif not non_empty_seed_files:
                add(
                    "seed_corpus",
                    "failed",
                    "At least one non-empty regular seed file is required.",
                )
            else:
                oversized = [
                    (name, size)
                    for name, size in seed_sizes
                    if size > limits.max_input_bytes
                ]

                if oversized:
                    oversized.sort()
                    details = ", ".join(
                        f"{name} ({size} bytes)"
                        for name, size in oversized[:20]
                    )
                    if len(oversized) > 20:
                        details += ", ..."
                    add(
                        "seed_corpus",
                        "failed",
                        f"Seeds exceed the configured "
                        f"{limits.max_input_bytes}-byte limit: {details}.",
                    )
                else:
                    largest = max(size for _, size in seed_sizes)
                    empty_count = len(seed_sizes) - len(non_empty_seed_files)
                    empty_note = (
                        f" {empty_count} zero-byte seed(s) are also present."
                        if empty_count
                        else ""
                    )
                    add(
                        "seed_corpus",
                        "passed",
                        f"{len(non_empty_seed_files)} non-empty regular "
                        f"files; {total_seed_bytes} bytes total; largest "
                        f"{largest} bytes; all within the configured "
                        f"limit.{empty_note}",
                    )

    # Keep output outside the repository and target source tree.
    output_parent = target.output_parent

    if not output_parent.is_dir():
        add(
            "output_parent",
            "failed",
            f"Output parent is missing: {output_parent}",
        )
    elif _paths_overlap(output_parent, root):
        add(
            "output_parent",
            "failed",
            "Output parent must be separate from the project repository.",
        )
    elif _paths_overlap(output_parent, target.source_dir):
        add(
            "output_parent",
            "failed",
            "Output parent must be separate from the target source tree.",
        )
    elif not os.access(output_parent, os.W_OK | os.X_OK):
        add(
            "output_parent",
            "failed",
            "Output parent lacks write/search access.",
        )
    else:
        add(
            "output_parent",
            "passed",
            "Existing output parent is outside the repository and target "
            "source tree and has write/search access.",
        )

    # Only the fixed AFL++ command is allowed. Adapter TOML must not
    # become a general-purpose executable or command specification.
    if config.fuzzer.executable != "afl-fuzz":
        add(
            "fuzzer_executable",
            "failed",
            "Only the literal PATH-resolved 'afl-fuzz' command is allowed.",
        )
        add(
            "fuzzer_version",
            "not_run",
            "The configured executable is not the approved AFL++ command.",
        )
    else:
        fuzzer_path = shutil.which("afl-fuzz")

        if fuzzer_path is None:
            add(
                "fuzzer_executable",
                "failed",
                "Cannot find the approved 'afl-fuzz' executable on PATH.",
            )
        else:
            resolved_fuzzer = Path(fuzzer_path).resolve()
            add(
                "fuzzer_executable",
                "passed",
                f"Resolved executable: {resolved_fuzzer}",
            )

            try:
                with (
                    tempfile.TemporaryFile(mode="w+b") as stdout_file,
                    tempfile.TemporaryFile(mode="w+b") as stderr_file,
                ):
                    result = subprocess.run(
                        [str(resolved_fuzzer), "--version"],
                        cwd=root,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout_file,
                        stderr=stderr_file,
                        timeout=5,
                        check=False,
                        shell=False,
                        preexec_fn=_fuzzer_output_limit_callback(
                            _MAX_FUZZER_VERSION_STREAM_BYTES
                        ),
                    )
                    stdout_size, stdout_bytes = _read_bounded_output_file(
                        stdout_file,
                        _MAX_FUZZER_VERSION_STREAM_BYTES,
                    )
                    stderr_size, stderr_bytes = _read_bounded_output_file(
                        stderr_file,
                        _MAX_FUZZER_VERSION_STREAM_BYTES,
                    )
            except subprocess.TimeoutExpired:
                add(
                    "fuzzer_version",
                    "failed",
                    "AFL++ --version did not finish within five seconds.",
                )
            except (OSError, subprocess.SubprocessError) as exc:
                add(
                    "fuzzer_version",
                    "failed",
                    f"Could not safely execute AFL++ --version: {exc}",
                )
            else:
                if (
                    stdout_size >= _MAX_FUZZER_VERSION_STREAM_BYTES
                    or stderr_size >= _MAX_FUZZER_VERSION_STREAM_BYTES
                ):
                    add(
                        "fuzzer_version",
                        "failed",
                        "AFL++ --version reached the bounded output limit "
                        f"({_MAX_FUZZER_VERSION_OUTPUT_BYTES} bytes combined); "
                        "complete version output cannot be verified.",
                    )
                else:
                    version_output = (
                        stdout_bytes + b"\n" + stderr_bytes
                    ).decode("utf-8", errors="replace")
                    version_pattern = (
                        r"(?<![0-9A-Za-z])"
                        + re.escape(config.fuzzer.expected_version)
                        + r"(?![0-9A-Za-z.+-])"
                    )

                    if result.returncode != 0:
                        add(
                            "fuzzer_version",
                            "failed",
                            "AFL++ --version exited with status "
                            f"{result.returncode}.",
                        )
                    elif re.search(version_pattern, version_output) is None:
                        actual = version_output.strip() or "(no version output)"
                        add(
                            "fuzzer_version",
                            "failed",
                            f"Expected AFL++ {config.fuzzer.expected_version}; "
                            f"received {actual!r}.",
                        )
                    else:
                        add(
                            "fuzzer_version",
                            "passed",
                            f"Installed AFL++ matches "
                            f"{config.fuzzer.expected_version}.",
                        )


    # These are separate required campaign-acceptance gates.
    add(
        "harness_smoke_validation",
        "not_run",
        "This preflight does not execute the harness or test its behavior.",
    )
    add(
        "coverage_diversity",
        "not_run",
        "Coverage feedback checks remain a separate validation step.",
    )
    add(
        "build_provenance",
        "not_run",
        "Binary freshness, compiler flags and instrumentation identity "
        "are not established by file-existence checks.",
    )

    return PreflightReport(
        target_name=target.name,
        target_version=target.version,
        checks=tuple(checks),
    )
