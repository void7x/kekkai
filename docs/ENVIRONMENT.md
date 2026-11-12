# Development Environment Snapshot

- **Toolchain snapshot:** 2026-11-04
- **Pilot follow-through:** 2026-11-05
- **Environment:** Ubuntu 26.04.1 LTS on WSL 2
- **Status:** Phase 0 toolchain verification and the manual Phase 1 libpng 1.6.59 target pilot are complete. Reusable target-adapter and campaign-orchestration components remain Phase 2 work.

This file records observed environment state and distinguishes installed tools from capabilities that have actually been exercised.

## System

| Item | Observed value |
|---|---|
| Distribution | Ubuntu 26.04.1 LTS |
| Architecture | amd64 |
| Package indexes | `apt update` completed; no package updates were available at check time |

## Installed and verified

| Tool | Observed version/status |
|---|---|
| Git | 2.53.0 |
| Python | 3.14.4 |
| Python venv | Available; `python3 -m venv --help` passed |
| pip | 25.1.1 |
| GCC | 15.2.0 |
| CMake | 4.2.3 |
| Ninja | 1.13.2 |
| pkg-config | 2.5.1 |
| SQLite CLI | 3.46.1 |
| zlib development files | 1.3.1, reported by pkg-config |
| Clang | Ubuntu Clang 21.1.8 |
| Clang++ | Ubuntu Clang 21.1.8 |
| llvm-config | 21.1.8 |
| libclang-dev | Installed; APT package version 21.1.6-71 |
| AFL++ | 4.33c, observed in compiler-wrapper and fuzzer banners |
| `afl-clang-fast` | Available at `/usr/bin/afl-clang-fast` |
| `afl-clang-lto` | Available at `/usr/bin/afl-clang-lto` |

**AFL++ version-command note:** `afl-fuzz -V` expects a duration in seconds, not a version-only flag. The command printed the AFL++ 4.33c banner and then displayed usage because no duration was supplied. This was not an installation failure.

## Smoke-test evidence

A small C program that reads standard input was used to test the native toolchain.

| Check | Observed result |
|---|---|
| AFL++ instrumented build | Passed; compiler reported 5 instrumented locations with no collisions |
| AFL++ coverage feedback | Passed; `afl-showmap` created `coverage.map`, containing 3 lines |
| ASan + UBSan build | Passed |
| Sanitizer runtime execution | Passed; program printed `KEKKAI smoke test passed` with no sanitizer diagnostics |

At the time of this 2026-11-04 toolchain snapshot, these checks verified the compiler wrapper, basic AFL++ feedback and Clang sanitizer runtime. They did not yet validate a third-party library or a KEKKAI harness. The subsequent libpng 1.6.59 pilot verification is recorded below.

## libpng 1.6.59 pilot follow-through — 2026-11-05

The manual first-target pilot exercised the installed toolchain against pinned libpng 1.6.59. Evidence and detailed commands are in `docs/tasks/LIBPNG_AFL_BUILD_VERIFICATION.md`.

| Check | Result |
|---|---|
| Baseline libpng build | Passed |
| Configured upstream CTest suite | 37/37 passed |
| AFL++-instrumented libpng build | Passed |
| Instrumentation/coverage comparison | Passed; target-library instrumentation was observable |
| Corrected harness regression corpus | 12/12 passed under ASan+UBSan |
| Bounded AFL++ smoke campaign | Completed; 280,452 executions in 300 seconds |
| Retained AFL++ queue replay | 262/262 passed under separate ASan+UBSan build |

**Campaign limitation:** The command requested `-t 1000+`, but AFL++ 4.33c selected an effective timeout of 5 ms from the fast seed timings. The campaign also recorded 34 timeout events and stopped with 134 queue entries pending. The result is a bounded smoke test, not a comprehensive fuzzing campaign and not evidence that libpng is free of defects.

System zlib was not instrumented. Forced allocation-failure injection was not performed. The retained-corpus sanitizer result applies only to the 262 saved queue entries, not all fuzzing executions.

## Remaining target-specific work

| Item | State |
|---|---|
| Manual libpng 1.6.59 harness and pilot integration | Completed |
| Reusable target-adapter configuration | Phase 2; not implemented |
| Automated harness-validation workflow | Phase 2; not implemented |
| Automated AFL++ campaign manager | Phase 2; not implemented |
| Fixed-timeout policy and effective-timeout verification | Phase 2; not implemented |
| libclang runtime/package compatibility in a real integration | Not yet exercised |
| Forced allocation-failure injection | Not tested |
| Crash evidence database and version-aware replay | Phases 3–4; not implemented |

## Next engineering milestone — Phase 2

Proceed from the manually verified libpng pilot to a small, repeatable orchestration workflow:

1. Define a minimal adapter configuration for this one target.
2. Validate configured source, build, harness, seed and executable paths before launching anything.
3. Add explicit harness smoke checks and coverage-diversity checks.
4. Launch AFL++ through Python subprocess argument arrays, not shell-concatenated commands.
5. Capture exact arguments, environment, tool versions, logs, exit status and campaign statistics.
6. Enforce explicit duration, memory and execution-time policies. A fixed 1,000 ms policy must use `-t 1000` and verify the effective timeout; `-t 1000+` is an adaptive policy with a 1,000 ms ceiling, not a fixed one-second timeout.
7. Distinguish completed, failed, timed-out and interrupted campaigns.

Keep generated builds, corpora, logs and campaign output outside the Git repository. Do not add a dashboard or database in this milestone.

## Reproducibility and safety

Record exact tool versions, source revisions, build configuration, harness identity, commands, and campaign limits for each experiment. Preserve original crash inputs and their hashes. Do not run campaigns as root. Keep the repository in the WSL Linux filesystem and use a project-local Python virtual environment. WSL 2 is a development workspace, not a security boundary.
