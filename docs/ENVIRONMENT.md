# Development Environment Snapshot

**Checked:** 2026-11-04  
**Environment:** Ubuntu 26.04.1 LTS on WSL 2  
**Status:** Core AFL++ instrumentation, coverage feedback, and ASan/UBSan smoke tests passed. Some supporting development packages remain unverified.

This file records observed environment state. It distinguishes installed tools from capabilities that have actually been exercised.

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
| GCC | 15.2.0 |
| CMake | 4.2.3 |
| SQLite CLI | 3.46.1 |
| Clang | Ubuntu Clang 21.1.8 |
| Clang++ | Ubuntu Clang 21.1.8 |
| llvm-config | 21.1.8 |
| libclang-dev | Installed; APT package version 21.1.6-71 |
| AFL++ | 4.33c, observed in compiler-wrapper banner |
| `afl-clang-fast` | Available at `/usr/bin/afl-clang-fast` |
| `afl-clang-lto` | Available at `/usr/bin/afl-clang-lto` |

## Smoke-test evidence

A small C program that reads standard input was used to test the native toolchain.

| Check | Observed result |
|---|---|
| AFL++ instrumented build | Passed; compiler reported 5 instrumented locations with no collisions |
| AFL++ coverage feedback | Passed; `afl-showmap` created `coverage.map`, containing 3 lines |
| ASan + UBSan build | Passed |
| Sanitizer runtime execution | Passed; program printed `KEKKAI smoke test passed` with no sanitizer diagnostics |

This verifies that the selected AFL++ compiler wrapper can instrument and build a small target, that AFL++ can collect execution feedback from it, and that the Clang sanitizer build runs in this environment. It does not yet validate a real third-party library, a KEKKAI harness, or a sustained fuzzing campaign.

## Still to verify

| Component | State |
|---|---|
| Python venv/pip support | Not yet independently verified |
| Ninja | Not yet independently verified |
| pkg-config | Not yet independently verified |
| zlib development headers | Not yet independently verified |
| libclang runtime package details | Not independently recorded |
| Real target build and harness | Not started |

## Next engineering milestone

Proceed to the first target feasibility check, with **libpng** as the pilot candidate. Before launching any fuzzing campaign:

1. Pin the exact libpng source revision and record its provenance.
2. Inspect the source and select a meaningful parsing entry point.
3. Create a small reviewed harness; do not assume automatic harness generation.
4. Build with AFL++ instrumentation and compatible sanitizers.
5. Prove representative valid, empty, and malformed inputs reach the intended library code.
6. Confirm coverage feedback and enforce execution/resource limits.
7. Only then begin a bounded fuzzing campaign.

If libpng cannot be integrated cleanly, record the concrete blocker before considering one alternative. Do not claim target support until the integration is demonstrated.

## Reproducibility and safety

Record exact tool versions, source revisions, build configuration, harness identity, commands, and campaign limits for each experiment. Preserve original crash inputs and their hashes. Do not run campaigns as root. Keep the repository in the WSL Linux filesystem and use a project-local Python virtual environment. WSL 2 is a development workspace, not a security boundary.
