# Development Environment Snapshot

**Checked:** 2026-11-04  
**Environment:** Ubuntu on WSL 2  
**Status:** Partial toolchain verification; AFL++ setup is still pending.

This file records observed environment state, not an assumption that every required tool is ready. Update it only after rerunning the verification commands and checking the actual output.

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

## Pending installation or verification

| Component | State at this check |
|---|---|
| AFL++ | Not installed |
| `afl-clang-fast` | Not found |
| `afl-clang-lto` | Not yet checked |
| `libclang-rt-dev` | Not installed |
| ASan/UBSan runtime functionality | Not yet verified with a compiled test |
| Python venv/pip support | Not yet verified |
| Ninja and pkg-config | Not yet verified |
| zlib development headers | Not yet verified |

## Next setup action

Install the missing packages using the Ubuntu package manager:

```bash
sudo apt update
sudo apt install -y \
  afl++ \
  libclang-rt-dev \
  ninja-build \
  pkg-config \
  python3-venv \
  python3-pip \
  zlib1g-dev
```

Then verify:

```bash
afl-fuzz -V
command -v afl-clang-fast
command -v afl-clang-lto
clang --version | head -n 1
llvm-config --version
```

AFL++ availability alone does not prove the complete fuzzing toolchain works. Phase 0 is complete only after a small native test is compiled with the selected AFL++ instrumentation and sanitizer configuration, executed successfully, and the results are recorded.

## Reproducibility note

Record exact versions and test results before beginning the first target build. Do not run campaigns as root. Keep the repository in the WSL Linux filesystem and use a project-local Python virtual environment. WSL 2 is a development workspace, not a security boundary.
