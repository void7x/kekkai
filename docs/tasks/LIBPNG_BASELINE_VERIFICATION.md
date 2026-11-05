# libpng 1.6.59 — Baseline Verification Record

**Date:** 2026-11-04  
**Branch:** `feature/libpng-first-target`  
**Status:** Passed

## Environment observed

- Ubuntu Clang / Clang++: 21.1.8
- CMake: 4.2.3
- Ninja: 1.13.2
- zlib: 1.3.1

## CMake configuration verified

- Generator: Ninja
- Build type: `RelWithDebInfo`
- C compiler: `/usr/bin/clang`
- C++ compiler: `/usr/bin/clang++`
- `PNG_SHARED=ON`
- `PNG_STATIC=ON`
- `PNG_TESTS=ON`
- `PNG_TOOLS=OFF`

CMake generated `pnglibconf.h` in the baseline build directory. The following feature macros were confirmed enabled:

- `PNG_READ_SUPPORTED`
- `PNG_SEQUENTIAL_READ_SUPPORTED`
- `PNG_SET_USER_LIMITS_SUPPORTED`

## Build result

Command:

```bash
cmake --build "$HOME/kekkai-work/builds/libpng-1.6.59-baseline" --parallel 2
```

Result: all 49 Ninja steps completed. The following artifacts were present:

- `libpng16.so.16.59.0`
- `libpng16.a`
- `pngtest`
- `pngvalid`

## Upstream test result

Command:

```bash
ctest --test-dir "$HOME/kekkai-work/builds/libpng-1.6.59-baseline" --output-on-failure --parallel 2
```

**37/37 passed; 0 failed; 0 skipped shown.** Total CTest time: 83.82 seconds.

This verifies the normal baseline build and its configured upstream test suite in the current WSL 2 environment. It does not yet verify AFL++ instrumentation, the KEKKAI harness, sanitizer behavior in the target integration, or any fuzzing campaign.

## Next gate

The separate AFL++-instrumented static-library build, UBSan trap-mode smoke test, final corrected harness source review, end-to-end coverage comparison, resource-limit checks and corrected 12-input ASan+UBSan diagnostic replay have passed; see `LIBPNG_AFL_BUILD_VERIFICATION.md`. No `afl-fuzz` campaign has started. A bounded smoke campaign is the next separate decision and requires explicit project-owner approval of its duration, memory cap, WSL resource availability and stop conditions. Forced allocation-failure injection was not performed.
