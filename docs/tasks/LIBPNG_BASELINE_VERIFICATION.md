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

At the time of this baseline checkpoint, AFL++ instrumentation, the KEKKAI harness, sanitizer behavior and fuzzing had not yet been verified. Their subsequent verification is recorded in the first-target pilot follow-through.

## First-target pilot follow-through

The separate AFL++-instrumented static-library build, UBSan trap-mode test, corrected harness review, coverage comparison, resource-limit checks and 12-input ASan+UBSan diagnostic replay passed. A subsequent owner-approved five-minute AFL++ smoke campaign completed with 280,452 executions, 252 new corpus entries, zero saved crashes and zero saved hangs. AFL++ selected a 5 ms effective execution timeout and recorded 34 timeout events. All 262 retained queue entries passed separate ASan+UBSan replay. The bounded campaign does not establish absence of defects; forced allocation-failure injection remains untested, and system zlib was not instrumented. See `LIBPNG_AFL_BUILD_VERIFICATION.md` for details.
