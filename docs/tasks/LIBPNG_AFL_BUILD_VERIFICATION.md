# libpng 1.6.59 — AFL++ Build Verification Record

**Date:** 2026-11-05  
**Branch:** `feature/libpng-first-target`  
**Status:** AFL++ static-library build passed; UBSan trap-mode smoke test passed; harness not yet implemented.

## Source and build identity

- Source: libpng 1.6.59
- Source directory: `~/kekkai-work/downloads/libpng-1.6.59`
- AFL++ build directory: `~/kekkai-work/builds/libpng-1.6.59-afl-ubsan`
- AFL++ version: 4.33c
- Clang/LLVM version: 21.1.8
- CMake generator: Ninja
- Build type: `RelWithDebInfo`
- zlib resolved by CMake: 1.3.1 at `/usr/lib/x86_64-linux-gnu/libz.so`
- CMake options: `PNG_SHARED=OFF`, `PNG_STATIC=ON`, `PNG_TESTS=OFF`, `PNG_TOOLS=OFF`, `PNG_FRAMEWORK=OFF`, `CMAKE_POSITION_INDEPENDENT_CODE=ON`
- C compiler: `/usr/bin/afl-clang-fast`
- `AFL_USE_UBSAN=1` was exported during configuration and compilation.
- The generated build-directory `pnglibconf.h` was checked for read, sequential-read, interlacing, setjmp and user-limit support.

## Library build result

The verbose Ninja build completed all 18 build steps. It compiled 17 libpng C translation units through `afl-clang-fast` and created:

`~/kekkai-work/builds/libpng-1.6.59-afl-ubsan/libpng16.a`

The archive was present and measured approximately 2.5 MiB.

The compiler output included `SanitizerCoveragePCGUARD` instrumentation messages for libpng source functions and the final summary:

- **1,987 locations instrumented**
- **0 collisions**
- AFL++ reported **UBSAN mode**

This is evidence that the target library itself was built with AFL++ coverage instrumentation, rather than compiling only a future harness with the wrapper. Actual end-to-end AFL feedback from the harness is still a separate acceptance gate.

## UBSan trap-mode verification

A disposable C probe deliberately performed signed integer overflow. The AFL++ compiler-wrapper debug output showed these effective compiler flags:

```text
-fsanitize=undefined
-fsanitize-trap=undefined
-fno-omit-frame-pointer
```

The probe terminated with signal 4 (`SIGILL`); the shell reported exit status 132. The deliberate undefined behavior therefore triggered the expected UBSan trap.

Because this profile uses trap mode, the compiler does not need to emit the usual `__ubsan_*` runtime-handler references. The earlier `nm` search returning no such references is not a failure and must not be used as the acceptance test for this configuration. Trap mode reports termination rather than a normal UBSan diagnostic message.

The probe verifies the AFL++ wrapper's UBSan trap behavior. The libpng build log independently reported UBSAN mode; this record does not claim that a per-object disassembly audit of all 17 archive members was performed.

## Scope and remaining gates

This record verifies the AFL++ static-library build and the compiler-wrapper UBSan trap behavior only. It does **not** verify a KEKKAI harness, end-to-end AFL coverage feedback, sanitizer diagnostics on libpng through the harness, or vulnerability discovery.

Remaining work for this task:

1. Implement the manually authored C harness using the approved bounded-input, callback, error-recovery, chunk-limit, row-decoding and end-info design.
2. Compile it against this profile's generated headers and exact `libpng16.a`, plus the profile's zlib and math dependencies.
3. Validate representative valid, empty, malformed, truncated, oversized and row/pixel-limit cases.
4. Demonstrate AFL++ coverage feedback from the instrumented libpng library.
5. Build a separate clean ASan+UBSan diagnostic profile that recompiles both libpng and the harness, then replay the representative corpus.
6. Only after the validation gates pass, consider a short bounded smoke campaign. No sustained campaign is authorized by this record.

No downloaded libpng source, build directory, temporary corpus or generated binary is added to the repository.
