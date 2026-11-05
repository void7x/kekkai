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


## End-to-end coverage-map comparison

**Date:** 2026-11-05

A control executable was built with the same AFL++-instrumented harness source but linked against the ordinary, uninstrumented baseline archive. This distinguishes instrumentation in the harness from instrumentation in libpng itself.

Commands used AFL++ `afl-showmap` with `-m 512 -t 1000+` against the same four testcase files:

- valid 1×1 PNG;
- empty input;
- malformed non-PNG bytes;
- truncated PNG.

The instrumented-libpng executable acquired a **20,800-byte** AFL map. The control executable linked to baseline libpng acquired a **192-byte** AFL map. Per-input non-zero map-entry counts were:

| Input | AFL-instrumented libpng | Baseline uninstrumented libpng |
|---|---:|---:|
| Valid | 517 | 23 |
| Empty | 176 | 20 |
| Malformed | 189 | 24 |
| Truncated | 519 | 27 |

The control executable still has AFL++ instrumentation in the harness itself (168 locations reported when it was compiled); its smaller map is therefore expected. The substantially larger map for the instrumented-libpng executable, together with the 1,987-location instrumentation report from the library build, is evidence that AFL++ coverage instrumentation is present in libpng and observable through the harness.

These map-entry counts are per-input observations, not stable cross-build identifiers and not a measure of unique source lines or vulnerability severity. Raw map IDs must not be compared as stable identifiers across different builds.

## Current validation boundary

At this point:

- AFL++ instrumented static libpng build: passed.
- AFL++ UBSan trap-mode probe: passed.
- Harness compile/link against the instrumented archive: passed without compiler warnings in the captured output.
- Valid, empty, malformed, truncated and over-8-MiB functional smoke inputs: passed with expected outcomes.
- Same-input AFL map comparison against uninstrumented libpng: passed as described above.

Still pending:

- Adam7/interlaced PNG testcase.
- Explicit width, total-pixel and chunk-allocation limit tests.
- Repeated-run/determinism check.
- Separate clean ASan+UBSan rebuild of both libpng and harness, followed by corpus replay.
- Final source review and bounded smoke-fuzz decision.

No sustained fuzzing campaign has been started.
