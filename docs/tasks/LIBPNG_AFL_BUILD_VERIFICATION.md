# libpng 1.6.59 — AFL++ Build Verification Record

**Date:** 2026-11-05  
**Branch:** `feature/libpng-first-target`  
**Status:** First-target build and corrected harness validation gates passed, including baseline tests, AFL++ instrumentation, resource limits, separate ASan+UBSan replay (12/12), and final corrected coverage comparison. Forced allocation-failure injection was not performed. No AFL++ fuzzing campaign has started; bounded-campaign parameters still require project-owner approval.

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

## Initial library-build checkpoint (historical; superseded by later validation records)

This initial section records the library-build checkpoint. Later sections in this document record the harness implementation, end-to-end coverage feedback, sanitizer replay, source-review corrections and final regression results.

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

## Intermediate validation snapshot before Adam7 and resource-limit checks

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


## Interlaced PNG and repeatability checks

**Date:** 2026-11-05

A valid 8×8 RGBA Adam7-interlaced PNG was generated locally and decoded by the harness. The harness exited normally with no libpng fatal diagnostic.

The exact same Adam7 testcase was then run twice with `afl-showmap` against the AFL++-instrumented libpng executable. Results:

- AFL map size reported by AFL++: 20,800 bytes on both runs.
- Non-zero map entries: 579 on both runs.
- Both map files had SHA-256:
  `de40ce918f88d0458e97462641b24d107b22de3aae191cd8ccc09276211ff2e1`.
- `cmp` reported the two map files identical.

This confirms repeatable coverage for this specific interlaced testcase in the current build and environment. It is not a general determinism guarantee for all inputs, processes or builds.

This was the initial row-buffer implementation. During final source review on 2026-11-05, it was replaced with calls to `png_read_row(png_ptr, NULL, NULL)` for each row/pass because the harness does not produce pixel output and does not need to retain row contents between Adam7 passes. The harness still enforces the 64 KiB decoded-row-size ceiling.

## Intermediate harness validation snapshot before resource-limit and sanitizer checks

Passed so far:

- Harness build/link against the AFL++-instrumented libpng archive.
- Valid, empty, malformed, truncated and over-8-MiB input smoke tests.
- Instrumented-libpng versus uninstrumented-libpng coverage-map comparison.
- Valid Adam7 input decode.
- Two-run identical AFL coverage map for the Adam7 testcase.

Still pending:

- Explicit dimension and total-pixel budget tests.
- Ancillary chunk allocation-limit test.
- Separate ASan+UBSan rebuild of both libpng and harness, followed by corpus replay.
- Final source review and bounded smoke-fuzz decision.


## Resource-limit boundary tests

**Date:** 2026-11-05

Six additional controlled PNG inputs tested the approved harness limits. All six harness processes exited normally with status 0 and the expected parser/limit behavior was observed.

| Test | Observed behavior |
|---|---|
| Width 8,193 | libpng rejected the IHDR under the configured 8,192-pixel width limit and emitted an explanatory warning |
| Height 8,193 | libpng rejected the IHDR under the configured 8,192-pixel height limit and emitted an explanatory warning |
| 8,192 × 2,048 pixels | Harness rejected the image before row decoding because the 16,000,000-pixel budget would be exceeded |
| RGBA16 row at exactly 64 KiB | Accepted and decoded successfully; confirms the inclusive decoded-row-size boundary |
| Ancillary tEXt allocation above 256 KiB | libpng refused the over-limit internal chunk-buffer allocation, emitted `tEXt: out of memory`, and continued safely without retaining that text chunk |
| 130 tEXt chunks with cache limit 128 | libpng reached its configured chunk-cache limit, emitted `tEXt: no space in chunk cache`, and continued safely without retaining excess text chunks |

**Interpretation:** the image dimension and pixel-budget limits cause parser/harness rejection. The chunk allocation and cache limits are not whole-file rejection policies: libpng handles those ancillary metadata conditions by warning and skipping/unretaining the affected chunk data. The test verifies safe limit behavior, not that every over-limit ancillary chunk makes the PNG invalid.

The inputs and logs remain under `~/kekkai-work/verification/libpng-harness`, outside the repository.

## Intermediate validation snapshot after resource-limit checks and before ASan+UBSan replay

Passed:

- AFL++ static-library build and UBSan trap-mode probe.
- Harness build/link and initial valid/invalid/oversized input checks.
- AFL coverage comparison showing the larger instrumented-libpng map.
- Valid Adam7 decode and identical two-run coverage maps for that input.
- Width, height, total-pixel and exact decoded-row-size boundary tests.
- Ancillary chunk allocation and cache-limit warning/skip tests.

Remaining:

- Separate clean ASan+UBSan build of both libpng and harness.
- Replay the representative corpus against that diagnostic build.
- Final harness source review, including cleanup and resource-limit behavior.
- Decide on a short bounded smoke fuzz run only after all validation gates pass.


## Separate ASan+UBSan diagnostic build and replay

**Date:** 2026-11-05

A clean diagnostic profile was configured separately from the AFL++ build:

- Build directory: `~/kekkai-work/builds/libpng-1.6.59-asan-ubsan`
- Compiler: Clang 21.1.8
- CMake build type: `RelWithDebInfo`
- C flags: `-fsanitize=address,undefined -fno-omit-frame-pointer`
- Executable linker flags: `-fsanitize=address,undefined`
- CMake options: `PNG_SHARED=OFF`, `PNG_STATIC=ON`, `PNG_TESTS=OFF`, `PNG_TOOLS=OFF`, `PNG_FRAMEWORK=OFF`
- zlib: 1.3.1, `/usr/lib/x86_64-linux-gnu/libz.so`, headers under `/usr/include`
- Generated `pnglibconf.h` was checked for read, sequential read, ancillary chunks, interlacing, setjmp and user-limit support.
- `compile_commands.json` contained 17 translation units; all 17 commands included the ASan+UBSan flags and frame-pointer flag.
- The 17-object static archive `libpng16.a` was created successfully (approximately 4.2 MiB).
- The manually authored harness was compiled and linked against this exact archive, the matching source/build include directories, system zlib and math library. The resulting diagnostic executable was approximately 4.4 MiB.

The diagnostic executable replayed these 12 inputs under:

```text
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1
UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1
```

| Input | Result |
|---|---|
| Valid 1×1 PNG | Passed |
| Valid Adam7-interlaced PNG | Passed |
| Malformed non-PNG input | Passed |
| Truncated PNG | Passed |
| Empty input | Passed |
| Width over limit | Passed |
| Height over limit | Passed |
| Total pixels over limit | Passed |
| Exact 64 KiB row boundary | Passed |
| Ancillary chunk allocation over limit | Passed |
| Chunk cache over limit | Passed |
| Input over 8 MiB | Passed |

**Result: 12/12 processes exited with status 0; no AddressSanitizer, LeakSanitizer or UndefinedBehaviorSanitizer diagnostic was detected by the replay checks.** Per-input logs are stored outside the repository under `~/kekkai-work/verification/libpng-harness/asan-ubsan`.

This is a successful run of the defined diagnostic corpus, not proof of absence of defects. The system zlib dependency was not rebuilt with sanitizers, so zlib internals are outside this instrumentation result.

## Diagnostic-replay checkpoint (superseded by final corrected regression closure)

Passed: baseline upstream tests; AFL++ target-library build and UBSan trap-mode probe; harness functional tests; target-library coverage-map comparison; Adam7 and repeatability check; approved resource-limit tests; clean ASan+UBSan library/harness build; and 12-input sanitizer replay.

Final harness source review and the planned regression checks are complete for the current implementation. The corrected 12-input ASan+UBSan replay, chunk-limit warning checks, five-input instrumented-versus-control coverage comparison, and byte-identical Adam7 map repeat passed. Forced allocation-failure injection was not performed and is recorded as an untested path. A bounded AFL++ smoke campaign remains a separate step requiring explicit project-owner approval of runtime and resource parameters. No `afl-fuzz` campaign has started.


## Final corrected harness review and regression closure

**Date:** 2026-11-05

The final source review identified and corrected two issues in the manually authored C harness:

1. **Adam7 row handling:** the first implementation reused one application row buffer across every row and pass. Because this harness does not validate or emit pixels, it now calls `png_read_row(png_ptr, NULL, NULL)` for each row in every pass. The application-owned row buffer, its allocation and cleanup were removed. The `png_get_rowbytes()` check remains as a 64 KiB decoded-row-size ceiling; it is not an application buffer allocation.
2. **Fatal allocation classification:** the fatal error callback now marks allocation-related errors as harness failures before `png_longjmp()`. The classifier recognizes the pinned libpng 1.6.59 messages `out of memory`, case variants used by its allocation functions, and `insufficient memory` from its `Z_MEM_ERROR` reporting path. This matching is confined to the fatal error callback; non-fatal ancillary chunk warnings remain on the separate warning callback and do not set the harness-failure flag.

Both corrections were followed by rebuilds of the AFL++/UBSan harness, the separate ASan+UBSan harness and the AFL-instrumented control harness linked against the ordinary baseline libpng archive. No compiler warnings or errors appeared in the captured build output.

### Corrected sanitizer replay

The final corrected ASan+UBSan executable replayed all 12 testcases successfully, with each process exiting status 0 and no ASan, LeakSanitizer or UBSan diagnostic detected:

- valid PNG and Adam7-interlaced PNG;
- malformed, truncated and empty inputs;
- width, height and total-pixel limit cases;
- exact 64 KiB decoded-row-size boundary;
- ancillary chunk allocation and chunk-cache limit cases;
- over-8-MiB input.

Logs: `~/kekkai-work/verification/libpng-harness/asan-ubsan-final`.

The two chunk-limit cases still produce their expected non-fatal diagnostics:

- `tEXt: out of memory`
- `tEXt: no space in chunk cache`

### Corrected AFL++ coverage comparison

The corrected AFL++ harness linked to instrumented libpng was compared with the same corrected harness linked to the ordinary, uninstrumented baseline archive. `afl-showmap -m 512 -t 1000+` returned the following non-zero tuple counts:

| Input | Instrumented libpng | Baseline control |
|---|---:|---:|
| Valid | 509 | 26 |
| Empty | 181 | 25 |
| Malformed | 194 | 29 |
| Truncated | 513 | 32 |
| Adam7 | 556 | 28 |

All five inputs showed more tuples with instrumented libpng than with the baseline control. The corrected Adam7 map was then repeated; both map files were byte-for-byte identical with SHA-256:

`1e9c29e05e7bfa4caf91a4c69488e607fb8dc7e997e794ae37e3e38a9c3fb6d5`.

Logs and maps: `~/kekkai-work/verification/libpng-harness/coverage-final`.

### Remaining limitations and next decision

The allocation-failure classifier was checked against the exact libpng 1.6.59 source strings and fatal-error flow. **No forced allocation-failure/fault-injection test was performed**, so the behavior is source-reviewed but not experimentally triggered. The existing corpus also does not establish absence of defects. System zlib remains uninstrumented.

The source-review and defined validation gates for the current harness are closed. No `afl-fuzz` campaign has started. A short bounded smoke campaign is a separate next step and requires explicit approval of its duration, memory cap, WSL resource availability and stop conditions. A sustained campaign is outside this first-target task.
