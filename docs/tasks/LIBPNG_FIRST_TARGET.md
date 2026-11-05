# First Target Integration — libpng 1.6.59

**Status:** In progress — baseline, AFL++ instrumentation, corrected harness source review, 12-input ASan+UBSan replay, resource-limit tests and final coverage regression passed; bounded smoke-campaign parameters still require project-owner approval  
**Base branch:** `development`  
**Task branch:** `feature/libpng-first-target`  
**Target:** libpng 1.6.59  
**Approval:** 2026-11-04

This document defines the first bounded target-integration task. It does not claim that libpng support, a harness, or a fuzzing campaign already exists.

## 1. Goal

Build and validate one real native target integration for KEKKAI:

- build the pinned libpng source in a normal baseline configuration;
- build an AFL++-instrumented static libpng library;
- write one small, manually reviewed C harness;
- feed test files to libpng through an in-memory read callback;
- exercise sequential PNG reading, including image data and end chunks;
- validate the harness with valid, empty, malformed and truncated inputs;
- verify AFL++ coverage feedback and ASan/UBSan diagnostics;
- preserve commands, build configuration and test evidence.

This task proves one useful target path. It does not establish support for arbitrary C/C++ projects.

## 2. Source identity and provenance

- Upstream release page: https://sourceforge.net/projects/libpng/files/libpng16/1.6.59/
- Source archive: `libpng-1.6.59.tar.xz`
- Archive SHA-256: `d80dd2a38a37f803cb9b6ac7b14bd6e74ddc3b654780a8380bdf93523fdb4389`
- Version confirmed in `png.h`: `PNG_LIBPNG_VER_STRING "1.6.59"`
- Local source directory currently used: `~/kekkai-work/downloads/libpng-1.6.59`

The archive checksum was verified after download and again before extraction. The source is kept outside the KEKKAI repository. Do not vendor the archive or copy the full third-party source tree into this repository. Retain the upstream license and provenance information with local experiment records.

## 3. Scope

### In scope

1. Inspect the generated libpng configuration and confirm that the required sequential read and resource-limit features are enabled.
2. Produce a normal baseline build and run the applicable upstream tests.
3. Produce a separate AFL++-instrumented build of libpng as a static library.
4. Write one C harness with:
   - a bounded input-file read into memory;
   - a custom libpng read callback over that memory;
   - correct handling of callback over-read/truncated input;
   - libpng error recovery and safe cleanup;
   - explicit image and chunk/resource limits where the generated configuration supports them;
   - sequential decoding by rows rather than allocating the entire image;
   - completion through `png_read_end()`.
5. Exercise real libpng code with representative valid and malformed inputs. The initial valid, empty, malformed, truncated and over-8-MiB functional smoke tests have passed.
6. Verify coverage feedback from the instrumented library and harness. An `afl-showmap` comparison against the same AFL-instrumented harness linked to uninstrumented baseline libpng demonstrated a 20,800-byte target map versus a 192-byte control map; details are in `LIBPNG_AFL_BUILD_VERIFICATION.md`.
7. Validate a valid 8×8 RGBA Adam7 PNG and confirm two identical coverage maps for that testcase (579 non-zero entries; matching SHA-256 recorded in `LIBPNG_AFL_BUILD_VERIFICATION.md`).
7. Run sanitizer validation and record the results.
8. Keep all build directories, temporary corpora, logs and crash artifacts outside tracked source unless a small fixture is explicitly approved.

### Explicitly out of scope

- Long-running or multi-worker fuzzing campaigns.
- Persistent-mode optimization.
- Automatic harness generation.
- General-purpose support for arbitrary libraries.
- Source-function ranking or broader libclang integration.
- CASR integration, database implementation, dashboard or AI features.
- Claiming that any observed crash is a vulnerability without investigation.

A short, bounded smoke campaign may be run only after all harness-validation gates pass. A sustained campaign is a separate task.

## 4. Build profiles

Use separate, clean CMake build directories. Never reuse a build directory after changing compiler, source revision, sanitizer or instrumentation settings.

### Profile A — baseline build

Purpose: establish a normal libpng build and run upstream tests without AFL instrumentation.

Planned CMake settings:

- `PNG_SHARED=ON`
- `PNG_STATIC=ON`
- `PNG_TESTS=ON`
- `PNG_TOOLS=OFF`
- Clang as the ordinary compiler, with the actual compiler version recorded.

The pinned source's CMake file enters its test configuration only when both `PNG_TESTS` and `PNG_SHARED` are enabled. Keep the shared build enabled for this validation profile. Run the configured test suite and record any unavailable or platform-inapplicable tests.

### Profile B — AFL++ fuzzing build

Purpose: compile the libpng target code and harness with AFL++ coverage instrumentation.

Planned CMake settings:

- `PNG_SHARED=OFF`
- `PNG_STATIC=ON`
- `PNG_TESTS=OFF`
- `PNG_TOOLS=OFF`
- C compiler: `afl-clang-fast`
- AFL++ UBSan mode: `AFL_USE_UBSAN=1`, subject to a compile-and-run compatibility check.

Important distinction: `PNG_STATIC=ON` builds libpng as a static archive. It does **not** mean linking the final harness executable with the compiler's full `-static` option. Do not add `-static` to the harness link. The executable must remain compatible with the sanitizer/runtime libraries it uses.

Verify that the library translation units—not only the harness—were compiled with the AFL++ wrapper. Use build logs and coverage observations from representative inputs as evidence.

### Sanitizer validation — separate diagnostic configuration

AddressSanitizer and UndefinedBehaviorSanitizer must be exercised against the same harness and a documented test corpus. Use a clean Clang sanitizer build for ASan+UBSan checks and replay; do not silently combine it with, or substitute it for, the AFL++ fuzzing build.

AFL++ documentation warns that ASan reserves a very large virtual-address region on 64-bit systems and makes memory-limit handling difficult. It recommends additional care such as cgroup-based limits or using a non-ASan fuzzing build followed by ASan examination of the corpus. Therefore, the initial sustained AFL++ campaign must not depend on an ASan-instrumented 64-bit target unless a safe memory-control strategy is demonstrated first.

AFL++ documents `AFL_USE_UBSAN=1` for its UBSan mode. Confirm the actual compiler output and runtime behavior rather than assuming the environment variable alone proves instrumentation.

For Profile B, export `AFL_USE_UBSAN=1` before CMake configuration and keep it set during both the library build and the harness compile/link. Verify the effective compile commands and the resulting instrumentation; do not rely on the environment variable name alone. For each profile, explicitly set `CMAKE_BUILD_TYPE=RelWithDebInfo`. For the static AFL++ profile, also set `CMAKE_POSITION_INDEPENDENT_CODE=ON`.

The separate ASan+UBSan diagnostic profile must rebuild **both libpng and the harness** with `-fsanitize=address,undefined` and `-fno-omit-frame-pointer`. Do not reuse Profile B's archive for this profile. Keep the system zlib dependency consistent and record its resolved version, include path and library. System zlib will not be instrumented in this pilot; document that its internal coverage and sanitizer instrumentation are absent.


## 5. Harness behavior

The proposed input contract is one testcase path supplied by AFL++ using `@@`. The harness reads that file into a bounded memory buffer; the custom callback then supplies bytes to libpng from that buffer.

The intended sequential read path is:

1. Read the testcase into a bounded input buffer; reject files larger than the approved input limit before reading the full input.
2. Create the libpng read structure, primary info structure and separate end-info structure. Treat unexpected allocation/creation failure as a harness failure, not as an ordinary malformed-PNG result.
3. Establish error recovery before any libpng call that may invoke its fatal-error path. Keep mutable cleanup state in a heap-allocated per-input context initialized before `setjmp`; do not rely on modified, non-volatile automatic locals after `longjmp`.
4. Set the custom in-memory read callback. It must retrieve its cursor via `png_get_io_ptr()`, compare requested bytes to remaining bytes before copying, call `png_error()` on a short read, and never copy or return normally after that fatal error call. Any custom fatal error callback must save a bounded diagnostic and call `png_longjmp(png_ptr, 1)`; it must not return.
5. Apply `png_set_user_limits()` and chunk/resource limits before `png_read_info()`. Never pass zero to `png_set_chunk_malloc_max()`, because zero means unlimited. Treat chunk-cache maximum as a count of cached variable-length chunks.
6. Set the explicit CRC policy before reading metadata: `png_set_crc_action(png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE)`. This coverage-oriented fuzzing policy uses data even when chunk checksums are wrong; it is not strict checksum-validation mode. Do not patch the pinned libpng source to disable checksums.
7. Read PNG metadata. Validate width, height and the total pixel budget using overflow-safe arithmetic before decoding any rows.
8. Configure selected transforms, call `png_set_interlace_handling()` when the generated feature is enabled, and do so before `png_read_update_info()`. Read `height` rows for each reported interlace pass.
9. Check `png_get_rowbytes()` against the 64 KiB decoded-row-size ceiling after update-info. Because this harness does not produce or validate pixels, call `png_read_row(png_ptr, NULL, NULL)` for each row in every reported pass; do not allocate an application row buffer, call `png_read_image()`, or allocate a full image.
10. Call `png_read_end(png_ptr, end_info_ptr)` with the non-NULL end-info structure so post-IDAT ancillary chunks are parsed.
11. Save useful bounded error/warning diagnostics, then destroy all libpng structures and release harness-owned state on normal and error paths.

This harness is intended to exercise parsing/decoding code, not to validate final pixel output. It supplies NULL for both row and display-row arguments to `png_read_row()` because it does not need to retain or reconstruct pixels across Adam7 passes. The 64 KiB check is a decoded-row-size ceiling, not an application row-buffer allocation. This is a bounded parser/decoder-coverage harness.

Do not assume every optional resource-limit or interlacing API exists: mechanically check the generated `pnglibconf.h` feature macros and fail clearly or document a justified fallback. For libpng 1.6.59, `png_set_chunk_cache_max()` and `png_set_chunk_malloc_max()` are declared inside the single `PNG_SET_USER_LIMITS_SUPPORTED` guard in `png.h`; there are no separate `PNG_SET_CHUNK_CACHE_LIMIT_SUPPORTED` or `PNG_SET_CHUNK_MALLOC_LIMIT_SUPPORTED` feature macros. Check the actual declarations/guard in the pinned public header rather than testing invented per-API macros.

### Approved pilot resource limits — 2026-11-04

The project owner approved these initial limits for the laptop-based libpng pilot. They are task-specific starting limits, not universal KEKKAI defaults.

| Resource | Approved limit | Enforcement |
|---|---:|---|
| Input file | 8 MiB | Reject before reading the testcase into memory |
| Image width | 8,192 pixels | `png_set_user_limits()`, before `png_read_info()` |
| Image height | 8,192 pixels | `png_set_user_limits()`, before `png_read_info()` |
| Total image pixels | 16,000,000 | Overflow-safe width/height check after IHDR and before row decoding |
| Decoded row size | 64 KiB | Check `png_get_rowbytes()` after `png_read_update_info()`; no application row buffer is allocated |
| Individual ancillary chunk allocation | 256 KiB | `png_set_chunk_malloc_max()`; zero is forbidden because it means unlimited |
| Cached variable ancillary chunks | 128 per info structure | `png_set_chunk_cache_max()`; this is a count, not a byte limit |
| AFL++ timeout | 1,000 ms plus AFL++ calibration (`-t 1000+`) | Apply to the later bounded fuzzing run |
| AFL++ target memory | 512 MiB (`-m 512`) | Apply to the non-ASan AFL++/UBSan target; review WSL resource availability before the campaign |

These limits must be enforced in the harness and recorded in each experiment. The total-pixel budget bounds decoded work that is not adequately constrained by compressed input size or row size alone. Reassess a limit only if a measured compatibility or coverage need justifies a change, and record the reason.

## 6. Acceptance criteria

This task is complete only when all applicable checks below have retained evidence.

### Source and build

- The archive checksum and source version are recorded.
- Both baseline and AFL++ configurations use separate clean build directories.
- Baseline compilation succeeds.
- The applicable upstream libpng tests run; results and skipped tests are recorded.
- AFL++ compilation succeeds for the libpng source translation units and the harness.
- The generated configuration contains the required sequential-read and selected resource-limit features, or any limitation is documented.

### Harness and configuration decisions accepted before implementation

- CRC policy for the coverage-oriented harness: `PNG_CRC_QUIET_USE` for critical and ancillary chunks. This is not strict checksum-validation mode.
- A non-NULL end-info structure is required for the `png_read_end()` call.
- The short-read callback rejects before any out-of-bounds copy and signals a fatal libpng error.
- Mutable cleanup state changed after `setjmp` remains valid after `longjmp`; use a pre-initialized heap context or correctly volatile-qualified automatic state.
- Interlaced input uses the interlace-handling API before update-info and calls `png_read_row(png_ptr, NULL, NULL)` for each row in every reported pass; no pixel-row buffer is maintained.
- Harness include paths and its static archive come from the same profile build; do not accidentally link a system libpng.
- The ASan+UBSan diagnostic build instruments both libpng and the harness.

### Harness correctness

- A representative valid PNG reaches the libpng read path and completes as expected.
- Empty, malformed and truncated inputs terminate safely through the harness's error path.
- Image and allocation limits are enforced.
- Row-by-row decoding is used; no unbounded full-image allocation is introduced by the harness.
- Both success and libpng error paths release resources safely.
- Repeated runs on the same input are sufficiently deterministic for the chosen execution mode.

### Instrumentation and diagnostics

- AFL++ coverage feedback is produced by the instrumented executable.
- Evidence supports that the target library code is instrumented, not merely the harness.
- ASan+UBSan validation runs on the representative corpus and any later replay artifacts.
- Sanitizer diagnostics, warnings and inconclusive results are preserved and reviewed; they are not silently dismissed.
- A bounded smoke fuzz run, if performed, records exact command, duration, exit state, limits, tool versions and logs.

### Repository and reproducibility

- Build trees, downloaded source, temporary corpora and generated crash artifacts remain outside tracked repository files.
- The feature branch contains only the approved task documentation and implementation scope.
- The final diff is reviewed; no unrelated architecture, dependency or formatting changes are included.
- The task report lists files changed, commands actually run, test outcomes, limitations and the next milestone.

## 7. Safety, recovery and change control

- Do not run the target or fuzzer as root.
- Do not disable host security controls.
- Apply time, memory and process limits appropriate to the selected sanitizer mode.
- WSL 2 is a development workspace, not a security boundary; use an isolated VM for risky samples.
- Preserve original testcases and crash evidence unchanged. Minimized inputs are separate derived artifacts.
- If the target build or harness fails, stop at the failing gate, capture the error and diagnose one cause at a time. Do not widen project scope to hide a failed integration.
- Any change to target revision, build strategy, dependency or architecture requires an evidence-based proposal and project-owner approval.

## 8. Completion report template

At task close, record:

- source revision and archive checksum;
- compiler, linker, CMake, Ninja, AFL++ and sanitizer versions;
- exact CMake options, compiler/linker flags and commands;
- harness source and binary hashes;
- resource limits and corpus file hashes;
- upstream test results;
- harness validation results;
- coverage feedback evidence;
- sanitizer results;
- campaign duration and exit state, if a smoke run occurred;
- known limitations and unresolved issues;
- reviewed Git diff and next milestone.

## 9. References

- libpng 1.6.59 release and source archive: https://sourceforge.net/projects/libpng/files/libpng16/1.6.59/
- AFL++ ASan guidance, including 64-bit memory-limit caveats: https://aflplus.plus/docs/notes_for_asan/
- AFL++ sanitizer environment variables: https://aflplus.plus/docs/env_variables/
- AFL++ best practices: https://aflplus.plus/docs/best_practices/


## 10. Execution status update — 2026-11-05

The separate diagnostic profile rebuilt all 17 libpng C translation units with AddressSanitizer and UndefinedBehaviorSanitizer, then linked the manually authored harness against that exact archive. The generated configuration header and all 17 compile-command sanitizer flags were verified.

The defined 12-input diagnostic corpus passed: valid and Adam7 PNGs; malformed, truncated and empty inputs; width, height and total-pixel limit cases; the exact 64 KiB row boundary; both ancillary chunk-limit cases; and the over-8-MiB input. Every process exited with status 0 and no ASan, LeakSanitizer or UBSan diagnostic was detected. Detailed commands, configuration and outcomes are in `LIBPNG_AFL_BUILD_VERIFICATION.md`.

The source-review and defined validation gates for the corrected harness are now closed. The corrected source removes the shared row-buffer implementation for Adam7 and classifies fatal libpng allocation failures in the error callback. The 12-input ASan+UBSan replay, both chunk-limit warning checks and final five-input AFL++ coverage comparison passed. The exact results and the allocation-failure fault-injection limitation are recorded in `LIBPNG_AFL_BUILD_VERIFICATION.md`. This does not prove absence of defects or instrument system zlib. A short bounded AFL++ smoke campaign is a separate next step requiring explicit project-owner approval of duration, memory cap, WSL resource availability and stop conditions. No campaign has started.


## 11. Corrected harness verification closure — 2026-11-05

Final source review led to two narrow corrections. The harness now passes NULL row pointers to `png_read_row()` for every row and Adam7 pass because pixel output is not required; the 64 KiB `png_get_rowbytes()` check remains a decoded-row-size ceiling, not a buffer allocation. The fatal error callback now classifies libpng 1.6.59 allocation-related fatal messages (including chunk-prefixed out-of-memory and zlib insufficient-memory messages) as harness failures. Chunk warnings remain non-fatal because they use the separate warning callback.

The latest AFL++, baseline-control and ASan+UBSan harness executables were rebuilt. The corrected 12-input ASan+UBSan replay passed without sanitizer diagnostics. The five-input coverage comparison passed for valid, empty, malformed, truncated and Adam7 files; the corrected Adam7 coverage map was byte-identical on repeat. Both ancillary chunk-limit warnings were preserved. The exact counts, hash and log paths are recorded in `LIBPNG_AFL_BUILD_VERIFICATION.md`.

A forced allocation-failure test was not performed; this classification is source-reviewed but not fault-injection-tested. The defined harness source-review and regression gates are closed. A bounded smoke campaign remains unstarted pending explicit approval of its time, memory and stop parameters.
