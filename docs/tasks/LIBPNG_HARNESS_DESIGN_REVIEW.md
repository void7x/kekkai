# libpng 1.6.59 — Independent Harness Design Review

**Date:** 2026-11-04  
**Applies to:** `docs/tasks/LIBPNG_FIRST_TARGET.md`  
**Status:** Technical review completed; design clarifications accepted; pilot resource limits approved by project owner on 2026-11-04; no harness implementation started.

This addendum records the independent review and the architecture/review lead's verification against the exact libpng `v1.6.59` source tag and current AFL++ guidance. It supplements the approved task; it does not widen the project scope.

## 1. Verified design corrections required before harness coding

### 1.1 CRC and Adler handling

The fuzzing harness should call this before `png_read_info()`:

```c
png_set_crc_action(png_ptr, PNG_CRC_QUIET_USE, PNG_CRC_QUIET_USE);
```

This is the same policy used by libpng 1.6.59's upstream OSS-Fuzz reader harness. It lets mutations progress beyond checksum rejection and into deeper parsing/decoding code. This deliberately means the primary coverage-guided run is not validating CRC/Adler checksum enforcement. Preserve valid checksum-bearing seeds; checksum-specific strict validation can be a separate later check. Do not patch libpng source to disable checks.

### 1.2 Read and retain post-IDAT ancillary chunks

Create a second `png_info` object (`end_info_ptr`) and pass it to `png_read_end()`. In libpng 1.6.59, a NULL `info_ptr` causes post-IDAT chunks other than the special IEND/IHDR cases to be skipped over with CRC handling rather than passed through normal ancillary-chunk parsing. A non-NULL end-info object gives the harness coverage of trailing text, time, profile and other handled chunks.

The official 1.6.59 OSS-Fuzz harness also creates and passes an end-info object.

**CVE scope clarification:** libpng advisory GHSA-qvg3-h654-xq3j says the 1.6.0–1.6.58 use-after-free requires the sequential reader to call `png_read_end()` after `png_read_info()` but *before* starting row reading. Our approved harness reads image rows before `png_read_end()`; it therefore does not reproduce that vulnerable call sequence, and we must not claim it does. The selected 1.6.59 release is patched. The end-info object is required here to exercise post-IDAT ancillary parsing, not to claim discovery or reproduction of that known CVE.

### 1.3 Exact short-read callback contract

The custom `png_rw_ptr` callback returns `void`; it cannot report a short read with a return value. It must:

1. Retrieve its bounded input cursor/state using `png_get_io_ptr()`.
2. Compare the requested `length` against the number of bytes remaining before copying.
3. Call `png_error(png_ptr, "...")` immediately when the request exceeds the remaining input.
4. Never continue to `memcpy` or return normally after the fatal error call.

If a custom error callback is installed, it must save a bounded diagnostic message and call `png_longjmp(png_ptr, 1)`; it must never simply return. A warning callback may save a bounded warning/count without longjmp. Keep hot-path diagnostics in a small fixed-size buffer rather than printing one message per testcase.

### 1.4 Safe state across setjmp/longjmp

C says that non-volatile automatic objects local to the function containing `setjmp` become indeterminate after `longjmp` if they were changed between the two calls. The harness must not rely on local pointers/flags modified after setjmp during cleanup.

Preferred design: allocate one per-input context/state structure before setjmp, initialize its pointer before setjmp, and do not reassign that automatic pointer afterward. Store mutable cleanup state in the heap-allocated context: libpng pointers, input cursor, row-buffer pointer, and bounded diagnostic buffers. Alternatively, any modified automatic object used after longjmp must be correctly volatile-qualified. Keep the implementation simple and document the chosen pattern.

### 1.5 Explicit build configuration

- Profile A has already been configured with `CMAKE_BUILD_TYPE=RelWithDebInfo`; keep that in the task record.
- Set `CMAKE_BUILD_TYPE=RelWithDebInfo` explicitly for Profile B and the sanitizer diagnostic profile as well.
- AFL++'s compiler wrapper appends `-O3` by default unless configured otherwise. Therefore, do not repeat the claim that an unset CMake build type necessarily means an unoptimized AFL++ binary. Instead, record the effective verbose compile/link commands and optimization flags for every profile.

### 1.6 Header and library provenance in the standalone harness build

The CMake `png_static` target exposes both the pinned source directory and the profile's build directory as public build include directories. The standalone harness compile must use the matching pair so that it sees the source `png.h`/ `pngconf.h` and the generated build-directory `pnglibconf.h`.

Link the harness to the exact `libpng16.a` produced by the same profile, plus the zlib and math dependencies resolved for that profile. Do not use `-lpng` or another system libpng.

**Avoid overstating the mismatch risk:** `png_struct` is opaque to the public API; a consumer-side `pnglibconf.h` mismatch does not directly rewrite the private structure layout used inside the library. It can still expose the wrong optional feature declarations/macros or lead to linking the wrong symbols/library. Also, libpng's version check intentionally compares compatibility through the major/minor part (the first two dots); patch releases in the 1.6 series are intended to be binary compatible. We still pin and record the exact archive, generated header and static archive for reproducibility.

### 1.7 Resource and CPU limits must be numerical

Apply `png_set_user_limits()` after creating the read structure and before `png_read_info()`. In addition, check the total pixel count after reading IHDR, using division to avoid multiplication overflow, and check rowbytes after `png_read_update_info()` before allocating the row buffer.

Do not assume that a per-chunk allocation cap also limits total decoded image work. Add a total-pixel budget and an explicit AFL timeout. Important libpng semantics:
- `png_set_chunk_malloc_max(png_ptr, 0)` means unlimited; zero is not a safe restrictive value.
- `png_set_chunk_cache_max()` limits the number of variable ancillary chunks stored; when separate pre-IDAT and end-info structures are used, the limit applies separately to each.
- `png_set_user_limits()` must be applied before `png_read_info()`.

**Approved initial limits for this laptop pilot (project-owner approval: 2026-11-04):**

| Resource | Proposed initial cap | Enforcement |
|---|---:|---|
| Input file | 8 MiB | Reject before reading into memory |
| Image width | 8,192 pixels | `png_set_user_limits()` |
| Image height | 8,192 pixels | `png_set_user_limits()` |
| Total pixels | 16,000,000 | Overflow-safe check after IHDR, before row decoding |
| Decoded row buffer | 64 KiB | Check `png_get_rowbytes()` after update-info |
| Individual ancillary chunk allocation | 256 KiB | `png_set_chunk_malloc_max()`; never pass zero |
| Cached variable ancillary chunks | 128 per info structure | `png_set_chunk_cache_max()` |
| AFL execution timeout | 1,000 ms with AFL++ auto-scaling | Explicit `-t 1000+` on the later bounded campaign |
| AFL target memory | 512 MiB | Explicit `-m 512` for the non-ASan AFL++/UBSan target |

These are approved conservative pilot limits, not permanent platform-wide defaults. Enforce and record them in the harness and campaign metadata. Review actual WSL memory availability before the first campaign; change a limit only with a documented reason and project-owner approval.

### 1.8 Interlaced PNGs

If `PNG_READ_INTERLACING_SUPPORTED` is enabled, call:

```c
passes = png_set_interlace_handling(png_ptr);
```

before `png_read_update_info()`. Then read `height` rows for each returned pass. The 1.6.59 upstream OSS-Fuzz harness uses this pass-major pattern with one reusable row buffer. Our harness is a parser/decoder coverage target, not a pixel-output validator; document that the reused row buffer is not intended to reconstruct a correct final interlaced image. Do not claim pixel correctness from this harness.

### 1.9 Sanitizer profile must instrument both library and harness

The third, clean diagnostic build must rebuild **both libpng and the harness** with `-fsanitize=address,undefined` and `-fno-omit-frame-pointer`. Reusing Profile B's non-ASan archive is not acceptable for full library diagnostics.

Profile B remains AFL++ coverage-instrumented with `AFL_USE_UBSAN=1` (and no ASan for this 64-bit WSL setup). Export the variable before CMake configuration and keep it set for the AFL++ library build and harness compile/link. Verify the actual commands and resulting instrumentation; do not rely on the environment variable name alone.

AFL++ explains the 64-bit ASan virtual-address-space versus `RLIMIT_AS` issue and discusses cgroups and corpus-then-ASan replay. The existing `https://aflplus.plus/docs/notes_for_asan/` link resolves and is valid; do not remove it based on the contrary claim in the independent review. The page explicitly discusses the ASan mapping, memory limits and replay alternative.

## 2. Additional checks accepted for implementation

- Mechanically check the generated `pnglibconf.h` for the exact required features before accepting a profile, including read, sequential read, setjmp, interlacing and `PNG_SET_USER_LIMITS_SUPPORTED`. In libpng 1.6.59, the public declarations for both `png_set_chunk_cache_max()` and `png_set_chunk_malloc_max()` are guarded by `PNG_SET_USER_LIMITS_SUPPORTED`; separate per-chunk-limit feature macros do not exist in this release.
- Record whether CMake used the AWK/DFA generation path or the prebuilt header fallback, and record the selected AWK executable.
- Record resolved zlib version, include directory and library for each profile. Keep zlib consistent between profiles.
- Set `CMAKE_POSITION_INDEPENDENT_CODE=ON` for the static AFL++ target build as a conservative link-compatibility measure.
- Verify library instrumentation, not just harness instrumentation. Preserve verbose compiler output/`AFL_DEBUG` evidence and perform a same-seed coverage comparison against a harness linked to an uninstrumented libpng archive.
- Use a small selected seed corpus from the pinned source's `contrib/pngsuite` and `contrib/testpngs`, plus the upstream `contrib/oss-fuzz/png.dict` where suitable. Hash the selected seed files.
- Keep the harness in C and on the public libpng API. Do not copy the upstream OSS-Fuzz harness wholesale, include private headers, or define `PNG_INTERNAL`.
- System zlib remains the approved initial dependency and will not be instrumented in this first target task. Explicitly document that AFL coverage and sanitizer instrumentation do not include zlib internals.
- Keep CRC/Adler-ignore policy explicit in the harness record. A separate strict-checksum test mode may be considered later, but do not add a second fuzzing mode to this first implementation slice without a demonstrated need.

## 3. Review findings that were not accepted verbatim

- The independent review called the AFL++ ASan documentation URL stale/nonexistent. It currently resolves to the official AFL++ “Notes for using ASAN with afl-fuzz” page, so the URL remains valid.
- The review described the wrong-header risk as changing a consumer-visible `png_struct` layout. The public structure is opaque; the real concerns are optional feature macros/declarations and accidental linkage to a different library.
- The review tied the 1.6.59 end-info advice to the known use-after-free advisory. The non-NULL end-info object is still required for full post-IDAT ancillary parsing, but our row-first harness sequence is explicitly not the vulnerable sequence described by the advisory.

## 4. Source references used for verification

- Exact libpng 1.6.59 source tag: https://github.com/pnggroup/libpng/tree/v1.6.59
- Upstream 1.6.59 OSS-Fuzz harness: https://github.com/pnggroup/libpng/blob/v1.6.59/contrib/oss-fuzz/libpng_read_fuzzer.cc
- 1.6.59 sequential reader: https://github.com/pnggroup/libpng/blob/v1.6.59/pngread.c
- 1.6.59 input callback dispatch: https://github.com/pnggroup/libpng/blob/v1.6.59/pngrio.c
- 1.6.59 public API declarations: https://github.com/pnggroup/libpng/blob/v1.6.59/png.h
- C setjmp/longjmp rule: C standard §7.13.2.1 (automatic locals changed after setjmp become indeterminate unless volatile-qualified)
- AFL++ ASan guidance: https://aflplus.plus/docs/notes_for_asan/
- AFL++ compiler environment variables: https://aflplus.plus/docs/env_variables/
- libpng 1.6.59 security advisory: https://github.com/pnggroup/libpng/security/advisories/GHSA-qvg3-h654-xq3j

## 5. Current implementation status

The baseline libpng 1.6.59 build and all 37 configured upstream tests have passed, as recorded in `LIBPNG_BASELINE_VERIFICATION.md`. The AFL++ static-library build and UBSan trap-mode smoke test have now passed, as recorded in `LIBPNG_AFL_BUILD_VERIFICATION.md`. The C harness, separate ASan+UBSan diagnostic build and fuzzing campaign remain not started.
