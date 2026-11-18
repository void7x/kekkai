# Phase 2 — Harness Validation Verification

**Date:** 2026-11-11
**Branch:** `feature/fuzzing-orchestration`
**Status:** Campaign orchestration implemented and tested; successful live campaign and adapter-driven builds outstanding

## 1. Goal

Verify configuration validation, preflight checks, harness smoke behavior, and AFL++ coverage-feedback diversity and repeatability for libpng.

This report does not claim that the Phase 2 campaign manager is complete.

## 2. Implemented files

- `engine/adapters/config.py` — strict TOML configuration validation.
- `engine/fuzzing/preflight.py` — source, harness, binary, corpus, tool and resource checks.
- `engine/fuzzing/provenance.py` — build-artifact hashes, compiler, CMake and toolchain provenance verification.
- `engine/fuzzing/smoke.py` — bounded harness smoke validation.
- `engine/fuzzing/coverage.py` — per-seed coverage maps, diversity, repeatability and bounded process/map handling.
- `engine/fuzzing/campaign.py` — fixed single-worker AFL++ command, campaign metadata, bounded logs, watchdog, process-group cleanup and lifecycle states.
- `targets/libpng/adapter.toml` — libpng 1.6.59 adapter configuration.
- `targets/libpng/build-provenance.toml` — expected build-artifact and toolchain provenance.
- Six test modules covering configuration, preflight, smoke, coverage, provenance and campaign orchestration.

## 3. Automated test results

Command: `python3 -m unittest discover -s tests -v`

**Result: 77 tests passed.**

Campaign lifecycle tests use controlled fake processes. They do not substitute for a successful real AFL++ campaign.

Default discovery without `-s tests` found zero tests with the current repository layout.

## 4. Preflight verification

The configured libpng preflight passed.

- Target: libpng 1.6.59.
- AFL++ executable: `/usr/bin/afl-fuzz`.
- AFL++ version: 4.33c.
- Seed corpus: 10 non-empty regular files.
- Aggregate seed size: 266,045 bytes.
- Largest seed: 262,225 bytes.
- Source, harness, binary, limits and output-parent checks: passed.

## 5. Harness smoke verification

The actual harness smoke validation passed **13/13 expected cases**, covering valid, malformed, truncated, boundary and missing-input cases.

## 6. Real AFL++ coverage verification

The real coverage validator was executed using the configured libpng adapter.

**Result: PASS**

- `afl-showmap` version: 4.33c.
- Seed maps captured: 10.
- Distinct seed maps: 10.
- Coverage diversity: passed.
- Adam7 repeatability: passed.
- Both repeat maps matched the initial Adam7 map.

| Seed case | Coverage tuples |
|---|---:|
| valid_png | 505 |
| adam7_png | 552 |
| malformed_png | 190 |
| truncated_png | 509 |
| width_limit | 276 |
| height_limit | 276 |
| pixel_limit | 322 |
| row_boundary | 505 |
| chunk_allocation_limit | 562 |
| chunk_cache_limit | 625 |

Initial Adam7 map SHA-256:

`e4487f9cda4ff43ac5545a897b1764914c4b8540772802ec8db5e3168104433d`

Both repeat maps had the same SHA-256.

These tuple counts describe AFL++ map output for this build and configuration. They are not source-line or function coverage percentages.

## 7. Implemented safety boundaries

- Subprocesses use argument arrays and `shell=False`.
- Inherited AFL environment variables are removed during coverage execution.
- Process output is redirected to temporary files with an 8 MiB per-stream limit.
- Captured diagnostic output is bounded.
- Coverage maps are limited to 8 MiB and checked as regular files.
- Coverage execution uses the configured 512 MiB memory limit and 1,000 ms target timeout.
- Temporary coverage maps are stored outside the repository.
- Original seed files are not intentionally modified.
- Coverage validation refuses to run as root.

## 8. Campaign orchestration implementation and verification

The campaign manager is implemented and automated-test verified.

Implemented behavior:

- Runs preflight, build-provenance, harness-smoke and coverage gates before campaign launch.
- Builds a fixed single-worker AFL++ argument array without shell execution or arbitrary commands.
- Creates a unique campaign directory outside the repository and target source tree.
- Records adapter configuration, validation reports, tool version, limits, command, timestamps, PID, exit status and final state in `campaign.json`.
- Captures stdout and stderr in separate bounded logs.
- Applies the configured AFL++ duration, target memory, execution timeout and generated-input limits.
- Uses an external watchdog and process-group signal escalation.
- Records completed, failed and interrupted states.
- Stops the process group if PID metadata cannot be persisted.

The installed AFL++ 4.33c build reported a maximum `-G` value of 1,048,576 bytes. The campaign command builder now caps generated inputs at 1 MiB while retaining the adapter's 8 MiB harness input limit. The command-builder test verifies both values.

The configured campaign duration is 300 seconds, with a 330-second external watchdog. AFL++'s `-m 512` is its target-process memory limit, not a hard cap on total fuzzer-process memory.

### Safe integration verification

All four real validation gates passed together while the actual campaign launcher was mocked. This verified the validation sequence without starting AFL++.

### First live launch attempt

- Campaign ID: `campaign-20261111T142331Z-39b29367416b`
- Result: failed, exit code 1.
- AFL++ rejected `-G 8388608` because the installed build supports at most 1,048,576.
- The process exited before creating the AFL output directory.
- No fuzzing activity or target crash is claimed from this attempt.
- The failed campaign metadata and logs are preserved outside the repository.

After that attempt, the command builder was corrected to cap `-G` at 1 MiB. The complete regression suite later passed 100/100, and the safe integration check passed again with the real campaign launch blocked.

This earlier status was superseded by the successful live campaign and sanitizer replay recorded in Section 9.

## 9. Final Phase 2 acceptance results - 2026-11-11

**Phase 2 is complete for the libpng 1.6.59 adapter.**

### Clean build and validation
- Adapter-driven clean build completed successfully.
- All four validation gates passed.
- Harness smoke: 13/13 cases passed.
- Coverage: 10 distinct seed maps; Adam7 repeatability passed.
- Full automated regression suite: 100/100 passed.

### Live AFL++ campaign
- Campaign: `campaign-20261111T165629Z-a5b8f194db6d`
- Duration: 300 seconds; exit code 0.
- Executions: 365,986; speed: 1,219.94/sec.
- New corpus entries: 328; final queue: 338 files.
- Bitmap coverage: 5.06%; stability: 100%.
- Saved crashes: 0; saved hangs: 0.
- Completed cycles: 0. The campaign stopped at its configured time limit.

### Independent sanitizer replay
- ASan+UBSan replay: 338/338 retained inputs passed.
- Sanitizer diagnostics: 0; non-zero exits: 0; timeouts: 0; anomalies: 0.
- Replay report: `~/kekkai-work/verification/libpng-harness/afl-corpus-asan-ubsan-20261111-campaign-20261111T165629Z-a5b8f194db6d/results.tsv`

### Limitations
- Sanitizer replay covered retained queue inputs, not every fuzzing execution.
- System zlib was not rebuilt with sanitizers.
- Zero saved crashes does not establish absence of vulnerabilities.
- This acceptance applies only to the libpng 1.6.59 adapter.

No files were staged, committed or pushed.
