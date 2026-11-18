# Phase 2 Security and Reliability Remediation Verification

**Implementation started:** 2026-11-12
**Report updated:** 2026-11-18
**Working branch:** `fix/phase2-security-remediation`
**Base commit:** `5883c98a9e383daf40045440d456c5afe222a94d`
**State:** Implemented, committed and pushed to `fix/phase2-security-remediation`. Not merged.

> Verification note: GitHub Actions run [#44253310644](https://github.com/void7x/kekkai/actions/runs/44253310644), on Ubuntu 24.04 with Python 3.11, compiled the Python sources and passed all 166 unit and integration tests (5.767 seconds). This automated run does not claim a new native build, coverage validation, or live AFL++ campaign.

## 1. Scope and change control

This report records the Phase 2 security and reliability remediation for the initial libpng 1.6.59 pilot. It separates implemented controls, test evidence and residual limitations.

Implementation changes are committed and pushed on `fix/phase2-security-remediation`. The `main`, `development` and original feature branches were not modified. No merge was performed. No new AFL++ campaign was launched as part of this remediation.

## 2. Remediation status

| Finding | Current status | Implementation and evidence |
|---|---|---|
| F-01: source authenticity | Implemented; source-tree TOCTOU limitation remains | The libpng 1.6.59 archive is SHA-256 pinned. Tar entries are inspected defensively; unsafe paths, duplicate entries, links, special files and excessive entry/file sizes are rejected. The extracted tree is compared by path, type, size, executable bit and content hash. |
| F-02: build reuse provenance | Implemented; filesystem and tool trust limitations remain | Build metadata schema version 2 records source archive/tree identity and build details. Reuse verification checks source identity, build steps, environment/configuration and six artifact hashes, including CMake and toolchain details. |
| F-03: SIGTERM process cleanup | Implemented and integration-tested | The shared process-group registry handles SIGTERM and stops registered groups. External-SIGTERM integration tests cover both build and campaign orchestrators, descendant cleanup and final interrupted metadata. |
| F-04: root execution | Implemented and tested | Public build and campaign entry points reject root before build planning or campaign setup. Smoke and coverage retain their root checks. |
| F-05: symlink/path handling | Improved and tested; path-check TOCTOU limitation remains | Configuration checks relevant path components for symlinks; source archive/tree validation and recovery reject symlinked paths and unsafe archive entries. Some checks still use path-based check-then-open operations. |
| F-06: inherited environment and tool lookup | Implemented with an explicit system-tool trust boundary | Tool lookup uses `os.defpath`; subprocesses receive controlled environments and argument arrays without shell execution. Version probes and output are bounded. Tool binaries are not cryptographically pinned. |
| F-07: total campaign storage | Implemented for the libpng pilot with an enforced filesystem ceiling; no per-campaign reservations | The adapter writes to a dedicated, verified ext4 filesystem backed by an exact 4 GiB image. The storage verifier checks the expected UUID, mountpoint, backing image, ownership, permissions and mount options. Filesystem capacity bounds aggregate campaign storage on this mount. |
| F-08: failed-build recovery | Implemented as a manual, non-destructive operator workflow | The recovery CLI validates eligible failed/interrupted build metadata and paths, then archives the build directory without overwriting an existing archive. A recovery manifest is published atomically. Original logs and partial outputs are preserved. Automatic retry/restart/cleanup is not implemented. |
| N-01: descendants after normal leader exit | Implemented and tested | Process-group liveness checks detect surviving non-zombie members and stop them after the leader exits. |
| N-02: timeout descendant cleanup | Implemented and tested | The process-group runner cleans descendants after timeout and interruption; build and campaign use registered process groups. |
| N-03: artifact-size mismatch | Implemented and tested | Build and provenance verification share a 16 MiB artifact limit. Regression coverage rejects oversized artifacts. |
| N-04: fixture semantic validity | Implemented and tested for the current libpng fixtures | Fixture validation checks PNG structure, CRCs, dimensions, interlacing, row sizes, chunk limits and image-data properties before harness execution. All 10 original fixtures passed validation. |

## 2A. Independent audit findings: implementation and regression status

The following records the current code-review status for findings P2-001 through P2-009. It is an implementation-status summary, not an independent auditor's final acceptance.

| Finding | Current remediation status | Evidence / remaining qualification |
|---|---|---|
| P2-001: storage ownership and permissions | Implemented | The mounted filesystem root must be current-user-owned with mode 0700. The backing image must be current-user-owned with private mode 0600. Failed-build archive roots are checked for ownership and mode. Storage and recovery regression tests pass. |
| P2-002: symlink handling across configured paths | Implemented with residual path-race limitation | Symlink components are checked for all configured path fields before resolution. Tests cover the source, archive, harness source/binary, seed directory, build directory, campaign storage image and output parent. Path-based checks remain subject to TOCTOU races, as documented. |
| P2-003: process interruption and lifecycle | Implemented and regression-tested | The process registry checks interruption before child launch, applies per-group grace periods, handles registration races, and propagates managed-process SIGTERM interruption. Build and campaign integration tests pass. |
| P2-004: storage mount helper | Implemented | The helper uses isolated Python invocation, quoted heredocs and argument passing; validates the image and paths before privileged loop/mount operations; then applies private mountpoint ownership and mode and verifies the result. |
| P2-005: campaign metadata durability | Implemented | Metadata writes flush and fsync the temporary file, atomically replace the destination and fsync the containing directory. Initial, intermediate and final write failures are handled explicitly. |
| P2-006: smoke fixture semantic checks | Implemented and regression-tested | PNG text separators, chunk-cache limits and pixel/dimension limits are checked. Harness diagnostics are captured and reported. Fixture and smoke regression tests pass. |
| P2-007: build provenance validation | Implemented and regression-tested | Provenance inputs are size-bounded, hashes are computed from the bounded bytes, recorded build commands are checked, and AFL++ version is compared with adapter configuration. CI tests use an isolated fake AFL++ executable rather than assuming a host package is installed. |
| P2-008: failed-build archive path/ownership | Implemented and regression-tested | Archive-root path overlap, symlink, directory type, ownership and mode checks are present. Recovery regression tests cover ownership, permissions and overlap. |
| P2-009: coverage-map validation and output handling | Implemented and regression-tested for the issues identified in the available audit summary | Coverage-map locations are normalized before duplicate detection, map reads are no-follow and size-bounded, and truncated output uses actual line breaks. Coverage regression tests pass. The detailed P2-008/P2-009 recommendation pages were not present in the supplied audit excerpt, so final auditor confirmation remains pending. |

**Closeout status:** The branch now has regression coverage for the identified issues and CI passes. Keep Phase 2 pending until the independent auditor confirms the complete findings, including the full P2-008 and P2-009 details, and the owner completes the remaining local environment checks.

## 3. Source authentication and build provenance

The authenticated source archive SHA-256 is:

`d80dd2a38a37f803cb9b6ac7b14bd6e74ddc3b654780a8380bdf93523fdb4389`

The verified extracted source-tree SHA-256 is:

`907e78ca78b3e4ca59275d62f82522bef402ab3c455c0b4fa67467b7e3aa53a3`

The recorded clean build location is:

`~/kekkai-work/builds/libpng-1.6.59-afl-ubsan-phase2-authenticated`

Build metadata schema version 2 records completed status, all three completed build steps, source archive/tree identity and six artifact hashes. The provenance verifier checks source identity, build identity, harness source and binary hashes, library archive, CMake cache, compile database, generated header, compiler, AFL++ version, zlib version and expected build configuration.

### Residual source-identity limitation

Source verification is point-in-time. The extracted source directory remains mutable between verification and compiler reads. A same-user process could theoretically modify files in that interval. An immutable or isolated authenticated build input would be needed to remove this TOCTOU exposure. Current symlink checks also cannot eliminate races where a path changes after it has been checked.

## 4. Process lifecycle and environment controls

The shared process helper:

- Starts subprocesses in their own sessions/process groups.
- Registers managed groups for SIGTERM cleanup.
- Escalates termination through SIGINT, SIGTERM and SIGKILL.
- Cleans surviving descendants after normal leader exit, timeout and interruption.
- Preserves `check=False` return-code behavior and raises `CalledProcessError` for `check=True` on nonzero exit.

The build integration test sends an external SIGTERM to the real build orchestrator and verifies descendant cleanup and interrupted step/build metadata. The campaign integration test sends an external SIGTERM to the campaign orchestrator and verifies the fuzzer and its descendant stop and the final `campaign.json` records interruption, including an end timestamp and SIGTERM message.

Tool lookup is deterministic through `os.defpath`. Validation subprocesses receive controlled environments; version probes have bounded time/output. Shell execution is not used for these tool invocations.

### Residual process/tool limitations

- An orchestrator killed with SIGKILL cannot execute its cleanup handler.
- Linux `/proc` process-group inspection is the verified path for the WSL/Linux environment.
- Python `preexec_fn` remains a possible deadlock concern if these execution paths are embedded in a multithreaded host process.
- Tool versions and paths are checked, but tool binaries are not cryptographically pinned. System package management and filesystem integrity remain part of the trust boundary.

## 5. Bounded campaign storage (F-07)

The libpng adapter's `output_parent` resolves to:

`/home/sahil/kekkai-work/campaign-storage`

The backing image is:

`/home/sahil/kekkai-work/campaign-quota.ext4`

Expected filesystem UUID:

`e8657221-eb6f-41ca-b087-76912b527e4b`

The image is exactly 4 GiB. The storage verifier checks the expected ext4 filesystem and UUID, exact mountpoint, mount uniqueness, loop-device backing-file identity, ownership, restrictive permissions, absence of unexpected nested mounts and required `nodev,nosuid,noexec` mount options. The adapter configuration was checked to resolve to the verified mountpoint. The observed mount was `/dev/loop0`, with ext4 and the required options.

This provides a hard aggregate filesystem-capacity ceiling for campaign outputs directed to this mount. It is not an application-level per-campaign quota system.

### Residual storage limitations

- There are no per-campaign reservations or allocation budgets.
- There is no configured minimum-free-space reserve threshold.
- A full-filesystem fault-injection test and graceful-stop behavior under `ENOSPC` have not been established by the recorded evidence.
- The storage image must be mounted and verified before a campaign is run. A WSL restart may require remounting it.

## 6. Failed-build recovery (F-08)

The manual recovery entry point is:

`python3 scripts/recover_failed_build.py`

The recovery implementation accepts only eligible terminal failed/interrupted build metadata, validates required metadata fields and paths, rejects symlinked or overlapping paths, and uses a non-overwriting atomic directory move. The recovery archive is created with restrictive permissions. Its manifest records the build metadata SHA-256 and is published atomically without replacing an existing manifest. Existing logs and partial outputs are retained; recovery does not delete the original evidence as a cleanup shortcut.

The CLI help was inspected, and the recovery test module covers failed/interrupted archival, rejection of running/completed builds, metadata/path validation, symlink cases, manifest conflicts, competing writers and collision handling.

### Recovery limitations

- Recovery is a deliberate manual operator action. Automatic retries, restarts and cleanup are not implemented.
- The recovery manifest hashes `build.json`; it does not independently hash every archived artifact.
- The documented default-config invocation assumes the command is run from the repository root; use `--config` when invoking it with another adapter configuration.

## 7. Verification evidence

### Automated tests

Command:

`python3 -m unittest discover -s tests -v`

**Latest verified result: 166 tests passed, 0 failures, 0 errors (5.767 seconds) in GitHub Actions run #44253310644.**

The suite includes the external-SIGTERM build and campaign integration tests, failed-build recovery tests, process-group tests, source identity tests and storage verification tests.

Python compilation (`python -m compileall -q engine tests scripts`) also passed in the same GitHub Actions run. A fresh `git diff --check` was not part of that workflow run.

### Real build and validation evidence

The previously recorded Phase 2 pilot validation includes:

- Authenticated clean libpng build: completed.
- Build provenance: passed.
- Preflight: passed; AFL++ 4.33c resolved as `/usr/bin/afl-fuzz`.
- Harness smoke: 13 cases passed, 0 failures.
- Coverage: 10 seed maps captured, all distinct.
- Adam7 repeatability: both repeat maps matched the initial map.
- AFL-showmap version: 4.33c.

The coverage tuple counts are AFL++ map feedback for this build/configuration. They are not source-line or function coverage percentages. Preflight separately reports smoke, coverage and build provenance as `NOT_RUN` by design; those gates were run separately and passed.

The smoke runner validates all 10 original fixtures before execution. It checks PNG signatures, IHDR metadata, chunk boundaries and CRCs, IEND or intentional truncation, interlace mode and applicable decompressed scanline structure, dimensions/pixel/row-byte bounds, oversized text chunks and chunk-cache count. Bounded decompression rejects decompression-bomb input. Regression tests reject invalid fixture metadata and corrupted CRCs before harness execution.

No new live AFL++ campaign was launched as part of this remediation. The historical 300-second campaign and sanitizer replay remain evidence from the earlier Phase 2 verification; this report does not claim a new campaign result.

## 8. Remaining accepted limitations and future work

1. Build from an immutable authenticated source snapshot to close the source verification TOCTOU window.
2. Consider descriptor-based/no-follow file access where path-based check-then-open races matter.
3. Add per-campaign storage reservations or budgets only if the pilot's requirements need isolation beyond the dedicated filesystem ceiling; separately define low-space and `ENOSPC` behavior.
4. Consider replacing `preexec_fn` if multithreaded-host execution becomes supported.
5. Define a stronger toolchain trust policy, such as pinned tool packages/binaries, if the threat model requires it.
6. Expand recovery integrity manifests to hash individual artifacts if later workflows require independent archive verification.

These limitations do not invalidate the tested initial libpng pilot controls, but they must remain visible and must not be described as solved.

## 9. Final Phase 2 assessment

**Assessment: functionally complete for the initial libpng 1.6.59 pilot, subject to the limitations recorded above and final local closeout checks.**

The implementation covers the Phase 2 pilot workflow: strict adapter configuration, authenticated source/build provenance, native build orchestration, harness smoke/coverage validation, bounded campaign storage, controlled process lifecycle and non-destructive failed-build recovery. This does not mean KEKKAI's later roadmap capabilities are complete. Source intelligence, broader target adapters, advanced multi-worker fuzzing, persistent mode, differential version analysis, SQLite-backed crash intelligence, dashboard and optional AI remain later phases.

## 10. Repository hygiene

One-time patch scripts and rollback support files are development artifacts, not KEKKAI runtime components. They must remain outside the repository and must not be added to project commits. The remediation commits contain only the reviewed source, tests, CI workflow and documentation changes.

## 11. Change-control state

- Remediation code and tests are committed and pushed on `fix/phase2-security-remediation`.
- Current code/test commit before this documentation closeout: `620c36f5d575c9f564917288e34da5a5c16bd79d`.
- No changes were made to `main`, `development` or the original feature branch.
- No merge was performed and no Phase 3 implementation work was started.
- No new fuzzing campaign was launched.
- Independent auditor final confirmation and remaining local environment checks are still required before Phase 2 sign-off.
