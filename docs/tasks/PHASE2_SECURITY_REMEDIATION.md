# Phase 2 Security and Reliability Remediation Verification

**Implementation started:** 2026-11-12
**Report updated:** 2026-11-18
**Working branch:** `fix/phase2-security-remediation`
**Base commit:** `5883c98a9e383daf40045440d456c5afe222a94d`
**State:** Independently audited and **APPROVED WITH ACCEPTED LIMITATIONS** for the initial libpng 1.6.59 pilot. Documentation closeout is recorded on `fix/phase2-security-remediation`; integration into `development` is proposed by pull request and has not yet occurred.

> Independent audit: read-only review of implementation commit `a55326e0a58680895ce82de5b0b2b3056f8f1669` on 2026-11-18. Verdict: **APPROVED WITH ACCEPTED LIMITATIONS**; no blocking defects identified. The auditor independently ran Python compilation and all 166 tests (5.872 seconds).
>
> Latest GitHub Actions evidence: run [#44254082914](https://github.com/void7x/kekkai/actions/runs/44254082914), Ubuntu 24.04 / Python 3.11, compilation passed and all 166 tests passed (7.155 seconds). Local WSL checks are recorded in Section 7. No new live AFL++ campaign was launched during the remediation closeout.

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

The following records the final read-only independent auditor assessment of findings P2-001 through P2-009 at implementation commit `a55326e0a58680895ce82de5b0b2b3056f8f1669`. The auditor supplied and reviewed the complete original P2-008 and P2-009 recommendations.

| Finding | Current remediation status | Evidence / remaining qualification |
|---|---|---|
| P2-001: storage ownership and permissions | Implemented | The mounted filesystem root must be current-user-owned with mode 0700. The backing image must be current-user-owned with private mode 0600. Failed-build archive roots are checked for ownership and mode. Storage and recovery regression tests pass. |
| P2-002: symlink handling across configured paths | Implemented with residual path-race limitation | Symlink components are checked for all configured path fields before resolution. Tests cover the source, archive, harness source/binary, seed directory, build directory, campaign storage image and output parent. Path-based checks remain subject to TOCTOU races, as documented. |
| P2-003: process interruption and lifecycle | Implemented and regression-tested | The process registry checks interruption before child launch, applies per-group grace periods, handles registration races, and propagates managed-process SIGTERM interruption. Build and campaign integration tests pass. |
| P2-004: storage mount helper | Implemented | The helper uses isolated Python invocation, quoted heredocs and argument passing; validates the image and paths before privileged loop/mount operations; then applies private mountpoint ownership and mode and verifies the result. |
| P2-005: campaign metadata durability | Implemented | Metadata writes flush and fsync the temporary file, atomically replace the destination and fsync the containing directory. Initial, intermediate and final write failures are handled explicitly. |
| P2-006: smoke fixture semantic checks | **Partially resolved; accepted as non-blocking by the auditor** | The malformed tEXt separator, per-info-structure chunk-cache count and pixel-limit fixture semantics were corrected and regression-tested. Remaining polish: smoke execution checks expected exit codes but does not assert the expected stderr diagnostic text for valid PNG cases; width-limit and height-limit fixtures verify the exceeded dimension but do not fully assert all IHDR fields. |
| P2-007: build provenance validation | **Resolved** | Provenance inputs are size-bounded, hashes are computed from the bounded bytes, recorded build commands are checked, and AFL++ version is compared with adapter configuration. Schema-1 harness source/binary reads are bounded. Tests use isolated fake tool executables rather than assuming host AFL++ is installed. |
| P2-008: failed-build archive path/ownership and harness-source path | **Partially resolved; accepted as non-blocking by the auditor** | Failed-build archive root overlap, symlink, directory type, ownership and mode checks are present and regression-tested. Remaining polish: `verify_build_outputs()` still derives the harness source path from `__file__` rather than accepting the configured `config.target.harness_source`. Build planning and the provenance verifier also validate the configured harness source, which mitigates the issue for the current adapter. |
| P2-009: coverage-map validation and output handling | **Partially resolved; accepted as non-blocking by the auditor** | Coverage-map locations are normalized before duplicate detection, map reads are no-follow and size-bounded, and the coverage truncation marker uses a real newline. Remaining polish: four campaign error strings still contain literal `\\n` sequences; coverage version probing reads the tail of `afl-showmap -h` output, which is sufficient for the current AFL++ 4.33c banner (~1.6 KiB) but fragile for longer output; the coverage temp-directory overlap check is one-directional and does not match the bidirectional check used by smoke validation. |

**Closeout status:** The independent auditor returned **APPROVED WITH ACCEPTED LIMITATIONS** and identified no blocking defects. P2-006, P2-008 and P2-009 remain partially resolved with specific non-blocking follow-ups above. Phase 2 is approved for integration into `development` after pull-request review. Do not describe these three findings as fully resolved.

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

**Latest GitHub Actions result:** 166 tests passed, 0 failures, 0 errors (7.155 seconds) in run [#44254082914](https://github.com/void7x/kekkai/actions/runs/44254082914), using Python 3.11 on Ubuntu 24.04. Python compilation passed in that workflow.

**Independent auditor verification:** At the exact audited implementation commit, the auditor independently ran Python compilation and all 166 tests (5.872 seconds), with zero failures and zero errors.

**Local WSL verification (2026-11-18):**
- Environment: Ubuntu 26.04.1 LTS.
- Python 3.11.18: compilation passed; 166 tests passed (5.912 seconds).
- Python 3.14.4: compilation passed; 166 tests passed (6.805 seconds).
- `git diff --check` passed; working tree was clean before the documentation closeout update.

The suite includes external-SIGTERM build and campaign integration tests, failed-build recovery tests, process-group tests, source identity tests and storage verification tests.

### Real build and validation evidence

The existing authenticated libpng 1.6.59 build was independently re-verified locally in WSL on 2026-11-18; no rebuild was necessary.

**Build provenance: PASS.** The configured source archive and extracted tree matched their pinned identities; build metadata matched the adapter and target; all three recorded build steps were complete; all six recorded artifact hashes matched; the CMake configuration, 17 compile-database translation units, compiler, AFL++ and zlib versions matched the expected configuration.

**Adapter preflight: PASS.** The source version, harness source and binary, input-size limit, 10-file seed corpus, external output path, authenticated campaign storage and AFL++ 4.33c were verified.

**Campaign storage: PASS.** The 4 GiB ext4 image UUID and loop-device backing file matched. The image was changed from mode 0644 to the required 0600 only after its UUID and user ownership were confirmed. The mounted ext4 root was verified as current-user-owned with mode 0700 and required `nodev,nosuid,noexec` mount options. The observed device was `/dev/loop0`; capacity was 4,143,677,440 bytes and available space was 3,911,081,984 bytes at verification time.

**Harness smoke: PASS.** 13 cases passed, 0 failures.

**AFL++ coverage: PASS.** All 10 seed maps were non-empty, valid and distinct. AFL++ tuple counts were `505, 552, 190, 509, 276, 276, 322, 505, 562, 625`. Both Adam7 repeat runs produced 552 tuples and identical map SHA-256 values.

The coverage tuple counts are AFL++ map feedback for this build/configuration. They are not source-line or function coverage percentages. Preflight separately reports smoke, coverage and build provenance as `NOT_RUN` by design; those gates were run separately and passed.

The smoke runner validates the 10 original fixtures before execution. It checks PNG signatures, IHDR metadata, chunk boundaries and CRCs, IEND or intentional truncation, interlace mode and applicable decompressed scanline structure, dimensions/pixel/row-byte bounds, oversized text chunks and chunk-cache count. Bounded decompression rejects decompression-bomb input. Regression tests reject invalid fixture metadata and corrupted CRCs before harness execution.

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

**Independent verdict (2026-11-18): APPROVED WITH ACCEPTED LIMITATIONS.**

The independent auditor reviewed the exact implementation commit `a55326e0a58680895ce82de5b0b2b3056f8f1669`, recovered the complete original P2-008 and P2-009 recommendations, inspected the implementation and regression tests, and found no blocking defects. The auditor independently compiled the Python sources and passed all 166 tests.

The auditor classified P2-001 through P2-005 and P2-007 as resolved. P2-006, P2-008 and P2-009 remain partially resolved with the non-blocking follow-ups recorded in Section 2A. The accepted architectural and operational limitations are recorded in Section 8 and remain visible.

The implementation and local verification cover the initial libpng 1.6.59 Phase 2 pilot: strict adapter configuration, authenticated source/build provenance, native build orchestration, harness smoke/coverage validation, bounded campaign storage, controlled process lifecycle and non-destructive failed-build recovery. This does not mean KEKKAI's later roadmap capabilities are complete. Source intelligence, broader target adapters, advanced multi-worker fuzzing, persistent mode, differential version analysis, SQLite-backed crash intelligence, dashboard and optional AI remain later phases.

**Integration status:** Approved for integration into `development` through pull-request review. This report update does not merge the branch. `main` remains untouched.

## 10. Repository hygiene

One-time patch scripts and rollback support files are development artifacts, not KEKKAI runtime components. They must remain outside the repository and must not be added to project commits. The remediation commits contain only the reviewed source, tests, CI workflow and documentation changes.

## 11. Change-control state

- Audited implementation commit: `a55326e0a58680895ce82de5b0b2b3056f8f1669` on `fix/phase2-security-remediation`.
- The independent audit was read-only and returned **APPROVED WITH ACCEPTED LIMITATIONS**.
- Phase 2 documentation closeout is recorded in this branch; the documentation changes do not alter the audited implementation code.
- The branch is proposed for integration into `development` via pull request. It has not been merged.
- `main` remains untouched.
- No Phase 3 implementation work was started and no new live AFL++ campaign was launched.
- P2-006, P2-008 and P2-009 retain the non-blocking follow-up items listed in Section 2A.
