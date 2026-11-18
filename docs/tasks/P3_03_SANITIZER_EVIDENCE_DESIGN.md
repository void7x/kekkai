# P3-03 Design: Bounded ASan/UBSan Evidence Collection

**Status:** Draft; pending one independent read-only design review and project-owner approval.  
**Base:** `development` at `64db5c3050fd68ac601dd189b89b1c6e3f574e0e`  
**Feature branch:** `feature/p3-03-sanitizer-evidence`  
**Scope:** Build one verified ASan+UBSan diagnostic profile for the pinned libpng 1.6.59 adapter, execute one selected imported AFL observation once, and preserve the result as immutable evidence.  
**Dependencies:** P3-01 evidence store and P3-02 AFL observation ingestion. No new third-party runtime dependency is proposed.

## 1. Goal

Collect reproducible sanitizer evidence for one existing P3-02 observation without changing its original testcase or campaign record.

A successful collection records:

1. The exact separately built ASan+UBSan diagnostic build and its verified provenance.
2. The exact original testcase artifact selected by observation UID.
3. The command, fixed sanitizer environment, start/end time, process exit code or terminating signal, timeout/interruption state and output-truncation state.
4. The raw stdout and stderr as immutable content-addressed artifacts.
5. A conservative indication of whether a recognized sanitizer report signature appeared in the captured output.

A sanitizer report signature is evidence to review, not a confirmed defect or vulnerability. A run with no recognized signature is not proof that the input is safe or that no defect exists.

## 2. Current-code findings

- P3-01 provides immutable content-addressed artifacts, immutable observations, target/version/build/campaign foreign keys, and build roles `fuzz`, `diagnostic_replay` and `control`.
- P3-02 imports only terminal schema-v2 AFL++ campaign crashes and hangs. Each observation links to the original testcase artifact and the exact fuzz build and campaign.
- The current `observations` table intentionally models AFL crash/hang facts. It has no sanitizer execution result, raw diagnostic output or diagnostic-build link.
- The current AFL build profile uses `afl-clang-fast` with UBSan trap mode. It is not the ASan+UBSan diagnostic profile and must not be reused as one.
- The Phase 2 verification record documents an earlier separate ASan+UBSan build and retained-corpus replay. That manual run did not create P3-03-compatible per-observation database records or a reusable machine-readable execution manifest.
- The evidence migration framework is checksum-pinned, transactional and backs up an existing database before applying a new migration.

## 3. Scope and explicit boundaries

### In scope

- One fixed libpng 1.6.59 diagnostic build using ordinary Clang, not AFL++ compiler wrappers.
- A one-observation, one-process diagnostic execution selected by an existing P3-02 `observation_uid`.
- A new immutable database record for each execution attempt.
- Preservation of both process output streams as evidence artifacts.
- Conservative recognition of AddressSanitizer, LeakSanitizer and UndefinedBehaviorSanitizer report signatures.
- Resource, filesystem, process-lifecycle, provenance and migration checks.
- Unit and integration tests for success, failure, timeout, interruption, truncation, malformed evidence and retry behavior.

### Out of scope

- Starting AFL++, importing queue entries, or importing schema-v1 campaigns.
- Replaying every observation automatically or running parallel replay workers.
- Replaying queue entries that were not imported as P3-02 observations.
- General-purpose replay across arbitrary commands, targets, versions or build profiles.
- Multiple-attempt reproduction policy, cross-version comparison, minimization, crash grouping or root-cause analysis.
- CASR, symbolication pipelines, UI, networking, AI, or a new runtime dependency.
- Any vulnerability, severity, exploitability or fixed/not-fixed verdict.

P3-03 provides a narrow diagnostic execution primitive only. P3-04 remains responsible for the broader reproduction/replay engine.

## 4. Operator interface

Provide two fixed-purpose commands:

- Build: `scripts/build_libpng_diagnostic.py --config targets/libpng/adapter.toml --project-root <absolute-repository-path> --build-dir <absolute-clean-build-path>`
- Collect one observation: `scripts/collect_sanitizer_evidence.py --evidence-root <absolute-evidence-root> --diagnostic-build-dir <absolute-build-path> --observation-uid <obs-uid>`

The build directory must be new, user-owned, non-symlinked and outside the repository, target source, campaign output, and evidence-store roots. It must not overlap the existing AFL build directory. Build output and temporary execution input remain outside Git.

The collection command accepts one valid observation UID and one verified diagnostic build. It does not accept a user-supplied executable, shell command, environment override, arbitrary argument list, input path or timeout override. The target binary and original input are derived from verified build and evidence-store records.

If the evidence database contains no imported P3-02 observations, collection reports that no eligible observation exists. It must not fabricate a testcase or use an AFL queue entry as a crash/hang observation.

## 5. Diagnostic build contract

Use a separate clean CMake/Ninja build directory for the same authenticated libpng 1.6.59 source tree and the repository-owned harness.

- Compiler: the installed ordinary `/usr/bin/clang` (not `afl-clang-fast`); record the resolved executable path and exact version output.
- CMake build type: `RelWithDebInfo`.
- Compile every libpng translation unit and the harness with `-fsanitize=address,undefined -fno-omit-frame-pointer -g`.
- Link the harness with `-fsanitize=address,undefined` using Clang as the final linker driver so the sanitizer runtimes are linked.
- Do not set `AFL_USE_UBSAN`, `AFL_USE_ASAN` or AFL instrumentation options in this profile.
- Retain the current libpng build options, generated-header feature checks, harness source identity, pinned source archive/tree identity and system zlib 1.3.1 resolution.
- System zlib remains an uninstrumented external dependency and must be stated in the build metadata and report.
- Record a separate profile identifier such as `libpng-asan-ubsan`, `build_role='diagnostic_replay'`, the exact compiler/tool versions, CMake cache, compile database, harness/library hashes, commands, environment and terminal build state in schema-v2 `build.json`.
- Verify all 17 libpng compile-database entries contain the ASan+UBSan instrumentation flags; verify the harness compile/link command contains the same sanitizer set and frame-pointer/debug flags; verify the executable and all expected build artifacts are regular files with recorded hashes.
- Reject an existing build directory. A change in source, compiler, flags or sanitizer profile requires a new clean build directory.

The diagnostic build must be verified independently. Do not accept a directory merely because it contains a file named `kekkai_png_harness`.

## 6. One-observation execution contract

Before launching the process:

1. Open the evidence store using the existing protections and verify the store and selected artifact.
2. Resolve the observation UID to its row, source campaign, source fuzz build and original artifact. Require the observation, campaign and source build to agree on target/version/build/campaign identity.
3. Require the source build role to be `fuzz`, the diagnostic build role to be `diagnostic_replay`, and both builds to identify the same libpng target version and authenticated source-tree identity.
4. Verify the diagnostic build metadata digest and the executable hash against the registered build record.
5. Require the original artifact to be a verified regular content-addressed object and no larger than the originating campaign's recorded `max_input_bytes` (the current adapter limit is 8 MiB).
6. Verify all evidence/build/temp paths are outside the repository and do not overlap each other or protected source/campaign paths.

Materialize only the selected original artifact into a new private, mode-0700 temporary directory outside the repository/evidence root. Verify the materialized bytes against the observation's artifact SHA-256 before execution. Never modify the original campaign file or the immutable evidence-store object.

Launch only the verified harness binary with the temporary testcase path as its single input argument. Use an argument array, `shell=False`, a minimal fixed environment and a new process session. Record the exact command and environment. The environment must explicitly set:

- `ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1`
- `UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1`
- a minimal deterministic `PATH` and `LC_ALL=C`

No inherited `LD_PRELOAD`, AFL variables, user-provided environment or shell expansion is permitted. If the approved symbolizer path is available, verify and record it before adding `ASAN_SYMBOLIZER_PATH`; otherwise preserve raw output and record that symbolization was unavailable. Never discard raw output after symbolization.

Use one process per invocation. Apply a fixed wall-clock watchdog (5 seconds), a CPU-time limit (3 seconds), a private temporary directory and the existing process-group TERM/KILL cleanup mechanism. Capture stdout and stderr separately, retaining at most 8 MiB per stream and recording whether either stream was truncated. Continue draining after the retention limit so a child cannot block on a full pipe.

### ASan address-space and memory-limit requirement

Do not apply `RLIMIT_AS` to the ASan process. ASan reserves a large virtual-address range on 64-bit systems, so an address-space limit can reject ASan's shadow mapping even when actual resident-memory use is small.

Before launch, require a usable cgroup v2 memory boundary for the diagnostic child. The implementation must use an existing delegated/private child cgroup with a finite `memory.max` no greater than the approved 1 GiB ceiling, and must verify the limit is active for the launched process. It must not require root, modify a parent/system cgroup, disable host security controls or silently continue without the memory ceiling. If safe cgroup setup or verification is unavailable, refuse the execution before launching the harness and preserve a clear blocked result; do not substitute `RLIMIT_AS` or an unbounded run.

The exact cgroup delegation and cleanup approach must be checked on the user's WSL 2 environment during implementation. This is a design gate, not an assumption that the current WSL environment already provides delegation.

## 7. Sanitizer output interpretation

Preserve raw bytes from stdout and stderr. Do not trust decoded text, a process exit code or a signal alone as a sanitizer diagnosis.

The initial bounded classifier recognizes only these report signatures:

- AddressSanitizer: `ERROR: AddressSanitizer:`
- LeakSanitizer: `ERROR: LeakSanitizer:`
- UndefinedBehaviorSanitizer: the Clang UBSan `runtime error:` diagnostic marker.

Store the matching family names as a sorted canonical JSON array. Treat these matches as report signatures observed in process output, not proof that the target contains a security defect. A future parser may extract structured stack frames, but P3-03 must retain and cite the raw logs as the authoritative evidence.

Use a separate assessment field:

- `report_signature_observed`: at least one recognized marker is present in the retained output. This remains a candidate report for review.
- `no_signature_observed`: process exited with code 0 and neither stream was truncated.
- `inconclusive`: timeout, interruption, launch failure, non-zero exit without a recognized marker, signal without a recognized marker, or truncated output without a recognized marker.

A signal or non-zero exit without a recognized sanitizer signature is not relabeled as an ASan/UBSan finding. A recognized signature remains report evidence even if the process later times out or its output is truncated. No-report status means only that this one execution produced no recognized signature in complete captured output.

## 8. Database extension

Add checksum-pinned migration `002_sanitizer_runs.sql`. Do not alter migration 001 or rewrite existing targets, builds, campaigns, artifacts or observations.

Add immutable table `sanitizer_runs` with at least:

- generated `run_uid` (unique, fixed-format identifier);
- `target_id`, `target_version_id`, `source_build_id`, `campaign_id` and `observation_id`;
- `diagnostic_build_id`;
- `original_artifact_id`, `stdout_artifact_id` and `stderr_artifact_id`;
- exact `command_json` and fixed `environment_json`;
- execution status (`exited`, `signaled`, `timed_out`, `interrupted`, `launch_failed`);
- nullable exit code and terminating signal, with checks preventing contradictory values;
- sorted `sanitizer_families_json` and the assessment from Section 7;
- stdout/stderr truncation flags;
- normalized UTC start, end and record timestamps.

Use composite foreign keys to prove that the source observation belongs to the recorded source build, target/version and campaign, and that the diagnostic build belongs to the same target/version. Add an insert trigger that rejects a source build whose role is not `fuzz`, a diagnostic build whose role is not `diagnostic_replay` or whose state is not `completed`, and an original artifact that differs from the observation's original artifact. Add update/delete prevention triggers for sanitizer-run rows. Logs reference the existing immutable `artifacts` table; do not store unbounded text blobs in SQLite.

Each invocation is a distinct immutable attempt with a fresh UID. A retry creates another row and never overwrites or reclassifies an earlier run. Do not add a general finding or vulnerability status to this table.

Update `engine/evidence/migrations.py` with the exact SHA-256 of migration 002 and contiguous version metadata. Preserve the existing checksum for migration 001. The existing migration system must create and verify its pre-migration backup before applying migration 002.

## 9. Artifact publication and transaction ordering

1. Validate the database observation, campaign, both builds, source identities, input artifact, paths and resource gates before launching the target.
2. Execute the one fixed process and capture bounded stdout/stderr files.
3. Publish stdout and stderr through `EvidenceStore` as content-addressed artifacts. Empty streams are valid artifacts. Verify their returned size and SHA-256.
4. Recheck build metadata, executable identity, source input digest and output snapshots before database commit.
5. In one SQLite `BEGIN IMMEDIATE` transaction, register/reuse the diagnostic build, register/reuse both log artifacts, and insert the immutable `sanitizer_runs` row.
6. If artifact publication succeeds but the database transaction fails, leave the content-addressed objects intact as detectable orphans. Retry is a new attempt; do not delete or rewrite any published object.
7. Close the database and clean the private temporary input, output staging files and delegated cgroup in all paths. Cleanup failure must be surfaced and recorded without deleting evidence.

The original AFL testcase, P3-02 observation, campaign metadata, fuzz build and prior sanitizer runs are never updated or deleted.

## 10. Expected modules and files

Expected focused changes (subject to design review):

- `engine/build/diagnostic.py`: fixed diagnostic build plan and strict output verification.
- `engine/build/runner.py`: only the minimal shared runner integration required for the separate diagnostic role; do not weaken AFL build verification.
- `engine/evidence/sql/002_sanitizer_runs.sql`: additive table, constraints, foreign keys and immutability triggers.
- `engine/evidence/migrations.py`: register checksum-pinned migration 002.
- `engine/evidence/repository.py`: typed immutable insertion/query helpers for sanitizer-run rows.
- `engine/evidence/sanitizer.py`: strict observation/build validation, one-shot execution, output classification and evidence publication.
- `scripts/build_libpng_diagnostic.py` and `scripts/collect_sanitizer_evidence.py`: fixed operator entry points.
- `tests/test_diagnostic_build.py`, `tests/test_sanitizer_evidence.py`, and migration/repository tests as needed.
- `docs/tasks/P3_03_SANITIZER_EVIDENCE_DESIGN.md`: this decision record, updated after review and implementation.

Do not refactor the AFL campaign runner, generic process layer, P3-02 importer or existing migration 001 unless the review identifies a specific necessary correction.

## 11. Acceptance checks

### Diagnostic build

- Clean build uses the pinned libpng archive/source identity and exact repository harness.
- All 17 libpng translation units and the harness are verified as ASan+UBSan instrumented.
- Final harness link includes the corresponding ASan+UBSan runtimes.
- Build role/profile, compiler, flags, zlib limitation, commands, environment, timestamps and artifact hashes are recorded in schema-v2 build metadata.
- AFL instrumentation and UBSan trap mode are absent from this diagnostic profile.
- A second build attempt refuses to overwrite the existing build directory.

### Collection and evidence

- Only an existing P3-02 observation UID can be selected.
- Original artifact bytes are re-hashed before execution; source campaign and database evidence remain unchanged.
- Only the verified diagnostic harness is executed; no shell, arbitrary command or inherited user environment is accepted.
- Cgroup-v2 memory gate, wall timeout, CPU limit, output caps and process-group cleanup are enforced.
- Exit code, signal, timeout/interruption, stdout/stderr truncation, recognized report family and assessment are recorded without conflating them.
- Stdout/stderr are stored as verified immutable content-addressed artifacts.
- A sanitizer run links to the same observation, source fuzz build, target/version and campaign, plus a completed diagnostic build for that target/version.
- Repeated runs create separate immutable records. Database failure leaves no partial relational rows; already published log objects remain detectable as orphans.
- Missing observations, invalid build provenance, changed artifacts, symlinks, special files, oversized input/output, absent cgroup delegation, timeout, interruption and malformed output paths fail safely.

### Regression and migrations

- Migration 001 checksum and applied history remain unchanged.
- Migration 002 is checksum-pinned, transactional, backed up, and tested on an existing P3-01/P3-02 database.
- Foreign-key, role, immutability and contradictory process-state constraints are tested.
- Existing P3-01 and P3-02 tests remain green on Python 3.11 and 3.14.
- A real diagnostic build and one real imported-observation run are performed only when the required pinned source/build material, an imported observation and the cgroup memory gate are available. Otherwise the blocked condition is recorded; mocks are not presented as real sanitizer evidence.

## 12. Review questions and risk focus

The independent read-only reviewer should focus especially on:

1. Whether the one-observation diagnostic execution is correctly separated from P3-04's general replay engine.
2. Whether the additive relational design has sound composite foreign keys, role checks, immutability and retry behavior.
3. Whether the build verifier proves every libpng unit and the harness are actually ASan+UBSan-instrumented and does not reuse AFL build products.
4. Whether the cgroup-v2 gate is technically enforceable in unprivileged WSL 2 and whether its refusal behavior is safe and practical.
5. Whether output signature classification avoids treating arbitrary stderr, exit codes or signals as confirmed sanitizer findings.
6. Whether log limits, process termination, artifact publication, migration backup and orphan recovery are sufficient.
7. Any required blockers separately from optional improvements.

Return one verdict: **APPROVED FOR IMPLEMENTATION**, **APPROVED WITH LIMITATIONS**, or **CHANGES REQUIRED**. Cite exact files/lines and verified assumptions. Do not edit code, tests, configuration or documentation; do not create/switch branches, commit, push, merge, open or update pull requests, change repository settings, or access secrets. Review access must remain read-only.

## 13. References

- Project workflow and mandatory gates: `docs/WORKFLOW_DECISIONS.md`, Sections 8, 9 and 11.
- Phase 3 roadmap: `docs/DEVELOPMENT_PLAN.md`.
- Prior diagnostic build/replay record: `docs/tasks/LIBPNG_AFL_BUILD_VERIFICATION.md`.
- P3-02 observation and provenance contract: `docs/tasks/P3_02_AFL_EVIDENCE_INGESTION_DESIGN.md`.
- Clang 21.1.0 AddressSanitizer build, runtime and report-symbolization guidance: https://releases.llvm.org/21.1.0/tools/clang/docs/AddressSanitizer.html
- Clang 21.1.0 UndefinedBehaviorSanitizer flags and runtime-report behavior: https://releases.llvm.org/21.1.0/tools/clang/docs/UndefinedBehaviorSanitizer.html
- AFL++ ASan memory/address-space caveats and corpus-replay guidance: https://aflplus.plus/docs/notes_for_asan/
