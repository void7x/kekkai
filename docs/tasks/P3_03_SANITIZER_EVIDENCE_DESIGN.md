# P3-03 Design: Bounded ASan/UBSan Evidence Collection

**Status:** Owner-approved for implementation. WSL 2 feasibility probes passed for memory, swap, task limits, read-only cgroup controls and descendant cleanup. CPU quota readback remains a pre-execution implementation check.  
**Base:** development at 64db5c3050fd68ac601dd189b89b1c6e3f574e0e  
**Feature branch:** feature/p3-03-sanitizer-evidence  
**Original reviewed draft:** 48ea0ab19467844a997152566e2c8ecca591d067  
**Scope:** Build one verified ASan+UBSan diagnostic profile for pinned libpng 1.6.59, execute one selected imported AFL observation once, and preserve the result as immutable evidence.  
**Dependencies:** P3-01 evidence store and P3-02 AFL observation ingestion. No new third-party runtime dependency is proposed.

## 1. Goal and evidence meaning

Collect reproducible sanitizer evidence for one existing P3-02 observation without changing its original testcase or campaign record.

A successful attempt links the exact diagnostic build, selected observation and original testcase artifact, fixed command and environment, execution and resource-limit facts, and captured stdout/stderr artifacts. A recognized output marker is candidate evidence for review, not a confirmed defect or vulnerability. No recognized marker does not prove that the input is safe or that no defect exists.

## 2. Decisions made after the independent review

The original review identified three blockers. This revision makes these design decisions:

- **B01, bounded execution:** Use only a transient system-managed systemd service with `DynamicUser=yes`, not a per-user service, scope or post-launch PID migration. The system manager creates the service cgroup and applies resource properties before executing the trusted pre-exec guard. The target receives an ephemeral unprivileged UID, no capabilities, `NoNewPrivileges=yes`, and a read-only cgroup view through `ProtectControlGroups=strict`. Any failed or unprovable check blocks execution. `sudo` is used only to ask the system manager to create/inspect/stop the service; the guard and target never run as root.
- **B02, effective instrumentation:** Approve Clang 21.1.8, matching the existing recorded Phase 2 diagnostic build. Verify the exact 17-source set, tokenized compile/link commands, absence of sanitizer overrides, exact archive membership, runtime identity and executable sanitizer behavior. Flag presence alone is insufficient.
- **B03, attempt recovery:** Register a fully verified diagnostic build as completed before collection. Create a durable per-attempt recovery manifest before execution. Distinguish preflight blocks from harness executions, and record capture completeness separately from retention truncation and artifact publication. Preserve unpublished stream data. Complete recordable workload cleanup before inserting the immutable final row.

The systemd approach is conditional, not assumed to work on WSL 2. WSL support for systemd does not prove that the user manager can apply the required resource controllers or that the workload cannot migrate outside the bounded cgroup. The real WSL integration gate in Section 12 is mandatory. There is no unbounded fallback.

## 3. Existing architecture and constraints

- P3-01 provides immutable content-addressed artifacts, immutable observations, target/version/build/campaign relationships, and build roles fuzz, diagnostic_replay and control.
- P3-02 imports terminal schema-v2 AFL++ crashes and hangs. Each observation links to its original testcase artifact, exact fuzz build and campaign.
- The observations table records AFL facts; it does not model sanitizer execution or diagnostic output.
- The AFL build uses afl-clang-fast and UBSan trap mode. It is not the diagnostic profile and must not be reused.
- The prior diagnostic record documents a separate Clang 21.1.8 ASan+UBSan build of all 17 libpng C translation units and the repository harness. The retained 262-entry corpus replay completed without a detected sanitizer report. System zlib 1.3.1 was not instrumented.
- The existing repository supports immutable build registration. The diagnostic build must be registered with completed status before collection starts.
- The migration system is checksum-pinned, transactional and performs a pre-migration backup. Existing orphan detection in the evidence store must be reused. Do not alter migration 001 or the existing migration framework's guarantees.

## 4. Scope and threat boundary

### In scope

- One fixed libpng 1.6.59 diagnostic build using ordinary Clang 21.1.8.
- One harness execution selected by an existing P3-02 observation UID.
- An immutable attempt record for each execution and each recorded preflight block.
- Bounded raw output preservation, sanitizer marker classification and recovery of partial publication.
- Resource, filesystem, provenance, process-lifecycle and migration checks.
- Unit tests plus a separately reported real WSL environment gate.

### Out of scope

- Starting AFL++, importing queue entries, schema-v1 campaigns or unimported testcases.
- Batch or parallel replay, arbitrary targets/commands, P3-04's general replay engine, minimization, grouping, root-cause analysis or vulnerability verdicts.
- UI, networking, AI, CASR, symbolication pipeline or new runtime dependencies.
- Defending the host against an intentional same-UID escape or a successful arbitrary-code-execution exploit in the target.

**Threat model limitation:** WSL 2 is not a security boundary. The fixed local harness and target may crash, hang, fork accidentally or consume resources, but are not treated as deliberately hostile code attempting a kernel/system-manager exploit. The target runs under a systemd `DynamicUser` identity, with no capabilities and a read-only cgroup view. The cgroup is a resource-control boundary, not a hostile-code sandbox. Risky samples or deliberate escape testing require a separately approved isolated VM design. This is consistent with the project's workflow decisions.

P3-03 supplies one narrow diagnostic execution primitive. P3-04 remains responsible for the broader reproduction/replay engine.

## 5. Operator commands and durable attempt staging

Provide two fixed-purpose commands:

- Build a diagnostic profile using the approved adapter, repository root and a new build directory.
- Collect one observation using the evidence root, registered diagnostic-build identifier and one observation UID.

The build directory must be new, user-owned, non-symlinked, outside the repository, source tree, campaign output and evidence root, and distinct from the AFL build directory. Build output and execution input remain outside Git.

The collection command does not accept a user-supplied executable, shell command, environment override, argument list, input path, timeout or resource-limit override. It derives the executable and input from verified build and evidence records.

After validating the selected observation and completed diagnostic build, allocate a fresh lowercase UUIDv4 run UID and create an exclusive attempt directory in a dedicated recovery directory adjacent to, but outside, the evidence-store root. The recovery directory is owned by the current user, non-symlinked, mode 0700, on a filesystem with a verified free-space reserve. Files inside it are mode 0600 and exclusively created. It must not overlap the repository, source tree, campaign or evidence-store objects.

Before launching systemd or the harness, write and fsync a versioned recovery manifest containing run UID, observation UID, diagnostic build ID, original artifact digest, policy identifier, intended command, requested resource limits, attempt timestamps and current state. Atomically update and fsync it as the attempt advances.

Bound the recovery directory by a documented per-attempt size ceiling and a small configurable count of unresolved attempts. Never automatically delete unresolved attempts. Refuse another collection if an unresolved attempt exists or the recovery quota would be exceeded, and display the exact recovery path. Recovery staging is separate from the evidence store's internal ingestion staging; it must not use names or paths that the store's stale-ingest cleanup could remove.

A missing eligible observation is reported as such. Do not fabricate a testcase or treat an AFL queue entry as an imported crash/hang observation.

## 6. Diagnostic build contract

Use a separate clean CMake/Ninja directory for the authenticated libpng 1.6.59 source tree and repository-owned harness.

### Approved toolchain

- Compiler: ordinary /usr/bin/clang, not afl-clang-fast.
- Approved upstream version: Clang 21.1.8, matching the recorded prior diagnostic build.
- Resolve the executable and record its path, SHA-256, complete version output, LLVM version, package identity/version/architecture and Clang resource directory.
- Record SHA-256 and resolved paths for the ASan and UBSan runtimes selected from that resource directory, plus their supplying package identities.
- A different compiler patch version, compiler binary digest, runtime package set or path is not silently accepted. Supporting another version requires an approved toolchain-policy change.
- Record exact CMake and Ninja paths, versions and executable hashes.
- Build type: RelWithDebInfo.
- Use the authenticated libpng source archive/tree identity and exact repository harness identity.
- Keep the existing libpng build options, generated-header feature checks and system zlib 1.3.1 resolution. System zlib remains uninstrumented and this limitation is recorded.

### Effective compile and link verification

Compile exactly the expected 17 libpng C translation units, once each, and the repository harness with the required ASan+UBSan options, frame pointers and debug information. Link the harness with the same sanitizer set using Clang as the final linker driver.

Parse compile_commands.json as structured JSON. Verify argv tokens. If only a command string is available, tokenize it once with a documented parser and reject ambiguous or unparseable commands. Do not use substring checks as proof of effective flags.

The verifier must:

- Match the normalized source set against the exact 17 expected source paths, once each, with a unique object destination for every source.
- Confirm the compiler path resolves to the approved Clang executable.
- Reject compiler launchers, wrappers, plugins, injected compiler loads, unapproved Clang config, response files and unexpected argument indirection.
- Reject effective-option overrides including -fno-sanitize, sanitizer trap mode, minimal runtime, no-runtime-linking, sanitizer ignorelists/blacklists and equivalent conflicting options, regardless of option order.
- Verify the harness compile and final link commands use the same approved Clang driver, the exact newly built libpng archive and the required sanitizer flags. Reject a second or alternate libpng archive.
- Inspect the static archive member list and map its 17 object members to the expected compile outputs. Reject missing, duplicate or unexpected members.
- Inspect object/archive and harness symbols for expected ASan instrumentation references and UBSan handlers where source operations generate checks. Do not require every translation unit to reference a UBSan handler when it contains no UBSan-checkable operation.
- Run disposable compiler/runtime self-tests: one known ASan violation and one known UBSan violation. Both must produce the expected family marker and non-zero termination. These probes verify the toolchain, not the target; they are not sanitizer-run records.
- Verify the harness, archive, generated headers, CMake cache, compile database and required outputs are regular non-symlink files with recorded sizes and SHA-256 values.

Do not require a shared libasan entry or use ldd as the sole test. Clang may link sanitizer runtimes statically; link-driver/runtime provenance and controlled runtime probes establish the intended runtime behavior.

Record profile libpng-asan-ubsan, build role diagnostic_replay, source identity, compiler/runtime identities, compile database, normalized source set, archive members, effective commands, environment, zlib limitation, terminal build state and artifact hashes in build metadata. Keep the existing schema-v2 build contract compatible and add diagnostic-specific fields without changing AFL profile interpretation.

Reject an existing build directory. A changed source, compiler, flags or sanitizer profile requires a new clean directory.

### Build registration order

Only after the build succeeds and every verification passes, register it through the existing immutable build repository path with role diagnostic_replay and status completed. Link it to the registered libpng target/version and exact source-tree identity. Do not register a failed or partially verified build as completed. The collector accepts only a registered completed diagnostic build; it never registers a build after executing the target.

## 7. One-observation execution and resource boundary

### Preflight validation

Before starting the service:

1. Open and verify the evidence store.
2. Resolve the observation UID to its observation, source campaign, source fuzz build and original artifact. Require all target/version/build/campaign identities to agree.
3. Require source role fuzz, diagnostic role diagnostic_replay, completed diagnostic status, matching libpng target version and authenticated source-tree identity.
4. Reverify diagnostic metadata digest, compiler/runtime identities, harness executable and archive hashes against the registered build.
5. Verify the original artifact is a regular content-addressed object and does not exceed the originating campaign's recorded max_input_bytes (currently 8 MiB).
6. Validate absolute, non-symlinked, non-overlapping build, evidence, source, campaign, recovery and temporary paths.
7. Verify recovery capacity and filesystem reserve; refuse if prior unresolved attempt data remains.

Materialize only the selected original artifact into the private attempt directory. Create input/output files exclusively with mode 0600 and no-follow semantics. Re-hash the input immediately before execution. Never modify the original campaign testcase or evidence-store object.

### Sole launch mechanism: transient systemd system service

P3-03 v1 uses `sudo systemd-run --system` to create a unique transient **.service** unit. It must not use `--user`, `--scope`, or start the harness with Popen and then migrate its PID. The privileged system manager creates the service cgroup and applies controls before executing the trusted guard.

The caller must have permission to use sudo for the system manager. The implementation must use non-interactive sudo after an explicit authorization step (for example, the operator runs `sudo -v`); if authorization is unavailable, it refuses before creating a unit. The Python collector, guard and target are never executed as root. No parent/system cgroup is manually modified, no controller is manually enabled, and no unrelated service is changed.

The successful WSL feasibility probe on 2026-11-18 used:
- `DynamicUser=yes`, `NoNewPrivileges=yes`, an empty `CapabilityBoundingSet`, and `ProtectControlGroups=strict`.
- `MemoryMax=1G`, `MemorySwapMax=0`, and `TasksMax=64`.
- The workload observed `memory.max=1073741824`, `memory.swap.max=0`, and `pids.max=64`.
- `/sys/fs/cgroup` was mounted read-only; attempts to write `cgroup.procs` failed with `EROFS`.
- A child created a separate session and ignored SIGTERM. Stopping the service removed the child and the temporary runtime directory.
- The service ran under a dynamic UID (63295 in the observed run), with zero effective capabilities and `NoNewPrivs=1`.

The above confirms this mechanism on the tested WSL instance. The implementation must still check every requested property, including CPU quota, read its effective value inside the guard, and fail closed when any requested property is unavailable.

Use service Type=exec and `systemd-run --system --quiet --pipe --remain-after-exit --unit=<unique-unit> --service-type=exec`. Do not add `--wait` or `--collect` to this lifecycle. `--pipe` connects the collector's stdin/stdout/stderr to the service and waits for the transient service to terminate. `RemainAfterExit=yes` keeps the unit available after the guard process exits so the collector can inspect its final result and preserved runtime files. The collector polls the guard's durable status, explicitly stops only this attempt's unit, then collects the `systemd-run` pipe result and final manager properties. It calls `systemctl clean --what=runtime` and `systemctl reset-failed` only after the service subtree is verified empty and both streams have durable copies. Any failed inspection or cleanup retains attempt resources and recovery metadata.

The fixed policy requests:

- `DynamicUser=yes`.
- `ProtectControlGroups=strict`, `NoNewPrivileges=yes`, empty `CapabilityBoundingSet=`, and `Delegate=no`.
- `MemoryMax=1G` and `MemoryAccounting=yes`.
- `MemorySwapMax=0`.
- `CPUQuota=60%` and `CPUQuotaPeriodSec=100ms`.
- `RuntimeMaxSec=5s`.
- `TasksMax=32`.
- `KillMode=control-group`, `TimeoutStopSec=1s`, and `SendSIGKILL=yes`.
- `LimitCORE=0`.

CPUQuota=60% limits the service to roughly 60% of one CPU. Together with the five-second service runtime ceiling, this is approximately three CPU-seconds, subject to kernel quota-period accounting. It is a cgroup-wide rate limit, not a per-process RLIMIT_CPU guarantee. Memory and swap are separate controls and both must be read back.

Do not use `LoadCredential=` for the testcase: the systemd v257 accumulated credential-size ceiling is 1 MiB per unit, below the approved 8 MiB input limit. Instead, after the testcase, harness and guard have been verified in the unprivileged collector, copy each into a unique root-owned file directly under `/run` using a fixed privileged helper. Each copy is opened exclusively with no-follow semantics, checked as a regular file, hashed while copying, compared with the expected digest and size, set to mode `0400`, and fsynced with its parent directory. The root staging names include the fresh attempt UID and have fixed `input`, `harness` or `guard` suffixes.

The service uses `BindReadOnlyPaths=` for all three staged files, placing them at fixed paths inside its private `RuntimeDirectory`. The root-owned staged files are not world-readable. After systemd starts the service as a DynamicUser, the guard first completes its resource checks and waits at a private-staging barrier. The collector reads back the service's `MainPID`, `ControlGroup` and complete requested manager policy. A fixed privileged helper confirms that the PID is still in that exact cgroup, obtains its effective non-root UID/GID, and transfers ownership of only the three attempt-owned staging files to that UID/GID while retaining mode `0400`. The helper fsyncs the files and `/run`; the collector records this identity handoff in the recovery manifest before releasing the guard.

The guard then hashes the bound harness and testcase against the registered harness digest and immutable original-artifact digest, and verifies from `/proc/self/mountinfo` that the guard, harness and testcase are mounted read-only. It signals a second pre-exec barrier. The collector reads back all requested unit properties again and requires the same `MainPID` and `ControlGroup` as the first check. Only after both the guard's effective cgroup/file checks and the manager's second property check pass does the collector send the final one-byte authorization token. Any timeout, mismatch, failed inspection, unexpected process identity or closed authorization pipe stops the attempt unit without dispatching the harness.

The target receives only the fixed input path as its single argument. Its stdin is `DEVNULL`; the guard uses the service pipe only for the two authorization bytes. No repository, campaign, evidence database, evidence-store object tree or host home directory is mounted into the service. No writable host path is exposed to the target.

A trusted pre-exec guard runs inside the already constrained service. Before dispatching the harness it verifies:

- `/proc/self/cgroup` is in the service's cgroup namespace; a namespace-relative path of `/` is acceptable and expected with the tested `ProtectControlGroups=strict` setup.
- The cgroup filesystem is mounted read-only and the visible `cgroup.procs` / `cgroup.threads` controls are not writable by the dynamic workload identity.
- Actual `memory.max` is finite and no greater than 1 GiB; `memory.swap.max` is exactly zero; `cpu.max` and `pids.max` reflect the approved bounds.
- The system manager confirms the complete unit policy before private staging is released, and confirms it again immediately before final execution authorization. The same active `MainPID` and `ControlGroup` must remain in place across both reads; `Delegate=no` is required.
- The workload receives no writable cgroup subtree.
- The guard verifies that its own file, the fixed harness and the fixed testcase are read-only bind mounts, and hashes the harness and testcase after the DynamicUser ownership handoff.
- RLIMIT_AS inherited by the guard is unlimited. Do not set RLIMIT_AS.
- The guard waits at two explicit barriers: private-file verification first, final manager authorization second. No harness process is created before the second token is received. A refusal, timeout or EOF at either barrier is a preflight block, not a harness execution.

Do not rely on `ProtectControlGroups=yes`; the implementation uses `ProtectControlGroups=strict` on a system service and verifies the read-only cgroup mount inside the process. If the check cannot prove that the workload cannot change its cgroup membership, the gate fails.

The workload runs as the dynamically allocated unprivileged UID, never root. This cgroup is not a security boundary against a kernel/system-manager exploit or deliberate hostile code able to attack the host through unrelated interfaces. Such work requires a separate isolated-VM design.

If sudo authorization, systemd, required controllers, a requested property, property readback, pre-exec validation, cgroup read-only checks or whole-subtree cleanup is unavailable, record a blocked_preflight attempt and do not dispatch the harness. Do not substitute RSS polling, RLIMIT_AS or unbounded execution.

### Harness process and output

The guard execs only the verified harness with the materialized testcase as its single argument. Use argv and execve, not a shell. Construct a fresh allowlisted environment:

- ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:abort_on_error=1.
- UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1.
- Minimal fixed PATH and LC_ALL=C.
- If a verified symbolizer is available, record its path and digest. Otherwise set symbolize=0 and disable automatic symbolizer discovery.

Do not inherit LD_PRELOAD, AFL variables, Python/user environment, D-Bus/session values or secret-bearing environment values. The harness uses stdin=DEVNULL, a fixed private working directory and closed unrelated file descriptors. The guard records successful harness exec only after `Popen` has returned successfully; launcher/guard errors are kept separate from harness stdout/stderr. Do not inherit a finite RLIMIT_AS. Disable core dumps through the service policy.

Capture stdout and stderr separately. Retain at most 8 MiB per stream. Continue draining after the retention cap and discard excess bytes so the child cannot block on a full pipe. Preserve retained bytes exactly; do not decode before hashing. Record read completion independently from truncation. Reader shutdown/join must be bounded and verified.

### Descendant cleanup

Process-group TERM/KILL is secondary only. Use systemd KillMode=control-group to stop all processes in the service cgroup, including descendants that create new sessions/process groups. On normal exit, timeout or handled interruption:

1. Stop the unique transient unit if needed.
2. Allow the configured TERM interval, then require KILL for remaining unit processes.
3. Wait for cgroup.events to report populated=0.
4. Verify no descendant remains in the service subtree.
5. Collect final unit result and resource counters before cleaning the attempt-owned RuntimeDirectory and resetting the transient unit.
6. Never stop or modify unrelated services, parent cgroups or the user manager.
7. If the manager inspection fails, do not treat it as proof that the unit is absent. Only a positive `LoadState=not-found` response or a verified inactive/failed unit with an empty or removed cgroup proves that cleanup completed.

If cleanup or populated=0 verification fails, record cleanup_status=failed, retain the manifest and report the exact unit name. Do not claim cleanup succeeded.

## 8. Sanitizer marker interpretation

Preserve raw bytes from stdout and stderr. Recognize only these byte markers:

- ASan: ERROR: AddressSanitizer:
- LSan: ERROR: LeakSanitizer:
- UBSan: runtime error:

A bare runtime error: string may be arbitrary target output; call it an observed marker, not an authenticated UBSan report. Raw logs remain authoritative.

Scan the complete retained byte prefixes, not individual read chunks, so markers split across reads are detected. A marker that crosses the retention boundary and is not wholly retained is not counted; truncation prevents a no-signature result.

Classification precedence:

- **report_signature_observed:** harness exec succeeded and at least one marker is present in retained stdout/stderr. This remains candidate evidence if execution later times out, is interrupted, terminates by signal or output is truncated.
- **no_signature_observed:** harness exec succeeded; service completed normally with exit code 0; both streams have complete capture; neither is truncated; both streams were successfully published; and no marker is present.
- **inconclusive:** every other combination, including blocked preflight, launch failure, timeout/interruption without a marker, signal/non-zero exit without a marker, capture failure, publication failure or truncation without a marker.

Do not classify systemd/guard diagnostics as harness output. A failed stream read never permits no_signature_observed.

Store family names as a sorted unique canonical JSON array from address, leak and undefined_behavior. Families are output markers, not confirmed vulnerabilities.

## 9. Additive database migration

Add checksum-pinned migration 002_sanitizer_runs.sql. Do not modify migration 001 or rewrite existing rows.

Add an immutable STRICT table sanitizer_runs with non-null identity fields and explicit ON DELETE RESTRICT foreign keys. Use composite FKs to prove the observation belongs to the recorded source build, target/version and campaign, and the diagnostic build belongs to the same target/version. An insert trigger rejects source roles other than fuzz, diagnostic roles other than diagnostic_replay, diagnostic builds not completed, and an original artifact different from the observation's artifact.

Each attempt has a canonical lowercase UUIDv4 run_uid. Do not make observation/build pairs unique: a retry is a new fact.

Record:
- Target, version, source build, campaign, observation, diagnostic build and original artifact IDs.
- Versioned execution-policy identifier, non-empty argv JSON, fixed environment JSON, resource-policy JSON and runtime-observation JSON.
- Attempt start/finish timestamps for every final row; nullable execution start/finish timestamps, null when harness exec never succeeded.
- execution_status: blocked_preflight, launch_failed, exited, signaled, timed_out or interrupted.
- Nullable exit code and signal with cross-field checks. For exited, require successful exec, execution timestamps, exit code 0..255 and no signal. For signaled, require successful exec, timestamps, valid signal and no exit code. Timed_out/interrupted require successful exec and timestamps; final exit or signal may be present or unknown but not both. blocked_preflight/launch_failed require no successful exec, execution timestamps, exit code or signal.
- Sanitizer family JSON and assessment; record/attempt/execution timestamps in normalized UTC form and enforce ordering.
- cleanup_status complete/failed/not_required and bounded detail.
- Actual kernel, WSL and systemd versions where available, requested/effective cgroup controls, unit/cgroup identity, memory/CPU counters and memory/swap event counters where supported.

For each stream independently, record nullable artifact FK, capture_state (not_started, complete, read_failed), truncated boolean and publication_state (not_started, published, pending_recovery).

Stream invariants:
- A completed empty stream is a valid zero-byte artifact and must be published.
- A truncated stream can still be capture_state=complete if EOF was reached after retaining the cap.
- A read error is read_failed even if a prefix was captured and published.
- published requires a non-null artifact FK; not_started requires no artifact and truncated=false; pending_recovery requires no artifact FK and an existing retained stage file plus manifest entry.
- If one publication succeeds and the other fails, preserve the published artifact and the only unpublished staging copy.
- Enforce the 8 MiB per-artifact ceiling in application code and a database trigger, despite the larger general store limit.
- stdout and stderr may reference the same artifact, including the same empty artifact.

Validate JSON type/shape using SQLite JSON functions; validate family allowlist/sorted uniqueness and all booleans as 0/1. Use a truth table across status, timestamps, exit/signal, stream states, truncation, publication, families and assessment.

Assessment constraints:
- A non-empty family array requires report_signature_observed.
- no_signature_observed is allowed only for exited with code 0, successful complete captures, no truncation, both artifacts published and an empty family array.
- All other combinations require inconclusive.

Add attempt-history and diagnostic-build indexes. Add update/delete prevention triggers. Preserve existing P3-01 immutability rules.

Update migrations.py with migration 002's exact checksum and contiguous version. Keep migration 001's checksum and history unchanged. Reuse the existing backup, transaction and foreign-key verification path. A failed backup/checksum/foreign-key validation blocks the migration.

## 10. Failure recording, publication and recovery ordering

The fsynced recovery manifest is the fallback record when publication or the database commit cannot complete. It does not replace the final immutable DB row when that row is possible.

1. Validate all evidence identities, completed builds, source hashes, input artifact, store health, paths and recovery capacity.
2. Create a fresh run UID, attempt directory, manifest and bounded private staging files; fsync the manifest before service launch.
3. If resource preflight fails, do not dispatch the harness. Record blocked_preflight, inconclusive, null execution times, not_started stream states and no stream artifacts, plus the exact refusal reason and observed resource state.
4. If the service or guard cannot exec the harness, record launch_failed. Do not classify launcher/guard diagnostics as sanitizer output.
5. Once exec succeeds, record execution start, run once, capture both streams and record complete/read_failed and truncated independently.
6. Stop and verify the whole service subtree, collect resource observations and determine cleanup status before final immutable insertion.
7. Publish each successfully captured stream independently through EvidenceStore. Verify size and SHA-256. Publish complete empty streams as zero-byte artifacts.
8. If publication fails, retain the capped private stage file and manifest, set pending_recovery and surface the exact path. Never delete the only unpublished copy.
9. Remove input and stage files only when no longer the only copy. Record cleanup failure before insertion; retain the recovery manifest if any cleanup or publication is incomplete.
10. Recheck diagnostic build metadata, executable and original-input digest.
11. In one BEGIN IMMEDIATE transaction, register/reuse successfully published stream artifacts and insert the immutable run row. The diagnostic build is already registered.
12. If DB commit fails, retain the manifest and unpublished stage files. Published CAS objects remain intact and are discoverable as unreferenced objects by existing store verification. Report run UID and recovery path.
13. After successful row commit and complete cleanup, remove the recovery manifest and attempt directory. If a crash leaves a manifest, reconcile it against run_uid in the DB before any cleanup.

Handled SIGINT/SIGTERM stops the service, drains what remains, records interrupted and inserts a row when the database is available. SIGKILL, kernel failure or power loss cannot guarantee a final row. The guarantee is best-effort recovery from the last fsynced manifest/stage files if the filesystem survives. Never claim every interruption creates a completed DB row.

The original testcase, P3-02 observation, campaign metadata, fuzz build and prior sanitizer rows are never modified or deleted. Every retry gets a fresh UID.

## 11. Focused implementation files

Expected files, subject to final approved scope:

- engine/build/diagnostic.py for the fixed build plan and effective-command verification.
- Minimal integration in engine/build/runner.py without weakening AFL verification.
- engine/evidence/sql/002_sanitizer_runs.sql and checksum registration in engine/evidence/migrations.py.
- Typed sanitizer-run and diagnostic-build lookup methods in engine/evidence/repository.py.
- engine/evidence/sanitizer.py for evidence validation, attempt recovery, service orchestration, classification and publication.
- engine/evidence/sanitizer_exec_guard.py for pre-exec resource checks and harness-exec handshake.
- scripts/build_libpng_diagnostic.py and scripts/collect_sanitizer_evidence.py.
- Focused build, evidence, migration, repository and recovery tests.
- This design record.

Do not refactor the AFL campaign runner, P3-02 importer, generic process layer or migration 001 absent a specific approved reason.

## 12. Acceptance checks and real WSL gate

### Build and instrumentation

- The authenticated pinned source and exact repository harness are used.
- Clang 21.1.8 and its runtime/package identity match the approved policy.
- Exactly 17 expected libpng source files appear once, with unique object outputs.
- Tokenized compile/link verification rejects wrappers, response files, plugins, conflicting later flags, sanitizer-disable/trap/minimal-runtime/ignorelist options and alternate archives.
- Every expected unit and the harness have effective ASan+UBSan compile settings; the final link uses the exact newly built archive and approved Clang runtime.
- Archive member/object/source mapping, symbols and disposable ASan/UBSan runtime probes are checked.
- Build metadata is registered as completed before collection. AFL instrumentation and UBSan trap mode are absent.
- A second build attempt refuses to overwrite the existing directory.

### Real resource-boundary test

Mocks do not satisfy this gate. On the actual supported WSL 2 environment, use only harmless test executables before any real imported observation. Verify:

- Actual WSL version/configuration, kernel, systemd version and user-manager reachability.
- A transient .service starts with Type=exec, not a scope.
- All requested memory, swap, CPU, runtime, task and kill properties are accepted.
- From inside the service, the guard reads effective memory.max <=1 GiB, memory.swap.max=0, cpu.max, pids.max and relevant ancestor controls before test exec.
- The workload UID cannot write cgroup.procs in ancestors above the service subtree. If this cannot be established, production collection remains blocked.
- A harmless process forks a child and a setsid child; service shutdown/timeout kills every descendant and cgroup.events reaches populated=0.
- Normal exit, timeout and handled interruption clean up only the attempt-owned unit. Parent cgroups and unrelated services remain unchanged.
- Missing/invalid resource properties or permission boundaries fail closed before test exec.
- The test records configured/effective properties, cgroup readings, memory/swap events and cleanup result.

If WSL lacks any property or permission boundary, record the blocked result. Do not enable controllers manually, alter parent/system cgroups, run the target as root or replace the gate with a weaker approximation.

### Collection, recovery and database tests

- Only existing P3-02 observation UIDs and registered completed diagnostic builds are accepted.
- Every source/build/artifact identity mismatch and direct SQL constraint violation is rejected.
- Original bytes are re-hashed; original campaign and database evidence remain unchanged.
- No shell, arbitrary command or inherited user environment is accepted.
- Empty logs, exact 8 MiB and cap-plus-one output, malformed bytes, split markers and retention-boundary markers are tested.
- Capture read failure, truncation and publication failure are separate states.
- Blocked preflight and launch failure do not claim harness execution or create fake stream artifacts.
- Test partial publication, retained recovery files, cleanup failure, DB commit failure and manifest reconciliation.
- Test marker precedence with timeout, signal, interruption and truncation; no-signature requires clean exit and fully captured, published streams.
- Handled interruption is tested. SIGKILL/power-loss is documented as best-effort staging recovery only.
- Retries get fresh UIDs and never alter prior rows.
- Migration 001 checksum/history remain unchanged. Migration 002 backup, checksum, transaction, FK enforcement and rollback are tested against an existing P3-01/P3-02 database.
- Existing P3-01/P3-02 suites remain green on Python 3.11 and 3.14.
- Mocked orchestration tests remain separate from the real WSL integration gate. No unavailable environment or missing observation is reported as successful real evidence.

## 13. References and approval gate

Project references:
- docs/WORKFLOW_DECISIONS.md, including WSL risk limits and mandatory review gates.
- docs/DEVELOPMENT_PLAN.md.
- docs/tasks/LIBPNG_AFL_BUILD_VERIFICATION.md.
- docs/tasks/P3_02_AFL_EVIDENCE_INGESTION_DESIGN.md.
- Original design review baseline commit 48ea0ab19467844a997152566e2c8ecca591d067.

Technical references:
- Linux 6.6 cgroup v2: https://www.kernel.org/doc/html/v6.6/admin-guide/cgroup-v2.html
- systemd 257 systemd-run: https://www.freedesktop.org/software/systemd/man/257/systemd-run.html
- systemd 257 resource control: https://www.freedesktop.org/software/systemd/man/257/systemd.resource-control.html
- systemd 257 execution environment: https://www.freedesktop.org/software/systemd/man/257/systemd.exec.html
- systemd 257 process killing: https://www.freedesktop.org/software/systemd/man/257/systemd.kill.html
- Microsoft WSL systemd support: https://learn.microsoft.com/en-us/windows/wsl/systemd
- Clang AddressSanitizer documentation for LLVM 21: https://releases.llvm.org/21.1.0/tools/clang/docs/AddressSanitizer.html
- Clang UndefinedBehaviorSanitizer documentation for LLVM 21: https://releases.llvm.org/21.1.0/tools/clang/docs/UndefinedBehaviorSanitizer.html
- AFL++ sanitizer notes: https://aflplus.plus/docs/notes_for_asan/

This owner-approved revision records the successful harmless WSL 2 system-service probes and defines the tested system-managed launch model. It does not authorize weakening any failed runtime check. The implementation must still verify CPU quota and all effective limits before executing a target. If any check fails, record blocked_preflight and stop rather than using an unbounded fallback.
