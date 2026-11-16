# Development Plan

This plan follows [Workflow and Technology Decisions](WORKFLOW_DECISIONS.md). Every individual task must use the repeatable engineering procedure and mandatory stop points in sections 11 and 12 of that document. Each phase is a verified slice; a phase is not complete because code was generated, and its acceptance checks must pass.

## Working rules

- Keep main stable and use development for reviewed integration.
- Create focused feature branches from development.
- One implementation owner works on a task at a time.
- Material architecture or dependency changes require review first.
- Do not claim tests or capabilities that were not actually run.
- Preserve experiment settings and output needed to reproduce results.
- Keep secrets, databases and large generated campaign artifacts out of Git.

## Phase 0 — Environment and toolchain verification

**Goal:** Confirm a usable native development and fuzzing environment in Ubuntu on WSL 2.

Work:
- verify Ubuntu release and architecture;
- update existing package indexes and install security/package updates appropriately;
- verify Git, Python, GCC, CMake and SQLite already present;
- finish Clang/LLVM, linker and libclang installation using packages compatible with the Ubuntu release;
- install or build AFL++ with LLVM instrumentation support;
- verify ASan/UBSan runtime support;
- confirm Python virtual-environment support and basic native debugging tools;
- clone KEKKAI into the Linux filesystem.

Acceptance:
- exact Ubuntu release and tool versions recorded;
- clang, clang++, llvm-config and linker are available;
- AFL++ fuzzer and compiler wrapper are available;
- a minimal native test can compile with coverage instrumentation and sanitizer flags;
- no fuzz target is run as root;
- repository is checked out on the intended development branch.

## Phase 1 — First target proof of work

**Goal:** Build and fuzz one real C/C++ parser target.

Pilot: libpng, conditional on feasibility.

Work:
- choose and pin the exact libpng release or commit;
- inspect build instructions and dependencies;
- select a meaningful image-input parsing API;
- write a minimal reviewed C/C++ harness;
- create a small seed corpus with clear provenance;
- build the target and harness in a clean directory with AFL++ instrumentation and compatible ASan/UBSan settings;
- validate ordinary, empty and malformed input behavior;
- run a short smoke test followed by a bounded campaign.

Acceptance:
- clean build completes using recorded commands;
- harness demonstrably reaches the intended libpng path;
- valid and malformed input behavior is understood;
- AFL++ starts and reports actual campaign activity/coverage feedback;
- time and memory limits work;
- source revision, compiler, flags, harness identity, corpus hashes and campaign settings are recorded;
- any crash is preserved as an observation, not labelled a vulnerability.

If libpng is unsuitable, stop and document the reason before selecting one alternative.

## Phase 2 — Harness validation and campaign orchestration

**Goal:** Turn the proof of work into a repeatable target-adapter workflow.

Work:
- define a small adapter configuration format;
- validate paths, build prerequisites and harness outputs;
- add explicit harness smoke checks and coverage-diversity checks;
- invoke AFL++ using safe subprocess argument arrays;
- capture campaign logs, status, configuration and tool versions;
- enforce timeouts and resource constraints;
- distinguish completed, failed and interrupted runs.

Acceptance:
- a target can be built and fuzzed from a validated adapter;
- invalid configuration fails clearly;
- the harness validation report explains its results;
- campaign state and logs are traceable;
- no arbitrary command execution path is introduced.

### Verified progress — 2026-11-11

Implemented and verified:
- Strict TOML adapter configuration and path validation.
- Libpng preflight and existing build-provenance checks.
- Harness smoke validation: 13/13 cases passed.
- AFL++ coverage validation: 10/10 distinct seed maps.
- Adam7 coverage repeatability: passed.
- Single-worker campaign orchestration, metadata, bounded logs, watchdog, process-group cleanup and lifecycle-state handling.
- AFL++ generated-input argument capped at the installed build's verified 1 MiB maximum; harness input limit remains 8 MiB.
- Safe integration check: all four validation gates passed with the actual campaign launch blocked.
- Automated tests: 100/100 passed.

The first live orchestrator launch failed before fuzzing because the configured AFL++ `-G` value exceeded the installed tool's maximum. The command builder has since been corrected and reverified. A successful 300-second live campaign and 338-input sanitizer replay were completed on 2026-11-11.

**Phase 2 is complete for the libpng 1.6.59 adapter.** The clean build, four validation gates, live campaign and retained-corpus sanitizer replay passed. See the Phase 2 verification report for evidence and limitations.

## Security remediation verification - 2026-11-12 to 2026-11-16

A follow-up security remediation was implemented on the local
`fix/phase2-security-remediation` branch. The work strengthens the initial
libpng 1.6.59 pilot without expanding Phase 2 into the later roadmap phases.

### Latest recorded verification

- Full automated test suite: **143 tests passed, 0 failures, 0 errors**
  (5.868 seconds).
- `git diff --check`: passed during the latest working-tree review.
- Authenticated libpng 1.6.59 clean build completed.
- Build provenance verification passed, including archive identity,
  extracted source-tree identity, build configuration and artifact hashes.
- Preflight passed.
- Harness smoke validation: 13/13 cases passed.
- Coverage validation: 10 distinct seed maps; Adam7 repeatability passed.
- No new live AFL++ campaign was launched during this remediation.

### Security and reliability remediation

- **Source authenticity and provenance:** The exact libpng archive is
  SHA-256 pinned. Archive entries and the extracted source tree are checked.
  Build metadata schema version 2 records source identity and artifact hashes.
- **Process lifecycle:** Shared process-group handling covers timeout,
  interruption, descendant cleanup and SIGTERM.
- **SIGTERM integration:** External SIGTERM integration tests for both build
  and campaign orchestration passed. They verify descendant cleanup and
  interrupted final metadata.
- **Root protection:** Public build and campaign entry points reject root
  execution.
- **Filesystem and configuration checks:** Symlink and unsafe-path checks,
  controlled subprocess environments and bounded tool-version probes are
  implemented.
- **Artifact limits:** Build and provenance verification share a 16 MiB
  artifact limit.
- **Fixture validation:** The current libpng fixtures receive semantic PNG
  checks, including bounded decompression and CRC validation.
- **Adapter configuration:** The current adapter configuration schema is
  version 4.

### Campaign storage and failed-build recovery

- **F-07 storage:** Campaign output is directed to a dedicated ext4 filesystem
  backed by an exact 4 GiB image. The storage verifier checks the expected
  filesystem UUID, mountpoint, backing image, ownership, permissions and
  mount options. This enforces an aggregate filesystem capacity ceiling for
  the configured pilot storage.
- **F-08 recovery:** A manual recovery CLI validates eligible failed or
  interrupted build metadata and archives the build directory
  non-destructively. It preserves logs and partial outputs and publishes a
  recovery manifest without overwriting an existing archive.

### Remaining limitations

- Source verification is point-in-time. The source tree remains mutable
  between verification and compiler reads, so the TOCTOU risk is not fully
  eliminated.
- Some path checks remain subject to filesystem race conditions.
- The 4 GiB storage filesystem does not provide per-campaign reservations or
  an application-managed minimum-free-space threshold. Full-filesystem
  failure behavior has not been established through fault injection.
- Failed-build recovery is a manual archival workflow. Automatic retry,
  restart and cleanup are not implemented.
- Tool binaries are version-checked but not cryptographically pinned.
- Python `preexec_fn` remains a potential deadlock concern in a multithreaded
  host process.
- An orchestrator killed with SIGKILL cannot execute its own cleanup handler.

**Assessment:** Functionally complete for the initial libpng 1.6.59 pilot,
subject to the limitations above and final local closeout checks. This does
not claim that future KEKKAI capabilities such as crash intelligence,
cross-version comparison, source intelligence, dashboard or AI assistance
are implemented.

The remediation remains local to `fix/phase2-security-remediation`. It has
not been committed, pushed or merged into `development` or `main`. No new
live fuzzing campaign was started during this remediation.

See [Phase 2 Security Remediation Verification](tasks/PHASE2_SECURITY_REMEDIATION.md)
for finding-by-finding status, evidence and limitations.


## Phase 3 — Crash evidence, reproduction and persistence

**Goal:** Make every interesting observation reviewable and recoverable.

Work:
- preserve immutable original testcases and SHA-256 hashes;
- store large files on disk and metadata in SQLite;
- define versioned database schema/migrations;
- ingest sanitizer reports, signals, exit status and campaign links;
- implement replay against the recorded build;
- add minimization as a separate derived artifact;
- add transparent heuristic crash grouping;
- record reproduced, not reproduced and inconclusive outcomes.

Acceptance:
- each artifact links to a target, version, build and campaign;
- original bytes remain available after minimization;
- database records survive application restart;
- replay result and exact command are recorded;
- grouping never deletes raw evidence and can be reviewed.

## Phase 4 — Version-aware replay and comparison

**Goal:** Deliver KEKKAI's main differentiator.

Work:
- register multiple exact revisions of the same supported target;
- build comparable instrumented versions with recorded configuration;
- replay the same saved testcase against each version;
- compare sanitizer category, signal, normalized stack evidence and reproduction outcome;
- show material build/harness/configuration differences;
- use newly observed, persistent and not re-observed labels;
- flag ambiguous signature matches for human review.

Acceptance:
- each comparison is traceable to exact target revisions and build identities;
- original testcase bytes are identical across replay attempts;
- results distinguish crash reproduction from heuristic group matching;
- the report never labels not re-observed as fixed;
- differences and uncertainty are visible.

## Phase 5 — Source inspection and additional target adapters

**Goal:** Reduce manual work without pretending source analysis is a vulnerability oracle.

Work:
- use Clang tooling/libclang to inspect C/C++ declarations and source locations;
- rank likely input-processing entry points using explainable features;
- show why each candidate was ranked;
- keep human selection and harness review;
- add a second target only after the adapter boundary is validated by the first.

Acceptance:
- candidate source locations are traceable;
- ranking output is explainable and explicitly heuristic;
- analysis does not claim vulnerability detection;
- second target passes the same build/harness/campaign validation before being marked supported.

## Phase 6 — Reports and local dashboard

**Goal:** Present the verified workflow and evidence clearly.

Work:
- add a Flask service layer over tested core modules;
- provide read-only target, campaign, artifact, reproduction and version-comparison views;
- generate evidence-linked reports;
- later add safe start/stop controls through validated service methods.

Acceptance:
- dashboard figures match database records;
- no arbitrary shell commands or unrestricted paths can be triggered through routes;
- failures, interruption and uncertainty are visible;
- core CLI workflow functions without the dashboard.

## Phase 7 — Optional AI, benchmark evaluation and hardening

**Goal:** Assess optional explanation value and prepare an honest technical demonstration.

AI work is only after approval and only after the evidence pipeline is stable:
- summarize selected sanitizer output and stack evidence;
- propose possible causes and manual checks;
- keep external transmission disabled by default;
- never allow AI to confirm a vulnerability or change a finding status;
- evaluate incorrect as well as useful suggestions.

Evaluation and hardening:
- test against controlled known-defect programs;
- where compatible, assess a documented Magma setup;
- report benchmark rediscoveries separately from independently validated findings;
- test failure, timeout, interruption, duplicate grouping and version comparison;
- document supported target revisions, setup, limitations and reproducible commands.

Acceptance:
- results are honestly categorized;
- a clean environment can reproduce the demonstrated workflow;
- limitations, false positives and inconclusive results are documented;
- dependencies, permissions, artifacts and secrets are reviewed.

## Milestone reporting rule

A capability is complete only when implementation exists, acceptance checks pass, actual test evidence is retained and documentation reflects reality. Planned modules must never be described as implemented.
