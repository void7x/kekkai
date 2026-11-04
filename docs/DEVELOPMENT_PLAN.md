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
