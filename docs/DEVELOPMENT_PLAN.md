# Development Plan

## Working rules

- Implement one verifiable slice at a time.
- Keep `main` stable; integrate reviewed work through `development`.
- Use focused `feature/<short-name>` branches.
- The implementation agent may write code, but architecture changes and dependency additions require review.
- Generated code is not complete until its acceptance checks pass.
- Record exact target revisions, tool versions and commands used in experiments.
- Do not commit generated campaign output, secrets or unreviewed binary crash artifacts.

## Phase 0 — Repository and environment foundation

**Goal:** Establish a reproducible development workspace.

Work:
- initialize repository documentation and Git workflow;
- use Ubuntu on WSL 2 as the main Linux development environment;
- keep the working tree in the Linux filesystem, such as `/home/sahil/kekkai`;
- install and verify Git, Python, build-essential, CMake, GDB, SQLite and supporting utilities;
- inspect available Clang/LLVM versions before selecting compatible AFL++ packages;
- create a Python virtual environment when Python dependencies are introduced.

Exit checks:
- repository clones successfully into Ubuntu;
- Git identity and branch workflow are configured;
- tool versions can be printed and recorded;
- no application feature is claimed at this phase.

## Phase 1 — First native target proof of work

**Goal:** Demonstrate that the selected environment can build and fuzz one real C/C++ parser target.

Candidate: **libpng**, subject to feasibility checks.

Work:
- choose and pin an exact source release or commit;
- inspect the build system and available examples/harness options;
- select one meaningful input-processing entry point;
- create a minimal, reviewed fuzzing harness;
- prepare a small, provenance-documented seed corpus;
- compile a clean build with AFL++ instrumentation and compatible diagnostics;
- run a short smoke test and a bounded fuzzing campaign.

Exit checks:
- a clean build succeeds from documented instructions;
- the harness accepts expected inputs and handles empty/malformed inputs safely;
- AFL++ starts and reports campaign activity;
- compiler, toolchain, source revision and campaign settings are recorded;
- any observed crashes are saved as test evidence, not automatically labelled vulnerabilities.

If libpng cannot be built or harnessed reliably in the chosen environment, document the blocker and evaluate another suitable target before expanding the platform.

## Phase 2 — Campaign and evidence pipeline

**Goal:** Make campaign execution and results repeatable.

Work:
- define target-adapter configuration;
- add safe process invocation, working directories and resource limits;
- capture AFL++ logs, exit status and campaign configuration;
- ingest crash testcases and diagnostic output;
- hash and preserve original artifacts;
- keep generated output outside Git.

Exit checks:
- a campaign can be started from a validated configuration;
- campaign completion, failure and interruption are distinguishable;
- an observed testcase can be traced to its target, build and campaign.

## Phase 3 — Crash analysis and reproduction

**Goal:** Turn raw crash files into reviewable evidence.

Work:
- parse relevant ASan/UBSan diagnostics;
- create heuristic crash signatures;
- group likely duplicates without discarding originals;
- implement replay against the recorded build;
- record reproduced, not reproduced and inconclusive outcomes;
- optionally evaluate CASR after checking compatibility and licensing.

Exit checks:
- original and derived/minimized inputs remain separately available;
- a reviewer can inspect why two crashes were grouped;
- reproduction attempts retain their commands and results;
- no crash is automatically promoted to a confirmed vulnerability.

## Phase 4 — Version-aware comparison and persistence

**Goal:** Track observations across target versions.

Work:
- introduce SQLite schema and controlled migrations;
- persist targets, versions, adapters, builds, campaigns, artifacts and reproduction attempts;
- define stable finding signatures and comparison records;
- implement newly observed, persistent and not re-observed states.

Exit checks:
- campaign and finding records survive application restart;
- comparisons use explicitly recorded versions and configurations;
- not re-observed is never displayed as fixed without independent validation.

## Phase 5 — Local reporting and dashboard

**Goal:** Make verified results understandable and accessible.

Work:
- add a Flask application and structured service layer;
- show targets, campaign status, crashes, evidence and reproduction state;
- add reports and filters;
- keep the first dashboard iteration read-only;
- later add validated actions for starting and stopping campaigns.

Exit checks:
- dashboard values match persisted records;
- routes do not expose arbitrary shell execution or unrestricted filesystem access;
- application errors and interrupted campaigns are visible.

## Phase 6 — Optional AI-assisted analysis

**Goal:** Evaluate whether AI improves the explanation and triage of evidence.

This is a proposed enhancement and requires project-guide approval because a dedicated AI module is not part of the submitted synopsis scope.

Work, only after approval:
- define a provider-independent analysis interface;
- select minimal evidence for analysis;
- produce structured hypotheses and investigation suggestions;
- keep all AI output separate from confirmed finding status;
- keep external transmission disabled by default and document privacy controls;
- compare AI suggestions with human-reviewed conclusions.

Exit checks:
- the core platform works with AI disabled;
- AI output is clearly marked as unverified;
- no AI-generated conclusion changes a finding's status automatically;
- evaluation records usefulness and incorrect suggestions, not only successful examples.

## Phase 7 — Evaluation, hardening and final documentation

**Goal:** Evaluate the implemented system and prepare an honest project demonstration.

Work:
- test with controlled programs containing known defects;
- where compatible, evaluate against a documented benchmark such as Magma;
- test failure cases, interrupted campaigns, duplicate grouping and version comparisons;
- document setup, supported target configuration, limitations and reproducible results;
- review dependencies, permissions, secrets and artifact handling.

Exit checks:
- results distinguish controlled known defects, benchmark observations and any independently validated new discoveries;
- known limitations are documented;
- a clean environment can reproduce the demonstrated workflow using recorded instructions.

## Development completion criteria

A milestone is complete only when:
1. the implementation exists in the repository;
2. automated or documented manual tests pass;
3. actual command output or test evidence is retained;
4. behavior and limitations are documented;
5. the code is reviewed before integration.

Do not report planned components as implemented. Do not report a fuzzer crash as a zero-day without independent technical validation and an appropriate novelty assessment.
