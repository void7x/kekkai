# KEKKAI — Workflow and Technology Decisions

**Status:** Locked project baseline  
**Applies to:** Project scope, architecture, technology selection and implementation order  
**Change policy:** Do not change a locked decision casually. A proposed change must include the problem it solves, alternatives considered, evidence that the current choice is insufficient, and its impact on completed work. Record an approved material change here.

This document is the engineering source of truth. The academic synopsis does not prevent us from making sound implementation decisions; project-guide or submission requirements must still be respected.

## 1. Project definition

KEKKAI is an **evidence-driven, local-first platform for discovering and investigating potential defects in selected native C/C++ input-processing software**.

The project is not a general web scanner, remote network scanner, automatic exploit generator or promise of zero-day discovery.

The engineering objective is to make the full experiment traceable and useful:

- identify an appropriate input-processing entry point;
- build and validate a meaningful harness;
- run coverage-guided fuzzing;
- preserve raw evidence;
- reproduce and investigate crashes;
- compare observations across explicitly recorded software versions;
- communicate only conclusions supported by evidence.

The standout feature is **version-aware, evidence-preserving investigation**, not a large number of superficial features or an AI label.

## 2. Locked technology choices

| Layer | Decision | Boundary |
|---|---|---|
| Main platform/orchestration | Python | Starts processes, validates configuration, records experiments and coordinates modules. It is not the CPU-heavy fuzzing engine. |
| Target and fuzz harnesses | C/C++ | Native code calls the selected library's input-processing API. |
| Compiler/toolchain | Clang/LLVM | Use a compatible, recorded version for instrumentation and later source inspection. GCC may be used where target compatibility requires it. |
| Fuzzing engine | AFL++ | Coverage-guided fuzzing of instrumented native targets. |
| Runtime diagnostics | ASan and UBSan | Enable only where compatible with the selected target and record the exact build flags. |
| Source intelligence | Clang tooling/libclang | A later supporting feature for locating and ranking candidate input-processing functions; not a vulnerability oracle and not a prerequisite for the first proof of work. |
| Metadata store | SQLite | Campaign, target, build, finding, reproduction and comparison metadata. |
| Artifact storage | Local filesystem | Original testcases, minimized derivatives, logs and other large files; store hashes and references in SQLite. |
| Reporting UI | Flask plus HTML/CSS/JavaScript | Build only after the core workflow and evidence records are reliable. |
| Optional triage tool | CASR | Evaluate after a real crash pipeline exists and compatibility is checked. |
| Evaluation | Controlled test targets and compatible Magma benchmark | Keep known benchmark findings separate from any independently validated new discovery. |
| Optional AI | Evidence explanation/summarization only | Not required for operation; no automatic vulnerability verdict or status change. |

### Explicitly rejected for the initial build

- No full rewrite in Rust merely because a reference project uses Rust.
- No microservices or distributed fuzzing infrastructure.
- No React/Node frontend or dashboard-first implementation.
- No local LLM/Ollama dependency.
- No external AI dependency in the core workflow.
- No automatic build support for every arbitrary C/C++ project.
- No automatic harness generation treated as trustworthy without validation.
- No QEMU, FRIDA, Unicorn or other binary-only AFL++ modes unless a concrete target later requires them.

AFL++ performs the CPU-intensive mutation and target execution. Python is sufficient for the initial orchestration, files, database and process-management workload. We will profile before considering a lower-level rewrite.

## 3. Target decision

**Pilot: libpng, conditional on feasibility.**

libpng is the first candidate because it parses structured image input and gives us a focused native-library use case. It is not yet an implemented or verified adapter.

Before a real campaign:
1. Select and pin an exact upstream release or commit.
2. Verify build instructions and dependencies in our Ubuntu environment.
3. Identify a meaningful public parsing path.
4. Implement a small, reviewed harness that sends input bytes into that path.
5. Validate ordinary, empty and malformed input behavior.
6. Confirm AFL++ instrumentation and sanitizer diagnostics work.
7. Record the build, source revision and harness identity.

If this cannot be demonstrated, document why and assess one better-fit target. Do not broaden the target list to hide a failed first integration.

## 4. Exact end-to-end workflow

### Step A — Target and experiment identity
Register the supported target, exact source revision, adapter, build profile and execution limits. Every campaign must be traceable to these details.

### Step B — Source understanding and harness
For the first target, manually identify the input-processing API and write a minimal native harness. Source inspection tooling may later help rank candidate functions, but it must not invent or silently approve a harness.

### Step C — Harness and build validation
Before a campaign, verify:
- the target and harness build from a clean build directory;
- the harness reaches the intended library code;
- representative valid inputs are handled as expected;
- empty and malformed inputs do not cause harness bugs unrelated to the target's intended behavior;
- input handling is deterministic enough for the chosen fuzzing mode;
- the instrumented executable runs and produces coverage feedback;
- timeouts, memory bounds and other campaign limits are configured.

A harness that merely compiles is not necessarily a useful harness.

### Step D — Bounded fuzzing
Run AFL++ against the validated instrumented target with a small documented seed corpus and optional target-specific dictionary. Capture exact command arguments, environment, tool versions, campaign duration, logs and exit state. Consider persistent mode only after state-reset correctness is demonstrated; speed is not worth false results.

### Step E — Evidence preservation
For every observed crash, preserve the original testcase and compute a cryptographic hash. Record the target revision, build/harness identity, campaign, diagnostic type/output, signal or exit status and timestamp. Never overwrite original evidence.

### Step F — Crash investigation
Replay the saved testcase against the recorded build. Where useful, create minimized inputs as separate derived artifacts. Group likely duplicates using transparent heuristic signatures, but retain raw artifacts and allow ambiguous cases to remain separate. Record reproduced, not reproduced or inconclusive outcomes.

### Step G — Version-aware comparison
For a prior finding, replay the same saved input against each explicitly recorded version where builds are available. Compare diagnostic category and normalized stack evidence, and retain uncertainty when symbols or code locations differ.

Use only these primary labels:
- **Newly observed**
- **Persistent**
- **Not re-observed**

Show differences in source revision, compiler, flags, harness, corpus and other material settings. Do not claim a finding is fixed solely because a later run did not reproduce it. Do not compare raw AFL++ edge-map identifiers across different builds as though they were stable finding identities.

### Step H — Persistence and reports
Use SQLite for structured metadata and a filesystem artifact store for large files. Reports should connect each conclusion to its original evidence, reproduction attempts and experiment configuration.

### Step I — Dashboard and optional AI
Add the local Flask dashboard after the command-line core workflow is stable. Begin with read-only views. Optional AI may explain evidence and propose investigation questions; it cannot certify a vulnerability, set severity as fact or change finding status.

## 5. Finding lifecycle and language

Keep these states distinct:
1. **Observed crash** — a tool reported abnormal termination or a sanitizer diagnostic.
2. **Reproduced crash** — saved input caused the failure again under a recorded setup.
3. **Triaged candidate** — a reviewer identified a plausible defect mechanism.
4. **Confirmed defect** — the software defect was independently established.
5. **Security-relevant vulnerability** — evidence supports security impact under an explicit threat model.

A crash count is not a vulnerability count. “Unique crash group” is a heuristic, not a proof of a unique root cause. Novelty requires research beyond KEKKAI's own results.

## 6. Reproducibility requirements

Record, at minimum:
- target name, upstream source URL and exact release/commit;
- adapter and harness revision/hash;
- compiler, linker, LLVM and AFL++ versions;
- build flags and sanitizer configuration;
- seed corpus file hashes and dictionary identity;
- campaign arguments, environment, start/end time and resource limits;
- original testcase SHA-256 and artifact path;
- sanitizer report, signal/exit status and stack evidence;
- reproduction and minimization commands/results;
- version-comparison settings and any configuration differences.

Never silently reuse stale build products between materially different configurations.

## 7. Development environment and safety

- Use Ubuntu on WSL 2 for ordinary development and initial controlled fuzzing.
- Keep the repository in the Linux filesystem, not in the Windows-mounted filesystem, for Linux build/fuzz workloads.
- Use Python virtual environments; do not replace Ubuntu's system Python.
- Do not run fuzz targets as root or use sudo for campaigns.
- Apply time, memory and process limits.
- WSL 2 is not a security boundary. Use an appropriately isolated VM for risky samples or reproduction work.
- Do not disable host security controls to improve fuzzing.
- Keep secrets, private source, databases and generated crash artifacts out of Git.

## 8. Work division and review

- **Project owner:** approves scope, target selection and material changes; runs commands and shares test output.
- **Architecture/review lead (assistant):** maintains this decision baseline, researches design choices, reviews agent output, defines acceptance tests and verifies claims.
- **Implementation agent:** implements the approved, bounded engineering task. It must not silently replace the stack, widen scope, claim tests it did not run or commit/push changes outside the agreed workflow.

Use one implementation owner per task. Review a completed slice before starting another major feature.

## 9. Git workflow

- **main** is the stable reviewed baseline.
- **development** is the integration branch.
- Each implementation task uses a focused **feature/<short-name>** branch from development.
- Review diffs and run acceptance checks before merging to development.
- Only verified milestones move from development to main.

## 10. Change control

The workflow is locked as the default plan. It may change only when a concrete technical constraint, test result, project-guide requirement or measured bottleneck justifies it. Record what changed, why, alternatives considered and which phases are affected before implementation adopts the change.

## 11. Repeatable engineering workflow — every task

This procedure applies to every code, test, documentation, build-system, database, dashboard and target-integration task. The phase plan says **what** we build; this section says **how** every change is made and verified. Follow it in order. Do not skip a gate just to move faster.

### 11.1 Define and approve one bounded task

Before editing files, write down:

- **Goal:** one clear behavior or outcome.
- **Reason:** the user problem or technical requirement it solves.
- **Scope:** files/modules expected to change and what is explicitly out of scope.
- **Dependencies and risks:** new packages, external source, platform assumptions, security impact and compatibility concerns.
- **Acceptance checks:** observable conditions that will prove the task is complete.
- **Verification plan:** exact build/test/manual checks that can realistically be run.
- **Recovery plan:** how to revert or disable the change without losing user data or original evidence.

Inspect the current code and documentation before proposing a new module or abstraction. Prefer the smallest complete change. Do not begin implementation while the intended behavior or acceptance criteria are materially ambiguous. Ask one focused question only when a decision cannot safely be inferred; otherwise state a conservative assumption and proceed.

A task is not approved merely because an implementation agent says it is ready. The project owner approves its scope and any material trade-off.

### 11.2 Research and design before implementation

- Read the relevant source files, interfaces, tests, project decisions and applicable upstream documentation.
- Verify version-sensitive claims against the actual pinned version, not only a blog post, search snippet or a different release.
- For third-party source, record the official source URL, exact tag/commit, archive checksum or other available provenance, license and required dependencies before building it.
- Sketch the data flow and interfaces affected. Identify error paths, resource ownership, cleanup, input limits and platform-specific behavior where relevant.
- Reuse a current dependency or standard-library facility where suitable. Add a dependency only when a concrete requirement justifies it; record why and pin or constrain it appropriately.
- Do not design speculative frameworks, plugin systems or generic abstractions for hypothetical future targets.

If research disproves the proposed approach, stop before implementation and present the evidence and a smaller alternative.

### 11.3 Establish an isolated Git checkpoint

For code changes:

1. Start from the latest `development` branch.
2. Check `git status`, the current branch and the latest commit.
3. Do not overwrite, discard, reset or silently stash existing user changes. Stop and inspect a dirty working tree first.
4. Create one focused `feature/<short-name>` branch from the updated `development` branch.
5. Keep unrelated tasks and formatting changes out of that branch.

Documentation-only corrections to this source-of-truth workflow may be made on `development` when explicitly requested. Never develop on `main`. Generated build trees, virtual environments, downloaded third-party source, databases, campaign output, crash artifacts and secrets must stay outside tracked source unless a specific small fixture is intentionally approved.

Use separate clean build directories for materially different source revisions, compilers, flags, sanitizers or instrumentation modes. Never trust stale binaries after changing build inputs.

### 11.4 Implement in small, reviewable slices

- One implementation owner works on a task at a time. Do not have multiple agents edit the same files or implement overlapping designs in parallel.
- Give an implementation agent the approved goal, scope, constraints, acceptance checks and required report format. It may not silently change architecture, dependencies, public interfaces or project scope.
- The implementation agent must not commit or push unless the project owner explicitly authorizes that action. It must report changed files, important design choices, commands actually run, test results, known limitations and unfinished work.
- Make the smallest vertical slice that can be built and exercised. Compile or run targeted checks after each meaningful slice rather than generating a large unverified change.
- Handle errors explicitly. Validate external input, paths and configuration; use safe process argument arrays rather than shell-concatenated commands; set time/resource limits for launched tools; clean up processes and temporary resources on failure.
- Preserve compatibility deliberately. Do not make unrelated refactors, rename public interfaces or reformat entire files as part of a focused fix.
- Do not suppress warnings, weaken tests, remove failing checks or broaden permissions merely to get a green result.

If implementation reveals that the approved scope is insufficient, pause and propose the change with its reason and impact before expanding the task.

### 11.5 Verify from narrow to broad

Run checks in this order, using the checks that apply to the task:

1. **Diff hygiene:** inspect changed files and run `git diff --check`.
2. **Targeted check:** compile or test the exact module/behavior changed.
3. **Regression check:** reproduce the reported defect or add a test that would fail before the fix and pass after it.
4. **Boundary and failure checks:** test invalid, empty, truncated, oversized and unexpected input where relevant; test timeouts, missing files, permission errors and cleanup paths where relevant.
5. **Integration check:** verify interaction with the real neighboring module or pinned third-party target—not only a mock—where feasible.
6. **Clean reproducibility check:** repeat the relevant build/test from a clean, configuration-specific build directory.
7. **Broader suite:** run the existing project test suite and static/format checks that are actually configured.

Do not introduce a new test framework or quality tool without a task-specific reason. A test is evidence only if it was actually run. Record the command, environment/configuration, exit result and any relevant output. Clearly label checks as passed, failed, blocked or not run; never turn “not run” into “passed”.

For KEKKAI's native fuzzing path, compilation alone is not acceptance. The harness must reach the intended library code, behave correctly on representative valid/empty/malformed inputs, produce AFL++ coverage feedback, and run with explicit time and memory limits before a campaign is accepted. Do not start a sustained campaign until those gates pass.

### 11.6 Review correctness, security and scope

Before integration, review the complete diff—not only the agent's summary—and check:

- every changed file belongs to the approved task;
- control flow, error handling, cleanup and resource bounds are correct;
- user-controlled values cannot become arbitrary shell commands or unrestricted paths;
- no secrets, private data, downloaded source archives, generated binaries, databases or crash artifacts were added accidentally;
- dependencies, licenses, source provenance and version pins are appropriate;
- tests cover the changed behavior and a regression case where applicable;
- documentation describes only behavior that exists and has been verified;
- no unsupported vulnerability, performance, compatibility or completion claim is made.

If a review concern is unresolved, do not merge. Record it as a blocker or a known limitation instead of hiding it.

### 11.7 Integrate only after the gate passes

A task can be integrated only when:

- its acceptance checks pass, or every remaining exception is explicitly accepted by the project owner;
- the diff has been reviewed;
- actual test evidence is available;
- required documentation is updated;
- the branch is based on the current `development` branch and has no unexplained changes.

The project owner authorizes commits, pushes and merges. Do not let an implementation agent perform them by default. Merge focused work into `development` only after review. Move verified milestones from `development` to `main` deliberately; `main` is not a working branch.

After integration, verify the resulting branch/commit and working-tree state. Record the commit identifier and what was actually verified.

### 11.8 Handle failures without creating more failures

When a command, build or test fails:

1. Stop the sequence at the first meaningful failure; do not continue as though later output were trustworthy.
2. Preserve the exact error, command, exit code, relevant logs, source revision and tool versions.
3. Identify the failing layer: environment, dependency, configure/build, harness, target, test, orchestration or data.
4. Reproduce the failure with the smallest controlled case.
5. Change one likely cause at a time and rerun the narrowest relevant check.
6. Once corrected, run the regression check and the affected integration checks again.
7. Record unresolved uncertainty and the next safe action.

Do not respond to an unexplained failure by randomly upgrading packages, changing several flags, deleting build/artifact directories or rewriting unrelated code. Clean generated files only after confirming they are disposable; never delete original crash evidence or user data as part of troubleshooting.

### 11.9 Definition of done and task report

A task is **done** only when its intended behavior exists, the agreed acceptance checks have actually passed, the diff has been reviewed, required documentation reflects reality, and the resulting Git state is known. If any of these are missing, report the task as partial or blocked—not complete.

Close each task with a short record:

- **Outcome:** what changed.
- **Files/branch/commit:** where the change lives.
- **Verification:** exact checks run and their pass/fail/blocked status.
- **Limitations:** what remains untested or uncertain.
- **Next action:** one concrete next step.

Keep the work incremental. Complete and verify one task before starting another major task.

## 12. Mandatory stop points

Pause for project-owner review before:

- changing a locked technology, architecture boundary, project goal or target scope;
- adding a non-trivial runtime/build dependency;
- changing a public API or persistent database format;
- expanding from the pilot target to another target;
- running a longer fuzzing campaign or a test with materially different risk/resource requirements;
- transmitting source code, crash artifacts or logs outside the local environment;
- committing, pushing, merging or releasing work when that action has not been explicitly authorized.

Routine implementation choices within an approved task do not need a separate approval round. This keeps control over material risks without turning every small edit into a meeting.

