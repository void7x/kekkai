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
