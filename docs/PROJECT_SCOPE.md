# Project Scope

## 1. Project identity

**Name:** KEKKAI  
**Full title:** Evidence-Driven C/C++ Vulnerability Discovery and Analysis Platform  
**Type:** Local-first native software security research and engineering project.

KEKKAI helps investigate potential defects in selected C/C++ software that processes untrusted or structured input. It organizes target setup, harness validation, coverage-guided fuzzing, crash evidence, reproduction and cross-version comparison.

The original academic motivation concerns zero-day vulnerability discovery. KEKKAI cannot guarantee a zero-day discovery or prove novelty merely because a fuzzer reports a crash.

The locked technical direction and workflow are defined in [Workflow and Technology Decisions](WORKFLOW_DECISIONS.md).

## 2. Problem statement

Native parsers and other input-processing components can contain defects that are difficult to expose with ordinary tests. Researchers must configure builds and harnesses, run fuzzing campaigns, preserve crash inputs, reproduce failures, distinguish likely duplicates and understand whether an observation also occurs in other software versions.

KEKKAI aims to make this work repeatable and evidence-driven for a carefully selected set of supported targets.

## 3. Aim

Design and implement a modular local platform that orchestrates fuzz testing of selected native C/C++ components and supports evidence collection, crash investigation and version-aware comparison.

## 4. Objectives

1. Establish a reproducible Ubuntu/WSL2 toolchain for native fuzzing.
2. Build and validate one meaningful harness for a selected parser library.
3. Run bounded AFL++ campaigns with compatible ASan/UBSan diagnostics.
4. Preserve original crash artifacts and experiment provenance.
5. Replay, minimize and group crashes without losing original evidence.
6. Compare finding observations across explicitly recorded software versions.
7. Store metadata in SQLite and large artifacts on disk.
8. Add source inspection, reports and a local dashboard after the core works.
9. Evaluate optional AI assistance without making it a core dependency.
10. Evaluate the implementation against controlled test cases and, where compatible, an established benchmark.

## 5. Target scope

### 5.1 Pilot target

**libpng is the first candidate, conditional on feasibility.**

It is a C library that processes structured image input. Before treating it as supported, we must pin an exact source revision, build it cleanly, identify a meaningful parsing path, validate a harness, and prove AFL++ instrumentation and sanitizer diagnostics work.

If these checks fail, document the reason and evaluate one alternative target. Do not claim arbitrary C/C++ target support.

### 5.2 Future target scope

Future adapters may support other native image, archive, document or structured-data parsers. Each target requires its own build profile, harness, seeds and acceptance checks. Additional targets are not part of the first proof of work.

### 5.3 Boundaries

- Local, authorized testing only.
- Native C/C++ target code and harnesses.
- Explicit, reviewed target adapters.
- Bounded fuzzing campaigns.
- No web/network scanning.
- No automatic exploitation.
- No automatic vulnerability or novelty verdict.

## 6. Functional requirements

### FR-01 — Target registration
Record a target identifier, source location, exact source revision, adapter identity and relevant build settings.

### FR-02 — Target adapter
Describe the build steps, harness, seed corpus, optional dictionary, instrumentation and execution constraints for each supported target.

### FR-03 — Harness/build validation
Confirm clean compilation, intended library-code reachability, expected behavior for representative inputs, useful instrumentation feedback and configured resource limits before a campaign is accepted.

### FR-04 — Campaign orchestration
Run AFL++ using validated arguments, controlled working directories and explicit time/resource limits. Preserve logs, exit state, tool versions and campaign configuration.

### FR-05 — Evidence collection
Preserve each original crash testcase and record its SHA-256, target revision, build/harness identity, campaign, diagnostic output, signal/exit status and time. Keep large artifacts on disk and metadata in SQLite.

### FR-06 — Grouping and minimization
Create heuristic crash groups and minimized derivatives where useful. Never overwrite or discard the original testcase. Keep uncertain grouping decisions reviewable.

### FR-07 — Reproduction
Replay saved inputs against the recorded build where possible. Record reproduced, not reproduced or inconclusive, including commands and results.

### FR-08 — Version-aware comparison
Replay prior finding inputs against explicitly recorded versions and compare diagnostic evidence. Use “newly observed”, “persistent” and “not re-observed”. A missing later observation is not proof of a fix.

### FR-09 — Source inspection
Use Clang tooling/libclang later to help locate and rank candidate input-processing functions. This is a source-understanding aid, not an automatic vulnerability detector or substitute for a reviewed harness.

### FR-10 — Persistence and reporting
Store structured experiment and finding metadata in SQLite, link to filesystem artifacts, and produce evidence-linked reports.

### FR-11 — Local dashboard
Add a Flask dashboard after the engine and evidence model are stable. Start with read-only views; do not expose arbitrary command execution.

### FR-12 — Optional AI explanation
If approved, allow an AI service to summarize selected sanitizer reports, stack traces and source excerpts and suggest manual investigation steps. AI results are unverified hypotheses and cannot change finding status or assert a vulnerability. External transmission is disabled by default.

## 7. Finding lifecycle

1. **Observed crash:** a tool reported an abnormal termination or sanitizer finding.
2. **Reproduced crash:** saved input triggered the failure again under a documented setup.
3. **Triaged candidate:** a reviewer identified a plausible defect mechanism.
4. **Confirmed defect:** the underlying defect was independently established.
5. **Security-relevant vulnerability:** security impact is supported under a stated threat model.

A crash, unique crash group, confirmed defect and security vulnerability are not interchangeable.

## 8. Non-functional requirements

- **Reproducibility:** capture exact source, compiler, instrumentation, harness, corpus and campaign configuration.
- **Traceability:** link every finding to its target, version, campaign and original input.
- **Evidence preservation:** originals remain immutable; derived artifacts remain linked.
- **Modularity:** target-specific logic stays in adapters.
- **Reliability:** failed, timed-out and interrupted runs are reported distinctly.
- **Resource control:** support campaign time and memory limits.
- **Local-first operation:** core functionality requires no cloud service or AI model.
- **Security:** no unnecessary privileges, arbitrary dashboard shell execution or external data transfer by default.

## 9. Evaluation

Evaluate in separate categories:

- controlled programs with known injected defects;
- a compatible and documented benchmark such as Magma;
- any independently validated defect discovered during research.

Possible measurements include build/harness success, campaign execution, coverage observations, reproduction rate, evidence completeness, duplicate-group usefulness and version-comparison correctness. A benchmark rediscovery must not be reported as a new zero-day.

## 10. Explicit non-goals

KEKKAI will not initially:
- scan websites or remote networks;
- promise support for arbitrary software;
- automatically exploit crashes;
- guarantee a zero-day discovery;
- label a crash as a vulnerability without triage;
- declare a bug fixed solely because it was not re-observed;
- depend on external AI for core functionality;
- introduce a distributed service architecture without a measured need.

## 11. Current status

The repository is at the documentation and environment-verification stage. The core native toolchain has been verified through AFL++ instrumentation, coverage-feedback and ASan/UBSan smoke tests in Ubuntu on WSL 2. Real target integration, libclang runtime compatibility, and a sustained fuzzing campaign remain unverified. No application engine, target adapter, campaign manager, database or dashboard is currently claimed as implemented.
