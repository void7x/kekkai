# Architecture

## 1. Principles

KEKKAI is built around a real, reproducible native fuzzing workflow—not a dashboard or a large collection of empty modules.

1. **Evidence first:** preserve what the tools actually observed.
2. **Target adapters:** isolate target-specific build, harness and corpus details.
3. **Validated harnesses:** a successful compile is not proof that fuzzing reaches the intended code.
4. **Reproducibility:** every result links to exact source and experiment configuration.
5. **Version awareness:** replay the same evidence across recorded software versions.
6. **Conservative interpretation:** a crash is not automatically a defect or vulnerability.
7. **Local-first and modular:** optional integrations must not block the core engine.

This is an intended architecture. The modules are not yet implemented.

## 2. System data flow

~~~text
Target Registry + Pinned Source Revision
                  |
                  v
       Target Adapter / Build Profile
                  |
        +---------+---------+
        |                   |
        v                   v
 Source Inspection     Native Harness
 (later, supporting)        |
                            v
                 Harness + Build Validation
                            |
                            v
                  AFL++ Campaign Manager
                     + ASan / UBSan
                            |
                            v
                    Raw Crash Evidence
                            |
                            v
                Reproduction / Minimization
                            |
                            v
                 Grouping and Human Triage
                            |
                            v
              Version-aware Replay / Comparison
                            |
                 +----------+----------+
                 |                     |
                 v                     v
          SQLite Metadata       Filesystem Artifacts
                 |
                 v
           Reports / Dashboard
                 |
                 +---- Optional AI explanation
~~~

## 3. Components and responsibilities

### 3.1 Target registry

Stores target identity, exact upstream revision, adapter, local source path and supported build profiles. Only explicitly registered and validated targets may be launched.

### 3.2 Target adapter

An adapter describes one supported target:
- upstream source and exact version/commit;
- source and build directories;
- dependencies and build commands;
- selected input-processing entry point;
- harness source and binary;
- seed corpus and optional dictionary;
- instrumentation/sanitizer options;
- resource limits and expected execution behavior.

Keep the interface minimal until a second target proves which details are truly reusable. The pilot adapter is for libpng, conditional on feasibility.

### 3.3 Source inspection

Clang tooling/libclang may later parse declarations and help locate functions that receive input buffers, streams or structured data. It should rank candidates with explainable signals and point to source locations. It does not prove reachability, synthesize a trustworthy harness by itself or detect vulnerabilities automatically.

The first proof of work may use a manually selected public API and manually written harness.

### 3.4 Build manager

Builds the target and harness in a clean, configuration-specific directory. It captures compiler, linker, LLVM and AFL++ versions, command arguments, flags, output and resulting binary identity. It must not silently reuse outputs from a different compiler, sanitizer or instrumentation configuration.

### 3.5 Harness validation

Before launching a long campaign, run an explicit validation stage:
- compilation succeeds from a clean state;
- the harness calls the intended target API;
- representative valid inputs reach the target and behave as expected;
- empty and malformed inputs are handled by the harness without unrelated harness defects;
- coverage feedback changes across representative inputs;
- the harness is sufficiently deterministic for its configured execution mode;
- timeout and memory settings are enforced.

The validation report should explain which checks passed, failed or were not applicable. It must not pretend that a single metric proves harness quality.

### 3.6 Fuzzing campaign manager

Runs AFL++ through a safe process layer. It validates adapter paths and arguments, uses argument arrays rather than shell-concatenated commands, sets a controlled working directory and captures environment/log/exit details. It supports explicit campaign duration and resource limits. A failed or interrupted campaign remains distinguishable from a successful campaign.

Start with a simple AFL++ mode. Consider parallel workers, dictionaries, corpus minimization and persistent mode only when a use case and correctness test justify them. Persistent mode requires reliable state reset; speed alone is not sufficient.

### 3.7 Evidence collector and artifact store

For every observed crash:
- preserve the original bytes unchanged;
- calculate SHA-256;
- record target revision, build profile, harness identity and campaign;
- save sanitizer output, signal/exit status and timestamp where available;
- retain the source path or artifact identifier.

Large testcases, minimized derivatives and logs belong in a controlled filesystem artifact store. SQLite stores searchable metadata, hashes and references. Minimized inputs are separate derived artifacts linked to their original.

### 3.8 Reproduction and minimization

Replay an artifact against the exact recorded build when possible. Store command, environment, result, exit status and diagnostic output. Record one of reproduced, not reproduced or inconclusive.

Minimization may use AFL++ tooling after a failure can be reproduced. Never replace the original input with the minimized one.

### 3.9 Crash grouping and triage

Create candidate signatures from evidence such as sanitizer category, signal and normalized stack frames. Treat these signatures as heuristics: different bugs can share stack shapes, and one bug can produce different stacks across builds. Keep raw artifacts and reviewer override ability.

A finding's status is advanced only through evidence and human review.

### 3.10 Version-aware comparison

This is a primary KEKKAI capability.

For each prior finding:
1. Identify the exact source revisions and their recorded build/harness configurations.
2. Replay the original saved testcase against each available version.
3. Collect sanitizer category, signal, normalized stack and reproduction results.
4. Compare evidence while exposing configuration differences.
5. Record the result as newly observed, persistent or not re-observed, with uncertainty where matching is ambiguous.

Do not treat raw AFL++ edge-map IDs as stable identifiers across different builds. Do not infer “fixed” from absence in a finite campaign. A changed stack or symbol location may require manual mapping.

### 3.11 Persistence layer

SQLite stores targets, versions, adapter/build profiles, harness records, campaigns, artifact metadata, crash groups/findings, reproduction attempts, version comparisons and reports. Use controlled schema versions/migrations. Store binary inputs and large logs outside SQLite.

Add persistence when the first stable evidence records are defined; do not build a complicated database before the first target proof of work.

### 3.12 Reporting and dashboard

Generate evidence-linked reports from stored records. Add Flask only after the engine and core data model are stable. The first dashboard should be read-only. Any later campaign controls must call validated service methods and enforce explicit limits; Flask routes must never expose arbitrary shell commands or unrestricted filesystem access.

### 3.13 Optional AI explanation

If approved, pass only selected evidence such as sanitizer output, stack trace, target version and a relevant source excerpt. AI may explain terminology, suggest root-cause hypotheses and propose manual checks. It must cite the evidence it used and label uncertainty.

AI cannot verify a vulnerability, decide novelty, set a factual severity, or change finding state. External transfer of source code, crashes or logs is disabled by default. The core workflow must function with AI disabled.

## 4. Core data model (conceptual)

- **Target:** project/library identity.
- **TargetVersion:** exact source revision and provenance.
- **BuildProfile:** compiler/tool versions, flags, sanitizer and instrumentation options.
- **Harness:** source/binary identity and validation result.
- **Campaign:** target version, build, harness, corpus, arguments, limits, timestamps and outcome.
- **Artifact:** original or derived input/log, hash, type and storage reference.
- **FindingGroup:** heuristic grouping of one or more observations.
- **ReproductionAttempt:** artifact, build, command and result.
- **VersionComparison:** compared versions, replay evidence, label and confidence/notes.
- **Report:** a generated view of recorded evidence.

The schema should be implemented only when the fields have a demonstrated use. Prefer migrations and explicit identifiers.

## 5. Security and operational boundaries

- Run only authorized local targets.
- Do not run fuzz targets as root.
- Bound time, memory and process count.
- Treat target source, archives, inputs, logs and AI responses as untrusted data.
- Validate every path and executable configured by an adapter.
- Keep process invocation out of direct web request handlers.
- Keep credentials and generated crash artifacts out of Git.
- Do not transmit source, testcases or logs to an external model by default.
- WSL 2 is a development workspace, not a security sandbox. Use a properly isolated VM for risky samples.

## 6. Implementation boundary

The first milestone is one target, one meaningful harness, one instrumented build and one bounded campaign. Do not build the dashboard, broad source analyser, automatic harness generator, distributed system or AI service before this path works.

Create abstractions only when they reduce actual duplication or make a tested responsibility clearer.
