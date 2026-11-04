# Project Scope

## 1. Project identity

**Name:** KEKKAI  
**Full title:** Modular C/C++ Vulnerability Discovery and Analysis Platform  
**Project type:** Local-first software security research and engineering project.

KEKKAI is intended to help users discover, reproduce and investigate potential defects in selected native C/C++ software components that process untrusted or structured input. It combines target-specific fuzzing setup, coverage-guided fuzzing, runtime diagnostics, crash evidence management and cross-version comparison.

The word **zero-day** in the academic project title describes the research motivation. The platform cannot establish that a defect is unknown to the vendor or the wider community, and it cannot guarantee that a zero-day will be discovered.

## 2. Problem statement

Testing input-processing native software is difficult because malformed or unexpected inputs can reach complex parsing paths. Manual testing and isolated command-line tools can produce useful evidence, but researchers still need to configure builds and harnesses, manage fuzzing campaigns, preserve crashes, reproduce failures, distinguish duplicate reports and compare behavior across versions.

KEKKAI aims to organise those activities into a repeatable workflow for a deliberately limited set of supported C/C++ targets.

## 3. Aim

To design and implement a modular platform that orchestrates local fuzz testing of selected C/C++ parser libraries and helps analyse, validate, record and compare potential defects using reproducible evidence.

## 4. Objectives

1. Define a target-adapter approach for supported native C/C++ components.
2. Record target identity, source version and build configuration for each experiment.
3. Prepare or configure an appropriate fuzzing harness and initial seed corpus.
4. Build targets with compatible fuzzing instrumentation and runtime diagnostics.
5. Orchestrate bounded AFL++ coverage-guided campaigns.
6. Preserve crash inputs and diagnostic output as traceable evidence.
7. Group likely duplicate crashes without deleting original evidence.
8. Replay saved inputs to assess reproducibility.
9. Compare finding signatures between recorded target versions without treating a missing observation as proof of a fix.
10. Present campaign and finding records through local reports and, in a later phase, a Flask dashboard.

## 5. Initial target scope

### 5.1 Candidate pilot

**libpng** is the proposed first target because it is a native C library that processes structured image input. It is a candidate, not yet a validated integration.

Before committing to a full campaign, the team must:
- verify that the selected source release or commit can be built in the chosen Ubuntu environment;
- identify an appropriate public parsing entry point and a suitable harness strategy;
- record the exact source revision and build options;
- confirm that the selected build can be instrumented with the intended AFL++ and sanitizer toolchain.

The exact libpng release or commit must be pinned in target configuration and recorded with each campaign. Do not assume that an upstream-provided harness, corpus or result is original KEKKAI work.

### 5.2 Extensibility

The design should allow future adapters for other selected C/C++ libraries that process structured or externally supplied data (for example, archive, document or image parsers). Additional targets are future work and must not be described as supported until their adapters and test workflows pass.

### 5.3 Initial constraints

- Initial campaigns run locally in a controlled Ubuntu/WSL2 development environment.
- Target selection and adapter configuration are explicit; the MVP does not promise automatic support for arbitrary source trees.
- A custom harness or build configuration may be required for each target.
- Fuzzing duration, memory and CPU use must be bounded.
- Source inspection with Clang tooling/libclang may assist investigation, but it does not automatically identify a correct harness or prove a defect.

## 6. Functional scope

### F-01 — Target registration and provenance
The system should record a target name, local source location, exact version or commit, adapter identifier and relevant build details.

### F-02 — Target adapter
A supported target should have an explicit adapter configuration describing its build steps, harness, seed corpus, optional dictionary, instrumentation options and execution constraints.

### F-03 — Instrumented build
The build workflow should record compiler/toolchain versions and options. It should fail clearly when required dependencies or instrumentation are unavailable.

### F-04 — Fuzz campaign orchestration
The platform should invoke AFL++ for a configured local target using structured process arguments, a known working directory and explicit time/resource limits. Campaign configuration and logs should be retained.

### F-05 — Evidence collection
For each observed crash, preserve the original test case and relevant metadata, including target revision, campaign, harness/build identity, diagnostic output and timestamp. Large binary artifacts should be stored on disk, with their paths and hashes recorded in the database.

### F-06 — Crash grouping
The system may group likely duplicates using reproducible signatures such as sanitizer type and normalized stack information. Grouping is heuristic: it must not discard raw evidence, and ambiguous cases must remain reviewable.

### F-07 — Reproduction and triage
A saved test case should be replayable against its recorded build when possible. The system should record whether a crash reproduced, did not reproduce or could not be tested. A crash is not automatically a confirmed vulnerability.

### F-08 — Version comparison
The system should compare finding signatures across explicitly recorded versions:
- **Newly observed:** present in the newer campaign and not observed in the earlier campaign.
- **Persistent:** observed in both campaigns.
- **Not re-observed:** observed earlier but absent from the newer campaign.

“Not re-observed” must not be presented as “fixed” without independent validation. Fuzzing is finite and non-deterministic.

### F-09 — Reports and dashboard
The system should produce a technical summary of targets, campaigns, observed crashes, reproduction state and version comparisons. A local Flask dashboard is planned after the core engine is validated.

### F-10 — Optional AI assistance
An optional AI service may summarise selected sanitizer output, stack traces and source context, and suggest investigation steps. This enhancement is proposed and subject to project-guide approval. AI output must be marked as an unverified hypothesis, must not independently mark a finding as a vulnerability, and must not be required for the core workflow.

## 7. Finding terminology and lifecycle

KEKKAI should use conservative statuses:

1. **Observed crash:** a tool reported an abnormal termination or sanitizer finding.
2. **Reproduced crash:** the saved input triggered the recorded failure again under a documented setup.
3. **Triaged candidate:** evidence has been reviewed and a plausible defect mechanism is identified.
4. **Confirmed defect:** the underlying software defect has been independently established.
5. **Security-relevant vulnerability:** evidence supports a security impact under a stated threat model.

The system must not automatically promote a crash to a confirmed defect or vulnerability. Novelty and security impact require investigation beyond the fact that a fuzzer found a crash.

## 8. Explicit non-goals

The initial project is not intended to:
- scan websites or remote networks;
- fuzz arbitrary software without a reviewed target adapter;
- automatically exploit crashes or generate weaponised payloads;
- guarantee discovery of all defects or any zero-day;
- claim that a crash is a vulnerability without triage;
- declare a defect fixed solely because a later campaign did not reproduce it;
- require an external AI service for core functionality.

## 9. Non-functional requirements

- **Reproducibility:** record source revision, build configuration, tool versions, harness identity, corpus identity and campaign options.
- **Traceability:** each finding should link back to its target, version, campaign and original input evidence.
- **Modularity:** target-specific build and harness details should remain in adapters rather than being hard-coded throughout the platform.
- **Reliability:** campaign failures and interrupted runs should be represented explicitly, not silently treated as successful.
- **Resource control:** campaigns must support timeouts and memory/CPU limits appropriate to the environment.
- **Local-first operation:** the core workflow should work without an external AI API or cloud service.
- **Security:** do not expose arbitrary command execution through the dashboard; protect secrets and treat test inputs and logs as untrusted data.

## 10. Evaluation approach

Evaluation should use controlled demonstration programs with known defects and, where compatible with the chosen toolchain and licensing, an established fuzzing benchmark such as Magma. Measurements may include campaign duration, coverage observations, unique crash groups, reproduction rate, triage usefulness and version-comparison correctness.

Benchmark results, controlled-test results and newly discovered defects must be reported separately. A benchmark rediscovery is not a new zero-day discovery.

## 11. Project status

At repository initialization, KEKKAI is at the documentation and environment-setup stage. No fuzzing engine, target adapter, database, dashboard or AI service is claimed as implemented. Each capability will be marked complete only after implementation and verification.
