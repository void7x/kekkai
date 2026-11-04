# Architecture

## 1. Architecture principles

KEKKAI should be built around a small, verifiable fuzzing workflow first and expanded only after it works against a real supported target.

- **Evidence before interpretation:** AFL++ and sanitizers produce observations; analysis layers organise them.
- **Adapters isolate target-specific details:** build steps, harnesses, seeds and dictionaries belong to target adapters.
- **Local-first execution:** the core workflow should not depend on a remote service.
- **Reproducibility:** preserve exact target revisions and experiment configuration.
- **Conservative conclusions:** a crash, reproducible crash, confirmed defect and security vulnerability are distinct states.
- **Optional extensions:** the dashboard, CASR integration and AI assistance must not be hard requirements for a fuzzing campaign.

This document describes the intended design. It is not a claim that the modules already exist.

## 2. High-level data flow

```text
Target Registration
       |
       v
Target Adapter -----> Source Inspection (supporting aid)
       |
       v
Build and Instrumentation
       |
       v
Fuzz Harness + Seed Corpus
       |
       v
AFL++ Campaign <----> ASan / UBSan diagnostics
       |
       v
Raw Crash Evidence
       |
       v
Grouping and Reproduction
       |
       v
Triage and Version Comparison
       |
       +------> SQLite Metadata + Filesystem Artifact Store
       |
       +------> Reports / Local Flask Dashboard
                         |
                         +---- Optional AI Analysis Service
```

The optional AI service consumes selected evidence after collection. It does not control AFL++, decide whether a crash is real, or certify a vulnerability.

## 3. Main components

### 3.1 Target registry

Responsibilities:
- register a supported target and its adapter;
- record local source path and source revision;
- associate a target with recorded versions;
- validate that a requested target is explicitly supported.

A target should not be launched from an arbitrary path supplied to a web request. Registration and execution permissions belong to the trusted local configuration layer.

### 3.2 Target adapter

An adapter is the boundary between generic orchestration and one native software target. It should describe, in a reviewable configuration or implementation:
- target identifier and source revision;
- source/build directory;
- build commands and required dependencies;
- harness source and produced harness binary;
- seed corpus and optional dictionary;
- instrumentation and sanitizer options;
- input/output paths and resource limits.

The first adapter is planned for the candidate libpng target, subject to successful build and harness validation. Keep the adapter interface small until a second target demonstrates which abstractions are genuinely reusable.

### 3.3 Source inspection helper

Clang tooling or libclang may inspect C/C++ declarations and help locate candidate input-processing functions. This is an aid for understanding source code. It does not replace a human-reviewed harness and should not be represented as automatic vulnerability detection.

For the first working milestone, a manually selected entry point and a simple, reviewed harness are acceptable.

### 3.4 Build manager

Responsibilities:
- validate required compiler and build dependencies;
- prepare a clean target build;
- apply selected AFL++ instrumentation and compatible sanitizer flags;
- capture compiler version, build options and output;
- associate the binary with the target revision and harness identity.

Use separate build directories for materially different compiler, sanitizer or instrumentation configurations. Do not silently reuse stale build products.

### 3.5 Fuzzing campaign manager

Responsibilities:
- validate the target adapter and harness before launch;
- prepare a campaign workspace and seed corpus;
- invoke AFL++ with explicit arguments and environment;
- enforce configured duration and resource constraints;
- capture stdout/stderr, exit status and campaign metadata;
- mark interrupted or failed campaigns accurately.

The process layer should use argument arrays (not shell-concatenated command strings), a controlled working directory and validated paths. The dashboard must not expose arbitrary shell execution.

### 3.6 Evidence collector

For each observed crash, preserve:
- original testcase bytes as an artifact;
- a cryptographic hash of the testcase;
- target and source revision;
- build and harness identity;
- campaign identifier and relevant options;
- sanitizer type and diagnostic text, when available;
- observed signal/exit status and timestamps.

Keep large binary inputs in a filesystem artifact store. Keep searchable metadata and artifact references in SQLite. Do not modify the original testcase during minimisation; store minimized inputs as additional derived artifacts linked to the original.

### 3.7 Crash grouping and triage

Grouping may use sanitizer category, signal and normalized stack frames. It is heuristic, not proof that two crashes have the same root cause. Retain raw artifacts and allow a reviewer to split or merge groups.

Use explicit states such as observed, reproduced, triaged, confirmed defect and security-relevant vulnerability. Stronger states require human review.

### 3.8 Reproduction service

Replay a saved input against the matching recorded build and harness where possible. Record the exact command/environment, result, exit status, diagnostic output and whether reproduction succeeded, failed or was inconclusive.

A non-reproducing result is not by itself proof of a false positive or a fix.

### 3.9 Version comparison service

Compare signatures from campaigns associated with explicitly recorded target revisions. Report:
- **Newly observed:** present in the newer campaign and not observed in the earlier campaign.
- **Persistent:** observed in both campaigns.
- **Not re-observed:** observed earlier but absent from the newer campaign.

Do not equate not re-observed with fixed. Fuzzing is finite and non-deterministic; differences in build flags, corpus, duration and coverage can affect observations. Show relevant configuration differences.

### 3.10 Persistence layer

SQLite is planned for relational metadata. Core conceptual records include targets, target versions, adapters/build configurations, campaigns, crash artifacts, crash groups/findings, reproduction attempts, version comparisons, reports and (if approved) AI analysis records.

Use migrations or a controlled schema version from the beginning. Large testcase files and full campaign output should remain outside the database, with paths, hashes and metadata stored in SQLite.

### 3.11 Reporting and local dashboard

A Flask application is planned after the core workflow is verified. Start with read-only views: target and campaign summaries, crash evidence, reproduction history and version comparisons. Later actions may start or stop campaigns only through validated service methods and explicit limits.

### 3.12 Optional AI analysis service

If approved, an AI service may accept a carefully selected bundle of sanitizer output, stack trace, target version and relevant source excerpt. It may return a plain-language explanation, possible root-cause hypotheses, manual investigation steps and a structured report draft.

AI output must include uncertainty and evidence references. It must never be treated as proof, must not automatically alter finding status, and must not be a dependency of the core engine. External transmission of source code, crash inputs or logs must be disabled by default and require explicit configuration and authorization. Credentials, if used, belong only in server-side secret configuration.

## 4. Target adapter lifecycle

1. Register the target and record its source revision.
2. Validate dependencies and source/build paths.
3. Configure a reviewed harness and a small seed corpus.
4. Build a clean instrumented target.
5. Run a short smoke test with known-valid and malformed inputs.
6. Start a bounded AFL++ campaign.
7. Ingest and preserve output artifacts.
8. Replay selected crashes against the recorded build.
9. Review and label observations conservatively.

A target should not be marked supported until this path is tested and documented.

## 5. Data and artifact handling

- Use stable identifiers for targets, versions, campaigns and findings.
- Hash input artifacts so identical bytes can be recognised.
- Preserve original crash files; derived/minimized files are separate artifacts.
- Store paths relative to a controlled artifact root where practical.
- Validate paths before file access and do not trust filenames emitted by external tools.
- Record tool versions and campaign settings to support reproduction.
- Avoid storing secrets or unrelated personal data in logs and crash metadata.

## 6. Security and operational boundaries

- Initial operation is local and limited to targets the user owns or is authorized to test.
- Treat source archives, parser inputs, crash files, logs and AI responses as untrusted data.
- Execute fuzz targets with time, memory and process limits appropriate to the host.
- Do not run target processes with unnecessary privileges; never use `sudo` for fuzzing campaigns.
- Do not expose raw process execution or arbitrary file paths through Flask routes.
- Use safe subprocess argument handling and validate every adapter-defined executable/path.
- Keep credentials out of Git and browser code.
- Do not transmit source files or crash evidence to external AI services by default.
- WSL 2 is a development environment, not a security sandbox. Use an appropriately isolated VM for samples or reproduction workflows that could endanger the Windows host.

## 7. Proposed implementation boundaries

Implement in this order:
1. one reproducible target build and harness;
2. AFL++ campaign execution and sanitizer evidence;
3. crash artifact storage and reproduction;
4. grouping and version comparison;
5. SQLite-backed orchestration and reporting;
6. Flask dashboard;
7. optional integrations such as CASR and AI assistance.

Introduce interfaces where a real second implementation or test need justifies them. Avoid premature abstraction and unused modules added merely to match a planned folder tree.
