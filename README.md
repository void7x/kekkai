# KEKKAI

**KEKKAI — Evidence-Driven C/C++ Vulnerability Discovery and Analysis Platform**

KEKKAI is a local-first research platform for discovering, reproducing and investigating potential defects in selected native C/C++ software that processes untrusted or structured input.

Its defining capability is **evidence-driven, version-aware investigation**: a crash is preserved with the exact experiment that produced it, replayed for confirmation, and checked against other recorded software versions. KEKKAI reports what the evidence supports; it does not turn every crash into a claimed vulnerability.

> **Current status:** Phase 0 and Phase 1 are complete. The libpng 1.6.59 Phase 2 adapter and security remediation have received an independent **APPROVED WITH ACCEPTED LIMITATIONS** verdict at commit `a55326e0a58680895ce82de5b0b2b3056f8f1669`. GitHub Actions and local WSL verification passed all 166 automated tests; local build provenance, preflight, 13 smoke cases, 10 distinct AFL++ coverage maps and Adam7 repeatability also passed. P2-006, P2-008 and P2-009 have documented non-blocking follow-ups. See [Phase 2 Security Remediation Verification](docs/tasks/PHASE2_SECURITY_REMEDIATION.md) for the audit, evidence and accepted limitations. Integration into `development` is pending pull-request review. No new live AFL++ campaign was run during remediation.

## Locked project direction

The engineering workflow is recorded in [Workflow and Technology Decisions](docs/WORKFLOW_DECISIONS.md). That document is the project source of truth for scope, architecture, technology choices and implementation order. Changes to those decisions require a documented reason and review.

### Initial target

The first proof-of-work target, **libpng 1.6.59**, has completed its manual integration pilot. The pinned source, target-specific C harness, baseline and instrumented builds, coverage checks, bounded smoke campaign and retained-corpus sanitizer replay are documented under `docs/tasks/`.

The manual libpng pilot has since been extended into a reusable target adapter and bounded campaign orchestrator. The implementation and its historical live-campaign evidence are recorded in the Phase 2 verification report. The security-remediation review and its remaining limitations are recorded in the [security remediation report](docs/tasks/PHASE2_SECURITY_REMEDIATION.md).

### Core workflow

1. Register a supported target and pin its source revision.
2. Prepare a target-specific build, reviewed fuzz harness and seed corpus.
3. Validate the harness and instrumented build with smoke tests.
4. Run a bounded AFL++ coverage-guided fuzzing campaign with compatible ASan/UBSan diagnostics.
5. Preserve every original crash input and its provenance; group likely duplicates without discarding evidence.
6. Replay and, where useful, minimize saved inputs while retaining the original artifact.
7. Compare prior finding inputs and signatures across explicitly recorded target versions.
8. Store experiment metadata in SQLite and large artifacts on disk; produce reports.
9. Add the local dashboard only after the core workflow works.
10. Evaluate optional AI-assisted explanations only after the evidence pipeline is reliable and the privacy/approval requirements are settled.

### Version-comparison language

KEKKAI will use conservative labels:

- **Newly observed** — observed in the later experiment but not in the earlier recorded experiment.
- **Persistent** — observed in both.
- **Not re-observed** — observed earlier but not seen in the later experiment.

“Not re-observed” does not mean “fixed”. Fuzzing is finite and non-deterministic; configuration differences and changed execution paths can affect results.

## Technology decisions

| Area | Decision |
|---|---|
| Orchestration and platform logic | Python |
| Native target and harness code | C/C++ |
| Compiler and source tooling | Clang/LLVM; libclang/Clang tooling for later source inspection |
| Coverage-guided fuzzer | AFL++ |
| Runtime diagnostics | AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan), where compatible |
| Metadata | SQLite |
| Large crash and campaign artifacts | Filesystem artifact store with hashes and database references |
| Dashboard, after core validation | Flask with HTML/CSS/JavaScript |
| Optional crash triage helper | CASR, after compatibility review |
| Evaluation | Controlled known-defect programs and a compatible benchmark such as Magma |
| Optional AI | Evidence summarization only; never required by the core workflow |

We are **not** switching the whole project to Rust, introducing microservices, building the dashboard first, or depending on a local or external AI model for core functionality. A technology change requires measured need and review.

## Development order

- **Phase 0:** Verify Ubuntu/WSL2 and the native fuzzing toolchain.
- **Phase 1:** Build and fuzz the first target with a validated minimal harness.
- **Phase 2:** Harden harness checks, target adapters and campaign orchestration.
- **Phase 3:** Build crash evidence, reproduction, minimization, grouping and persistence.
- **Phase 4:** Implement version-aware replay and comparison.
- **Phase 5:** Add source inspection and additional target adapters only when justified.
- **Phase 6:** Add a local reporting layer and Flask dashboard.
- **Phase 7:** Evaluate optional AI assistance, benchmarks and final hardening.

The acceptance checks for each phase are in [Development Plan](docs/DEVELOPMENT_PLAN.md).

## Repository layout

The repository will grow only as implementation needs each module. The planned shape is:

~~~text
kekkai/
├── engine/
│   ├── adapters/
│   ├── build/
│   ├── harnesses/
│   ├── fuzzing/
│   ├── evidence/
│   ├── triage/
│   └── versioning/
├── targets/
│   └── libpng/
├── backend/             # later: Flask application
├── tests/
├── scripts/
└── docs/
~~~

Do not create empty modules just to match this tree. Large generated campaigns, databases, crash artifacts and secrets stay out of Git.

## Development environment

Ubuntu on WSL 2 is the primary development environment. Keep the working repository in the Linux filesystem (for example, /home/sahil/kekkai) for native build and fuzzing workloads. Use a Python virtual environment for project packages. The precise package installation path depends on the Ubuntu release and available LLVM/AFL++ versions.

WSL 2 is a development environment, not a security sandbox. Do not run campaigns as root. Use a suitably isolated VM for experiments that could endanger the host.

## Git workflow

- **main:** stable, reviewed milestones.
- **development:** integration branch.
- **feature/<short-name>:** focused implementation branches created from development.

Review and test feature work before integrating it into development; merge only stable milestones into main.

## Responsible research and limitations

Use KEKKAI only on software you own, software you are explicitly authorized to test, or research targets whose terms permit the work. Campaigns must have time and resource limits.

A fuzzer crash is an observation, not automatically a defect or security vulnerability. Reproduction, technical triage, impact analysis and any novelty assessment require separate evidence. KEKKAI cannot guarantee discovery of a zero-day.

## Documentation

- [Workflow and Technology Decisions](docs/WORKFLOW_DECISIONS.md)
- [Project Scope](docs/PROJECT_SCOPE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Development Plan](docs/DEVELOPMENT_PLAN.md)
- [Development Environment Snapshot](docs/ENVIRONMENT.md)
