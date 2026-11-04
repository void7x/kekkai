# KEKKAI

**Kekkai — Modular C/C++ Vulnerability Discovery and Analysis Platform**

Kekkai is a planned, local-first research platform for discovering and investigating potential defects in selected native C/C++ software components that process untrusted or structured input.

The initial work will focus on establishing a reproducible fuzzing workflow for one supported parser library, then building the platform around that verified workflow. The first candidate target is **libpng**, subject to build and harness feasibility checks. Its exact source release or commit will be pinned and recorded before a campaign is treated as an experiment.

> **Project status:** Initial repository and project documentation only. The fuzzing engine, adapters, database, dashboard and AI-assisted analysis are planned; they are not implemented yet.

## What Kekkai is intended to do

1. Register a supported local C/C++ target and record its exact source version.
2. Configure a target-specific build, fuzzing harness and initial seed corpus.
3. Build the target with suitable fuzzing instrumentation and runtime diagnostics.
4. Run bounded, coverage-guided fuzzing with AFL++.
5. preserve crash inputs and diagnostic evidence, group likely duplicates, and replay findings.
6. Compare observed finding signatures across recorded software versions.
7. Present campaign and finding information through a local dashboard and reports.

The initial supported scope is deliberately narrow. The architecture should allow additional target adapters later, but Kekkai will not claim support for arbitrary C/C++ software until each adapter has been implemented and tested.

## Important terminology

A fuzzer-reported crash is an **observation**, not automatically a vulnerability. A finding must be reproduced and triaged before stronger conclusions are made. The project can help investigate potential previously unknown defects; it cannot guarantee discovery of a zero-day or prove that a defect was previously unknown.

## Planned technology

| Area | Planned technology |
|---|---|
| Platform orchestration | Python |
| Native target compilation | Clang/LLVM and, where useful, GCC |
| Coverage-guided fuzzing | AFL++ |
| Runtime diagnostics | AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan), where compatible |
| C/C++ source inspection | Clang tooling / libclang, as a supporting aid |
| Local metadata store | SQLite |
| Local dashboard (later phase) | Flask, HTML, CSS, Bootstrap and JavaScript |
| Optional crash analysis | CASR, after compatibility checks |
| Evaluation | Controlled test programs and a compatible benchmark such as Magma |
| Version control | Git and GitHub |

Versions and build options will be recorded per target and campaign. The table is a plan, not a claim that these dependencies are already installed or integrated.

## Planned repository layout

The following is the intended layout as implementation grows; folders will be added when their modules are introduced.

```text
kekkai/
├── backend/
│   └── app/                 # Flask application (later phase)
├── engine/
│   ├── adapters/             # Target-specific configuration
│   ├── harnesses/            # Native fuzzing harnesses
│   ├── fuzzing/              # Campaign orchestration
│   ├── crash_analysis/       # Evidence ingestion and triage
│   └── regression/           # Cross-version comparison
├── targets/
│   └── libpng/               # Initial candidate target adapter
├── tests/
├── scripts/
├── docs/
├── README.md
└── .gitignore
```

Large generated outputs, crash artifacts, local databases and secrets should stay out of Git. Small, curated seed files and reproducible test fixtures may be versioned when their provenance and licensing are clear.

## Development environment

The planned development environment is Ubuntu on WSL 2. Keep the working repository in the Linux filesystem (for example, `/home/sahil/kekkai`) rather than under `/mnt/c` for Linux build and fuzzing workloads.

The initial setup will use Ubuntu packages for system tools and a Python virtual environment for Python dependencies. Exact installation instructions will be added after the toolchain versions are checked.

## Git workflow

- `main`: stable, reviewed project state.
- `development`: integration branch for verified work.
- `feature/<short-name>`: focused implementation branches.

Changes should be reviewed and tested before merging into `development`; only stable, verified milestones should be merged into `main`. Do not commit credentials, API keys, private data, unreviewed crash samples or large generated campaign output.

## Responsible testing

Use Kekkai only with software you own, software for which you have explicit authorization to test, or research benchmarks and demonstration targets whose terms permit testing. Initial campaigns are intended to run locally in a controlled environment with resource limits. Kekkai is not a remote web scanner, an exploit-generation tool, or a guarantee of security.

## AI-assisted analysis (optional proposal)

An optional AI analysis service may later summarize sanitizer reports, stack traces and selected source context to suggest investigation steps. It will not replace fuzzing, reproduction or human triage, and its output must be labelled as a hypothesis rather than a confirmed vulnerability. This enhancement is subject to project-guide approval and privacy review; the core fuzzing workflow must remain usable without an AI service. No source code or crash data should be sent to an external model unless that behavior is explicitly configured and authorized.

## Documentation

- [Project scope](docs/PROJECT_SCOPE.md)
- [Architecture](docs/ARCHITECTURE.md)
- [Development plan](docs/DEVELOPMENT_PLAN.md)

