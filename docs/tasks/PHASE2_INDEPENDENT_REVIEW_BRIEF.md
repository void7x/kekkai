# KEKKAI Phase 2: Independent Security, Reliability and Architecture Review

## 1. Review assignment

Act as an independent senior security engineer, C/C++ fuzzing engineer,
Python systems engineer and software architect.

Repository: void7x/kekkai
Review branch: fix/phase2-security-remediation
Base commit: 5883c98a9e383daf40045440d456c5afe222a94d
Base branch: feature/fuzzing-orchestration

Review the actual code and tests at the review branch. Compare the branch
against the base commit. Do not rely only on this brief or the remediation
report.

This is an independent audit, not an implementation task.

## 2. KEKKAI's actual product vision

KEKKAI is intended to become an evidence-driven, AI-assisted, version-aware
vulnerability discovery and investigation platform for selected native
C/C++ software.

Its core lifecycle is:

1. Identify interesting input-processing functions in source code.
2. Prepare and validate effective native fuzzing harnesses.
3. Discover and investigate potential defects using controlled fuzzing.
4. Preserve, reproduce, group and minimize observations without losing
   original evidence.
5. Replay identical testcases against explicitly recorded software versions.
6. Compare evidence across versions without making unsupported fixed or
   vulnerable claims.
7. Optionally use AI to explain evidence and suggest investigations.
   AI must never independently declare a vulnerability.

The platform is local-first and evidence-first. It is not intended to be
a generic wrapper around AFL++, an arbitrary command execution service,
or a tool that guarantees zero-day discovery.

## 3. Architecture and technology direction

Current intended architecture:

- Python orchestration.
- Native C/C++ harnesses.
- Clang/LLVM and libclang for future source intelligence.
- AFL++ for coverage-guided fuzzing.
- ASan and UBSan for investigation.
- SQLite for metadata, with large artifacts stored on disk.
- Flask dashboard at a later phase.
- Optional, provider-independent AI integration at a later phase.

Do not recommend a wholesale rewrite or unnecessary new infrastructure.
Evaluate whether Phase 2 creates sound interfaces for later phases.

## 4. Phase 2 scope

Phase 2 extends the initial libpng 1.6.59 pilot into a repeatable,
validated target-adapter workflow.

It includes:

- Strict TOML adapter configuration.
- Target and path validation.
- Authenticated source archive and extracted source-tree identity.
- Controlled native build orchestration.
- Build metadata and provenance verification.
- Harness smoke validation and semantic PNG fixture checks.
- AFL++ coverage-diversity and repeatability checks.
- Bounded single-worker campaign orchestration.
- Controlled subprocess environments and resource limits.
- Process-group cleanup, timeout and interruption handling.
- Campaign storage backed by a dedicated 4 GiB ext4 image.
- Manual, non-destructive failed-build recovery.
- Tests and operator documentation.

Phase 2 is limited to the initial libpng pilot. Do not expect Phase 3 to 7
capabilities to be implemented yet.

## 5. Project context to read

Read the current branch versions of the following documents where present:

- README.md
- docs/PROJECT_SCOPE.md
- docs/ARCHITECTURE.md
- docs/WORKFLOW_DECISIONS.md
- docs/DEVELOPMENT_PLAN.md
- docs/tasks/PHASE2_SECURITY_REMEDIATION.md
- docs/tasks/CAMPAIGN_STORAGE_AND_BUILD_RECOVERY.md

Also inspect the implementation and tests, not just documentation.

## 6. Code areas to inspect

Review the complete branch diff and relevant surrounding code, especially:

- engine/adapters/config.py
- engine/build/libpng.py
- engine/build/runner.py
- engine/build/artifact_limits.py
- engine/build/source_identity.py
- engine/processes.py
- engine/storage.py
- engine/fuzzing/campaign.py
- engine/fuzzing/coverage.py
- engine/fuzzing/preflight.py
- engine/fuzzing/provenance.py
- engine/fuzzing/smoke.py
- targets/libpng/adapter.toml
- scripts/mount_campaign_storage.sh
- scripts/recover_failed_build.py
- all changed and newly added tests

Check other affected modules and callers when an interface or behavior
crosses file boundaries.

## 7. Audit requirements

### A. Security and trust boundaries

Look for:

- Path traversal, unsafe path resolution and symlink attacks.
- TOCTOU vulnerabilities and mutable source/build inputs.
- Unsafe archive parsing, extraction and duplicate-path behavior.
- Unsafe permissions, ownership and filesystem assumptions.
- Root execution and privilege boundary mistakes.
- Subprocess argument injection, shell use and inherited environment risks.
- Untrusted executable or compiler resolution.
- Missing file, archive, log, map or metadata size limits.
- Race conditions in artifact publication and recovery.
- Incorrect trust in metadata or hashes.
- Ways a malformed adapter or filesystem state could escape intended
  target, build or output boundaries.

### B. Build and provenance correctness

Verify:

- The source archive hash is checked against the expected value.
- Extracted source identity is checked correctly.
- Build metadata cannot be reused for a different source, build or config.
- Artifact hashes and provenance fields are actually verified.
- Compiler, AFL++, zlib and build configuration checks are meaningful.
- A partial, interrupted or tampered build cannot be mistaken for a
  completed trusted build.

### C. Process lifecycle and subprocess behavior

Inspect:

- SIGTERM registration and race handling.
- Process-group creation, registration and cleanup.
- Descendant cleanup after normal leader exit and timeout.
- Signal escalation and process reaping.
- Build and campaign interrupted-state metadata.
- Behavior when a child exits between registration and cleanup.
- Signal handler safety and concurrency assumptions.
- preexec_fn usage and multithreaded-host implications.
- Cases where the orchestrator itself is killed with SIGKILL.

### D. Harness, smoke and coverage validation

Inspect:

- Whether test inputs reach the intended target code.
- Whether valid and malformed fixture expectations are correct.
- PNG chunk boundaries, CRC, dimensions, decompression and resource bounds.
- Whether timeout and memory limits are applied as intended.
- Whether coverage maps are validated safely.
- Whether diversity and repeatability checks can produce misleading passes.
- Whether tests verify real behavior or only mock expected outcomes.

### E. Campaign orchestration

Inspect:

- AFL++ argument construction and version compatibility.
- Environment isolation and executable resolution.
- Time, memory, input, output and log bounds.
- Campaign directory creation and collision handling.
- Metadata consistency across completed, failed and interrupted states.
- Watchdog behavior and cleanup after unexpected failures.
- Whether arbitrary commands or arbitrary target paths can be introduced.

### F. Storage and recovery

Inspect:

- Exact image size and filesystem UUID validation.
- Mountpoint, backing-image and device identity verification.
- Ownership, permissions and nodev/nosuid/noexec mount restrictions.
- Symlink and nested-mount handling.
- Behavior at or near filesystem exhaustion.
- Failed-build eligibility checks.
- Recovery path overlap and symlink checks.
- Atomic no-overwrite archive and manifest publication.
- Recovery behavior after interruption or competing writers.
- Whether recovery preserves original logs and partial outputs.

### G. Tests and regression risk

The latest recorded full test run is 143 tests passing.

Independently assess:

- Whether the tests genuinely exercise the claimed behavior.
- Missing boundary, race, failure and interruption tests.
- Mocked tests that may conceal production defects.
- Integration tests that are flaky or incomplete.
- Existing Phase 1 and Phase 2 behavior that could regress.
- Whether test assertions are strong enough to detect incorrect metadata
  or incomplete cleanup.

Do not treat a passing suite as proof that no defects exist.

## 8. Known limitations already acknowledged

Do not report these as newly discovered without identifying an additional
impact or a specific failure beyond the known limitation:

- Source verification is point-in-time. The source tree remains mutable
  between verification and compiler reads.
- Some filesystem path checks remain subject to TOCTOU races.
- The 4 GiB storage filesystem gives an aggregate capacity ceiling, but
  there are no per-campaign reservations or application-managed minimum
  free-space threshold.
- Full-filesystem failure behavior has not been established through
  fault injection.
- Failed-build recovery is manual archival, not automatic retry or restart.
- Tool binaries are version-checked but not cryptographically pinned.
- preexec_fn may be unsafe in a multithreaded host process.
- SIGKILL cannot run the orchestrator's own cleanup handler.

Check whether implementation introduces additional unacknowledged risks.

## 9. Future-phase compatibility

Check that Phase 2 does not unnecessarily block:

Phase 3:
- Immutable original testcase evidence and SHA-256.
- SQLite metadata and filesystem artifact storage.
- Exact build and campaign provenance.
- Reproduction, minimization and transparent grouping.
- Human-reviewed reproduction outcomes.

Phase 4:
- Replay of identical original bytes against explicitly identified versions.
- Traceable build and harness differences.
- Newly observed, persistent and not re-observed labels.
- Not re-observed must never mean fixed.

Phase 5:
- Explainable Clang/libclang source intelligence.
- Human selection of candidate entry points.
- Additional target adapters only after validation.

Phase 6:
- Read-only Flask views and safe service methods.

Phase 7:
- Optional AI assistance, disabled by default for external data transfer.
- AI cannot declare vulnerabilities or change finding status.

Do not demand implementation of these future capabilities in Phase 2.
Identify only genuine interface or design problems that would make later
phases difficult or require unsafe duplication.

## 10. Review safety and access restrictions

This is a READ-ONLY review.

- Do not modify files.
- Do not commit, push, merge or create branches.
- Do not run destructive commands.
- Do not format, mount or unmount storage.
- Do not launch a live AFL++ campaign.
- Do not run unbounded fuzzing or resource-intensive experiments.
- Do not use root privileges.
- Do not attempt exploitation against external systems.
- You may inspect code, inspect Git history and run safe existing unit tests.
- Report any proposed code changes as recommendations only.

## 11. Required output

Return a structured independent audit:

1. Executive verdict:
   - No blocking findings
   - Blocking findings exist
   - Or review inconclusive

2. Findings, each with:
   - Unique ID.
   - Severity: Critical / High / Medium / Low / Informational.
   - Confidence: High / Medium / Low.
   - Exact file and line range.
   - Concrete failure scenario and preconditions.
   - Technical impact.
   - Evidence supporting the finding.
   - Minimal safe reproduction or test proposal.
   - Recommended remediation.
   - Whether it is already documented or previously addressed.

3. Missing tests:
   - Exact behavior not covered.
   - Why existing tests are insufficient.
   - Recommended test.

4. Architecture assessment:
   - Compatibility with the agreed KEKKAI direction.
   - Risks to Phase 3 and Phase 4 interfaces.
   - Unnecessary complexity or duplication, if any.

5. Documentation accuracy:
   - Claims not supported by code or tests.
   - Contradictions between code, reports and roadmap.

6. Final recommendation:
   - Safe to integrate after review.
   - Integrate only after listed fixes.
   - Do not integrate yet.

Be skeptical but evidence-based. Do not invent vulnerabilities, exaggerate theoretical risks, or report style preferences as security defects. Distinguish confirmed defects from hardening suggestions and false positives.

The review must identify the exact commit SHA audited.
