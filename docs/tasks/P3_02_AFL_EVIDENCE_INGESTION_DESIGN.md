# P3-02 Design: Immutable AFL Crash/Hang Evidence Ingestion

**Status:** Approved for implementation after independent read-only review  
**Base:** `development` at `bc738fbcbd0febcaa728440265601285d3295138`  
**Feature branch:** `feature/p3-02-afl-evidence-ingestion`  
**Scope:** Offline ingestion of terminal, single-worker libpng AFL++ campaigns into the P3-01 evidence store.  
**No implementation has started.**

## 1. Goal

Provide one explicit, repeatable operation that imports the original testcase files saved by AFL++ under a completed, failed or interrupted KEKKAI campaign. Each imported crash or hang becomes:

1. A content-addressed, read-only artifact in the P3-01 filesystem store.
2. An immutable `artifacts` row containing its SHA-256, size and storage path.
3. An immutable `observations` row linked by foreign keys to the exact target, target version, build and campaign.

The import must be safe to retry. It must not modify or delete the campaign output or the original AFL testcase files. An AFL observation remains an observation, not a confirmed defect or vulnerability.

## 2. Current-code findings

- `engine/fuzzing/campaign.py` writes an atomically replaced `campaign.json` with schema version 1. It records the campaign ID, terminal status, target/version, source and harness paths, seed directory, expected AFL++ version, configured limits, exact command, adapter-config path, validation reports and start/end times.
- Schema v1 does **not** record a hash of the adapter TOML or a seed-corpus manifest at campaign start. Hashing those files only at import time would not prove they were the files used by the campaign.
- `engine/build/runner.py` writes schema-v2 `build.json` with source archive/tree identities, build commands, environment, timestamps and hashes of the harness, library archive, CMake cache, compile database and generated header.
- P3-01 already provides the required seven tables, idempotent repository insert methods, SHA-256 content-addressed publication, source-file stability checks, immutable artifacts and observations, and the campaign/build foreign-key chain. No P3-01 schema change is proposed.
- The active libpng adapter is schema 4 and pins AFL++ 4.33c, a dedicated campaign output filesystem, and a single-worker command. The importer will support that current workflow only; it will not silently generalize to multiple AFL workers or other targets.

## 3. Provenance decision: campaign metadata schema v2

Update the campaign runner to emit `campaign.json` schema version 2. Before the first campaign write and before AFL++ starts, record an `identity` object containing:

- `adapter_config_sha256`: SHA-256 of the exact adapter TOML bytes.
- `seed_manifest_sha256`: SHA-256 of a canonical, filename-sorted manifest containing each direct regular seed file's name, byte size and SHA-256.
- `seed_count`: number of direct regular seed files in that manifest.
- `build_metadata_sha256`: SHA-256 of the verified `build.json` used by the campaign.

Also record a structured `toolchain` object with `compiler_version` and `aflpp_version` from the successful build-provenance result, plus `afl_showmap_version` from the successful coverage result. Do not make the importer parse human-readable report strings. The expected AFL++ version must match the observed `aflpp_version`.

The seed-manifest helper must enforce the existing preflight bounds (maximum 4,096 direct entries and 512 MiB total), reject symlinks and special files, open files without following links, and detect a file changing while it is hashed. It must produce deterministic canonical JSON and a stable digest.

At import time, recompute and compare the adapter-config, seed-manifest and build-metadata hashes. A missing or changed input means the importer cannot establish the original campaign provenance and must refuse the import before publishing or inserting anything.

**Compatibility rule:** schema-v1 campaign directories are not ingestible by P3-02 because they lack launch-time adapter/seed/build identity hashes. The importer must return a specific error explaining this. Do not manufacture historical hashes from whatever files happen to exist later. Existing schema-v1 campaigns remain intact and can still be inspected manually. A future, separately reviewed legacy-import path would need explicit provenance limitations; it is not part of this task.

## 4. Import API and CLI

Add a focused service, proposed as `engine/evidence/afl_ingest.py`, and a small operator entry point, proposed as `scripts/ingest_afl_evidence.py`.

The CLI takes explicit absolute paths:

- `--campaign-dir`: one terminal campaign directory.
- `--config`: the exact adapter TOML used by the campaign.
- `--evidence-root`: the separate P3-01 evidence-store root.

No automatic campaign-directory crawling, live-process integration, background watcher, network access or arbitrary command execution.

The CLI initializes/verifies the existing P3-01 store and migrations, then calls the service. It must refuse root execution. The evidence root must not overlap the repository, source tree, build directory or campaign output parent.

## 5. Validation gates before any artifact publication

The service must validate the complete campaign before the first write:

1. **Paths and ownership**
   - Require absolute, existing, user-owned paths with no symlink components.
   - Re-verify the adapter's pinned campaign-storage mount and require the campaign directory to be a direct child of its configured output parent.
   - Require the campaign directory, detected single-worker output root, and both `crashes/` and `hangs/` directories to be plain user-owned directories on the expected campaign filesystem. Both `crashes/` and `hangs/` must exist. A failed/interrupted campaign that ended before AFL++ created these directories is refused with a clear no-output validation error before any evidence-store write.
   - Require `campaign.json` to be a regular, user-owned, bounded file opened without following symlinks. Read it stably and reject duplicate JSON keys.

2. **Campaign identity**
   - Accept only metadata schema version 2 and a valid 38-byte `campaign-YYYYMMDDTHHMMSSZ-<12 lowercase hex>` identity.
   - Require the directory basename and `campaign_id` to agree.
   - Accept only terminal `completed`, `failed` or `interrupted` states with valid start/end timestamps. Reject `running`, missing end time, inconsistent target/version, mismatched adapter path or altered command/output paths.
   - Verify the captured adapter, seed and build metadata hashes against the exact files and paths used by this campaign.

3. **Build and target provenance**
   - Validate the current schema-v2 `build.json`, its campaign-captured hash, terminal completed state, target/version/profile/build-directory identity and recorded build-step structure.
   - Re-hash the six recorded build outputs and require them to match `build.json`; verify the pinned source archive/tree identity and harness identity against their recorded hashes and fixed build contract.
   - Do not re-run compiler or AFL++ version probes during historical import. Use the exact campaign-time version facts preserved in the successful provenance report inside `campaign.json`; refuse the import if required facts are absent or malformed.
   - Populate target, target-version and build records only from these verified records. Never infer a missing compiler version or substitute the currently installed version for a campaign-time version.
   - The deterministic `builds` mapping for this fixed profile is: `build_role='fuzz'`; `compiler_path='/usr/bin/afl-clang-fast'` from the verified recorded build command; `compiler_version` from the campaign-v2 structured toolchain; `cmake_build_type='RelWithDebInfo'` from the verified CMake cache; `aflpp_version` from the campaign-v2 observed version; `afl_instrumented_locations=NULL` because the schema-v2 adapter build verifier does not record a numeric count; `sanitizer_config_json` equal to canonical JSON `{"afl_debug":"1","afl_use_ubsan":"1","profile":"libpng-afl-ubsan"}`; and `environment_json` equal to canonical JSON of the exact `build.json.environment` object. These values are fixed-profile constants or exact verified facts.
   - Populate campaign metadata only from the campaign JSON, its captured identity, the exact command and any validated AFL++ statistics. Specifically, `campaign_metadata_sha256` is the SHA-256 of the exact raw final `campaign.json` bytes read during stable validation, and `afl_max_generated_bytes` comes from the validated positive integer immediately following the sole `-G` argument in the recorded command; reject missing, duplicate or mismatched `-G` arguments.

4. **AFL output structure**
   - Support only the current single-worker output layouts: crash/hang directories directly under the recorded AFL output root, or under its single `default/` worker directory. Detect the layout explicitly; refuse ambiguous or additional worker layouts.
   - Scan only direct entries in `crashes/` and `hangs/`. Ignore only AFL++'s `README.txt`, and only when it is a regular, user-owned file. Reject symlinks, directories, special files and unexpected filenames.
   - Parse filename tokens conservatively: the first token must be `id:<decimal>`; duplicate `id`, `sig`, `time` or `execs` keys are rejected; `sig` is required for crashes and must be decimal `1..255`; any `sig` token on a hang is rejected; `time` and `execs` are optional non-negative decimal integers. Preserve the complete original filename. Unknown tokens are retained in the filename but not interpreted. Perform this validation before publishing any artifact.
   - Record the worker identity as `default`. A crash signal maps to `observed_signal`; do not invent an exit code. A hang has no inferred signal or exit code.
   - Derive `source_file_mtime_utc` from the source file's nanosecond filesystem timestamp, normalized to the database's six-digit UTC format.

5. **Resource bounds and stability**
   - Reuse P3-01's 16 MiB per-artifact ceiling. Use named constants `MAX_IMPORT_OBSERVATIONS = 4096` and `MAX_IMPORT_TOTAL_BYTES = 512 * 1024 * 1024`, with tests that patch the limits for boundary cases.
   - During pre-scan, retain each candidate's `(st_dev, st_ino, st_size, st_mtime_ns, st_ctime_ns)` and exact entry set for both directories. Use descriptor-relative no-follow checks. After all copies complete and before opening the SQLite write transaction, re-scan both directories and require identical entry sets and snapshots; require each `StoredArtifact.size_bytes` to equal its pre-scan size. Any change aborts; already published copies remain detectable as unreferenced artifacts.
   - Compute `source_file_mtime_utc` from integer `st_mtime_ns`: `seconds, remainder = divmod(st_mtime_ns, 1_000_000_000)` and `microseconds = remainder // 1_000`, then format the UTC second and six-digit microseconds. Do not convert nanoseconds through floating-point `st_mtime`.
   - Publish original source files through `EvidenceStore.publish_file()`; do not rename, chmod, edit or delete anything in the campaign tree.

## 6. Metadata mapping

| P3-01 field | Authoritative source |
|---|---|
| Target name / version | Campaign JSON, cross-checked with adapter and build metadata |
| Source archive/tree hashes and source paths | Verified `build.json` and adapter |
| Build metadata hash / build artifact hashes | Campaign-v2 identity plus verified `build.json` |
| Compiler path/version, CMake build type, AFL++ version and sanitizer environment | Verified build command/cache/environment plus structured campaign-v2 `toolchain` facts and the deterministic profile mapping above |
| Campaign UID, paths, command, limits, status and timestamps | Terminal campaign JSON and exact adapter |
| Adapter-config hash and seed manifest hash/count | Campaign-v2 identity, recomputed and matched at import |
| Total executions / saved crash/hang counts / reported timeout | Bounded `fuzzer_stats` parser, where the corresponding key is present and validated |
| Crash/hang original artifact SHA-256 and size | Bytes copied from the original AFL testcase |
| AFL ID, signal, discovery time and exec count | Parsed source filename |
| Source-file mtime | Source file metadata observed during stable copy |

AFL++ documents the crash and hang output directories and describes `fuzzer_stats` fields such as `execs_done`, `saved_crashes`, `saved_hangs` and `exec_timeout`. The parser must be bounded, reject duplicate/malformed keys and treat absent optional metrics as unknown, not zero. It must not infer a metric from the command line when the output does not record it.

## 7. Write ordering, idempotency and recovery

1. Complete campaign, build, output-tree, filename and resource validation before publishing objects.
2. Publish each testcase into the content-addressed filesystem store. Each publication is verified by the store's SHA-256 and stable-source checks.
3. In one SQLite `BEGIN IMMEDIATE` transaction, insert/reuse target, target-version, build, campaign and artifact rows, then insert immutable crash/hang observations.
4. Re-importing identical campaign evidence returns existing row IDs and changes no immutable facts. Reusing an observation identity with different bytes or metadata raises a conflict.
5. If a process stops after object publication but before the database transaction commits, the published object remains an unreferenced content-addressed object. Retry reuses it; store verification reports any orphan. Never delete an original or published object to simulate rollback.

Keep the source campaign directory as the original evidence. The evidence store contains verified copies.

## 8. Explicitly out of scope

- Sanitizer report/log ingestion (P3-03).
- Reproduction, debugger invocation or replay (P3-04).
- Minimization or derived artifacts (P3-05).
- Crash grouping, root-cause inference, severity or vulnerability verdicts (P3-06 and later triage).
- Importing AFL queue entries, hangs' replay, `plot_data`, `fuzzer_setup`, stdout/stderr logs or core dumps.
- Multi-worker campaigns, parallel AFL instances, other fuzzer formats or targets.
- Database schema changes, new runtime dependencies, web UI, networking or AI.

## 9. Acceptance checks

- Campaign-v2 metadata records stable adapter/build/seed identities and rejects changed inputs.
- Only terminal campaign directories with a valid, matching provenance chain are accepted.
- Valid crash/hang testcases are copied byte-for-byte, hashed, and linked to correct target/version/build/campaign records.
- Filename parsing captures only supported AFL fields and does not infer unsupported signal/exit facts.
- Empty crash/hang folders produce zero observations without fabricating records; absent optional statistics remain `NULL`.
- Identical re-import is idempotent. Same filename/identity with altered bytes or conflicting metadata is rejected without modifying original evidence.
- Symlink, special-file, path-escape, malformed JSON, duplicate-key, malformed filename/stats, oversized file, count/total-budget overflow, source mutation and mid-import interruption cases fail safely.
- DB writes are transactional; any unreferenced object after interrupted publication is detectable by P3-01 verification.
- Test suite passes on Python 3.11 and 3.14; full regression suite remains green.
- Independent read-only implementation review has no unresolved blockers or important issues.

## 10. Independent review closeout

The read-only design review returned **APPROVED FOR IMPLEMENTATION**, with no blockers. Implementation must incorporate I01 (deterministic non-null database mappings and structured toolchain facts), I02 (filename bounds/duplicate-token rules and required crash/hang directories), and I03 (pre/post-copy source snapshots and integer-exact mtime conversion). Optional suggestions are to reject seed subdirectories and use named, testable import bounds; both are adopted above.

## 11. Review references

- Project workflow and mandatory gates: `docs/WORKFLOW_DECISIONS.md`, Sections 8, 9 and 11.
- Phase 3 goals/acceptance: `docs/DEVELOPMENT_PLAN.md`, Phase 3.
- Existing campaign metadata contract: `engine/fuzzing/campaign.py`.
- Existing build provenance: `engine/build/runner.py`, `engine/build/libpng.py`, `engine/fuzzing/provenance.py`.
- Existing database/store contract: `engine/evidence/repository.py`, `engine/evidence/store.py`, `engine/evidence/sql/001_initial_evidence_schema.sql`.
- AFL++ output and statistics documentation: https://aflplus.plus/docs/afl-fuzz_approach/ and https://aflplus.plus/docs/status_screen/.
