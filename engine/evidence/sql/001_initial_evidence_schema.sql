-- KEKKAI P3-01 initial evidence schema. Transaction control belongs to Python.
CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK (version >= 1),
    name TEXT NOT NULL UNIQUE CHECK (
        length(trim(name)) > 0 AND name NOT GLOB '*[^0-9a-z_]*'
    ),
    checksum_sha256 TEXT NOT NULL CHECK (
        length(checksum_sha256) = 64 AND length(CAST(checksum_sha256 AS BLOB)) = 64 AND checksum_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    applied_at TEXT NOT NULL CHECK (
        length(applied_at) = 27 AND length(CAST(applied_at AS BLOB)) = 27
        AND substr(applied_at, 1, 19) IS strftime('%Y-%m-%dT%H:%M:%S', substr(applied_at, 1, 19), '+0 seconds')
        AND substr(applied_at, 20, 1) = '.'
        AND substr(applied_at, 21, 6) NOT GLOB '*[^0-9]*'
        AND substr(applied_at, 27, 1) = 'Z'
    ),
    CHECK (instr(name, char(0)) = 0),
    CHECK (instr(checksum_sha256, char(0)) = 0),
    CHECK (instr(applied_at, char(0)) = 0)
) STRICT;

CREATE TABLE targets (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL UNIQUE CHECK (
        length(trim(name)) > 0 AND name = lower(trim(name))
        AND instr(name, '/') = 0 AND instr(name, char(92)) = 0
    ),
    description TEXT,
    created_at TEXT NOT NULL CHECK (
        length(created_at) = 27 AND length(CAST(created_at AS BLOB)) = 27
        AND substr(created_at, 1, 19) IS strftime('%Y-%m-%dT%H:%M:%S', substr(created_at, 1, 19), '+0 seconds')
        AND substr(created_at, 20, 1) = '.'
        AND substr(created_at, 21, 6) NOT GLOB '*[^0-9]*'
        AND substr(created_at, 27, 1) = 'Z'
    ),
    CHECK (instr(name, char(0)) = 0),
    CHECK (instr(description, char(0)) = 0),
    CHECK (instr(created_at, char(0)) = 0)
) STRICT;

CREATE TABLE target_versions (
    id INTEGER PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
    version TEXT NOT NULL CHECK (length(trim(version)) > 0),
    source_archive_sha256 TEXT NOT NULL CHECK (
        length(source_archive_sha256) = 64 AND length(CAST(source_archive_sha256 AS BLOB)) = 64 AND source_archive_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    source_tree_sha256 TEXT NOT NULL CHECK (
        length(source_tree_sha256) = 64 AND length(CAST(source_tree_sha256 AS BLOB)) = 64 AND source_tree_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    source_dir_recorded TEXT NOT NULL CHECK (length(trim(source_dir_recorded)) > 0),
    source_archive_path TEXT CHECK (
        source_archive_path IS NULL OR length(trim(source_archive_path)) > 0
    ),
    created_at TEXT NOT NULL CHECK (
        length(created_at) = 27 AND length(CAST(created_at AS BLOB)) = 27
        AND substr(created_at, 1, 19) IS strftime('%Y-%m-%dT%H:%M:%S', substr(created_at, 1, 19), '+0 seconds')
        AND substr(created_at, 20, 1) = '.'
        AND substr(created_at, 21, 6) NOT GLOB '*[^0-9]*'
        AND substr(created_at, 27, 1) = 'Z'
    ),
    UNIQUE (target_id, version, source_tree_sha256),
    UNIQUE (id, target_id),
    CHECK (instr(version, char(0)) = 0),
    CHECK (instr(source_archive_sha256, char(0)) = 0),
    CHECK (instr(source_tree_sha256, char(0)) = 0),
    CHECK (instr(source_dir_recorded, char(0)) = 0),
    CHECK (instr(source_archive_path, char(0)) = 0),
    CHECK (instr(created_at, char(0)) = 0)
) STRICT;

CREATE TABLE builds (
    id INTEGER PRIMARY KEY,
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
    target_version_id INTEGER NOT NULL,
    profile TEXT NOT NULL CHECK (length(trim(profile)) > 0),
    build_role TEXT NOT NULL CHECK (build_role IN ('fuzz', 'diagnostic_replay', 'control')),
    build_dir TEXT NOT NULL CHECK (length(trim(build_dir)) > 0),
    build_metadata_sha256 TEXT NOT NULL CHECK (
        length(build_metadata_sha256) = 64 AND length(CAST(build_metadata_sha256 AS BLOB)) = 64 AND build_metadata_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    harness_source_path TEXT NOT NULL CHECK (length(trim(harness_source_path)) > 0),
    harness_binary_path TEXT NOT NULL CHECK (length(trim(harness_binary_path)) > 0),
    harness_source_sha256 TEXT CHECK (
        harness_source_sha256 IS NULL OR (length(harness_source_sha256) = 64 AND length(CAST(harness_source_sha256 AS BLOB)) = 64 AND harness_source_sha256 NOT GLOB '*[^0-9a-f]*')
    ),
    harness_binary_sha256 TEXT CHECK (
        harness_binary_sha256 IS NULL OR (length(harness_binary_sha256) = 64 AND length(CAST(harness_binary_sha256 AS BLOB)) = 64 AND harness_binary_sha256 NOT GLOB '*[^0-9a-f]*')
    ),
    library_archive_sha256 TEXT CHECK (
        library_archive_sha256 IS NULL OR (length(library_archive_sha256) = 64 AND length(CAST(library_archive_sha256 AS BLOB)) = 64 AND library_archive_sha256 NOT GLOB '*[^0-9a-f]*')
    ),
    cmake_cache_sha256 TEXT CHECK (
        cmake_cache_sha256 IS NULL OR (length(cmake_cache_sha256) = 64 AND length(CAST(cmake_cache_sha256 AS BLOB)) = 64 AND cmake_cache_sha256 NOT GLOB '*[^0-9a-f]*')
    ),
    compile_database_sha256 TEXT CHECK (
        compile_database_sha256 IS NULL OR (length(compile_database_sha256) = 64 AND length(CAST(compile_database_sha256 AS BLOB)) = 64 AND compile_database_sha256 NOT GLOB '*[^0-9a-f]*')
    ),
    generated_header_sha256 TEXT CHECK (
        generated_header_sha256 IS NULL OR (length(generated_header_sha256) = 64 AND length(CAST(generated_header_sha256 AS BLOB)) = 64 AND generated_header_sha256 NOT GLOB '*[^0-9a-f]*')
    ),
    compiler_path TEXT NOT NULL CHECK (length(trim(compiler_path)) > 0),
    compiler_version TEXT NOT NULL CHECK (length(trim(compiler_version)) > 0),
    cmake_build_type TEXT NOT NULL CHECK (length(trim(cmake_build_type)) > 0),
    aflpp_version TEXT CHECK (aflpp_version IS NULL OR length(trim(aflpp_version)) > 0),
    afl_instrumented_locations INTEGER CHECK (
        afl_instrumented_locations IS NULL OR afl_instrumented_locations >= 0
    ),
    sanitizer_config_json TEXT NOT NULL CHECK (
        length(trim(sanitizer_config_json)) >= 2
        AND substr(sanitizer_config_json, 1, 1) = '{'
        AND substr(sanitizer_config_json, -1, 1) = '}'
    ),
    environment_json TEXT NOT NULL CHECK (
        length(trim(environment_json)) >= 2
        AND substr(environment_json, 1, 1) = '{'
        AND substr(environment_json, -1, 1) = '}'
    ),
    build_status TEXT NOT NULL CHECK (build_status IN ('completed', 'failed', 'interrupted')),
    started_at TEXT NOT NULL CHECK (
        length(started_at) = 27 AND length(CAST(started_at AS BLOB)) = 27
        AND substr(started_at, 1, 19) IS strftime('%Y-%m-%dT%H:%M:%S', substr(started_at, 1, 19), '+0 seconds')
        AND substr(started_at, 20, 1) = '.'
        AND substr(started_at, 21, 6) NOT GLOB '*[^0-9]*'
        AND substr(started_at, 27, 1) = 'Z'
    ),
    ended_at TEXT NOT NULL CHECK (
        length(ended_at) = 27 AND length(CAST(ended_at AS BLOB)) = 27
        AND substr(ended_at, 1, 19) IS strftime('%Y-%m-%dT%H:%M:%S', substr(ended_at, 1, 19), '+0 seconds')
        AND substr(ended_at, 20, 1) = '.'
        AND substr(ended_at, 21, 6) NOT GLOB '*[^0-9]*'
        AND substr(ended_at, 27, 1) = 'Z'
        AND ended_at >= started_at
    ),
    recorded_at TEXT NOT NULL CHECK (
        length(recorded_at) = 27 AND length(CAST(recorded_at AS BLOB)) = 27
        AND substr(recorded_at, 1, 19) IS strftime('%Y-%m-%dT%H:%M:%S', substr(recorded_at, 1, 19), '+0 seconds')
        AND substr(recorded_at, 20, 1) = '.'
        AND substr(recorded_at, 21, 6) NOT GLOB '*[^0-9]*'
        AND substr(recorded_at, 27, 1) = 'Z'
    ),
    FOREIGN KEY (target_version_id, target_id)
        REFERENCES target_versions(id, target_id) ON DELETE RESTRICT,
    UNIQUE (build_dir, build_metadata_sha256),
    UNIQUE (id, target_id, target_version_id),
    CHECK (
        (build_status = 'completed'
         AND harness_source_sha256 IS NOT NULL
         AND harness_binary_sha256 IS NOT NULL
         AND library_archive_sha256 IS NOT NULL
         AND cmake_cache_sha256 IS NOT NULL
         AND compile_database_sha256 IS NOT NULL
         AND generated_header_sha256 IS NOT NULL)
        OR build_status IN ('failed', 'interrupted')
    ),
    CHECK (instr(profile, char(0)) = 0),
    CHECK (instr(build_role, char(0)) = 0),
    CHECK (instr(build_dir, char(0)) = 0),
    CHECK (instr(build_metadata_sha256, char(0)) = 0),
    CHECK (instr(harness_source_path, char(0)) = 0),
    CHECK (instr(harness_binary_path, char(0)) = 0),
    CHECK (instr(harness_source_sha256, char(0)) = 0),
    CHECK (instr(harness_binary_sha256, char(0)) = 0),
    CHECK (instr(library_archive_sha256, char(0)) = 0),
    CHECK (instr(cmake_cache_sha256, char(0)) = 0),
    CHECK (instr(compile_database_sha256, char(0)) = 0),
    CHECK (instr(generated_header_sha256, char(0)) = 0),
    CHECK (instr(compiler_path, char(0)) = 0),
    CHECK (instr(compiler_version, char(0)) = 0),
    CHECK (instr(cmake_build_type, char(0)) = 0),
    CHECK (instr(aflpp_version, char(0)) = 0),
    CHECK (instr(sanitizer_config_json, char(0)) = 0),
    CHECK (instr(environment_json, char(0)) = 0),
    CHECK (instr(build_status, char(0)) = 0),
    CHECK (instr(started_at, char(0)) = 0),
    CHECK (instr(ended_at, char(0)) = 0),
    CHECK (instr(recorded_at, char(0)) = 0)
) STRICT;

CREATE TABLE campaigns (
    id INTEGER PRIMARY KEY,
    campaign_uid TEXT NOT NULL UNIQUE CHECK (
        length(campaign_uid) = 38
        AND length(CAST(campaign_uid AS BLOB)) = 38
        AND instr(campaign_uid, char(0)) = 0
        AND substr(campaign_uid, 1, 9) = 'campaign-'
        AND substr(campaign_uid, 10, 8) NOT GLOB '*[^0-9]*'
        AND substr(campaign_uid, 18, 1) = 'T'
        AND substr(campaign_uid, 19, 6) NOT GLOB '*[^0-9]*'
        AND substr(campaign_uid, 25, 2) = 'Z-'
        AND substr(campaign_uid, 27, 12) NOT GLOB '*[^0-9a-f]*'
    ),
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
    target_version_id INTEGER NOT NULL,
    build_id INTEGER NOT NULL,
    adapter_config_path TEXT NOT NULL CHECK (length(trim(adapter_config_path)) > 0),
    adapter_config_sha256 TEXT NOT NULL CHECK (
        length(adapter_config_sha256) = 64 AND length(CAST(adapter_config_sha256 AS BLOB)) = 64 AND adapter_config_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    campaign_dir TEXT NOT NULL UNIQUE CHECK (length(trim(campaign_dir)) > 0),
    afl_output_dir TEXT NOT NULL UNIQUE CHECK (length(trim(afl_output_dir)) > 0),
    campaign_metadata_sha256 TEXT NOT NULL CHECK (
        length(campaign_metadata_sha256) = 64 AND length(CAST(campaign_metadata_sha256 AS BLOB)) = 64 AND campaign_metadata_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    seed_dir TEXT NOT NULL CHECK (length(trim(seed_dir)) > 0),
    seed_manifest_sha256 TEXT NOT NULL CHECK (
        length(seed_manifest_sha256) = 64 AND length(CAST(seed_manifest_sha256 AS BLOB)) = 64 AND seed_manifest_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    seed_count INTEGER NOT NULL CHECK (seed_count >= 1),
    fuzzer_executable TEXT NOT NULL CHECK (length(trim(fuzzer_executable)) > 0),
    fuzzer_version TEXT NOT NULL CHECK (length(trim(fuzzer_version)) > 0),
    command_json TEXT NOT NULL CHECK (
        length(trim(command_json)) >= 2
        AND substr(command_json, 1, 1) = '['
        AND substr(command_json, -1, 1) = ']'
    ),
    duration_seconds INTEGER NOT NULL CHECK (duration_seconds > 0),
    memory_mib INTEGER NOT NULL CHECK (memory_mib > 0),
    timeout_ms INTEGER NOT NULL CHECK (timeout_ms > 0),
    effective_timeout_ms INTEGER CHECK (effective_timeout_ms IS NULL OR effective_timeout_ms > 0),
    max_input_bytes INTEGER NOT NULL CHECK (max_input_bytes > 0),
    afl_max_generated_bytes INTEGER NOT NULL CHECK (afl_max_generated_bytes > 0),
    status TEXT NOT NULL CHECK (status IN ('completed', 'failed', 'interrupted')),
    exit_code INTEGER,
    total_execs INTEGER CHECK (total_execs IS NULL OR total_execs >= 0),
    saved_crashes_reported INTEGER CHECK (saved_crashes_reported IS NULL OR saved_crashes_reported >= 0),
    saved_hangs_reported INTEGER CHECK (saved_hangs_reported IS NULL OR saved_hangs_reported >= 0),
    started_at TEXT NOT NULL CHECK (
        length(started_at) = 27 AND length(CAST(started_at AS BLOB)) = 27
        AND substr(started_at, 1, 19) IS strftime('%Y-%m-%dT%H:%M:%S', substr(started_at, 1, 19), '+0 seconds')
        AND substr(started_at, 20, 1) = '.'
        AND substr(started_at, 21, 6) NOT GLOB '*[^0-9]*'
        AND substr(started_at, 27, 1) = 'Z'
    ),
    ended_at TEXT NOT NULL CHECK (
        length(ended_at) = 27 AND length(CAST(ended_at AS BLOB)) = 27
        AND substr(ended_at, 1, 19) IS strftime('%Y-%m-%dT%H:%M:%S', substr(ended_at, 1, 19), '+0 seconds')
        AND substr(ended_at, 20, 1) = '.'
        AND substr(ended_at, 21, 6) NOT GLOB '*[^0-9]*'
        AND substr(ended_at, 27, 1) = 'Z'
        AND ended_at >= started_at
    ),
    recorded_at TEXT NOT NULL CHECK (
        length(recorded_at) = 27 AND length(CAST(recorded_at AS BLOB)) = 27
        AND substr(recorded_at, 1, 19) IS strftime('%Y-%m-%dT%H:%M:%S', substr(recorded_at, 1, 19), '+0 seconds')
        AND substr(recorded_at, 20, 1) = '.'
        AND substr(recorded_at, 21, 6) NOT GLOB '*[^0-9]*'
        AND substr(recorded_at, 27, 1) = 'Z'
    ),
    FOREIGN KEY (build_id, target_id, target_version_id)
        REFERENCES builds(id, target_id, target_version_id) ON DELETE RESTRICT,
    UNIQUE (id, target_id, target_version_id, build_id),
    CHECK (instr(campaign_uid, char(0)) = 0),
    CHECK (instr(adapter_config_path, char(0)) = 0),
    CHECK (instr(adapter_config_sha256, char(0)) = 0),
    CHECK (instr(campaign_dir, char(0)) = 0),
    CHECK (instr(afl_output_dir, char(0)) = 0),
    CHECK (instr(campaign_metadata_sha256, char(0)) = 0),
    CHECK (instr(seed_dir, char(0)) = 0),
    CHECK (instr(seed_manifest_sha256, char(0)) = 0),
    CHECK (instr(fuzzer_executable, char(0)) = 0),
    CHECK (instr(fuzzer_version, char(0)) = 0),
    CHECK (instr(command_json, char(0)) = 0),
    CHECK (instr(status, char(0)) = 0),
    CHECK (instr(started_at, char(0)) = 0),
    CHECK (instr(ended_at, char(0)) = 0),
    CHECK (instr(recorded_at, char(0)) = 0)
) STRICT;

CREATE TABLE artifacts (
    id INTEGER PRIMARY KEY,
    sha256 TEXT NOT NULL UNIQUE CHECK (
        length(sha256) = 64 AND length(CAST(sha256 AS BLOB)) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0 AND size_bytes <= 16777216),
    storage_relpath TEXT NOT NULL UNIQUE CHECK (
        length(storage_relpath) = 89 AND length(CAST(storage_relpath AS BLOB)) = 89
        AND substr(storage_relpath, 1, 15) = 'objects/sha256/'
        AND substr(storage_relpath, 16, 2) = substr(sha256, 1, 2)
        AND substr(storage_relpath, 18, 1) = '/'
        AND substr(storage_relpath, 19, 2) = substr(sha256, 3, 2)
        AND substr(storage_relpath, 21, 1) = '/'
        AND substr(storage_relpath, 22, 64) = sha256
        AND substr(storage_relpath, 86, 4) = '.bin'
    ),
    first_ingested_at TEXT NOT NULL CHECK (
        length(first_ingested_at) = 27 AND length(CAST(first_ingested_at AS BLOB)) = 27
        AND substr(first_ingested_at, 1, 19) IS strftime('%Y-%m-%dT%H:%M:%S', substr(first_ingested_at, 1, 19), '+0 seconds')
        AND substr(first_ingested_at, 20, 1) = '.'
        AND substr(first_ingested_at, 21, 6) NOT GLOB '*[^0-9]*'
        AND substr(first_ingested_at, 27, 1) = 'Z'
    ),
    last_verified_at TEXT NOT NULL CHECK (
        length(last_verified_at) = 27 AND length(CAST(last_verified_at AS BLOB)) = 27
        AND substr(last_verified_at, 1, 19) IS strftime('%Y-%m-%dT%H:%M:%S', substr(last_verified_at, 1, 19), '+0 seconds')
        AND substr(last_verified_at, 20, 1) = '.'
        AND substr(last_verified_at, 21, 6) NOT GLOB '*[^0-9]*'
        AND substr(last_verified_at, 27, 1) = 'Z'
        AND last_verified_at >= first_ingested_at
    ),
    CHECK (instr(sha256, char(0)) = 0),
    CHECK (instr(storage_relpath, char(0)) = 0),
    CHECK (instr(first_ingested_at, char(0)) = 0),
    CHECK (instr(last_verified_at, char(0)) = 0)
) STRICT;

CREATE TABLE observations (
    id INTEGER PRIMARY KEY,
    observation_uid TEXT NOT NULL UNIQUE CHECK (
        length(observation_uid) = 68 AND length(CAST(observation_uid AS BLOB)) = 68
        AND substr(observation_uid, 1, 4) = 'obs-'
        AND substr(observation_uid, 5, 64) NOT GLOB '*[^0-9a-f]*'
    ),
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
    target_version_id INTEGER NOT NULL,
    build_id INTEGER NOT NULL,
    campaign_id INTEGER NOT NULL,
    original_artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    observation_kind TEXT NOT NULL CHECK (observation_kind IN ('crash', 'hang')),
    afl_worker_name TEXT NOT NULL DEFAULT 'default' CHECK (
        length(trim(afl_worker_name)) > 0 AND instr(afl_worker_name, '/') = 0
        AND instr(afl_worker_name, char(92)) = 0 AND afl_worker_name NOT IN ('.', '..')
    ),
    afl_source_filename TEXT NOT NULL CHECK (
        length(trim(afl_source_filename)) > 0 AND instr(afl_source_filename, '/') = 0
        AND instr(afl_source_filename, char(92)) = 0
        AND afl_source_filename NOT IN ('.', '..', 'README.txt')
    ),
    afl_input_id TEXT CHECK (afl_input_id IS NULL OR length(trim(afl_input_id)) > 0),
    observed_signal INTEGER CHECK (observed_signal IS NULL OR observed_signal BETWEEN 1 AND 255),
    observed_exit_code INTEGER,
    afl_discovery_time_ms INTEGER CHECK (afl_discovery_time_ms IS NULL OR afl_discovery_time_ms >= 0),
    afl_discovery_execs INTEGER CHECK (afl_discovery_execs IS NULL OR afl_discovery_execs >= 0),
    source_file_mtime_utc TEXT NOT NULL CHECK (
        length(source_file_mtime_utc) = 27 AND length(CAST(source_file_mtime_utc AS BLOB)) = 27
        AND substr(source_file_mtime_utc, 1, 19) IS strftime('%Y-%m-%dT%H:%M:%S', substr(source_file_mtime_utc, 1, 19), '+0 seconds')
        AND substr(source_file_mtime_utc, 20, 1) = '.'
        AND substr(source_file_mtime_utc, 21, 6) NOT GLOB '*[^0-9]*'
        AND substr(source_file_mtime_utc, 27, 1) = 'Z'
    ),
    ingested_at TEXT NOT NULL CHECK (
        length(ingested_at) = 27 AND length(CAST(ingested_at AS BLOB)) = 27
        AND substr(ingested_at, 1, 19) IS strftime('%Y-%m-%dT%H:%M:%S', substr(ingested_at, 1, 19), '+0 seconds')
        AND substr(ingested_at, 20, 1) = '.'
        AND substr(ingested_at, 21, 6) NOT GLOB '*[^0-9]*'
        AND substr(ingested_at, 27, 1) = 'Z'
    ),
    FOREIGN KEY (campaign_id, target_id, target_version_id, build_id)
        REFERENCES campaigns(id, target_id, target_version_id, build_id) ON DELETE RESTRICT,
    UNIQUE (campaign_id, afl_worker_name, observation_kind, afl_source_filename),
    UNIQUE (id, target_id),
    UNIQUE (id, target_id, target_version_id, build_id, campaign_id),
    CHECK (instr(observation_uid, char(0)) = 0),
    CHECK (instr(observation_kind, char(0)) = 0),
    CHECK (instr(afl_worker_name, char(0)) = 0),
    CHECK (instr(afl_source_filename, char(0)) = 0),
    CHECK (instr(afl_input_id, char(0)) = 0),
    CHECK (instr(source_file_mtime_utc, char(0)) = 0),
    CHECK (instr(ingested_at, char(0)) = 0)
) STRICT;

CREATE TRIGGER prevent_artifact_deletion
BEFORE DELETE ON artifacts
BEGIN
    SELECT RAISE(ABORT, 'Evidence preservation violation: artifacts cannot be deleted.');
END;

CREATE TRIGGER prevent_artifact_mutation
BEFORE UPDATE OF id, sha256, size_bytes, storage_relpath, first_ingested_at ON artifacts
BEGIN
    SELECT RAISE(ABORT, 'Evidence preservation violation: artifact identity is immutable.');
END;

CREATE TRIGGER prevent_artifact_verification_regression
BEFORE UPDATE OF last_verified_at ON artifacts
WHEN NEW.last_verified_at < OLD.last_verified_at
BEGIN
    SELECT RAISE(ABORT, 'Evidence preservation violation: verification time cannot move backward.');
END;

CREATE TRIGGER prevent_observation_deletion
BEFORE DELETE ON observations
BEGIN
    SELECT RAISE(ABORT, 'Evidence preservation violation: observations cannot be deleted.');
END;

CREATE TRIGGER prevent_observation_mutation
BEFORE UPDATE ON observations
BEGIN
    SELECT RAISE(ABORT, 'Evidence preservation violation: observations are immutable.');
END;

CREATE INDEX idx_target_versions_target_id ON target_versions(target_id);
CREATE INDEX idx_builds_target_version_role ON builds(target_version_id, build_role, build_status);
CREATE INDEX idx_campaigns_build_id ON campaigns(build_id);
CREATE INDEX idx_campaigns_target_version_started ON campaigns(target_version_id, status, started_at);
CREATE INDEX idx_observations_campaign_kind ON observations(campaign_id, observation_kind, ingested_at);
CREATE INDEX idx_observations_original_artifact_id ON observations(original_artifact_id);
CREATE INDEX idx_observations_target_version ON observations(target_version_id, observation_kind, ingested_at);
