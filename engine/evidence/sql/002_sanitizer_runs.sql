-- Additive immutable sanitizer execution evidence.
CREATE TABLE sanitizer_runs (
    id INTEGER PRIMARY KEY,
    run_uid TEXT NOT NULL UNIQUE CHECK (
        length(run_uid) = 36
        AND length(CAST(run_uid AS BLOB)) = 36
        AND run_uid = lower(run_uid)
        AND substr(run_uid, 9, 1) = '-'
        AND substr(run_uid, 14, 1) = '-'
        AND substr(run_uid, 19, 1) = '-'
        AND substr(run_uid, 24, 1) = '-'
        AND substr(run_uid, 15, 1) = '4'
        AND substr(run_uid, 20, 1) IN ('8', '9', 'a', 'b')
        AND run_uid NOT GLOB '*[^0-9a-f-]*'
        AND length(run_uid) - length(replace(run_uid, '-', '')) = 4
    ),
    target_id INTEGER NOT NULL REFERENCES targets(id) ON DELETE RESTRICT,
    target_version_id INTEGER NOT NULL,
    source_build_id INTEGER NOT NULL,
    campaign_id INTEGER NOT NULL,
    observation_id INTEGER NOT NULL,
    diagnostic_build_id INTEGER NOT NULL,
    original_artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE RESTRICT,
    policy_id TEXT NOT NULL CHECK (length(policy_id) BETWEEN 1 AND 64),
    argv_json TEXT NOT NULL CHECK (
        json_valid(argv_json) AND json_type(argv_json) = 'array'
        AND length(argv_json) <= 4096
    ),
    environment_json TEXT NOT NULL CHECK (
        json_valid(environment_json) AND json_type(environment_json) = 'object'
        AND length(environment_json) <= 4096
    ),
    resource_policy_json TEXT NOT NULL CHECK (
        json_valid(resource_policy_json) AND json_type(resource_policy_json) = 'object'
        AND length(resource_policy_json) <= 4096
    ),
    runtime_observation_json TEXT NOT NULL CHECK (
        json_valid(runtime_observation_json) AND json_type(runtime_observation_json) = 'object'
        AND length(runtime_observation_json) <= 16384
    ),
    attempt_started_at TEXT NOT NULL CHECK (
        length(attempt_started_at) = 27
        AND attempt_started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'
        AND CAST(substr(attempt_started_at,6,2) AS INTEGER) BETWEEN 1 AND 12
        AND CAST(substr(attempt_started_at,9,2) AS INTEGER) BETWEEN 1 AND CASE
            WHEN CAST(substr(attempt_started_at,6,2) AS INTEGER) IN (1, 3, 5, 7, 8, 10, 12) THEN 31
            WHEN CAST(substr(attempt_started_at,6,2) AS INTEGER) IN (4, 6, 9, 11) THEN 30
            WHEN CAST(substr(attempt_started_at,6,2) AS INTEGER) = 2 AND (CAST(substr(attempt_started_at,1,4) AS INTEGER) % 400 = 0 OR (CAST(substr(attempt_started_at,1,4) AS INTEGER) % 4 = 0 AND CAST(substr(attempt_started_at,1,4) AS INTEGER) % 100 != 0)) THEN 29
            WHEN CAST(substr(attempt_started_at,6,2) AS INTEGER) = 2 THEN 28
            ELSE 0
        END
        AND CAST(substr(attempt_started_at,12,2) AS INTEGER) BETWEEN 0 AND 23
        AND CAST(substr(attempt_started_at,15,2) AS INTEGER) BETWEEN 0 AND 59
        AND CAST(substr(attempt_started_at,18,2) AS INTEGER) BETWEEN 0 AND 59
    ),
    attempt_finished_at TEXT NOT NULL CHECK (
        length(attempt_finished_at) = 27
        AND attempt_finished_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'
        AND CAST(substr(attempt_finished_at,6,2) AS INTEGER) BETWEEN 1 AND 12
        AND CAST(substr(attempt_finished_at,9,2) AS INTEGER) BETWEEN 1 AND CASE
            WHEN CAST(substr(attempt_finished_at,6,2) AS INTEGER) IN (1, 3, 5, 7, 8, 10, 12) THEN 31
            WHEN CAST(substr(attempt_finished_at,6,2) AS INTEGER) IN (4, 6, 9, 11) THEN 30
            WHEN CAST(substr(attempt_finished_at,6,2) AS INTEGER) = 2 AND (CAST(substr(attempt_finished_at,1,4) AS INTEGER) % 400 = 0 OR (CAST(substr(attempt_finished_at,1,4) AS INTEGER) % 4 = 0 AND CAST(substr(attempt_finished_at,1,4) AS INTEGER) % 100 != 0)) THEN 29
            WHEN CAST(substr(attempt_finished_at,6,2) AS INTEGER) = 2 THEN 28
            ELSE 0
        END
        AND CAST(substr(attempt_finished_at,12,2) AS INTEGER) BETWEEN 0 AND 23
        AND CAST(substr(attempt_finished_at,15,2) AS INTEGER) BETWEEN 0 AND 59
        AND CAST(substr(attempt_finished_at,18,2) AS INTEGER) BETWEEN 0 AND 59
        AND attempt_finished_at >= attempt_started_at
    ),
    execution_started_at TEXT CHECK (
        execution_started_at IS NULL OR (
            length(execution_started_at) = 27
        AND execution_started_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'
        AND CAST(substr(execution_started_at,6,2) AS INTEGER) BETWEEN 1 AND 12
        AND CAST(substr(execution_started_at,9,2) AS INTEGER) BETWEEN 1 AND CASE
            WHEN CAST(substr(execution_started_at,6,2) AS INTEGER) IN (1, 3, 5, 7, 8, 10, 12) THEN 31
            WHEN CAST(substr(execution_started_at,6,2) AS INTEGER) IN (4, 6, 9, 11) THEN 30
            WHEN CAST(substr(execution_started_at,6,2) AS INTEGER) = 2 AND (CAST(substr(execution_started_at,1,4) AS INTEGER) % 400 = 0 OR (CAST(substr(execution_started_at,1,4) AS INTEGER) % 4 = 0 AND CAST(substr(execution_started_at,1,4) AS INTEGER) % 100 != 0)) THEN 29
            WHEN CAST(substr(execution_started_at,6,2) AS INTEGER) = 2 THEN 28
            ELSE 0
        END
        AND CAST(substr(execution_started_at,12,2) AS INTEGER) BETWEEN 0 AND 23
        AND CAST(substr(execution_started_at,15,2) AS INTEGER) BETWEEN 0 AND 59
        AND CAST(substr(execution_started_at,18,2) AS INTEGER) BETWEEN 0 AND 59
            AND execution_started_at >= attempt_started_at
            AND execution_started_at <= attempt_finished_at
        )
    ),
    execution_finished_at TEXT CHECK (
        execution_finished_at IS NULL OR (
            length(execution_finished_at) = 27
        AND execution_finished_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'
        AND CAST(substr(execution_finished_at,6,2) AS INTEGER) BETWEEN 1 AND 12
        AND CAST(substr(execution_finished_at,9,2) AS INTEGER) BETWEEN 1 AND CASE
            WHEN CAST(substr(execution_finished_at,6,2) AS INTEGER) IN (1, 3, 5, 7, 8, 10, 12) THEN 31
            WHEN CAST(substr(execution_finished_at,6,2) AS INTEGER) IN (4, 6, 9, 11) THEN 30
            WHEN CAST(substr(execution_finished_at,6,2) AS INTEGER) = 2 AND (CAST(substr(execution_finished_at,1,4) AS INTEGER) % 400 = 0 OR (CAST(substr(execution_finished_at,1,4) AS INTEGER) % 4 = 0 AND CAST(substr(execution_finished_at,1,4) AS INTEGER) % 100 != 0)) THEN 29
            WHEN CAST(substr(execution_finished_at,6,2) AS INTEGER) = 2 THEN 28
            ELSE 0
        END
        AND CAST(substr(execution_finished_at,12,2) AS INTEGER) BETWEEN 0 AND 23
        AND CAST(substr(execution_finished_at,15,2) AS INTEGER) BETWEEN 0 AND 59
        AND CAST(substr(execution_finished_at,18,2) AS INTEGER) BETWEEN 0 AND 59
            AND execution_started_at IS NOT NULL
            AND execution_finished_at >= execution_started_at
            AND execution_finished_at <= attempt_finished_at
        )
    ),
    execution_status TEXT NOT NULL CHECK (
        execution_status IN (
            'blocked_preflight', 'launch_failed', 'exited',
            'signaled', 'timed_out', 'interrupted'
        )
    ),
    harness_exec_succeeded INTEGER NOT NULL CHECK (harness_exec_succeeded IN (0, 1)),
    exit_code INTEGER CHECK (exit_code IS NULL OR exit_code BETWEEN 0 AND 255),
    signal_number INTEGER CHECK (signal_number IS NULL OR signal_number BETWEEN 1 AND 64),
    sanitizer_families_json TEXT NOT NULL CHECK (
        json_valid(sanitizer_families_json)
        AND json_type(sanitizer_families_json) = 'array'
        AND length(sanitizer_families_json) <= 256
    ),
    assessment TEXT NOT NULL CHECK (
        assessment IN (
            'report_signature_observed',
            'no_signature_observed',
            'inconclusive'
        )
    ),
    cleanup_status TEXT NOT NULL CHECK (
        cleanup_status IN ('complete', 'failed', 'not_required')
    ),
    cleanup_detail TEXT CHECK (
        cleanup_detail IS NULL OR length(cleanup_detail) <= 1024
    ),
    recovery_path TEXT CHECK (
        recovery_path IS NULL OR length(recovery_path) <= 1024
    ),
    systemd_unit_name TEXT CHECK (
        systemd_unit_name IS NULL OR length(systemd_unit_name) <= 255
    ),
    kernel_version TEXT CHECK (kernel_version IS NULL OR length(kernel_version) <= 255),
    wsl_version TEXT CHECK (wsl_version IS NULL OR length(wsl_version) <= 255),
    systemd_version TEXT CHECK (systemd_version IS NULL OR length(systemd_version) <= 255),
    stdout_artifact_id INTEGER REFERENCES artifacts(id) ON DELETE RESTRICT,
    stdout_capture_state TEXT NOT NULL CHECK (
        stdout_capture_state IN ('not_started', 'complete', 'read_failed')
    ),
    stdout_truncated INTEGER NOT NULL CHECK (stdout_truncated IN (0, 1)),
    stdout_publication_state TEXT NOT NULL CHECK (
        stdout_publication_state IN ('not_started', 'published', 'pending_recovery')
    ),
    stdout_detail TEXT CHECK (stdout_detail IS NULL OR length(stdout_detail) <= 1024),
    stderr_artifact_id INTEGER REFERENCES artifacts(id) ON DELETE RESTRICT,
    stderr_capture_state TEXT NOT NULL CHECK (
        stderr_capture_state IN ('not_started', 'complete', 'read_failed')
    ),
    stderr_truncated INTEGER NOT NULL CHECK (stderr_truncated IN (0, 1)),
    stderr_publication_state TEXT NOT NULL CHECK (
        stderr_publication_state IN ('not_started', 'published', 'pending_recovery')
    ),
    stderr_detail TEXT CHECK (stderr_detail IS NULL OR length(stderr_detail) <= 1024),
    recorded_at TEXT NOT NULL CHECK (
        length(recorded_at) = 27
        AND recorded_at GLOB '[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]T[0-9][0-9]:[0-9][0-9]:[0-9][0-9].[0-9][0-9][0-9][0-9][0-9][0-9]Z'
        AND CAST(substr(recorded_at,6,2) AS INTEGER) BETWEEN 1 AND 12
        AND CAST(substr(recorded_at,9,2) AS INTEGER) BETWEEN 1 AND CASE
            WHEN CAST(substr(recorded_at,6,2) AS INTEGER) IN (1, 3, 5, 7, 8, 10, 12) THEN 31
            WHEN CAST(substr(recorded_at,6,2) AS INTEGER) IN (4, 6, 9, 11) THEN 30
            WHEN CAST(substr(recorded_at,6,2) AS INTEGER) = 2 AND (CAST(substr(recorded_at,1,4) AS INTEGER) % 400 = 0 OR (CAST(substr(recorded_at,1,4) AS INTEGER) % 4 = 0 AND CAST(substr(recorded_at,1,4) AS INTEGER) % 100 != 0)) THEN 29
            WHEN CAST(substr(recorded_at,6,2) AS INTEGER) = 2 THEN 28
            ELSE 0
        END
        AND CAST(substr(recorded_at,12,2) AS INTEGER) BETWEEN 0 AND 23
        AND CAST(substr(recorded_at,15,2) AS INTEGER) BETWEEN 0 AND 59
        AND CAST(substr(recorded_at,18,2) AS INTEGER) BETWEEN 0 AND 59
        AND recorded_at >= attempt_started_at
    ),
    FOREIGN KEY (target_version_id, target_id)
        REFERENCES target_versions(id, target_id) ON DELETE RESTRICT,
    FOREIGN KEY (source_build_id, target_id, target_version_id)
        REFERENCES builds(id, target_id, target_version_id) ON DELETE RESTRICT,
    FOREIGN KEY (diagnostic_build_id, target_id, target_version_id)
        REFERENCES builds(id, target_id, target_version_id) ON DELETE RESTRICT,
    FOREIGN KEY (campaign_id, target_id, target_version_id, source_build_id)
        REFERENCES campaigns(id, target_id, target_version_id, build_id) ON DELETE RESTRICT,
    FOREIGN KEY (observation_id, target_id, target_version_id, source_build_id, campaign_id)
        REFERENCES observations(id, target_id, target_version_id, build_id, campaign_id)
        ON DELETE RESTRICT,
    CHECK (
        (execution_status IN ('blocked_preflight', 'launch_failed')
            AND harness_exec_succeeded = 0
            AND execution_started_at IS NULL
            AND execution_finished_at IS NULL
            AND exit_code IS NULL
            AND signal_number IS NULL
            AND stdout_truncated = 0
            AND stderr_truncated = 0)
        OR
        (execution_status IN ('exited', 'signaled', 'timed_out', 'interrupted')
            AND harness_exec_succeeded = 1
            AND execution_started_at IS NOT NULL
            AND execution_finished_at IS NOT NULL
            AND NOT (exit_code IS NOT NULL AND signal_number IS NOT NULL))
    ),
    CHECK (
        (execution_status = 'exited' AND exit_code IS NOT NULL AND signal_number IS NULL)
        OR (execution_status = 'signaled' AND exit_code IS NULL AND signal_number IS NOT NULL)
        OR (execution_status IN ('timed_out', 'interrupted'))
        OR (execution_status IN ('blocked_preflight', 'launch_failed')
            AND exit_code IS NULL AND signal_number IS NULL)
    ),
    CHECK (
        (stdout_publication_state = 'published' AND stdout_artifact_id IS NOT NULL)
        OR (stdout_publication_state IN ('not_started', 'pending_recovery')
            AND stdout_artifact_id IS NULL)
    ),
    CHECK (
        (stderr_publication_state = 'published' AND stderr_artifact_id IS NOT NULL)
        OR (stderr_publication_state IN ('not_started', 'pending_recovery')
            AND stderr_artifact_id IS NULL)
    ),
    CHECK (
        (stdout_publication_state = 'not_started'
            AND stdout_capture_state IN ('not_started', 'read_failed')
            AND stdout_artifact_id IS NULL AND stdout_truncated = 0)
        OR (stdout_publication_state = 'published'
            AND stdout_capture_state IN ('complete', 'read_failed'))
        OR (stdout_publication_state = 'pending_recovery'
            AND stdout_capture_state IN ('complete', 'read_failed'))
    ),
    CHECK (
        (stderr_publication_state = 'not_started'
            AND stderr_capture_state IN ('not_started', 'read_failed')
            AND stderr_artifact_id IS NULL AND stderr_truncated = 0)
        OR (stderr_publication_state = 'published'
            AND stderr_capture_state IN ('complete', 'read_failed'))
        OR (stderr_publication_state = 'pending_recovery'
            AND stderr_capture_state IN ('complete', 'read_failed'))
    ),
    CHECK (
        execution_status NOT IN ('blocked_preflight', 'launch_failed')
        OR (stdout_capture_state = 'not_started'
            AND stderr_capture_state = 'not_started'
            AND stdout_publication_state = 'not_started'
            AND stderr_publication_state = 'not_started')
    ),
    CHECK (
        (stdout_publication_state != 'pending_recovery'
            AND stderr_publication_state != 'pending_recovery')
        OR recovery_path IS NOT NULL
    ),
    CHECK (
        (assessment = 'report_signature_observed'
            AND sanitizer_families_json != '[]'
            AND harness_exec_succeeded = 1)
        OR (assessment = 'no_signature_observed'
            AND sanitizer_families_json = '[]'
            AND execution_status = 'exited'
            AND exit_code = 0
            AND stdout_capture_state = 'complete'
            AND stderr_capture_state = 'complete'
            AND stdout_truncated = 0
            AND stderr_truncated = 0
            AND stdout_publication_state = 'published'
            AND stderr_publication_state = 'published')
        OR (assessment = 'inconclusive' AND sanitizer_families_json = '[]')
    ),
    CHECK (instr(run_uid, char(0)) = 0),
    CHECK (instr(policy_id, char(0)) = 0),
    CHECK (instr(argv_json, char(0)) = 0),
    CHECK (instr(environment_json, char(0)) = 0),
    CHECK (instr(resource_policy_json, char(0)) = 0),
    CHECK (instr(runtime_observation_json, char(0)) = 0),
    CHECK (instr(execution_status, char(0)) = 0),
    CHECK (instr(sanitizer_families_json, char(0)) = 0),
    CHECK (instr(assessment, char(0)) = 0),
    CHECK (instr(cleanup_status, char(0)) = 0),
    CHECK (instr(cleanup_detail, char(0)) = 0),
    CHECK (instr(recovery_path, char(0)) = 0),
    CHECK (instr(systemd_unit_name, char(0)) = 0),
    CHECK (instr(kernel_version, char(0)) = 0),
    CHECK (instr(wsl_version, char(0)) = 0),
    CHECK (instr(systemd_version, char(0)) = 0),
    CHECK (instr(stdout_detail, char(0)) = 0),
    CHECK (instr(stderr_detail, char(0)) = 0)
) STRICT;

CREATE TRIGGER sanitizer_runs_validate_roles
BEFORE INSERT ON sanitizer_runs
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM builds
        WHERE id = NEW.source_build_id
          AND target_id = NEW.target_id
          AND target_version_id = NEW.target_version_id
          AND build_role = 'fuzz'
    ) THEN RAISE(ABORT, 'Sanitizer run source build must have fuzz role.') END;

    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM builds
        WHERE id = NEW.diagnostic_build_id
          AND target_id = NEW.target_id
          AND target_version_id = NEW.target_version_id
          AND build_role = 'diagnostic_replay'
          AND build_status = 'completed'
    ) THEN RAISE(ABORT, 'Sanitizer run requires a completed diagnostic build.') END;

    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM observations
        WHERE id = NEW.observation_id
          AND original_artifact_id = NEW.original_artifact_id
    ) THEN RAISE(ABORT, 'Sanitizer run original artifact must match its observation.') END;

    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM artifacts
        WHERE id IN (NEW.stdout_artifact_id, NEW.stderr_artifact_id)
          AND size_bytes > 8388608
    ) THEN RAISE(ABORT, 'Sanitizer stream artifacts cannot exceed 8 MiB.') END;

    SELECT CASE WHEN json_type(NEW.sanitizer_families_json) != 'array'
        THEN RAISE(ABORT, 'Sanitizer families must be a JSON array.') END;

    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM json_each(NEW.sanitizer_families_json)
        WHERE type != 'text'
           OR value NOT IN ('address', 'leak', 'undefined_behavior')
    ) THEN RAISE(ABORT, 'Sanitizer family is not allowed.') END;

    SELECT CASE WHEN EXISTS (
        SELECT 1
        FROM json_each(NEW.sanitizer_families_json) AS earlier
        JOIN json_each(NEW.sanitizer_families_json) AS later
          ON CAST(earlier.key AS INTEGER) < CAST(later.key AS INTEGER)
         AND earlier.value >= later.value
    ) THEN RAISE(ABORT, 'Sanitizer families must be sorted and unique.') END;
END;

CREATE TRIGGER prevent_sanitizer_run_deletion
BEFORE DELETE ON sanitizer_runs
BEGIN
    SELECT RAISE(ABORT, 'Evidence preservation violation: sanitizer runs cannot be deleted.');
END;

CREATE TRIGGER prevent_sanitizer_run_mutation
BEFORE UPDATE ON sanitizer_runs
BEGIN
    SELECT RAISE(ABORT, 'Evidence preservation violation: sanitizer runs are immutable.');
END;

CREATE INDEX idx_sanitizer_runs_observation_attempt
    ON sanitizer_runs(observation_id, attempt_started_at);
CREATE INDEX idx_sanitizer_runs_diagnostic_build
    ON sanitizer_runs(diagnostic_build_id, attempt_started_at);
