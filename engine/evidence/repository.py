"""Typed, parameterized SQL operations for the P3-01 evidence schema."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Mapping
from contextlib import contextmanager
from typing import Iterator

from .database import canonical_json, immediate_transaction, normalize_utc_timestamp


class EvidenceConflictError(RuntimeError):
    """Raised when an idempotent key already exists with different facts."""


TARGET_COLUMNS = ("name", "description", "created_at")
TARGET_VERSION_COLUMNS = (
    "target_id", "version", "source_archive_sha256", "source_tree_sha256",
    "source_dir_recorded", "source_archive_path", "created_at",
)
BUILD_COLUMNS = (
    "target_id", "target_version_id", "profile", "build_role", "build_dir",
    "build_metadata_sha256", "harness_source_path", "harness_binary_path",
    "harness_source_sha256", "harness_binary_sha256", "library_archive_sha256",
    "cmake_cache_sha256", "compile_database_sha256", "generated_header_sha256",
    "compiler_path", "compiler_version", "cmake_build_type", "aflpp_version",
    "afl_instrumented_locations", "sanitizer_config_json", "environment_json",
    "build_status", "started_at", "ended_at", "recorded_at",
)
CAMPAIGN_COLUMNS = (
    "campaign_uid", "target_id", "target_version_id", "build_id",
    "adapter_config_path", "adapter_config_sha256", "campaign_dir", "afl_output_dir",
    "campaign_metadata_sha256", "seed_dir", "seed_manifest_sha256", "seed_count",
    "fuzzer_executable", "fuzzer_version", "command_json", "duration_seconds",
    "memory_mib", "timeout_ms", "effective_timeout_ms", "max_input_bytes",
    "afl_max_generated_bytes", "status", "exit_code", "total_execs",
    "saved_crashes_reported", "saved_hangs_reported", "started_at", "ended_at",
    "recorded_at",
)
ARTIFACT_COLUMNS = (
    "sha256", "size_bytes", "storage_relpath", "first_ingested_at", "last_verified_at",
)
SANITIZER_RUN_COLUMNS = (
    "run_uid", "target_id", "target_version_id", "source_build_id", "campaign_id",
    "observation_id", "diagnostic_build_id", "original_artifact_id", "policy_id",
    "argv_json", "environment_json", "resource_policy_json", "runtime_observation_json",
    "attempt_started_at", "attempt_finished_at", "execution_started_at",
    "execution_finished_at", "execution_status", "harness_exec_succeeded",
    "exit_code", "signal_number", "sanitizer_families_json", "assessment",
    "cleanup_status", "cleanup_detail", "recovery_path", "systemd_unit_name",
    "kernel_version", "wsl_version", "systemd_version", "stdout_artifact_id",
    "stdout_capture_state", "stdout_truncated", "stdout_publication_state",
    "stdout_detail", "stderr_artifact_id", "stderr_capture_state",
    "stderr_truncated", "stderr_publication_state", "stderr_detail", "recorded_at",
)
OBSERVATION_COLUMNS = (
    "observation_uid", "target_id", "target_version_id", "build_id", "campaign_id",
    "original_artifact_id", "observation_kind", "afl_worker_name", "afl_source_filename",
    "afl_input_id", "observed_signal", "observed_exit_code", "afl_discovery_time_ms",
    "afl_discovery_execs", "source_file_mtime_utc", "ingested_at",
)

_TIMESTAMP_COLUMNS = {
    "created_at", "started_at", "ended_at", "recorded_at", "first_ingested_at",
    "last_verified_at", "source_file_mtime_utc", "ingested_at",
    "attempt_started_at", "attempt_finished_at", "execution_started_at",
    "execution_finished_at",
}
_JSON_COLUMNS = {
    "sanitizer_config_json", "environment_json", "command_json", "argv_json",
    "resource_policy_json", "runtime_observation_json", "sanitizer_families_json",
}
_INTEGER_COLUMNS = {
    "target_id", "target_version_id", "build_id", "campaign_id", "original_artifact_id",
    "afl_instrumented_locations", "seed_count", "duration_seconds", "memory_mib",
    "timeout_ms", "effective_timeout_ms", "max_input_bytes", "afl_max_generated_bytes",
    "exit_code", "total_execs", "saved_crashes_reported", "saved_hangs_reported",
    "size_bytes", "observed_signal", "observed_exit_code", "afl_discovery_time_ms",
    "afl_discovery_execs", "source_build_id", "observation_id", "diagnostic_build_id",
    "harness_exec_succeeded", "signal_number", "stdout_artifact_id", "stdout_truncated",
    "stderr_artifact_id", "stderr_truncated",
}
_OPTIONAL_COLUMNS = {
    "description", "source_archive_path", "harness_source_sha256", "harness_binary_sha256",
    "library_archive_sha256", "cmake_cache_sha256", "compile_database_sha256",
    "generated_header_sha256", "aflpp_version", "afl_instrumented_locations",
    "effective_timeout_ms", "exit_code", "total_execs", "saved_crashes_reported",
    "saved_hangs_reported", "afl_input_id", "observed_signal", "observed_exit_code",
    "afl_discovery_time_ms", "afl_discovery_execs", "execution_started_at",
    "execution_finished_at", "cleanup_detail", "recovery_path", "systemd_unit_name",
    "kernel_version", "wsl_version", "systemd_version", "stdout_artifact_id",
    "stdout_detail", "stderr_artifact_id", "stderr_detail",
}


@contextmanager
def _write_scope(connection: sqlite3.Connection) -> Iterator[None]:
    if connection.in_transaction:
        yield
    else:
        with immediate_transaction(connection):
            yield


def make_observation_uid(
    campaign_uid: str,
    worker_name: str,
    observation_kind: str,
    source_filename: str,
) -> str:
    """Derive a stable observation ID from the campaign's original AFL identity."""
    components = (campaign_uid, worker_name, observation_kind, source_filename)
    if any(not isinstance(item, str) or "\x00" in item for item in components):
        raise ValueError("Observation identity components must be NUL-free strings.")
    material = "\0".join(components).encode("utf-8")
    return "obs-" + hashlib.sha256(material).hexdigest()


class EvidenceRepository:
    """Small repository layer; SQL identifiers are fixed constants, values are bound."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    @staticmethod
    def _normalize_record(
        columns: tuple[str, ...], record: Mapping[str, object]
    ) -> dict[str, object]:
        unknown = set(record) - set(columns)
        missing = set(columns) - set(record) - _OPTIONAL_COLUMNS
        if unknown:
            raise ValueError(f"Unknown record fields: {', '.join(sorted(unknown))}")
        if missing:
            raise ValueError(f"Missing required record fields: {', '.join(sorted(missing))}")
        normalized: dict[str, object] = {}
        for column in columns:
            value = record.get(column)
            if isinstance(value, str) and "\x00" in value:
                raise ValueError(f"{column} must not contain NUL bytes.")
            if column in _INTEGER_COLUMNS and value is not None and type(value) is not int:
                raise ValueError(f"{column} must be an integer (booleans are not accepted).")
            if column in _TIMESTAMP_COLUMNS and value is not None:
                value = normalize_utc_timestamp(str(value), column)
            elif column in _JSON_COLUMNS and value is not None:
                if isinstance(value, str):
                    try:
                        value = json.loads(value)
                    except json.JSONDecodeError as exc:
                        raise ValueError(f"{column} must contain valid JSON.") from exc
                value = canonical_json(value)
            normalized[column] = value
        return normalized

    def _insert_immutable(
        self,
        table: str,
        columns: tuple[str, ...],
        record: Mapping[str, object],
        unique_keys: tuple[tuple[str, ...], ...],
        ignored_on_conflict: tuple[str, ...] = (),
    ) -> int:
        values = self._normalize_record(columns, record)
        column_sql = ", ".join(columns)
        placeholders = ", ".join("?" for _ in columns)
        existing_rows: dict[int, sqlite3.Row | tuple] = {}
        with _write_scope(self.connection):
            for key_columns in unique_keys:
                where = " AND ".join(f"{column} IS ?" for column in key_columns)
                parameters = tuple(values[column] for column in key_columns)
                row = self.connection.execute(
                    f"SELECT id, {column_sql} FROM {table} WHERE {where}", parameters
                ).fetchone()
                if row is not None:
                    existing_rows[int(row[0])] = row
            if len(existing_rows) > 1:
                raise EvidenceConflictError(f"Conflicting unique identities in {table}.")
            if existing_rows:
                row = next(iter(existing_rows.values()))
                differing_columns = tuple(
                    column for index, column in enumerate(columns)
                    if column not in ignored_on_conflict and row[index + 1] != values[column]
                )
                if differing_columns:
                    raise EvidenceConflictError(
                        f"Existing {table} identity has different immutable facts."
                    )
                return int(row[0])
            cursor = self.connection.execute(
                f"INSERT INTO {table} ({column_sql}) VALUES ({placeholders})",
                tuple(values[column] for column in columns),
            )
            return int(cursor.lastrowid)

    def insert_target(self, record: Mapping[str, object]) -> int:
        return self._insert_immutable(
            "targets", TARGET_COLUMNS, record, (("name",),),
            ignored_on_conflict=("created_at",),
        )

    def insert_target_version(self, record: Mapping[str, object]) -> int:
        return self._insert_immutable(
            "target_versions", TARGET_VERSION_COLUMNS, record,
            (("target_id", "version", "source_tree_sha256"),),
            ignored_on_conflict=("created_at",),
        )

    def insert_build(self, record: Mapping[str, object]) -> int:
        return self._insert_immutable(
            "builds", BUILD_COLUMNS, record,
            (("build_dir", "build_metadata_sha256"),),
            ignored_on_conflict=("recorded_at",),
        )

    def insert_campaign(self, record: Mapping[str, object]) -> int:
        return self._insert_immutable(
            "campaigns", CAMPAIGN_COLUMNS, record,
            (("campaign_uid",), ("campaign_dir",), ("afl_output_dir",)),
            ignored_on_conflict=("recorded_at",),
        )

    def insert_artifact(self, record: Mapping[str, object]) -> int:
        values = self._normalize_record(ARTIFACT_COLUMNS, record)
        with _write_scope(self.connection):
            row = self.connection.execute(
                "SELECT id, size_bytes, storage_relpath, first_ingested_at, last_verified_at "
                "FROM artifacts WHERE sha256 = ?",
                (values["sha256"],),
            ).fetchone()
            if row is not None:
                expected = (values["size_bytes"], values["storage_relpath"])
                actual = (row[1], row[2])
                if actual != expected:
                    raise EvidenceConflictError("Existing artifact hash has conflicting size or storage identity.")
                if values["last_verified_at"] > row[4]:
                    self.connection.execute(
                        "UPDATE artifacts SET last_verified_at = ? WHERE id = ?",
                        (values["last_verified_at"], row[0]),
                    )
                return int(row[0])
            cursor = self.connection.execute(
                "INSERT INTO artifacts(sha256, size_bytes, storage_relpath, first_ingested_at, last_verified_at) "
                "VALUES (?, ?, ?, ?, ?)",
                tuple(values[column] for column in ARTIFACT_COLUMNS),
            )
            return int(cursor.lastrowid)

    def insert_observation(self, record: Mapping[str, object]) -> int:
        normalized = dict(record)
        if "observation_uid" not in normalized:
            required = ("campaign_uid", "afl_worker_name", "observation_kind", "afl_source_filename")
            missing = [key for key in required if key not in normalized]
            if missing:
                raise ValueError("Missing observation identity inputs: " + ", ".join(missing))
            normalized["observation_uid"] = make_observation_uid(
                str(normalized.pop("campaign_uid")),
                str(normalized["afl_worker_name"]),
                str(normalized["observation_kind"]),
                str(normalized["afl_source_filename"]),
            )
        return self._insert_immutable(
            "observations", OBSERVATION_COLUMNS, normalized,
            (
                ("observation_uid",),
                ("campaign_id", "afl_worker_name", "observation_kind", "afl_source_filename"),
            ),
            ignored_on_conflict=("ingested_at",),
        )

    def get_sanitizer_context(
        self, observation_uid: str, diagnostic_build_id: int
    ) -> dict[str, object] | None:
        """Resolve one observation and a completed-build candidate across P3-01 parents."""
        if not isinstance(observation_uid, str) or not observation_uid:
            raise ValueError("observation_uid must be a non-empty string.")
        if type(diagnostic_build_id) is not int or diagnostic_build_id <= 0:
            raise ValueError("diagnostic_build_id must be a positive integer.")
        row = self.connection.execute(
            """
            SELECT
                o.id AS observation_id,
                o.observation_uid,
                o.target_id,
                o.target_version_id,
                o.build_id AS source_build_id,
                o.campaign_id,
                o.original_artifact_id,
                o.observation_kind,
                c.campaign_uid,
                c.campaign_dir,
                c.afl_output_dir,
                c.max_input_bytes,
                sb.build_role AS source_build_role,
                sb.build_status AS source_build_status,
                sb.profile AS source_build_profile,
                sb.build_dir AS source_build_dir,
                sb.build_metadata_sha256 AS source_build_metadata_sha256,
                db.build_role AS diagnostic_build_role,
                db.build_status AS diagnostic_build_status,
                db.profile AS diagnostic_build_profile,
                db.build_dir AS diagnostic_build_dir,
                db.build_metadata_sha256 AS diagnostic_build_metadata_sha256,
                db.harness_source_path AS diagnostic_harness_source_path,
                db.harness_binary_path AS diagnostic_harness_binary_path,
                db.harness_source_sha256 AS diagnostic_harness_source_sha256,
                db.harness_binary_sha256 AS diagnostic_harness_binary_sha256,
                db.library_archive_sha256 AS diagnostic_library_archive_sha256,
                db.compiler_path AS diagnostic_compiler_path,
                db.compiler_version AS diagnostic_compiler_version,
                db.sanitizer_config_json AS diagnostic_sanitizer_config_json,
                db.environment_json AS diagnostic_environment_json,
                tv.version AS target_version,
                tv.source_archive_sha256,
                tv.source_tree_sha256,
                a.sha256 AS original_artifact_sha256,
                a.size_bytes AS original_artifact_size,
                a.storage_relpath AS original_artifact_relpath
            FROM observations AS o
            JOIN campaigns AS c
              ON c.id = o.campaign_id
             AND c.target_id = o.target_id
             AND c.target_version_id = o.target_version_id
             AND c.build_id = o.build_id
            JOIN builds AS sb
              ON sb.id = o.build_id
             AND sb.target_id = o.target_id
             AND sb.target_version_id = o.target_version_id
            JOIN builds AS db
              ON db.id = ?
             AND db.target_id = o.target_id
             AND db.target_version_id = o.target_version_id
            JOIN target_versions AS tv
              ON tv.id = o.target_version_id AND tv.target_id = o.target_id
            JOIN artifacts AS a ON a.id = o.original_artifact_id
            WHERE o.observation_uid = ?
            """,
            (diagnostic_build_id, observation_uid),
        ).fetchone()
        if row is None:
            return None
        names = (
            "observation_id", "observation_uid", "target_id", "target_version_id",
            "source_build_id", "campaign_id", "original_artifact_id", "observation_kind",
            "campaign_uid", "campaign_dir", "afl_output_dir", "max_input_bytes",
            "source_build_role", "source_build_status", "source_build_profile",
            "source_build_dir", "source_build_metadata_sha256",
            "diagnostic_build_role", "diagnostic_build_status", "diagnostic_build_profile",
            "diagnostic_build_dir", "diagnostic_build_metadata_sha256",
            "diagnostic_harness_source_path", "diagnostic_harness_binary_path",
            "diagnostic_harness_source_sha256", "diagnostic_harness_binary_sha256",
            "diagnostic_library_archive_sha256", "diagnostic_compiler_path",
            "diagnostic_compiler_version", "diagnostic_sanitizer_config_json",
            "diagnostic_environment_json", "target_version", "source_archive_sha256",
            "source_tree_sha256", "original_artifact_sha256", "original_artifact_size",
            "original_artifact_relpath",
        )
        return dict(zip(names, row))

    def insert_sanitizer_run(self, record: Mapping[str, object]) -> int:
        """Insert one immutable sanitizer attempt; a retry must use a new run UID."""
        return self._insert_immutable(
            "sanitizer_runs",
            SANITIZER_RUN_COLUMNS,
            record,
            (("run_uid",),),
        )

    def get_sanitizer_run(self, run_uid: str) -> dict[str, object] | None:
        """Return one persisted sanitizer attempt by immutable UID."""
        if not isinstance(run_uid, str) or not run_uid:
            raise ValueError("run_uid must be a non-empty string.")
        rows = self.connection.execute(
            "SELECT id, " + ", ".join(SANITIZER_RUN_COLUMNS)
            + " FROM sanitizer_runs WHERE run_uid = ?",
            (run_uid,),
        ).fetchone()
        if rows is None:
            return None
        return dict(zip(("id",) + SANITIZER_RUN_COLUMNS, rows))

    def list_sanitizer_runs(
        self, observation_uid: str
    ) -> tuple[dict[str, object], ...]:
        """List immutable attempts for one observation in recorded order."""
        if not isinstance(observation_uid, str) or not observation_uid:
            raise ValueError("observation_uid must be a non-empty string.")
        rows = self.connection.execute(
            "SELECT id, " + ", ".join(SANITIZER_RUN_COLUMNS)
            + " FROM sanitizer_runs WHERE observation_id = ("
            "SELECT id FROM observations WHERE observation_uid = ?"
            ") ORDER BY attempt_started_at, run_uid",
            (observation_uid,),
        ).fetchall()
        return tuple(
            dict(zip(("id",) + SANITIZER_RUN_COLUMNS, row)) for row in rows
        )

    def get_artifact(self, digest: str) -> dict[str, object] | None:
        row = self.connection.execute(
            "SELECT id, sha256, size_bytes, storage_relpath, first_ingested_at, last_verified_at "
            "FROM artifacts WHERE sha256 = ?",
            (digest,),
        ).fetchone()
        if row is None:
            return None
        keys = ("id", "sha256", "size_bytes", "storage_relpath", "first_ingested_at", "last_verified_at")
        return dict(zip(keys, row))

    def list_artifacts(self) -> tuple[dict[str, object], ...]:
        rows = self.connection.execute(
            "SELECT id, sha256, size_bytes, storage_relpath, first_ingested_at, last_verified_at "
            "FROM artifacts ORDER BY sha256"
        ).fetchall()
        keys = ("id", "sha256", "size_bytes", "storage_relpath", "first_ingested_at", "last_verified_at")
        return tuple(dict(zip(keys, row)) for row in rows)
