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
OBSERVATION_COLUMNS = (
    "observation_uid", "target_id", "target_version_id", "build_id", "campaign_id",
    "original_artifact_id", "observation_kind", "afl_worker_name", "afl_source_filename",
    "afl_input_id", "observed_signal", "observed_exit_code", "afl_discovery_time_ms",
    "afl_discovery_execs", "source_file_mtime_utc", "ingested_at",
)

_TIMESTAMP_COLUMNS = {
    "created_at", "started_at", "ended_at", "recorded_at", "first_ingested_at",
    "last_verified_at", "source_file_mtime_utc", "ingested_at",
}
_JSON_COLUMNS = {"sanitizer_config_json", "environment_json", "command_json"}
_INTEGER_COLUMNS = {
    "target_id", "target_version_id", "build_id", "campaign_id", "original_artifact_id",
    "afl_instrumented_locations", "seed_count", "duration_seconds", "memory_mib",
    "timeout_ms", "effective_timeout_ms", "max_input_bytes", "afl_max_generated_bytes",
    "exit_code", "total_execs", "saved_crashes_reported", "saved_hangs_reported",
    "size_bytes", "observed_signal", "observed_exit_code", "afl_discovery_time_ms",
    "afl_discovery_execs",
}
_OPTIONAL_COLUMNS = {
    "description", "source_archive_path", "harness_source_sha256", "harness_binary_sha256",
    "library_archive_sha256", "cmake_cache_sha256", "compile_database_sha256",
    "generated_header_sha256", "aflpp_version", "afl_instrumented_locations",
    "effective_timeout_ms", "exit_code", "total_execs", "saved_crashes_reported",
    "saved_hangs_reported", "afl_input_id", "observed_signal", "observed_exit_code",
    "afl_discovery_time_ms", "afl_discovery_execs",
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
