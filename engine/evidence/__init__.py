"""Local, evidence-preserving metadata and artifact storage for KEKKAI."""

from .database import (
    EvidenceDatabaseError,
    immediate_transaction,
    open_database,
    utc_now_iso,
)
from .repository import EvidenceConflictError, EvidenceRepository
from .store import (
    EvidenceIntegrityError,
    EvidenceStore,
    EvidenceStoreError,
    StoredArtifact,
)

__all__ = [
    "EvidenceConflictError",
    "EvidenceDatabaseError",
    "EvidenceIntegrityError",
    "EvidenceRepository",
    "EvidenceStore",
    "EvidenceStoreError",
    "StoredArtifact",
    "immediate_transaction",
    "open_database",
    "utc_now_iso",
]
