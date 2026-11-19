#!/usr/bin/env python3
"""Collect bounded ASan/UBSan evidence for one imported libpng observation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from engine.evidence.sanitizer import (  # noqa: E402
    SanitizerCollectionError,
    collect_sanitizer_evidence,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--evidence-root",
        required=True,
        help="existing P3-01 evidence store directory outside the checkout",
    )
    parser.add_argument(
        "--diagnostic-build-id",
        required=True,
        type=int,
        help="registered completed P3-03 diagnostic build ID",
    )
    parser.add_argument(
        "--observation-uid",
        required=True,
        help="exact imported P3-02 observation UID to execute once",
    )
    parser.add_argument(
        "--recovery-root",
        help="optional private recovery directory adjacent to the evidence root",
    )
    parser.add_argument(
        "--project-root",
        default=str(REPOSITORY_ROOT),
        help="KEKKAI repository checkout",
    )
    args = parser.parse_args()

    try:
        result = collect_sanitizer_evidence(
            args.evidence_root,
            args.diagnostic_build_id,
            args.observation_uid,
            recovery_root=args.recovery_root,
            project_root=args.project_root,
        )
    except (SanitizerCollectionError, OSError, ValueError, RuntimeError) as exc:
        print(f"Sanitizer collection refused or failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({
        "run_uid": result.run_uid,
        "database_row_id": result.database_row_id,
        "execution_status": result.execution_status,
        "assessment": result.assessment,
        "recovery_path": str(result.recovery_path) if result.recovery_path else None,
        "note": "Observed sanitizer markers are evidence, not a confirmed vulnerability.",
    }, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
