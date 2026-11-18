#!/usr/bin/env python3
"""Import original AFL++ crash and hang testcases into the KEKKAI evidence store."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from engine.evidence.afl_ingest import AflIngestError, ingest_afl_campaign


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--campaign-dir",
        required=True,
        help="absolute path to one terminal KEKKAI campaign directory",
    )
    parser.add_argument(
        "--config",
        required=True,
        help="absolute path to the exact schema-4 adapter TOML used by the campaign",
    )
    parser.add_argument(
        "--evidence-root",
        required=True,
        help="absolute path to the separate P3-01 evidence store",
    )
    args = parser.parse_args()
    try:
        result = ingest_afl_campaign(
            args.campaign_dir,
            args.config,
            args.evidence_root,
        )
    except (AflIngestError, OSError, ValueError) as exc:
        print(f"AFL++ evidence ingestion refused: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({
        "campaign_uid": result.campaign_uid,
        "crashes": result.crash_count,
        "hangs": result.hang_count,
        "artifacts": result.artifact_count,
        "total_bytes": result.total_bytes,
        "target_id": result.target_id,
        "target_version_id": result.target_version_id,
        "build_id": result.build_id,
        "campaign_row_id": result.campaign_row_id,
    }, sort_keys=True, indent=2))
    print("Original AFL++ campaign files were not modified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
