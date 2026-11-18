#!/usr/bin/env python3
"""Build and register the fixed libpng ASan+UBSan diagnostic profile."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from engine.adapters.config import AdapterConfigError, load_adapter_config
from engine.build.diagnostic import DiagnosticBuildError, build_libpng_diagnostic


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        default=str(REPOSITORY_ROOT / "targets/libpng/adapter.toml"),
        help="schema-4 libpng adapter TOML",
    )
    parser.add_argument(
        "--project-root",
        default=str(REPOSITORY_ROOT),
        help="KEKKAI repository root",
    )
    parser.add_argument(
        "--build-dir",
        required=True,
        help="new absolute diagnostic build directory outside protected project data",
    )
    parser.add_argument(
        "--evidence-root",
        required=True,
        help="separate P3-01 evidence store directory",
    )
    args = parser.parse_args()
    try:
        config = load_adapter_config(args.config, args.project_root)
        result = build_libpng_diagnostic(
            config,
            args.project_root,
            args.build_dir,
            args.evidence_root,
        )
    except (AdapterConfigError, DiagnosticBuildError, OSError, ValueError) as exc:
        print(f"Diagnostic build refused or failed: {exc}", file=sys.stderr)
        return 1

    print(json.dumps({
        "build_id": result.build_id,
        "build_dir": str(result.build_dir),
        "build_metadata": str(result.metadata_path),
        "build_metadata_sha256": result.metadata_sha256,
        "harness_sha256": result.harness_sha256,
        "library_archive_sha256": result.archive_sha256,
        "build_role": "diagnostic_replay",
        "status": "completed",
    }, sort_keys=True, indent=2))
    print("No AFL campaign files or existing build directories were modified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
