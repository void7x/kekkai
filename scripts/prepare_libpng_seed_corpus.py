#!/usr/bin/env python3
"""Prepare an expanded, deterministic libpng seed corpus outside the repository."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from engine.adapters.config import AdapterConfigError, load_adapter_config
from engine.fuzzing.libpng_seed_corpus import (
    SeedCorpusError,
    prepare_libpng_seed_corpus,
)


def _resolve_argument(value: str, root: Path) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = root / path
    return path


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Copy the existing ten-seed libpng corpus and append eight "
            "deterministic PNG variants into a new external directory."
        )
    )
    parser.add_argument(
        "--source-dir",
        required=True,
        help="Existing seed directory to preserve and copy.",
    )
    parser.add_argument(
        "--output-dir",
        help=(
            "New output directory. Defaults to the path configured in "
            "targets/libpng/adapter.toml."
        ),
    )
    args = parser.parse_args()

    try:
        config = load_adapter_config(
            PROJECT_ROOT / "targets" / "libpng" / "adapter.toml",
            PROJECT_ROOT,
        )
        source = _resolve_argument(args.source_dir, PROJECT_ROOT)
        destination = (
            _resolve_argument(args.output_dir, PROJECT_ROOT)
            if args.output_dir
            else config.target.seed_dir
        )
        result = prepare_libpng_seed_corpus(
            source,
            destination,
            repository_root=PROJECT_ROOT,
            target_source_root=config.target.source_dir,
            campaign_output_parent=config.target.output_parent,
            max_input_bytes=config.limits.max_input_bytes,
        )
    except (AdapterConfigError, SeedCorpusError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print("Seed corpus prepared successfully.")
    print(f"Directory: {result.destination}")
    print(f"Seed count: {result.seed_manifest.seed_count}")
    print(f"Total bytes: {result.seed_manifest.total_bytes}")
    print(f"Manifest SHA-256: {result.seed_manifest.sha256}")
    print("Added seeds:")
    for name in result.added_seed_names:
        print(f"  {name}")
    print("The source corpus was preserved.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
