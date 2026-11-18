#!/usr/bin/env python3
"""Safely archive a terminal failed/interrupted KEKKAI build."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPOSITORY_ROOT))

from engine.adapters.config import AdapterConfigError, load_adapter_config
from engine.build.libpng import BuildError
from engine.build.runner import recover_failed_build


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        default="targets/libpng/adapter.toml",
        help="adapter TOML path (default: targets/libpng/adapter.toml)",
    )
    args = parser.parse_args()
    try:
        config = load_adapter_config(args.config, REPOSITORY_ROOT)
        archived = recover_failed_build(config, REPOSITORY_ROOT)
    except (AdapterConfigError, BuildError, OSError, ValueError) as exc:
        print(f"Recovery refused: {exc}", file=sys.stderr)
        return 1
    print(f"Failed build preserved at: {archived}")
    print("Logs and partial outputs were retained. No build directory was deleted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
