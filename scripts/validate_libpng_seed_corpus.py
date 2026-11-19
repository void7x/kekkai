#!/usr/bin/env python3
"""Run bounded libpng harness and AFL coverage validation without fuzzing."""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

from engine.adapters.config import AdapterConfigError, load_adapter_config
from engine.fuzzing.coverage import CoverageValidationError, validate_coverage
from engine.fuzzing.smoke import HarnessSmokeError, run_harness_smoke


def main() -> int:
    try:
        config = load_adapter_config(
            PROJECT_ROOT / "targets" / "libpng" / "adapter.toml",
            PROJECT_ROOT,
        )
        smoke = run_harness_smoke(config, PROJECT_ROOT)
        print(smoke.format())
        if not smoke.passed:
            print("STOP: harness smoke validation failed; coverage was not run.")
            return 1

        coverage = validate_coverage(config, PROJECT_ROOT)
        print()
        print(coverage.format())
        if not coverage.passed:
            print(
                "STOP: supplemental seeds did not demonstrate all required "
                "coverage checks. No AFL++ campaign was started."
            )
            return 1
    except (
        AdapterConfigError,
        HarnessSmokeError,
        CoverageValidationError,
        OSError,
        ValueError,
    ) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    print()
    print(
        "Validation passed. This command did not start afl-fuzz. "
        "A new campaign still requires project-owner approval."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

