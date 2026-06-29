#!/usr/bin/env python3
"""CLI entry point for the P0 guardrail evaluation runner.

Examples:
  python scripts/run_p0.py                          # oracle self-test
  python scripts/run_p0.py --provider baseline      # intentionally weak negative control
  python scripts/run_p0.py --provider rules         # deterministic rule baseline
  python scripts/run_p0.py --provider file --predictions preds.jsonl
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from p0eval.runner import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
