#!/usr/bin/env python3
"""CLI script for Random Forest Error Analysis (Issue #13).

Generates evidence-driven error analysis report linking to verified split and model audit
artifacts without hardcoded metrics.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_SOURCE = PROJECT_ROOT / "src"
if str(LOCAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(LOCAL_SOURCE))

from network_anomaly.evaluation.error_analysis import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
