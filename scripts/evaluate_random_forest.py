#!/usr/bin/env python3
"""CLI evaluation script for Random Forest baseline on held-out Test set (Issue #12).

Executes post-training evaluation on locked Test partition with fail-closed prerequisite
verification of manifests and cryptographic hashes. Supports --verify-only mode.
"""

from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_SOURCE = PROJECT_ROOT / "src"
if str(LOCAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(LOCAL_SOURCE))

from network_anomaly.evaluation.test_evaluation import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
