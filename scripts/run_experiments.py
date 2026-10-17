#!/usr/bin/env python3
"""Experiment runner — step status is decided by implementation, not by exit code 0.

Exit codes:
  0 — step completed, or the optional data check was intentionally skipped (no dataset).
  1 — step ran and failed (for example: dataset CSV is invalid).
  2 — step is planned but NOT implemented. This is not a result and must not be
      reported as a successful experiment.

Usage:
  python scripts/run_experiments.py --step check-data
  python scripts/run_experiments.py --step baseline   # exits 2 until M2 implements it
"""
import argparse
import sys

import validate_data

EXIT_NOT_IMPLEMENTED = 2  # see docstring for the exit-code contract

# step -> (what the step will do, why it is not implemented yet)
NOT_IMPLEMENTED_STEPS = {
    "baseline": (
        "train the Random Forest baseline",
        "training requires a verified dataset and belongs to M2 / issue #10",
    ),
    "evaluate": (
        "evaluate a trained model",
        "training and evaluation belong to M3 / issues #12 and #13",
    ),
    "inference": (
        "run inference on new input",
        "the inference entrypoint belongs to M4 / issue #15",
    ),
}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run experiment steps")
    parser.add_argument(
        "--step",
        choices=["check-data", *NOT_IMPLEMENTED_STEPS],
        default="check-data",
        help="Experiment step to run",
    )
    args = parser.parse_args(argv)

    if args.step == "check-data":
        print("[run_experiments] Step check-data: delegating to scripts/validate_data.py")
        return validate_data.main([])

    planned, reason = NOT_IMPLEMENTED_STEPS[args.step]
    print(f"[run_experiments] Planned: {planned}")
    print(f"[run_experiments] Status: NOT IMPLEMENTED ({reason})")
    print(f"[run_experiments] Exit {EXIT_NOT_IMPLEMENTED} means the step is unimplemented, not that it succeeded.")
    return EXIT_NOT_IMPLEMENTED


if __name__ == "__main__":
    raise SystemExit(main())
