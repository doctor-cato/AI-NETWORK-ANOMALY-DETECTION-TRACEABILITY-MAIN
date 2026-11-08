#!/usr/bin/env python3
"""Experiment runner - step status is decided by implementation, not by exit code 0.

Exit codes:
  0 - ``check-data`` completed (or its optional default-dataset check was
      intentionally skipped because the raw CSV is absent), or ``baseline``
      training and verified reload completed via ``scripts/train_random_forest.py``.
  1 - ``check-data`` verified the dataset but reports ``ML_READY: BLOCKED``
      (for the current v3 audit this includes ``RAW_QUALITY: FINDINGS_RECORDED``),
      or ``baseline`` failed closed due to missing prerequisites / verification
      failure in ``scripts/train_random_forest.py``.
  2 - invalid command line (argparse default), or ``check-data`` found a
      source-integrity/corruption failure.
  3 - step (``evaluate``, ``inference``) is planned but NOT implemented. This is
      not a result and must not be reported as a successful experiment.

Usage:
  python scripts/run_experiments.py --step check-data
  python scripts/run_experiments.py --step baseline  # delegates to train_random_forest.py
  python scripts/run_experiments.py --step evaluate  # exits 3 until M3 implements it
"""

import argparse

EXIT_NOT_IMPLEMENTED = 3  # see docstring; 2 stays reserved for argparse usage errors

# step -> (what the step will do, why it is not implemented yet)
NOT_IMPLEMENTED_STEPS = {
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
    parser = argparse.ArgumentParser(
        description=(
            "Run experiment steps ('check-data' delegates to scripts/validate_data.py; "
            "'baseline' delegates to scripts/train_random_forest.py; "
            "'xgboost' delegates to scripts/train_xgboost.py; "
            "'evaluate' and 'inference' remain NOT IMPLEMENTED and exit 3)."
        )
    )
    parser.add_argument(
        "--step",
        choices=["check-data", "baseline", "xgboost", *NOT_IMPLEMENTED_STEPS],
        default="check-data",
        help="Experiment step to run",
    )
    args = parser.parse_args(argv)

    if args.step == "check-data":
        # Imported lazily so that reporting an unimplemented step never depends on
        # the package being installed.
        import validate_data

        print("[run_experiments] Step check-data: delegating to scripts/validate_data.py")
        return validate_data.main([])

    if args.step == "baseline":
        import train_random_forest

        print("[run_experiments] Step baseline: delegating to scripts/train_random_forest.py")
        return train_random_forest.main([])

    if args.step == "xgboost":
        import train_xgboost

        print("[run_experiments] Step xgboost: delegating to scripts/train_xgboost.py")
        return train_xgboost.main([])

    planned, reason = NOT_IMPLEMENTED_STEPS[args.step]
    print(f"[run_experiments] Planned: {planned}")
    print(f"[run_experiments] Status: NOT IMPLEMENTED ({reason})")
    print(
        f"[run_experiments] Exit {EXIT_NOT_IMPLEMENTED} means the step is unimplemented,"
        " not that it succeeded."
    )
    return EXIT_NOT_IMPLEMENTED


if __name__ == "__main__":
    raise SystemExit(main())
