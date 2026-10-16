#!/usr/bin/env python3
"""Experiment runner — planned; full implementation depends on dataset availability.

Usage: python scripts/run_experiments.py --step baseline
"""
import argparse
import sys


def main():
    parser = argparse.ArgumentParser(description="Run experiment steps")
    parser.add_argument(
        "--step",
        choices=["check-data", "baseline", "evaluate", "inference"],
        default="check-data",
        help="Experiment step to run",
    )
    args = parser.parse_args()
    if args.step == "check-data":
        print("[run_experiments] Planned: run validate_data.py on data/raw/")
        print("[run_experiments] Status: NOT RUN (dataset not yet downloaded)")
        sys.exit(0)
    elif args.step == "baseline":
        print("[run_experiments] Planned: train Random Forest baseline")
        print("[run_experiments] Status: NOT IMPLEMENTED (model module exists; training requires verified dataset)")
        sys.exit(0)
    elif args.step == "evaluate":
        print("[run_experiments] Planned: evaluate saved model")
        print("[run_experiments] Status: NOT IMPLEMENTED")
        sys.exit(0)
    elif args.step == "inference":
        print("[run_experiments] Planned: inference on new input")
        print("[run_experiments] Status: NOT IMPLEMENTED")
        sys.exit(0)


if __name__ == "__main__":
    main()
