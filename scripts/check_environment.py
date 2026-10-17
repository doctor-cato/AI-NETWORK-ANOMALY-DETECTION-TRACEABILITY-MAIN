#!/usr/bin/env python3
"""Check environment — Python version floor, third-party imports, and this package.

Exit code 0 only when every checked import succeeds. This is a setup check;
it says nothing about training or evaluation results.
"""
import sys

MIN_PYTHON = (3, 11)
PACKAGES = (
    "pandas",
    "numpy",
    "sklearn",
    "joblib",
    "matplotlib",
    "seaborn",
    "network_anomaly",
)


def main():
    failed = []
    required = ".".join(map(str, MIN_PYTHON))
    running = sys.version.split()[0]
    if sys.version_info < MIN_PYTHON:
        failed.append("python")
        print(f"FAIL python: {required}+ required, running {running}")
    else:
        print(f"OK python {running}")
    for pkg in PACKAGES:
        try:
            __import__(pkg)
            print(f"OK {pkg}")
        except Exception as e:
            failed.append(pkg)
            print(f"FAIL {pkg}: {e}")
    if failed:
        print("Environment check failed: " + ", ".join(failed))
        sys.exit(1)
    print("Environment check passed.")


if __name__ == "__main__":
    main()
