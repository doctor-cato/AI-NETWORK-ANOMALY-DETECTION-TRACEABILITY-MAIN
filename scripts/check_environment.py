#!/usr/bin/env python3
"""Check environment — basic import and version checks."""
import sys

def main():
    errors = []
    for pkg in ("pandas", "numpy", "sklearn", "matplotlib", "seaborn"):
        try:
            __import__(pkg)
            print(f"OK {pkg}")
        except Exception as e:
            errors.append((pkg, e))
            print(f"FAIL {pkg}: {e}")
    if errors:
        sys.exit(1)
    print("Environment check passed.")

if __name__ == "__main__":
    main()
