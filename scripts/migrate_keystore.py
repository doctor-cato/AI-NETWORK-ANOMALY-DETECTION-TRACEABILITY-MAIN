#!/usr/bin/env python3
"""Controlled migration of a legacy NetFlow Sentinel keystore.

Issue #119. Converts:

* a raw or POSIX-prefixed plaintext ``master.key`` into Windows DPAPI
  protection (POSIX keeps the ``0600`` permission model),
* plaintext DEK files into AES-256-GCM wrapped DEKs (v2 AAD), and
* v1 wrapped DEKs into the v2 format.

Every DEK is re-wrapped before the master key is protected, so a failure leaves
a usable keystore. The report never contains key bytes.

Exit codes: 0 = migrated or already current, 1 = failure, 2 = migration needed
with ``--verify-only`` (CI can treat this as SKIPPED rather than PASS).
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--keystore-dir",
        default="data/keys",
        help="keystore directory (default: data/keys)",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="inspect only; exit 2 when migration is still required",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print the report as JSON",
    )
    args = parser.parse_args(argv)

    from network_anomaly.crypto.key_manager import (
        KeyManager,
        KeyStorageError,
    )

    keystore = Path(args.keystore_dir)
    try:
        if args.verify_only:
            report = KeyManager.inspect_keystore(keystore)
            status = "MIGRATION_REQUIRED" if report["migration_required"] else "CURRENT"
            report["verify_status"] = status
            exit_code = 2 if report["migration_required"] else 0
        else:
            report = KeyManager.migrate_legacy_keystore(keystore)
            report["verify_status"] = "MIGRATED" if report.get("migrated") else "CURRENT"
            exit_code = 0
    except KeyStorageError as exc:
        print(f"FAILED: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"keystore: {report['keystore_dir']}")
        if args.verify_only:
            print(f"master key format: {report['master_key_format']}")
            print(f"status: {report['verify_status']}")
        else:
            print(f"master key migrated to: {report.get('master_key_migrated_to')}")
            print(f"status: {report['verify_status']}")
            print("plaintext DEKs re-wrapped: " f"{len(report.get('dek_rewrapped_plaintext', []))}")
            print("v1 DEKs upgraded: " f"{len(report.get('dek_rewrapped_v1', []))}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
