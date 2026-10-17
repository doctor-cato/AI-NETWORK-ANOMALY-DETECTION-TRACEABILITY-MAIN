#!/usr/bin/env python3
"""Record and recheck local UNSW-NB15 file bytes without modifying the CSVs."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from validate_data import DEFAULT_FILES, sha256_file

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_RAW = PROJECT_ROOT / "data" / "raw"
DEFAULT_MANIFEST = PROJECT_ROOT / "data" / "UNSW_NB15_MANIFEST.json"

SOURCE_PAGE = "https://research.unsw.edu.au/projects/unsw-nb15-dataset"


def record(files, destination, acquired_from, downloaded_at):
    if destination.exists():
        raise ValueError(f"manifest already exists: {destination}")
    if {path.name for path in files} != set(DEFAULT_FILES) or len(files) != len(DEFAULT_FILES):
        raise ValueError("record requires both published train/test split files")
    parsed = urlsplit(acquired_from)
    if (
        parsed.scheme != "https"
        or not parsed.netloc
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ValueError(
            "acquired-from must be an HTTPS URL without credentials, query or fragment"
        )
    acquired = datetime.fromisoformat(downloaded_at.replace("Z", "+00:00"))
    if acquired.tzinfo is None:
        raise ValueError("downloaded-at must include a UTC offset or Z")
    entries = []
    for path in files:
        if path.name not in DEFAULT_FILES:
            raise ValueError(f"unsupported split file: {path.name}")
        if not path.is_file():
            raise ValueError(f"missing dataset file: {path}")
        entries.append(
            {
                "file": path.name,
                "size_bytes": path.stat().st_size,
                "sha256": sha256_file(path),
            }
        )
    if len({entry["file"] for entry in entries}) != len(entries):
        raise ValueError("duplicate file names")
    manifest = {
        "variant": "UNSW-NB15 published training/testing partition",
        "source_page": SOURCE_PAGE,
        "acquired_from": acquired_from,
        "downloaded_at": downloaded_at,
        "recorded_at_utc": datetime.now(timezone.utc)
        .isoformat(timespec="seconds")
        .replace("+00:00", "Z"),
        "checksum_scope": "local file bytes; UNSW has not published a SHA-256 for comparison",
        "files": entries,
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"[dataset_manifest] RECORDED: {destination}")


def verify(manifest_path, directory):
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    entries = manifest["files"]
    if len(entries) != len(DEFAULT_FILES) or {entry["file"] for entry in entries} != set(
        DEFAULT_FILES
    ):
        raise ValueError("manifest requires both distinct train/test split files")
    for entry in entries:
        name = entry["file"]
        if name not in DEFAULT_FILES:
            raise ValueError(f"unsupported manifest file: {name}")
        path = directory / name
        if not path.is_file():
            raise ValueError(f"missing dataset file: {path}")
        if path.stat().st_size != entry["size_bytes"]:
            raise ValueError(f"size mismatch: {name}")
        if sha256_file(path) != entry["sha256"]:
            raise ValueError(f"SHA-256 mismatch: {name}")
        print(f"[dataset_manifest] VERIFIED local bytes: {name}")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("record", "verify"))
    parser.add_argument("--file", action="append", help="CSV path; repeat for both split files")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--directory", type=Path, default=DATA_RAW, help="CSV directory for verify")
    parser.add_argument(
        "--acquired-from", help="HTTPS page or stable file URL used to obtain the CSVs"
    )
    parser.add_argument("--downloaded-at", help="Actual acquisition timestamp in ISO 8601 UTC")
    args = parser.parse_args(argv)
    try:
        if args.action == "record":
            if not args.file:
                raise ValueError("record requires --file")
            if not args.acquired_from or not args.downloaded_at:
                raise ValueError("record requires --acquired-from and --downloaded-at")
            record(
                [Path(value) for value in args.file],
                args.manifest,
                args.acquired_from,
                args.downloaded_at,
            )
        else:
            verify(args.manifest, args.directory)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"[dataset_manifest] ERROR: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
