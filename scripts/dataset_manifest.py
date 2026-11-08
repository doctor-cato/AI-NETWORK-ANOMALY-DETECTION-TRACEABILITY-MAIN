#!/usr/bin/env python3
"""Verify the version-controlled NF-UNSW-NB15-v3 manifest against local bytes."""

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATA_RAW = PROJECT_ROOT / "data" / "raw"
DEFAULT_MANIFEST = PROJECT_ROOT / "data" / "NF_UNSW_NB15_V3_MANIFEST.json"
TIMESTAMP_PATTERN = re.compile(
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})"
)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def iter_timestamps(payload, prefix=""):
    if isinstance(payload, dict):
        for key, value in payload.items():
            field = f"{prefix}.{key}" if prefix else key
            if key.endswith("_at_utc"):
                yield field, value
            else:
                yield from iter_timestamps(value, field)
    elif isinstance(payload, list):
        for index, value in enumerate(payload):
            yield from iter_timestamps(value, f"{prefix}[{index}]")


def validate_timestamp(value, field):
    if not isinstance(value, str) or not TIMESTAMP_PATTERN.fullmatch(value):
        raise ValueError(f"{field} must be an ISO 8601 timestamp with explicit UTC offset")
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError(f"{field} must not be naive")


def safe_relative_path(value):
    path = Path(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ValueError(f"unsafe manifest file path: {value!r}")
    return path


def load_manifest(path):
    manifest = json.loads(path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported manifest schema_version")
    if manifest.get("dataset") != "NF-UNSW-NB15-v3":
        raise ValueError("manifest is not for NF-UNSW-NB15-v3")
    source = manifest["official_source"]
    if source.get("rdm_uuid") != "abd2f5d8-e268-4ff0-84fb-f2f7b3ca3e8f":
        raise ValueError("unexpected UQRDM dataset UUID")
    if source.get("access_type") != "OPEN":
        raise ValueError("manifest does not record OPEN access")
    for field, value in iter_timestamps(manifest):
        validate_timestamp(value, field)
    columns = manifest["schema"]["columns_in_order"]
    if len(columns) != 55 or len(set(columns)) != 55:
        raise ValueError("manifest schema must contain 55 distinct ordered columns")
    if columns[-2:] != ["Label", "Attack"]:
        raise ValueError("manifest targets must be Label and Attack")
    files = manifest["files"]
    if len(files) != 7 or len({entry["file"] for entry in files}) != 7:
        raise ValueError("manifest must contain seven distinct package files")
    return manifest


def verify(manifest_path, directory):
    manifest = load_manifest(manifest_path)
    package_name = manifest["package"]["local_directory"]
    if Path(package_name).name != package_name:
        raise ValueError("unsafe package local_directory")
    package = directory / package_name
    for entry in manifest["files"]:
        relative = safe_relative_path(entry["file"])
        target = package / relative
        if not target.is_file():
            raise ValueError(f"missing package file: {target}")
        if target.stat().st_size != entry["size_bytes"]:
            raise ValueError(f"size mismatch: {entry['file']}")
        digest = sha256_file(target)
        if digest != entry["sha256"]:
            raise ValueError(
                f"SHA-256 mismatch for {entry['file']}: expected {entry['sha256']}, got {digest}"
            )
        print(f"[dataset_manifest] VERIFIED local bytes: {entry['file']}")
    print("[dataset_manifest] PASS: NF-UNSW-NB15-v3 package matches " f"{manifest_path.name}")


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("verify",), nargs="?", default="verify")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--directory", type=Path, default=DATA_RAW)
    args = parser.parse_args(argv)
    try:
        verify(args.manifest, args.directory)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"[dataset_manifest] ERROR: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
