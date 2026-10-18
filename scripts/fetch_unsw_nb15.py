#!/usr/bin/env python3
"""Download the selected UNSW-NB15 train/test mirror without changing CSV bytes."""

import argparse
import hashlib
import os
import shutil
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DESTINATION = PROJECT_ROOT / "data" / "raw"
REVISION = "44bbd02b9e70f74dd915218d5eb702f125341ffc"
BASE_URL = (
    "https://raw.githubusercontent.com/Nir-J/ML-Projects/"
    f"{REVISION}/UNSW-Network_Packet_Classification"
)
FILES = {
    "UNSW_NB15_training-set.csv": {
        "size_bytes": 32293018,
        "sha256": "bec7dd5ec88dc2a0ccc7a07879d338395ed7421750f675fd0339e07dfe0648fa",
    },
    "UNSW_NB15_testing-set.csv": {
        "size_bytes": 15380800,
        "sha256": "734fe6642edf758f7c94d7d9149426b49d202fe8e7bf0bef47392489c3c0a559",
    },
}
# Staging lives beside the destination so the verified bytes can be swapped in atomically.
STAGING_PREFIX = ".unsw-nb15-staging-"


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_download(path, expected):
    """Raise unless the local bytes match the pinned size and SHA-256 exactly."""
    with path.open("rb") as stream:
        prefix = stream.read(256).lstrip()
    if prefix.lower().startswith((b"<!doctype html", b"<html", b"version https://git-lfs")):
        raise ValueError(f"unexpected HTML or Git LFS pointer: {path.name}")
    size = path.stat().st_size
    if size != expected["size_bytes"]:
        raise ValueError(
            f"size mismatch for {path.name}: expected {expected['size_bytes']}, got {size}"
        )
    digest = sha256_file(path)
    if digest != expected["sha256"]:
        raise ValueError(
            f"SHA-256 mismatch for {path.name}: expected {expected['sha256']}, got {digest}"
        )
    return digest


def download_to_staging(name, expected, staging, base_url):
    """Fetch one revision-pinned file into `staging`; returns the verified digest."""
    request = Request(f"{base_url}/{name}", headers={"User-Agent": "unsw-nb15-fetch/1"})
    with urlopen(request, timeout=60) as response:
        status = getattr(response, "status", 200)
        content_type = response.headers.get_content_type()
        if status != 200:
            raise ValueError(f"HTTP {status} for {name}")
        if content_type in {"text/html", "application/vnd.git-lfs+json"}:
            raise ValueError(f"unexpected Content-Type {content_type} for {name}")
        print(f"[fetch_unsw_nb15] DOWNLOAD: {name} <- {base_url}/{name}")
        with staging.open("wb") as output:
            shutil.copyfileobj(response, output)
    digest = verify_download(staging, expected)
    print(f"[fetch_unsw_nb15] VERIFIED: {name} bytes={expected['size_bytes']} sha256={digest}")
    return digest


def cache_is_valid(target, expected):
    """Return True only for a byte-exact local cache; never trust the name or size alone."""
    if not target.is_file():
        print(f"[fetch_unsw_nb15] CACHE_INVALID: {target.name}: absent at {target}")
        return False
    try:
        digest = verify_download(target, expected)
    except (ValueError, FileNotFoundError) as error:
        print(f"[fetch_unsw_nb15] CACHE_INVALID: {target.name}: {error}")
        return False
    print(
        f"[fetch_unsw_nb15] CACHE_HIT: {target.name} "
        f"bytes={expected['size_bytes']} sha256={digest}"
    )
    return True


def fetch(destination, files=None, base_url=None):
    files = FILES if files is None else files
    base_url = BASE_URL if base_url is None else base_url
    destination.mkdir(parents=True, exist_ok=True)
    staging = {name: destination / f"{STAGING_PREFIX}{name}" for name in files}
    try:
        pending = {}
        for name, expected in files.items():
            if cache_is_valid(destination / name, expected):
                continue
            pending[name] = download_to_staging(name, expected, staging[name], base_url)
        # Install only once every needed file is staged and verified, so a failed run
        # never leaves a half-populated data/raw/ directory.
        for name in pending:
            os.replace(staging[name], destination / name)
            print(f"[fetch_unsw_nb15] INSTALLED unchanged bytes: {destination / name}")
    finally:
        for path in staging.values():
            path.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    args = parser.parse_args(argv)
    try:
        fetch(args.destination)
    except (OSError, HTTPError, URLError, ValueError) as error:
        print(f"[fetch_unsw_nb15] ERROR: {error}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
