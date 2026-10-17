#!/usr/bin/env python3
"""Download the selected UNSW-NB15 train/test mirror without changing CSV bytes."""

import argparse
import hashlib
import shutil
import tempfile
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


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_download(path, expected):
    prefix = path.read_bytes()[:256].lstrip()
    if prefix.lower().startswith((b"<!doctype html", b"<html", b"version https://git-lfs")):
        raise ValueError(f"unexpected HTML or Git LFS pointer: {path.name}")
    if path.stat().st_size != expected["size_bytes"]:
        raise ValueError(
            f"size mismatch for {path.name}: expected {expected['size_bytes']}, "
            f"got {path.stat().st_size}"
        )
    digest = sha256_file(path)
    if digest != expected["sha256"]:
        raise ValueError(
            f"SHA-256 mismatch for {path.name}: expected {expected['sha256']}, got {digest}"
        )


def fetch(destination):
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="unsw-nb15-") as temporary:
        staging = Path(temporary)
        for name, expected in FILES.items():
            target = staging / name
            request = Request(f"{BASE_URL}/{name}", headers={"User-Agent": "unsw-nb15-fetch/1"})
            with urlopen(request, timeout=60) as response, target.open("wb") as output:
                status = getattr(response, "status", 200)
                content_type = response.headers.get_content_type()
                if status != 200:
                    raise ValueError(f"HTTP {status} for {name}")
                if content_type in {"text/html", "application/vnd.git-lfs+json"}:
                    raise ValueError(f"unexpected Content-Type {content_type} for {name}")
                shutil.copyfileobj(response, output)
            verify_download(target, expected)
            print(
                f"[fetch_unsw_nb15] VERIFIED staging: {name} "
                f"bytes={target.stat().st_size} sha256={expected['sha256']}"
            )
        for name, expected in FILES.items():
            target = destination / name
            staged = staging / name
            if target.exists():
                verify_download(target, expected)
                print(f"[fetch_unsw_nb15] EXISTS and matches manifest: {target}")
                continue
            shutil.copyfile(staged, target)
            verify_download(target, expected)
            print(f"[fetch_unsw_nb15] INSTALLED unchanged bytes: {target}")


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
