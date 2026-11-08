#!/usr/bin/env python3
"""Fetch and verify external NetFlow datasets for cross-dataset generalization.

Supported datasets:
- NF-CSE-CIC-IDS2018-v3 (UQ RDM DOI: 10.48610/ece9b83, UUID: 4ac221b1-6bd6-42b1-bdf7-03f4fc7efb22)
- NF-ToN-IoT-v3 (UQ RDM DOI: 10.48610/44d7c5e, UUID: 343e2e8c-6e6e-4a0c-813d-a46acea1b7f4)
- NF-BoT-IoT-v3 (UQ RDM DOI: 10.48610/73c4ebc, UUID: db0187cc-1f78-4215-8e34-303364498866)
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
import time
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DESTINATION = PROJECT_ROOT / "data" / "raw"

DATASET_CONFIGS = {
    "NF-CSE-CIC-IDS2018-v3": {
        "uuid": "4ac221b1-6bd6-42b1-bdf7-03f4fc7efb22",
        "archive_prefix": "f78acbaa2afe1595_NFV3DATA-A11964_A11964/",
        "csv_name": "data/NF-CICIDS2018-v3.csv",
        "sample_name": "NF-CSE-CIC-IDS2018-v3-sample100k.csv",
        "doi": "10.48610/ece9b83",
        "archive_size": 780113687,
        "default_sample_skip": 350000,
        "default_sample_take": 100000,
    },
    "NF-ToN-IoT-v3": {
        "uuid": "343e2e8c-6e6e-4a0c-813d-a46acea1b7f4",
        "archive_prefix": "02934b58528a226b_NFV3DATA-A11964_A11964/",
        "csv_name": "data/NF-ToN-IoT-v3.csv",
        "sample_name": "NF-ToN-IoT-v3-sample100k.csv",
        "doi": "10.48610/44d7c5e",
        "default_sample_skip": 0,
        "default_sample_take": 100000,
    },
    "NF-BoT-IoT-v3": {
        "uuid": "db0187cc-1f78-4215-8e34-303364498866",
        "archive_prefix": "db0187cc_NFV3DATA/",
        "csv_name": "data/NF-BoT-IoT-v3.csv",
        "sample_name": "NF-BoT-IoT-v3-sample100k.csv",
        "doi": "10.48610/73c4ebc",
        "default_sample_skip": 0,
        "default_sample_take": 100000,
    },
}


class BufferedHTTPRangeReader(io.RawIOBase):
    """Seekable, buffered HTTP range reader for remote ZIP archives."""

    def __init__(self, url: str, total_size: int, block_size: int = 4 * 1024 * 1024):
        self.url = url
        self.total_size = total_size
        self.block_size = block_size
        self.pos = 0
        self.buffer = b""
        self.buffer_start = 0
        self.bytes_fetched = 0

    def seek(self, offset: int, whence: int = io.SEEK_SET) -> int:
        if whence == io.SEEK_SET:
            self.pos = offset
        elif whence == io.SEEK_CUR:
            self.pos += offset
        elif whence == io.SEEK_END:
            self.pos = self.total_size + offset
        return self.pos

    def tell(self) -> int:
        return self.pos

    def read(self, size: int = -1) -> bytes:
        if size == -1 or self.pos + size > self.total_size:
            size = self.total_size - self.pos
        if size <= 0:
            return b""
        if not (self.buffer_start <= self.pos < self.buffer_start + len(self.buffer)):
            fetch_size = max(size, self.block_size)
            fetch_end = min(self.total_size - 1, self.pos + fetch_size - 1)
            req = urllib.request.Request(
                self.url,
                headers={"Range": f"bytes={self.pos}-{fetch_end}", "User-Agent": "Mozilla/5.0"},
            )
            with urllib.request.urlopen(req, timeout=30) as r:
                self.buffer = r.read()
            self.buffer_start = self.pos
            self.bytes_fetched += len(self.buffer)
        offset = self.pos - self.buffer_start
        chunk = self.buffer[offset : offset + size]
        self.pos += len(chunk)
        return chunk


def resolve_s3_download_url(rdm_uuid: str) -> Tuple[str, int]:
    """Retrieve presigned S3 download URL and archive content length from UQ RDM API."""
    api_url = f"https://api.rdm.uq.edu.au/datasets/{rdm_uuid}/download"
    req = urllib.request.Request(api_url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        if not data.get("canDownload"):
            raise PermissionError(f"Dataset {rdm_uuid} is not available for open download: {data}")
        s3_url = data["url"]

    # Probe archive size with range request
    range_req = urllib.request.Request(
        s3_url, headers={"Range": "bytes=0-0", "User-Agent": "Mozilla/5.0"}
    )
    with urllib.request.urlopen(range_req, timeout=15) as s3_resp:
        content_range = s3_resp.headers.get("Content-Range", "")
        if "/" in content_range:
            total_size = int(content_range.split("/")[-1])
        else:
            total_size = int(s3_resp.headers.get("Content-Length", 0))

    return s3_url, total_size


def fetch_dataset_sample(
    dataset_name: str,
    output_dir: Path,
    sample_rows: int = 100000,
    skip_rows: Optional[int] = None,
) -> Path:
    """Stream-extract a verified chronological sample slice from UQ NetFlow v3 archive."""
    if dataset_name not in DATASET_CONFIGS:
        raise ValueError(f"Unknown dataset: {dataset_name}. Supported: {list(DATASET_CONFIGS)}")

    cfg = DATASET_CONFIGS[dataset_name]
    output_dir.mkdir(parents=True, exist_ok=True)
    target_csv = output_dir / cfg["sample_name"]

    if target_csv.exists() and target_csv.stat().st_size > 0:
        print(f"Sample dataset already exists: {target_csv} ({target_csv.stat().st_size:,} bytes)")
        return target_csv

    print(f"Resolving UQ RDM download URL for {dataset_name} (UUID: {cfg['uuid']})...")
    s3_url, total_size = resolve_s3_download_url(cfg["uuid"])
    print(f"Remote archive size: {total_size:,} bytes")

    reader = BufferedHTTPRangeReader(s3_url, total_size)
    # Read end of file to populate zip central directory
    reader.seek(total_size - 256 * 1024)
    reader.read(256 * 1024)
    reader.seek(0)

    zf = zipfile.ZipFile(reader)
    file_path = cfg["archive_prefix"] + cfg["csv_name"]
    # Check if exact member exists or search
    matched_member = None
    for member in zf.namelist():
        if member.endswith(".csv") and ("CICIDS" in member or "NF-" in member):
            matched_member = member
            break
    if not matched_member:
        raise FileNotFoundError(f"Could not locate CSV in archive: {zf.namelist()}")

    skip = skip_rows if skip_rows is not None else cfg["default_sample_skip"]
    take = sample_rows

    print(f"Streaming {take:,} rows from {matched_member} (skipping {skip:,} initial rows)...")
    temp_csv = output_dir / f".{cfg['sample_name']}.staging"
    t0 = time.time()

    with zf.open(matched_member) as f:
        text_io = io.TextIOWrapper(f, encoding="utf-8")
        header = text_io.readline()

        for _ in range(skip):
            text_io.readline()

        lines = [header]
        attacks: Dict[str, int] = {}
        for _ in range(take):
            line = text_io.readline()
            if not line:
                break
            lines.append(line)
            attack = line.strip().split(",")[-1]
            attacks[attack] = attacks.get(attack, 0) + 1

    with open(temp_csv, "w", encoding="utf-8") as out_f:
        out_f.writelines(lines)

    # Atomic rename
    temp_csv.replace(target_csv)
    dt = time.time() - t0

    # Compute sha256
    h = hashlib.sha256()
    with open(target_csv, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    sha256 = h.hexdigest()

    print(f"Successfully extracted {len(lines)-1:,} rows to {target_csv} in {dt:.2f}s")
    print(f"SHA-256: {sha256}")
    print("Class distribution:")
    for k, v in sorted(attacks.items(), key=lambda x: -x[1]):
        print(f"  {k}: {v:,} ({v/(len(lines)-1)*100:.2f}%)")

    return target_csv


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch and verify external NetFlow datasets.")
    parser.add_argument(
        "--dataset",
        choices=list(DATASET_CONFIGS),
        default="NF-CSE-CIC-IDS2018-v3",
        help="Dataset name to acquire",
    )
    parser.add_argument(
        "--sample-rows",
        type=int,
        default=100000,
        help="Number of rows to stream extract (default: 100,000)",
    )
    parser.add_argument(
        "--skip-rows",
        type=int,
        default=None,
        help="Number of initial rows to skip",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_DESTINATION / "NF-CSE-CIC-IDS2018-v3",
        help="Output directory",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify existing dataset file without downloading",
    )

    args = parser.parse_args(argv)

    try:
        if args.verify_only:
            cfg = DATASET_CONFIGS[args.dataset]
            target = args.output_dir / cfg["sample_name"]
            if not target.exists():
                print(f"Target dataset file does not exist: {target}")
                return 1
            print(f"Verified dataset file exists: {target} ({target.stat().st_size:,} bytes)")
            return 0

        fetch_dataset_sample(
            dataset_name=args.dataset,
            output_dir=args.output_dir,
            sample_rows=args.sample_rows,
            skip_rows=args.skip_rows,
        )
        return 0
    except Exception as e:
        print(f"Error fetching dataset: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
