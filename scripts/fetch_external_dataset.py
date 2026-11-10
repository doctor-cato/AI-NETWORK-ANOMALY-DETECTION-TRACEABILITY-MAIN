#!/usr/bin/env python3
"""Fetch, sample, and verify external NetFlow datasets for cross-dataset generalization.

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
import random
import sys
import time
import urllib.request
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
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
        "stratified_sample_name": "NF-CSE-CIC-IDS2018-v3-stratified100k.csv",
        "doi": "10.48610/ece9b83",
        "archive_size": 780113687,
        "default_sample_skip": 350000,
        "default_sample_take": 100000,
    },
    "NF-ToN-IoT-v3": {
        "uuid": "343e2e8c-6e6e-4a0c-813d-a46acea1b7f4",
        "archive_prefix": "02934b58528a226b_NFV3DATA-A11964_A11964/",
        "csv_name": "data/NF-ToN-IoT-v3.csv",
        "sample_name": "NF-ToN-IoT-v3-sample50k.csv",
        "stratified_sample_name": "NF-ToN-IoT-v3-stratified50k.csv",
        "doi": "10.48610/44d7c5e",
        "default_sample_skip": 0,
        "default_sample_take": 50000,
    },
    "NF-BoT-IoT-v3": {
        "uuid": "db0187cc-1f78-4215-8e34-303364498866",
        "archive_prefix": "db0187cc_NFV3DATA/",
        "csv_name": "data/NF-BoT-IoT-v3.csv",
        "sample_name": "NF-BoT-IoT-v3-sample50k.csv",
        "stratified_sample_name": "NF-BoT-IoT-v3-stratified50k.csv",
        "doi": "10.48610/73c4ebc",
        "default_sample_skip": 0,
        "default_sample_take": 50000,
    },
    "NF-UNSW-NB15-v3": {
        "uuid": "abd2f5d8-e268-4ff0-84fb-f2f7b3ca3e8f",
        "archive_prefix": "f7546561558c07c5_NFV3DATA-A11964_A11964/",
        "csv_name": "data/NF-UNSW-NB15-v3.csv",
        "sample_name": "NF-UNSW-NB15-v3-sample50k.csv",
        "stratified_sample_name": "NF-UNSW-NB15-v3-stratified50k.csv",
        "doi": "10.48610/abd2f5d",
        "default_sample_skip": 0,
        "default_sample_take": 50000,
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
    sample_mode: str = "slice",
    random_seed: int = 42,
    max_scan_lines: Optional[int] = None,
) -> Path:
    """Stream-extract a verified chronological slice or stratified sample from UQ archive.

    Parameters
    ----------
    dataset_name : str
        Name of registered dataset config.
    output_dir : Path
        Directory to write CSV and companion manifest.
    sample_rows : int
        Number of rows to sample.
    skip_rows : Optional[int]
        Initial rows to skip (slice mode only).
    sample_mode : str
        'slice' (sequential historical slice) or 'stratified' (multi-class quota sampling).
    random_seed : int
        Seed for deterministic sampling in stratified mode.
    max_scan_lines : Optional[int]
        Optional cap on scanned stream lines (defaults to scanning entire stream).
    """
    if dataset_name not in DATASET_CONFIGS:
        raise ValueError(f"Unknown dataset: {dataset_name}. Supported: {list(DATASET_CONFIGS)}")

    cfg = DATASET_CONFIGS[dataset_name]
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = cfg["sample_name"] if sample_mode == "slice" else cfg["stratified_sample_name"]
    target_csv = output_dir / filename
    manifest_path = output_dir / f"{filename}.manifest.json"

    if target_csv.exists() and target_csv.stat().st_size > 0:
        print(f"Sample dataset already exists: {target_csv} ({target_csv.stat().st_size:,} bytes)")
        return target_csv

    print(f"Resolving UQ RDM download URL for {dataset_name} (UUID: {cfg['uuid']})...")
    s3_url, total_size = resolve_s3_download_url(cfg["uuid"])
    print(f"Remote archive size: {total_size:,} bytes")

    reader = BufferedHTTPRangeReader(s3_url, total_size)
    reader.seek(total_size - 256 * 1024)
    reader.read(256 * 1024)
    reader.seek(0)

    zf = zipfile.ZipFile(reader)
    matched_member = None
    for member in zf.namelist():
        if member.endswith(".csv") and ("CICIDS" in member or "NF-" in member):
            matched_member = member
            break
    if not matched_member:
        raise FileNotFoundError(f"Could not locate CSV in archive: {zf.namelist()}")

    print(f"Extracting sample ({sample_mode} mode, target={sample_rows:,} rows) from {matched_member}...")
    temp_csv = output_dir / f".{filename}.staging"
    t0 = time.time()
    attacks: Dict[str, int] = {}
    lines: List[str] = []

    rng = random.Random(random_seed)

    with zf.open(matched_member) as f:
        text_io = io.TextIOWrapper(f, encoding="utf-8")
        header = text_io.readline()
        lines.append(header)

        if sample_mode == "slice":
            skip = skip_rows if skip_rows is not None else cfg["default_sample_skip"]
            for _ in range(skip):
                text_io.readline()

            for _ in range(sample_rows):
                line = text_io.readline()
                if not line:
                    break
                lines.append(line)
                attack = line.strip().split(",")[-1]
                attacks[attack] = attacks.get(attack, 0) + 1
        else:
            # Multi-class streaming reservoir sampling (Waterman's Algorithm R per class)
            quota_per_class = max(1000, sample_rows // 15)
            class_reservoirs: Dict[str, List[str]] = {}
            class_counts: Dict[str, int] = {}
            seen_lines = 0

            while True:
                line = text_io.readline()
                if not line:
                    break
                seen_lines += 1
                if max_scan_lines is not None and seen_lines >= max_scan_lines:
                    break

                parts = line.strip().rsplit(",", 1)
                if len(parts) < 2:
                    continue
                attack = parts[1]

                class_counts[attack] = class_counts.get(attack, 0) + 1
                count = class_counts[attack]

                if attack not in class_reservoirs:
                    class_reservoirs[attack] = []

                res = class_reservoirs[attack]
                if len(res) < quota_per_class:
                    res.append(line)
                else:
                    # Reservoir replacement with probability quota_per_class / count
                    j = rng.randint(0, count - 1)
                    if j < quota_per_class:
                        res[j] = line

            # Assemble balanced / stratified sample across all collected attack families
            collected_sample: List[str] = []
            for atk, rows in class_reservoirs.items():
                collected_sample.extend(rows)
                attacks[atk] = len(rows)

            rng.shuffle(collected_sample)
            lines.extend(collected_sample[:sample_rows])

    with open(temp_csv, "w", encoding="utf-8") as out_f:
        out_f.writelines(lines)

    temp_csv.replace(target_csv)
    dt = time.time() - t0

    # Compute sha256
    h = hashlib.sha256()
    with open(target_csv, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    sha256 = h.hexdigest()

    # Generate companion sample manifest
    manifest_data = {
        "dataset_name": dataset_name,
        "sample_mode": sample_mode,
        "sample_rows_extracted": len(lines) - 1,
        "sample_sha256": sha256,
        "scanned_lines": seen_lines if sample_mode != "slice" else (skip + len(lines) - 1),
        "random_seed": random_seed if sample_mode != "slice" else None,
        "source_doi": cfg["doi"],
        "source_archive_member": matched_member,
        "class_distribution": attacks,
        "class_prevalence": {k: round(v / seen_lines, 6) for k, v in class_counts.items()} if sample_mode != "slice" else {},
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    with open(manifest_path, "w", encoding="utf-8") as mf:
        json.dump(manifest_data, mf, indent=2)

    print(f"Successfully extracted {len(lines)-1:,} rows to {target_csv} in {dt:.2f}s")
    print(f"SHA-256: {sha256}")
    print(f"Manifest saved: {manifest_path}")
    print("Class distribution:")
    for k, v in sorted(attacks.items(), key=lambda x: -x[1]):
        print(f"  {k}: {v:,} ({v/(len(lines)-1)*100:.2f}%)")

    return target_csv


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch, sample, and verify external NetFlow datasets.")
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
        help="Number of initial rows to skip (slice mode)",
    )
    parser.add_argument(
        "--sample-mode",
        choices=["slice", "stratified"],
        default="slice",
        help="Sampling mode: 'slice' (sequential) or 'stratified' (multi-class)",
    )
    parser.add_argument(
        "--random-seed",
        type=int,
        default=42,
        help="Random seed for stratified sampling",
    )
    parser.add_argument(
        "--max-scan-lines",
        type=int,
        default=None,
        help="Maximum stream lines to scan during stratified sampling (default: entire stream)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Output directory (default: data/raw/<dataset-name>)",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify existing dataset file without downloading",
    )

    args = parser.parse_args(argv)
    output_dir = args.output_dir if args.output_dir is not None else DEFAULT_DESTINATION / args.dataset

    try:
        if args.verify_only:
            cfg = DATASET_CONFIGS[args.dataset]
            target = output_dir / cfg["sample_name"]
            if not target.exists():
                print(f"Target dataset file does not exist: {target}")
                return 1
            print(f"Verified dataset file exists: {target} ({target.stat().st_size:,} bytes)")
            return 0

        fetch_dataset_sample(
            dataset_name=args.dataset,
            output_dir=output_dir,
            sample_rows=args.sample_rows,
            skip_rows=args.skip_rows,
            sample_mode=args.sample_mode,
            random_seed=args.random_seed,
            max_scan_lines=args.max_scan_lines,
        )
        return 0
    except Exception as e:
        print(f"Error fetching dataset: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
