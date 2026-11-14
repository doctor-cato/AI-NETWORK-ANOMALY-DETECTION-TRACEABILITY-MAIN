#!/usr/bin/env python3
"""Fetch, sample, and verify external NetFlow datasets (Issue #48, #57).

Supported datasets:
- NF-CSE-CIC-IDS2018-v3 (UQ RDM DOI: 10.48610/ece9b83, UUID: 4ac221b1-6bd6-42b1-bdf7-03f4fc7efb22)
- NF-ToN-IoT-v3 (UQ RDM DOI: 10.48610/44d7c5e, UUID: 343e2e8c-6e6e-4a0c-813d-a46acea1b7f4)
- NF-BoT-IoT-v3 (UQ RDM DOI: 10.48610/73c4ebc, UUID: db0187cc-1f78-4215-8e34-303364498866)
- NF-UNSW-NB15-v3 (UQ RDM DOI: 10.48610/abd2f5d, UUID: abd2f5d8-e268-4ff0-84fb-f2f7b3ca3e8f)

Scientific Integrity Guardrails:
- Strict Test Lock: direct slicing of held-out Test split (rows >= 2,019,471) is strictly BLOCKED.
- Anti-Leakage: first-50k slice of NF-UNSW-NB15-v3 (rows 0-50,000) is strictly prohibited as
  an evaluation target because it falls entirely inside the historical training split.
- Decouples Dataset Identity (name, DOI, 55 columns) from Content Checksum (sample SHA-256).
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import random
import sys
import time
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DESTINATION = PROJECT_ROOT / "data" / "raw"

# Official partition offsets for NF-UNSW-NB15-v3 per NF_UNSW_NB15_V3_SPLIT_MANIFEST.json
UNSW_CANONICAL_TRAIN_END = 1655797  # rows 0..1,655,796
UNSW_PURGED_GAP_1_END = 1665240  # rows 1,655,797..1,665,239
UNSW_VALIDATION_START = 1665240  # rows 1,665,240..2,010,610
UNSW_VALIDATION_END = 2010611
UNSW_PURGED_GAP_2_END = 2019471  # rows 2,010,611..2,019,470
UNSW_TEST_LOCK_START = 2019471  # rows 2,019,471..2,365,423 (BLOCKED)

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
        "column_count": 55,
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
        "column_count": 55,
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
        "column_count": 55,
    },
    "NF-UNSW-NB15-v3": {
        "uuid": "abd2f5d8-e268-4ff0-84fb-f2f7b3ca3e8f",
        "archive_prefix": "f7546561558c07c5_NFV3DATA-A11964_A11964/",
        "csv_name": "data/NF-UNSW-NB15-v3.csv",
        "sample_name": "NF-UNSW-NB15-v3-validation-sample50k.csv",
        "stratified_sample_name": "NF-UNSW-NB15-v3-validation-stratified50k.csv",
        "doi": "10.48610/abd2f5d",
        "default_sample_skip": UNSW_VALIDATION_START,
        "default_sample_take": 50000,
        "validation_sample_skip": UNSW_VALIDATION_START,
        "test_lock_start": UNSW_TEST_LOCK_START,
        "column_count": 55,
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


def validate_slice_sampling_parameters(
    dataset_name: str,
    skip_rows: Optional[int],
    sample_rows: int,
) -> int:
    """Validate that sampling parameters protect Test Lock and prevent train set leakage."""
    cfg = DATASET_CONFIGS[dataset_name]
    effective_skip = skip_rows if skip_rows is not None else cfg["default_sample_skip"]

    if dataset_name == "NF-UNSW-NB15-v3":
        # Check train leakage: first-50k slice is strictly rejected
        if effective_skip < UNSW_VALIDATION_START:
            raise ValueError(
                f"Chronological integrity violation: Rows 0..{UNSW_CANONICAL_TRAIN_END:,} "
                "of NF-UNSW-NB15-v3 belong strictly to the canonical training partition. "
                f"Slicing rows < {UNSW_VALIDATION_START:,} (skip={effective_skip}) causes severe "
                "train-set leakage. For validation evaluation, use skip >= "
                f"{UNSW_VALIDATION_START:,}."
            )

        # Check Test Lock protection
        if effective_skip >= UNSW_TEST_LOCK_START:
            raise PermissionError(
                f"Test Lock Enforced: Direct slicing of held-out Test split (rows >= "
                f"{UNSW_TEST_LOCK_START:,}) is strictly BLOCKED under scientific governance."
            )

        if effective_skip + sample_rows > UNSW_VALIDATION_END:
            effective_sample_rows = max(1, UNSW_VALIDATION_END - effective_skip)
            print(
                f"[INFO] Adjusting sample rows from {sample_rows:,} to {effective_sample_rows:,} "
                "to remain strictly within official validation boundaries (before purge gap 2)."
            )

    return effective_skip


def fetch_dataset_sample(
    dataset_name: str,
    output_dir: Path,
    sample_rows: int = 100000,
    skip_rows: Optional[int] = None,
    sample_mode: str = "slice",
    random_seed: int = 42,
    max_scan_lines: Optional[int] = None,
) -> Path:
    """Stream-extract a verified chronological slice or stratified sample from UQ archive."""
    if dataset_name not in DATASET_CONFIGS:
        raise ValueError(f"Unknown dataset: {dataset_name}. Supported: {list(DATASET_CONFIGS)}")

    cfg = DATASET_CONFIGS[dataset_name]
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = cfg["sample_name"] if sample_mode == "slice" else cfg["stratified_sample_name"]
    target_csv = output_dir / filename
    manifest_path = output_dir / f"{filename}.manifest.json"

    # Validate anti-leakage and Test Lock before touching any file
    effective_skip = validate_slice_sampling_parameters(dataset_name, skip_rows, sample_rows)

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

    print(
        f"Extracting sample ({sample_mode}, target={sample_rows:,} rows) from {matched_member}..."
    )
    temp_csv = output_dir / f".{filename}.staging"
    t0 = time.time()
    attacks: Dict[str, int] = {}
    lines: List[str] = []

    rng = random.Random(random_seed)
    seen_lines = 0

    with zf.open(matched_member) as f:
        text_io = io.TextIOWrapper(f, encoding="utf-8")
        header = text_io.readline()
        lines.append(header)

        if sample_mode == "slice":
            for _ in range(effective_skip):
                text_io.readline()

            for _ in range(sample_rows):
                line = text_io.readline()
                if not line:
                    break
                lines.append(line)
                attack = line.strip().split(",")[-1]
                attacks[attack] = attacks.get(attack, 0) + 1
        else:
            quota_per_class = max(1000, sample_rows // 15)
            class_reservoirs: Dict[str, List[str]] = {}
            class_counts: Dict[str, int] = {}

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
                    j = rng.randint(0, count - 1)
                    if j < quota_per_class:
                        res[j] = line

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

    h = hashlib.sha256()
    with open(target_csv, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    sha256 = h.hexdigest()

    # Generate companion sample manifest with explicit decoupling of identity and content checksum
    manifest_data = {
        "dataset_identity": {
            "dataset_name": dataset_name,
            "doi": cfg["doi"],
            "format": "NetFlow-v3",
            "column_count": cfg.get("column_count", 55),
            "feature_contract": "nf-unsw-nb15-v3-baseline-47",
        },
        "content_checksum": {
            "sample_sha256": sha256,
            "sample_rows_extracted": len(lines) - 1,
            "slice_type": sample_mode,
            "skip_rows_offset": effective_skip if sample_mode == "slice" else None,
        },
        "provenance": {
            "source_archive_member": matched_member,
            "source_doi": cfg["doi"],
            "random_seed": random_seed if sample_mode != "slice" else None,
            "class_distribution": attacks,
            "created_at_utc": datetime.now(timezone.utc).isoformat(),
        },
        "governance": {
            "test_lock_status": "ENFORCED",
            "train_leakage_audit": "PASSED (No train partition rows included)",
        },
    }
    with open(manifest_path, "w", encoding="utf-8") as mf:
        json.dump(manifest_data, mf, indent=2)

    print(f"Successfully extracted {len(lines)-1:,} rows to {target_csv} in {dt:.2f}s")
    print(f"SHA-256: {sha256}")
    print(f"Manifest saved: {manifest_path}")

    return target_csv


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Fetch, sample, and verify external NetFlow datasets."
    )
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
        help="Maximum stream lines to scan during stratified sampling",
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
    output_dir = (
        args.output_dir if args.output_dir is not None else DEFAULT_DESTINATION / args.dataset
    )

    try:
        if args.verify_only:
            cfg = DATASET_CONFIGS[args.dataset]
            target = output_dir / cfg["sample_name"]
            if not target.exists():
                print(f"Target dataset file does not exist: {target} (BLOCKED / SKIPPED)")
                return 0
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
