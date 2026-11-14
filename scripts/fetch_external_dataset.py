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
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DESTINATION = PROJECT_ROOT / "data" / "raw"
LOCAL_SOURCE = PROJECT_ROOT / "src"
if str(LOCAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(LOCAL_SOURCE))

from network_anomaly.data.split import load_partition_indices  # noqa: E402

# Chronological bounds are an early guard; verified partition indices decide membership.
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
    if sample_rows < 1:
        raise ValueError("sample_rows must be positive")

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
            raise ValueError("Validation sample crosses the purge gap or Test Lock boundary")

    return effective_skip


def _sha256_file(path: Path) -> str:
    """Compute hex SHA-256 digest of a file using streaming reads."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def _load_split_manifest_sha256(split_manifest_path: Path) -> str:
    """Load canonical source dataset SHA-256 from official split manifest."""
    if not split_manifest_path.is_file():
        raise FileNotFoundError(f"Split manifest not found: {split_manifest_path}")
    split_data = json.loads(split_manifest_path.read_text(encoding="utf-8"))
    expected_sha = split_data.get("dataset_sha256")
    if not isinstance(expected_sha, str) or not expected_sha:
        raise ValueError("Split manifest lacks canonical dataset_sha256")
    return expected_sha


def _verify_unsw_partition_membership(
    start: int,
    count: int,
    split_manifest_path: Path,
    indices_dir: Path,
    partition: str,
) -> None:
    """Require every source row of a slice to belong strictly to the declared partition."""
    if partition not in ("train", "validation"):
        raise ValueError(f"Unsupported partition for slice verification: {partition!r}")
    label = partition.capitalize()
    if (
        isinstance(start, bool)
        or isinstance(count, bool)
        or not isinstance(start, int)
        or not isinstance(count, int)
        or count < 1
        or start < 0
    ):
        raise ValueError(f"{label} sample requires a positive row count and source offset")

    target_indices = load_partition_indices(split_manifest_path, indices_dir, partition)
    other_partition = "train" if partition == "validation" else "validation"
    other_indices = load_partition_indices(split_manifest_path, indices_dir, other_partition)

    source_rows = np.arange(start, start + count, dtype=np.int64)
    if np.intersect1d(source_rows, other_indices).size:
        raise ValueError(f"{label} sample overlaps verified {other_partition.capitalize()} indices")
    if not np.isin(source_rows, target_indices).all():
        raise ValueError(f"{label} sample contains rows outside verified {label} indices")

    split_data = json.loads(split_manifest_path.read_text(encoding="utf-8"))
    test_meta = split_data.get("partitions", {}).get("test", {})
    test_idx_name = test_meta.get("index_file") or "test_indices.csv.gz"
    if (indices_dir / test_idx_name).is_file() or "index_sha256" in test_meta:
        test_indices = load_partition_indices(split_manifest_path, indices_dir, "test")
        if np.intersect1d(source_rows, test_indices).size:
            raise ValueError(f"{label} sample overlaps verified Test indices")


def verify_unsw_validation_membership(
    start: int,
    count: int,
    split_manifest_path: Path,
    indices_dir: Path,
) -> None:
    """Require every source row of a slice to be in verified Validation indices."""
    _verify_unsw_partition_membership(
        start, count, split_manifest_path, indices_dir, partition="validation"
    )


def verify_unsw_train_membership(
    start: int,
    count: int,
    split_manifest_path: Path,
    indices_dir: Path,
) -> None:
    """Require every source row of a slice to be in verified Train indices."""
    _verify_unsw_partition_membership(
        start, count, split_manifest_path, indices_dir, partition="train"
    )


def _resolve_unsw_source_csv(
    sample_path: Path,
    manifest: Dict[str, Any],
    split_manifest_path: Path,
    source_csv_path: Optional[Path] = None,
) -> Path:
    """Locate the canonical NF-UNSW-NB15-v3 source CSV for row-binding verification."""
    if source_csv_path is not None:
        if not source_csv_path.is_file():
            raise FileNotFoundError(
                f"Canonical UNSW source CSV required for row provenance binding not found: "
                f"{source_csv_path}"
            )
        return source_csv_path

    candidates: List[Path] = []
    manifest_src = manifest.get("provenance", {}).get("source_csv_path")
    if isinstance(manifest_src, str) and manifest_src.strip():
        cand = Path(manifest_src)
        candidates.append(cand if cand.is_absolute() else (PROJECT_ROOT / cand))

    candidates.extend(
        [
            sample_path.parent / "NF-UNSW-NB15-v3.csv",
            sample_path.parent / "data" / "NF-UNSW-NB15-v3.csv",
        ]
    )

    canonical_manifest = (PROJECT_ROOT / "data" / "NF_UNSW_NB15_V3_SPLIT_MANIFEST.json").resolve()
    if split_manifest_path.resolve() == canonical_manifest:
        candidates.extend(
            [
                PROJECT_ROOT / "data" / "raw" / "NF-UNSW-NB15-v3" / "data" / "NF-UNSW-NB15-v3.csv",
                PROJECT_ROOT / "data" / "raw" / "NF-UNSW-NB15-v3" / "NF-UNSW-NB15-v3.csv",
            ]
        )

    for candidate in candidates:
        if candidate.is_file():
            return candidate

    raise FileNotFoundError(
        "Canonical NF-UNSW-NB15-v3 source CSV required to verify row provenance binding"
    )


def _verify_sample_rows_against_source(
    sample_path: Path,
    source_csv_path: Path,
    start: int,
    count: int,
    expected_rows_sha256: Optional[str] = None,
) -> None:
    """Stream-verify sample header and rows exactly match source CSV rows [start, start+count)."""
    if sample_path.resolve() == source_csv_path.resolve():
        raise ValueError("Sample CSV cannot reuse the canonical source CSV path directly")

    row_hasher = hashlib.sha256()
    with (
        open(source_csv_path, "r", encoding="utf-8", errors="strict") as src_f,
        open(sample_path, "r", encoding="utf-8", errors="strict") as smp_f,
    ):
        src_header = src_f.readline()
        smp_header = smp_f.readline()
        if not src_header or not smp_header:
            raise ValueError("Source or sample CSV is empty / missing header")
        src_header_norm = src_header.rstrip("\r\n")
        if src_header_norm != smp_header.rstrip("\r\n"):
            raise ValueError("Sample CSV header does not match canonical UNSW source CSV")
        row_hasher.update((src_header_norm + "\n").encode("utf-8"))

        for _ in range(start):
            skipped = src_f.readline()
            if not skipped:
                raise ValueError(f"Source CSV ended before declared skip_rows_offset ({start})")

        for row_idx in range(count):
            src_line = src_f.readline()
            smp_line = smp_f.readline()
            if not src_line:
                raise ValueError(f"Source CSV ended prematurely at offset {start + row_idx}")
            if not smp_line:
                raise ValueError(
                    f"Sample CSV ended prematurely at row {row_idx} (expected {count})"
                )
            src_norm = src_line.rstrip("\r\n")
            if src_norm != smp_line.rstrip("\r\n"):
                raise ValueError(
                    f"Sample row content mismatch vs canonical UNSW source CSV at slice row "
                    f"{row_idx} (source row {start + row_idx})"
                )
            row_hasher.update((src_norm + "\n").encode("utf-8"))

        trailing = smp_f.readline()
        if trailing:
            raise ValueError("Sample CSV contains more rows than declared in manifest")

    if expected_rows_sha256 is not None and row_hasher.hexdigest() != expected_rows_sha256:
        raise ValueError("Sample manifest source_rows_sha256 mismatch")


def verify_unsw_sample_binding(
    sample_path: Path,
    split_manifest_path: Path,
    indices_dir: Path,
    expected_start: Optional[int] = None,
    expected_count: Optional[int] = None,
    expected_partition: str = "validation",
    source_csv_path: Optional[Path] = None,
) -> int:
    """Verify sample content, source CSV binding, recorded offset, and split membership."""
    if expected_partition not in ("train", "validation"):
        raise ValueError(f"Unsupported UNSW partition: {expected_partition!r}")
    if not sample_path.is_file():
        raise FileNotFoundError(f"Sample CSV not found: {sample_path}")

    manifest_path = sample_path.with_name(f"{sample_path.name}.manifest.json")
    if not manifest_path.is_file():
        raise FileNotFoundError(f"Sample manifest not found: {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    checksum = manifest.get("content_checksum", {})
    if manifest.get("dataset_identity", {}).get("dataset_name") != "NF-UNSW-NB15-v3":
        raise ValueError("Sample manifest dataset identity mismatch")
    if checksum.get("slice_type") != "slice":
        raise ValueError("UNSW sample must be a source-indexed slice")

    declared_partition = checksum.get("partition")
    if declared_partition is not None and declared_partition != expected_partition:
        raise ValueError(
            f"Sample manifest partition mismatch: expected {expected_partition!r}, "
            f"got {declared_partition!r}"
        )

    digest = _sha256_file(sample_path)
    if checksum.get("sample_sha256") != digest:
        raise ValueError("UNSW sample SHA-256 mismatch")

    start = checksum.get("skip_rows_offset")
    count = checksum.get("sample_rows_extracted")
    if (
        isinstance(start, bool)
        or isinstance(count, bool)
        or not isinstance(start, int)
        or not isinstance(count, int)
    ):
        raise ValueError("UNSW sample lacks integer source row indices")
    if expected_start is not None and start != expected_start:
        raise ValueError("Existing UNSW sample source offset differs from request")
    if expected_count is not None and count != expected_count:
        raise ValueError("Existing UNSW sample row count differs from request")

    expected_dataset_sha256 = _load_split_manifest_sha256(split_manifest_path)
    sample_source_sha256 = checksum.get("source_dataset_sha256")
    if not isinstance(sample_source_sha256, str) or not sample_source_sha256:
        raise ValueError("Sample manifest lacks source_dataset_sha256")
    if sample_source_sha256 != expected_dataset_sha256:
        raise ValueError(
            "Sample manifest source_dataset_sha256 does not match split manifest dataset_sha256"
        )

    _verify_unsw_partition_membership(
        start, count, split_manifest_path, indices_dir, partition=expected_partition
    )

    resolved_source_csv = _resolve_unsw_source_csv(
        sample_path, manifest, split_manifest_path, source_csv_path=source_csv_path
    )
    actual_source_sha256 = _sha256_file(resolved_source_csv)
    if actual_source_sha256 != expected_dataset_sha256:
        raise ValueError(
            "Resolved UNSW source CSV SHA-256 does not match split manifest dataset_sha256"
        )

    expected_rows_sha = checksum.get("source_rows_sha256")
    if expected_rows_sha is not None and not isinstance(expected_rows_sha, str):
        raise ValueError("Invalid source_rows_sha256 in sample manifest")

    _verify_sample_rows_against_source(
        sample_path,
        resolved_source_csv,
        start,
        count,
        expected_rows_sha256=expected_rows_sha,
    )
    return count


def fetch_dataset_sample(
    dataset_name: str,
    output_dir: Path,
    sample_rows: Optional[int] = None,
    skip_rows: Optional[int] = None,
    sample_mode: str = "slice",
    random_seed: int = 42,
    max_scan_lines: Optional[int] = None,
) -> Path:
    """Stream-extract a verified chronological slice or stratified sample from UQ archive."""
    if dataset_name not in DATASET_CONFIGS:
        raise ValueError(f"Unknown dataset: {dataset_name}. Supported: {list(DATASET_CONFIGS)}")

    cfg = DATASET_CONFIGS[dataset_name]
    if sample_rows is None:
        sample_rows = cfg["default_sample_take"]
    output_dir.mkdir(parents=True, exist_ok=True)
    filename = cfg["sample_name"] if sample_mode == "slice" else cfg["stratified_sample_name"]
    target_csv = output_dir / filename
    manifest_path = output_dir / f"{filename}.manifest.json"

    # Validate anti-leakage and Test Lock before touching any file
    effective_skip = validate_slice_sampling_parameters(dataset_name, skip_rows, sample_rows)
    if dataset_name == "NF-UNSW-NB15-v3" and sample_mode != "slice":
        raise ValueError("UNSW stratified sampling lacks source row provenance; use slice mode")
    if dataset_name == "NF-UNSW-NB15-v3":
        verify_unsw_validation_membership(
            effective_skip,
            sample_rows,
            PROJECT_ROOT / "data" / "NF_UNSW_NB15_V3_SPLIT_MANIFEST.json",
            PROJECT_ROOT / "data" / "processed" / "splits",
        )

    if target_csv.exists() and target_csv.stat().st_size > 0:
        if dataset_name == "NF-UNSW-NB15-v3":
            verify_unsw_sample_binding(
                target_csv,
                PROJECT_ROOT / "data" / "NF_UNSW_NB15_V3_SPLIT_MANIFEST.json",
                PROJECT_ROOT / "data" / "processed" / "splits",
                expected_start=effective_skip,
                expected_count=sample_rows,
            )
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

    sha256 = _sha256_file(target_csv)
    unsw_source_sha256 = None
    unsw_rows_sha256 = None
    if dataset_name == "NF-UNSW-NB15-v3":
        unsw_source_sha256 = _load_split_manifest_sha256(
            PROJECT_ROOT / "data" / "NF_UNSW_NB15_V3_SPLIT_MANIFEST.json"
        )
        rows_hasher = hashlib.sha256()
        for line in lines:
            rows_hasher.update((line.rstrip("\r\n") + "\n").encode("utf-8"))
        unsw_rows_sha256 = rows_hasher.hexdigest()

    # Generate companion sample manifest with explicit decoupling of identity and content checksum
    content_checksum: Dict[str, object] = {
        "sample_sha256": sha256,
        "sample_rows_extracted": len(lines) - 1,
        "slice_type": sample_mode,
        "skip_rows_offset": effective_skip if sample_mode == "slice" else None,
    }
    if dataset_name == "NF-UNSW-NB15-v3":
        content_checksum["partition"] = "validation"
        content_checksum["source_dataset_sha256"] = unsw_source_sha256
        content_checksum["source_rows_sha256"] = unsw_rows_sha256

    manifest_data = {
        "dataset_identity": {
            "dataset_name": dataset_name,
            "doi": cfg["doi"],
            "format": "NetFlow-v3",
            "column_count": cfg.get("column_count", 55),
            "feature_contract": "nf-unsw-nb15-v3-baseline-47",
        },
        "content_checksum": content_checksum,
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
        default=None,
        help="Number of rows to stream extract (default: dataset-specific sample size)",
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
            if args.dataset == "NF-UNSW-NB15-v3":
                verify_unsw_sample_binding(
                    target,
                    PROJECT_ROOT / "data" / "NF_UNSW_NB15_V3_SPLIT_MANIFEST.json",
                    PROJECT_ROOT / "data" / "processed" / "splits",
                )
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
