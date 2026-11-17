#!/usr/bin/env python3
"""Official AIT dataset manifest verifier, downloader, and synthetic fixture separator.

Implements Issue #83 for NetFlow Sentinel v2.0.

Separation policy:
- Official dataset source metadata and checksum verification operate on ``--data-dir``
  (default ``data/raw/ait``). Missing official raw data reports ``SKIPPED`` under
  ``--verify-only`` (exit 0) or ``FAILED`` under ``--require-data`` (exit 1).
- Synthetic schema-compatible fixtures live separately under
  ``tests/fixtures/ait_synthetic`` and are explicitly marked ``synthetic: true``
  without claiming official AIT Zenodo DOI provenance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

MANIFEST_PATH = Path("data/AIT_DATASETS_MANIFEST.json")
DEFAULT_DATA_DIR = Path("data/raw/ait")
SYNTHETIC_FIXTURE_DIR = Path("tests/fixtures/ait_synthetic")
SYNTHETIC_MANIFEST_PATH = SYNTHETIC_FIXTURE_DIR / "SYNTHETIC_FIXTURE_MANIFEST.json"

OFFICIAL_AIT_SPEC: Dict[str, Any] = {
    "dataset": "AIT-Suite-v2.1",
    "release_year": 2021,
    "synthetic": False,
    "official_source": {
        "publisher": "AIT Austrian Institute of Technology GmbH",
        "doi_netflow": "10.5281/zenodo.13168643",
        "doi_log": "10.5281/zenodo.19483937",
        "landing_page_netflow": "https://zenodo.org/records/13168643",
        "landing_page_log": "https://zenodo.org/records/19483937",
        "doi": "10.5281/zenodo.13168643",
        "landing_page": "https://zenodo.org/records/13168643",
        "access_type": "OPEN",
        "license_title": "Creative Commons Attribution-ShareAlike 4.0 International",
        "license_url": "https://creativecommons.org/licenses/by-sa/4.0/",
    },
    # Official Zenodo API endpoints for on-demand checksum lookup / download
    "zenodo_records": {
        "ait_netflow_v2": "https://zenodo.org/api/records/13168643",
        "ait_log_v2_1": "https://zenodo.org/api/records/19483937",
    },
}


def compute_sha256(file_path: Path) -> str:
    """Compute cryptographic SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest().lower()


def sanitize_url(url: str) -> str:
    """Ensure no auth credentials or query tokens leak into manifest/logs."""
    from urllib.parse import urlparse, urlunparse

    parsed = urlparse(url)
    clean_netloc = parsed.netloc.split("@")[-1]
    return urlunparse((parsed.scheme, clean_netloc, parsed.path, "", "", ""))


def _write_step_summary(lines: List[str]) -> None:
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if not summary_file:
        return
    try:
        with open(summary_file, "a", encoding="utf-8") as handle:
            handle.write("\n".join(lines) + "\n")
    except OSError:
        pass


def generate_synthetic_fixtures(
    output_dir: Path = SYNTHETIC_FIXTURE_DIR,
    manifest_path: Optional[Path] = None,
) -> Dict[str, Path]:
    """Generate clearly labeled synthetic schema fixtures for offline unit tests.

    These fixtures are NEVER placed in ``data/raw/ait`` and NEVER claim official
    AIT Zenodo DOI provenance.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    generated: Dict[str, Path] = {}

    flow_file = output_dir / "synthetic_netflow_fixture.csv"
    flow_content = (
        "FLOW_START_MILLISECONDS,FLOW_DURATION_MILLISECONDS,IPV4_SRC_ADDR,L4_SRC_PORT,"
        "IPV4_DST_ADDR,L4_DST_PORT,PROTOCOL,IN_BYTES,OUT_BYTES,IN_PKTS,OUT_PKTS,TCP_FLAGS,Attack\n"
        "1604563200000,150.0,192.168.1.100,52314,192.168.1.10,80,6,1240,4520,10,12,24,Benign\n"
        "1604563205000,20.0,192.168.1.105,44122,192.168.1.10,80,6,350,120,4,3,2,Reconnaissance\n"
        "1604563210000,12.0,192.168.1.105,44124,192.168.1.10,80,6,890,240,6,4,24,Exploits\n"
        "1604563215000,85.0,192.168.1.10,48992,10.0.0.99,4444,6,45000,1200,50,20,24,Backdoors\n"
        "1604563220000,45.0,192.168.1.10,51234,198.51.100.5,53,17,125000,450,100,10,0,Exfiltration\n"
    )
    flow_file.write_text(flow_content, encoding="utf-8")
    generated["synthetic_netflow_fixture.csv"] = flow_file

    dns_file = output_dir / "synthetic_dns_fixture.log"
    dns_content = (
        "ts,id.orig_h,id.orig_p,id.resp_h,id.resp_p,query,qtype_name,rcode,TTL\n"
        "1604563200.100,192.168.1.100,53412,192.168.1.1,53,intranet.corp,A,0,300\n"
        "1604563205.200,192.168.1.105,53414,192.168.1.1,53,web.corp,A,0,60\n"
        "1604563220.150,192.168.1.10,51234,198.51.100.5,53,tunnel.exfil-data.xyz,TXT,0,10\n"
    )
    dns_file.write_text(dns_content, encoding="utf-8")
    generated["synthetic_dns_fixture.log"] = dns_file

    web_file = output_dir / "synthetic_web_fixture.log"
    web_content = (
        '192.168.1.100 - - [05/Nov/2020:08:00:00 +0000] "GET /index.html HTTP/1.1" 200 4520 "-" "Mozilla/5.0"\n'
        '192.168.1.105 - - [05/Nov/2020:08:00:05 +0000] "GET /admin HTTP/1.1" 404 120 "-" "Gobuster/v3.1"\n'
        '192.168.1.105 - - [05/Nov/2020:08:00:10 +0000] "POST /api/upload.action HTTP/1.1" 200 240 "-" "Python-requests"\n'
    )
    web_file.write_text(web_content, encoding="utf-8")
    generated["synthetic_web_fixture.log"] = web_file

    auth_file = output_dir / "synthetic_auth_fixture.log"
    auth_content = (
        "Nov  5 08:00:00 server01 sshd[1234]: Accepted publickey for alice from 192.168.1.100 port 52314 ssh2\n"
        "Nov  5 08:00:08 server01 sshd[1288]: Failed password for invalid user root from 192.168.1.105 port 44120 ssh2\n"
        "Nov  5 08:00:12 server01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash\n"
    )
    auth_file.write_text(auth_content, encoding="utf-8")
    generated["synthetic_auth_fixture.log"] = auth_file

    target_manifest = manifest_path or (output_dir / "SYNTHETIC_FIXTURE_MANIFEST.json")
    fixture_entries = [
        {
            "file": name,
            "size_bytes": path.stat().st_size,
            "sha256": compute_sha256(path),
            "synthetic": True,
        }
        for name, path in generated.items()
    ]
    target_manifest.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "synthetic": True,
                "provenance_note": (
                    "Hand-crafted schema-compatible synthetic fixtures for offline unit tests. "
                    "NOT observed telemetry from AIT-Suite-v2.1."
                ),
                "generated_at_utc": datetime.now(timezone.utc).isoformat(),
                "files": fixture_entries,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return generated


def download_official_ait_subset(
    data_dir: Path,
    max_files: int = 1,
    timeout_s: float = 30.0,
) -> List[Path]:
    """Download official AIT artifacts from Zenodo on explicit request and verify MD5/SHA-256."""
    data_dir.mkdir(parents=True, exist_ok=True)
    downloaded: List[Path] = []
    api_url = OFFICIAL_AIT_SPEC["zenodo_records"]["ait_netflow_v2"]
    req = urllib.request.Request(api_url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout_s) as resp:
        record = json.loads(resp.read().decode("utf-8"))

    files = record.get("files", [])[: max(1, int(max_files))]
    for entry in files:
        key = entry.get("key")
        links = entry.get("links", {})
        dl_url = links.get("self")
        checksum_spec = str(entry.get("checksum", ""))
        if not key or not dl_url:
            continue
        dest = data_dir / key
        urllib.request.urlretrieve(dl_url, dest)
        if checksum_spec.startswith("md5:"):
            expected_md5 = checksum_spec.split(":", 1)[1].lower()
            actual_md5 = hashlib.md5(dest.read_bytes()).hexdigest().lower()
            if actual_md5 != expected_md5:
                dest.unlink(missing_ok=True)
                raise RuntimeError(
                    f"Checksum mismatch for {key}: expected md5:{expected_md5}, got {actual_md5}"
                )
        elif checksum_spec.startswith("sha256:"):
            expected_sha = checksum_spec.split(":", 1)[1].lower()
            actual_sha = compute_sha256(dest)
            if actual_sha != expected_sha:
                dest.unlink(missing_ok=True)
                raise RuntimeError(
                    f"Checksum mismatch for {key}: expected sha256:{expected_sha}, got {actual_sha}"
                )
        downloaded.append(dest)
    return downloaded


def _is_official_data_present(data_dir: Path) -> List[Path]:
    if not data_dir.exists():
        return []
    excluded_names = {
        "ait_netflow_v2.1_sample.csv",
        "ait_dns_v2.1_sample.log",
        "ait_web_v2.1_sample.log",
        "ait_auth_v2.1_sample.log",
    }
    candidates = [
        p
        for p in sorted(data_dir.rglob("*"))
        if p.is_file()
        and p.name not in excluded_names
        and not p.name.startswith(".")
        and p.suffix.lower() in {".csv", ".log", ".json", ".zip", ".tar", ".gz"}
    ]
    return candidates


def verify_and_generate_manifest(
    data_dir: Path,
    manifest_path: Path,
    source_url: Optional[str] = None,
    verify_only: bool = False,
    require_data: bool = False,
    expected_checksums: Optional[Dict[str, str]] = None,
) -> bool:
    """Verify official raw AIT files (if present) and update the source manifest honestly."""
    raw_files = _is_official_data_present(data_dir)

    if not raw_files:
        msg = f"[fetch_multi_source_dataset] SOURCE_INTEGRITY: SKIPPED — official AIT raw files absent ({data_dir})."
        if require_data or not verify_only:
            print(
                f"ERROR: Official AIT raw dataset is not present in {data_dir}. "
                "Synthetic fixtures are stored separately in tests/fixtures/ait_synthetic.",
                file=sys.stderr,
            )
            _write_step_summary(
                ["### AIT Dataset Verification: FAILED", f"- Missing raw files in `{data_dir}`"]
            )
            return False
        print(msg)
        _write_step_summary(
            [
                "### AIT Dataset Verification: SKIPPED",
                f"- Official raw dataset directory `{data_dir}` has no downloaded official AIT files.",
                "- Synthetic unit-test fixtures are separated in `tests/fixtures/ait_synthetic/`.",
            ]
        )
        return True

    files_manifest: List[Dict[str, Any]] = []
    has_failure = False
    checksums = expected_checksums or {}

    for file_path in raw_files:
        rel_name = str(file_path.relative_to(data_dir)).replace("\\", "/")
        actual_sha256 = compute_sha256(file_path)
        expected_sha = checksums.get(rel_name) or checksums.get(file_path.name)
        status = "RECORDED_UNPINNED"
        if expected_sha:
            if actual_sha256 != expected_sha.lower():
                print(f"ERROR: Checksum mismatch for {rel_name}", file=sys.stderr)
                has_failure = True
                status = "MISMATCH"
            else:
                status = "MATCH"
        files_manifest.append(
            {
                "file": rel_name,
                "size_bytes": file_path.stat().st_size,
                "sha256": actual_sha256,
                "verification_status": status,
            }
        )

    if has_failure:
        _write_step_summary(
            ["### AIT Dataset Verification: FAILED", "- Checksum mismatch detected."]
        )
        return False

    manifest_payload = {
        "schema_version": 2,
        "dataset": OFFICIAL_AIT_SPEC["dataset"],
        "release_year": OFFICIAL_AIT_SPEC["release_year"],
        "synthetic": False,
        "local_raw_status": "PRESENT",
        "official_source": OFFICIAL_AIT_SPEC["official_source"],
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "clean_source_url": (
            sanitize_url(source_url)
            if source_url
            else OFFICIAL_AIT_SPEC["official_source"]["landing_page"]
        ),
        "files": files_manifest,
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest_payload, indent=2) + "\n", encoding="utf-8")
    _write_step_summary(
        [
            "### AIT Dataset Verification: PASS",
            f"- Verified {len(files_manifest)} official file(s) in `{data_dir}`.",
        ]
    )
    print(f"SUCCESS: Official AIT manifest written to {manifest_path}")
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description="AIT Multi-Source Dataset Fetcher & Verifier")
    parser.add_argument(
        "--data-dir", type=Path, default=DEFAULT_DATA_DIR, help="Official raw data directory"
    )
    parser.add_argument(
        "--manifest-path", type=Path, default=MANIFEST_PATH, help="Official source manifest path"
    )
    parser.add_argument(
        "--generate-synthetic-fixtures",
        action="store_true",
        help="Generate synthetic schema-only fixtures into tests/fixtures/ait_synthetic/",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="Verify official files if present; report SKIPPED (exit 0) when raw data is absent",
    )
    parser.add_argument(
        "--require-data",
        action="store_true",
        help="Fail closed (exit 1) if official raw dataset files are missing",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Explicitly download official AIT files from Zenodo API",
    )
    parser.add_argument("--max-files", type=int, default=1, help="Max Zenodo files for --download")
    parser.add_argument("--url", type=str, default=None, help="Override clean source URL")

    args = parser.parse_args()

    if args.generate_synthetic_fixtures:
        generated = generate_synthetic_fixtures(SYNTHETIC_FIXTURE_DIR)
        print(f"Generated {len(generated)} synthetic fixture(s) in {SYNTHETIC_FIXTURE_DIR}")
        if args.verify_only and not args.download:
            pass

    if args.download:
        downloaded = download_official_ait_subset(args.data_dir, max_files=args.max_files)
        print(f"Downloaded {len(downloaded)} official AIT file(s) to {args.data_dir}")

    ok = verify_and_generate_manifest(
        data_dir=args.data_dir,
        manifest_path=args.manifest_path,
        source_url=args.url,
        verify_only=args.verify_only,
        require_data=args.require_data,
    )
    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
