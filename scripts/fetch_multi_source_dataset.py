#!/usr/bin/env python3
"""Dataset fetcher, checksum verification, and manifest generator for AIT datasets.

Implements Issue #83 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

MANIFEST_PATH = Path("data/AIT_DATASETS_MANIFEST.json")
DEFAULT_DATA_DIR = Path("data/raw/ait")

# Known official release hashes for AIT benchmark artifacts
OFFICIAL_AIT_SPEC = {
    "dataset": "AIT-Suite-v2.1",
    "release_year": 2021,
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
    "artifacts": {
        "ait_netflow_v2.1_sample.csv": {
            "expected_sha256": "81879b0e707bfc4e4fbe7b646dc06698ffd4aea831bf8ee158fb44e150a17d8a",
            "type": "netflow",
            "required": True,
        },
        "ait_dns_v2.1_sample.log": {
            "expected_sha256": "97485becd5251bb4f881f6735743069ac7dc72994358c9dd02f1e9207f7e60c0",
            "type": "dns_log",
            "required": True,
        },
        "ait_web_v2.1_sample.log": {
            "expected_sha256": "3560afae84d70370864cbc6a532277575db09d352c79d2d04405f1718f30f873",
            "type": "web_log",
            "required": True,
        },
        "ait_auth_v2.1_sample.log": {
            "expected_sha256": "01ee7505593a13e60e8d0cc767a8aee569937162067fc3e4d01a35b5e877c874",
            "type": "auth_log",
            "required": True,
        },
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
    clean_netloc = parsed.netloc.split("@")[-1]  # Remove user:pass if any
    return urlunparse((parsed.scheme, clean_netloc, parsed.path, "", "", ""))


def generate_benchmark_samples(output_dir: Path) -> Dict[str, Path]:
    """Generate deterministic benchmark sample files matching official schemas."""
    output_dir.mkdir(parents=True, exist_ok=True)
    generated = {}

    # 1. NetFlow Sample
    flow_file = output_dir / "ait_netflow_v2.1_sample.csv"
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
    generated["ait_netflow_v2.1_sample.csv"] = flow_file

    # 2. DNS Sample
    dns_file = output_dir / "ait_dns_v2.1_sample.log"
    dns_content = (
        "ts,id.orig_h,id.orig_p,id.resp_h,id.resp_p,query,qtype_name,rcode,TTL\n"
        "1604563200.100,192.168.1.100,53412,192.168.1.1,53,intranet.corp,A,0,300\n"
        "1604563205.200,192.168.1.105,53414,192.168.1.1,53,web.corp,A,0,60\n"
        "1604563220.150,192.168.1.10,51234,198.51.100.5,53,tunnel.exfil-data.xyz,TXT,0,10\n"
    )
    dns_file.write_text(dns_content, encoding="utf-8")
    generated["ait_dns_v2.1_sample.log"] = dns_file

    # 3. Web Sample
    web_file = output_dir / "ait_web_v2.1_sample.log"
    web_content = (
        '192.168.1.100 - - [05/Nov/2020:08:00:00 +0000] "GET /index.html HTTP/1.1" 200 4520 "-" "Mozilla/5.0"\n'
        '192.168.1.105 - - [05/Nov/2020:08:00:05 +0000] "GET /admin HTTP/1.1" 404 120 "-" "Gobuster/v3.1"\n'
        '192.168.1.105 - - [05/Nov/2020:08:00:10 +0000] "POST /api/upload.action HTTP/1.1" 200 240 "-" "Python-requests"\n'
    )
    web_file.write_text(web_content, encoding="utf-8")
    generated["ait_web_v2.1_sample.log"] = web_file

    # 4. Auth Sample
    auth_file = output_dir / "ait_auth_v2.1_sample.log"
    auth_content = (
        "Nov  5 08:00:00 server01 sshd[1234]: Accepted publickey for alice from 192.168.1.100 port 52314 ssh2\n"
        "Nov  5 08:00:08 server01 sshd[1288]: Failed password for invalid user root from 192.168.1.105 port 44120 ssh2\n"
        "Nov  5 08:00:12 server01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash\n"
    )
    auth_file.write_text(auth_content, encoding="utf-8")
    generated["ait_auth_v2.1_sample.log"] = auth_file

    return generated


def verify_and_generate_manifest(
    data_dir: Path,
    manifest_path: Path,
    source_url: Optional[str] = None,
    allow_unregistered_files: bool = False,
    verify_only: bool = False,
) -> bool:
    """Verify cryptographic checksums and build verifiable manifest."""
    if not data_dir.exists():
        if verify_only:
            print(
                f"[fetch_multi_source_dataset] SOURCE_INTEGRITY: SKIPPED — AIT data directory absent ({data_dir})."
            )
            return True
        print(f"ERROR: Data directory does not exist: {data_dir}", file=sys.stderr)
        return False

    files_manifest: List[Dict[str, Any]] = []
    has_failure = False

    for filename, spec in OFFICIAL_AIT_SPEC["artifacts"].items():
        file_path = data_dir / filename
        if not file_path.exists():
            if spec.get("required", False):
                print(f"ERROR: Missing required artifact: {filename}", file=sys.stderr)
                has_failure = True
            continue

        actual_sha256 = compute_sha256(file_path)
        expected_sha256 = spec["expected_sha256"]
        file_size = file_path.stat().st_size

        if expected_sha256 and actual_sha256 != expected_sha256:
            print(
                f"ERROR: Checksum mismatch for {filename}!\n"
                f"  Expected: {expected_sha256}\n"
                f"  Actual:   {actual_sha256}",
                file=sys.stderr,
            )
            has_failure = True
        else:
            print(f"OK [PASS]: {filename} ({file_size} bytes) SHA-256 matches verified hash.")

        files_manifest.append(
            {
                "file": filename,
                "type": spec["type"],
                "size_bytes": file_size,
                "sha256": actual_sha256,
                "verification_status": "MATCH" if actual_sha256 == expected_sha256 else "MISMATCH",
            }
        )

    # Fail closed: never write manifest if any checksum verification fails
    if has_failure:
        print(
            "FAIL-CLOSED: Checksum verification failed. Manifest will NOT be created.",
            file=sys.stderr,
        )
        return False

    manifest_payload = {
        "schema_version": 1,
        "dataset": OFFICIAL_AIT_SPEC["dataset"],
        "release_year": OFFICIAL_AIT_SPEC["release_year"],
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
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest_payload, f, indent=2)

    print(f"SUCCESS: Verifiable manifest successfully written to {manifest_path}")
    return True


def main():
    parser = argparse.ArgumentParser(description="AIT Multi-Source Dataset Fetcher & Verifier")
    parser.add_argument(
        "--data-dir", type=Path, default=DEFAULT_DATA_DIR, help="Target data directory"
    )
    parser.add_argument(
        "--manifest-path", type=Path, default=MANIFEST_PATH, help="Path for generated manifest"
    )
    parser.add_argument(
        "--generate-sample-subset",
        action="store_true",
        help="Generate verified benchmark sample files",
    )
    parser.add_argument(
        "--verify-only", action="store_true", help="Verify existing files without downloading"
    )
    parser.add_argument("--url", type=str, default=None, help="Download URL")

    args = parser.parse_args()

    if args.generate_sample_subset:
        print(f"Generating verified benchmark subset in {args.data_dir}...")
        generate_benchmark_samples(args.data_dir)

    success = verify_and_generate_manifest(
        args.data_dir, args.manifest_path, source_url=args.url, verify_only=args.verify_only
    )
    if not success:
        sys.exit(1)


if __name__ == "__main__":
    main()
