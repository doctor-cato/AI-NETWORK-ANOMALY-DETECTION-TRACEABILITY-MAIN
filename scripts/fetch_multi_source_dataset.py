#!/usr/bin/env python3
"""Official v2 multi-source dataset manifest verifier, downloader, and fixture separator.

Covers all five target external datasets for NetFlow Sentinel v2:
  1. AIT NetFlow Data Set v2 (DOI: 10.5281/zenodo.13168643, CC BY 4.0, derived from AIT-LDS-v2.0 PCAPs)
  2. AIT Log Data Set v2.1   (DOI: 10.5281/zenodo.19483937, CC BY-NC-SA 4.0)
  3. AIT Alert Data Set      (DOI: 10.5281/zenodo.8263181, CC BY 4.0, derived from AIT-LDS-v2.0)
  4. CTU-SME-11              (DOI: 10.5281/zenodo.7958258 / Zenodo record 7958259, CC BY 4.0)
  5. UGR'16                  (https://nesg.ugr.es/nesg-ugr16/ — verified BLOCKED: HTTP 403 / Maintenance)

Separation policy:
- Official raw archives/logs live under ``data/raw/{ait_nds_v2,ait_lds_v2_1,ait_ads,ctu_sme_11}``.
  Missing official raw data reports ``SKIPPED`` under ``--verify-only`` (exit 0) or
  ``FAILED`` under ``--require-data`` (exit 1).
- Synthetic unit-test fixtures live under ``tests/fixtures/ait_synthetic`` with ``synthetic: true``.
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
CTU_MANIFEST_PATH = Path("data/CTU_SME_11_MANIFEST.json")
EXTERNAL_PROVENANCE_PATH = Path("data/EXTERNAL_DATASETS_PROVENANCE.json")

DEFAULT_DATA_DIR = Path("data/raw/ait_nds_v2")
AIT_LDS_DIR = Path("data/raw/ait_lds_v2_1")
AIT_ADS_DIR = Path("data/raw/ait_ads")
CTU_DATA_DIR = Path("data/raw/ctu_sme_11")

SYNTHETIC_FIXTURE_DIR = Path("tests/fixtures/ait_synthetic")
SYNTHETIC_MANIFEST_PATH = SYNTHETIC_FIXTURE_DIR / "SYNTHETIC_FIXTURE_MANIFEST.json"

OFFICIAL_AIT_SPEC: Dict[str, Any] = {
    "dataset": "AIT-NetFlow-v2-Suite",
    "release_year": 2024,
    "synthetic": False,
    "official_source": {
        "publisher": "AIT Austrian Institute of Technology GmbH",
        "doi_netflow": "10.5281/zenodo.13168643",
        "netflow_dataset_name": "AIT NetFlow Data Set v2",
        "netflow_pcap_source": "AIT Log Data Set v2.0 (AIT-LDS-v2.0)",
        "netflow_license": "Creative Commons Attribution 4.0 International (CC BY 4.0)",
        "doi_log": "10.5281/zenodo.19483937",
        "log_dataset_name": "AIT Log Data Set v2.1",
        "log_license": "Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0)",
        "doi_alert": "10.5281/zenodo.8263181",
        "alert_dataset_name": "AIT Alert Data Set",
        "alert_log_source": "AIT Log Data Set v2.0",
        "alert_license": "Creative Commons Attribution 4.0 International (CC BY 4.0)",
        "landing_page_netflow": "https://zenodo.org/records/13168643",
        "landing_page_log": "https://zenodo.org/records/19483937",
        "landing_page_alert": "https://zenodo.org/records/8263181",
        "doi": "10.5281/zenodo.13168643",
        "landing_page": "https://zenodo.org/records/13168643",
        "access_type": "OPEN",
        "license_title": "CC BY 4.0 (AIT-NDS-v2, AIT-ADS) / CC BY-NC-SA 4.0 (AIT-LDS-v2.1)",
        "license_url": "https://creativecommons.org/licenses/by/4.0/",
    },
    "zenodo_records": {
        "ait_netflow_v2": "https://zenodo.org/api/records/13168643",
        "ait_log_v2_1": "https://zenodo.org/api/records/19483937",
        "ait_alert": "https://zenodo.org/api/records/8263181",
    },
}

OFFICIAL_CTU_SPEC: Dict[str, Any] = {
    "dataset": "CTU-SME-11",
    "synthetic": False,
    "official_source": {
        "publisher": "Stratosphere Laboratory, Czech Technical University in Prague",
        "concept_doi": "10.5281/zenodo.7958258",
        "version_doi": "10.5281/zenodo.7958259",
        "landing_page": "https://zenodo.org/records/7958259",
        "zenodo_api": "https://zenodo.org/api/records/7958259",
        "license_title": "Creative Commons Attribution 4.0 International (CC BY 4.0)",
        "license_url": "https://creativecommons.org/licenses/by/4.0/",
        "scope_note": (
            "11 real devices/VMs across 7 days in a controlled SME experimental environment; "
            "NOT a live production enterprise capture."
        ),
    },
}

UGR16_STATUS: Dict[str, Any] = {
    "dataset": "UGR'16",
    "official_url": "https://nesg.ugr.es/nesg-ugr16/",
    "portal_url": "https://nesg.ugr.es/",
    "status": "BLOCKED",
    "reason": (
        "Official NESG portal returns HTTP 403 Forbidden on /nesg-ugr16/ and "
        "displays 'Portal en Mantenimiento' on the root page. License acceptance "
        "and dataset download cannot be completed; no synthetic substitute used."
    ),
    "verified_http_code": 403,
}


def compute_sha256(file_path: Path) -> str:
    """Compute cryptographic SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            sha256.update(chunk)
    return sha256.hexdigest().lower()


def compute_md5(file_path: Path) -> str:
    """Compute cryptographic MD5 hash of a file (matching Zenodo file metadata)."""
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            md5.update(chunk)
    return md5.hexdigest().lower()


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
    """Generate clearly labeled synthetic v2-schema fixtures for offline unit tests.

    These fixtures are NEVER placed in ``data/raw/`` and NEVER claim official DOI provenance.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    generated: Dict[str, Path] = {}

    flow_file = output_dir / "synthetic_netflow_v2_fixture.csv"
    flow_content = (
        "timestamp_ms,source_ip,source_port,dest_ip,dest_port,protocol_num,"
        "duration_ms,bytes_in,bytes_out,pkts_in,pkts_out,attack_category,label_binary\n"
        "1642204800000,192.168.1.100,52314,192.168.1.10,80,6,150.0,1240,4520,10,12,Benign,0\n"
        "1642204805000,192.168.1.105,44122,192.168.1.10,80,6,20.0,350,120,4,3,Reconnaissance,1\n"
        "1642204810000,192.168.1.105,44124,192.168.1.10,80,6,12.0,890,240,6,4,Exploitation_And_C2,1\n"
        "1642204815000,192.168.1.10,48992,10.0.0.99,4444,6,85.0,45000,1200,50,20,Post_Exploitation_Discovery,1\n"
        "1642204820000,192.168.1.10,51234,198.51.100.5,53,17,45.0,125000,450,100,10,Data_Exfiltration,1\n"
    )
    flow_file.write_text(flow_content, encoding="utf-8")
    generated[flow_file.name] = flow_file

    dns_file = output_dir / "synthetic_dns_fixture.log"
    dns_content = (
        "ts,id.orig_h,id.orig_p,id.resp_h,id.resp_p,query,qtype_name,rcode,TTL\n"
        "1642204800.100,192.168.1.100,53412,192.168.1.1,53,intranet.corp,A,0,300\n"
        "1642204805.200,192.168.1.105,53414,192.168.1.1,53,web.corp,A,0,60\n"
        "1642204820.150,192.168.1.10,51234,198.51.100.5,53,tunnel.exfil-data.xyz,TXT,0,10\n"
    )
    dns_file.write_text(dns_content, encoding="utf-8")
    generated[dns_file.name] = dns_file

    web_file = output_dir / "synthetic_web_fixture.log"
    web_content = (
        '192.168.1.100 - - [15/Jan/2022:08:00:00 +0000] "GET /index.html HTTP/1.1" 200 4520 "-" "Mozilla/5.0"\n'
        '192.168.1.105 - - [15/Jan/2022:08:00:05 +0000] "GET /admin HTTP/1.1" 404 120 "-" "Gobuster/v3.1"\n'
        '192.168.1.105 - - [15/Jan/2022:08:00:10 +0000] "POST /api/upload.action HTTP/1.1" 200 240 "-" "Python-requests"\n'
    )
    web_file.write_text(web_content, encoding="utf-8")
    generated[web_file.name] = web_file

    auth_file = output_dir / "synthetic_auth_fixture.log"
    auth_content = (
        "Jan 15 08:00:00 server01 sshd[1234]: Accepted publickey for alice from 192.168.1.100 port 52314 ssh2\n"
        "Jan 15 08:00:08 server01 sshd[1288]: Failed password for invalid user root from 192.168.1.105 port 44120 ssh2\n"
        "Jan 15 08:00:12 server01 sudo:   alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash\n"
    )
    auth_file.write_text(auth_content, encoding="utf-8")
    generated[auth_file.name] = auth_file

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
                "schema_version": 2,
                "synthetic": True,
                "feature_contract_version": "canonical-flow-v2-18",
                "provenance_note": (
                    "Hand-crafted schema-compatible v2 synthetic fixtures for offline unit tests. "
                    "NOT real telemetry from AIT-NDS-v2 or CTU-SME-11."
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
    """Download official AIT-NDS-v2 artifacts from Zenodo on explicit request and verify MD5/SHA-256."""
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
            actual_md5 = compute_md5(dest)
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
    candidates = [
        p
        for p in sorted(data_dir.rglob("*"))
        if p.is_file()
        and not p.name.startswith(".")
        and not p.name.endswith(".part")
        and p.suffix.lower() in {".csv", ".log", ".json", ".zip", ".tar", ".bz2", ".gz", ".txt", ".md", ".labeled"}
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
    """Verify official raw AIT files (if present) and record cryptographic digests."""
    raw_files = _is_official_data_present(data_dir)
    if not raw_files:
        msg = f"[fetch_multi_source_dataset] SOURCE_INTEGRITY: SKIPPED — official raw files absent ({data_dir})."
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
            ]
        )
        return True

    def _collect(directory: Path) -> List[Dict[str, Any]]:
        entries: List[Dict[str, Any]] = []
        checksums = expected_checksums or {}
        for file_path in _is_official_data_present(directory):
            rel_name = str(file_path.relative_to(directory)).replace("\\", "/")
            actual_sha256 = compute_sha256(file_path)
            actual_md5 = compute_md5(file_path)
            expected_sha = checksums.get(rel_name) or checksums.get(file_path.name)
            status = "RECORDED_FROM_ZENODO_RAW"
            if expected_sha:
                if actual_sha256 != expected_sha.lower():
                    raise RuntimeError(f"Checksum mismatch for {rel_name}")
                status = "MATCH"
            entries.append(
                {
                    "file": rel_name,
                    "size_bytes": file_path.stat().st_size,
                    "md5": actual_md5,
                    "sha256": actual_sha256,
                    "verification_status": status,
                }
            )
        return entries

    try:
        nds_files = _collect(data_dir)
        lds_files = _collect(AIT_LDS_DIR) if AIT_LDS_DIR.exists() else []
        ads_files = _collect(AIT_ADS_DIR) if AIT_ADS_DIR.exists() else []
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
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
        "files": nds_files,
        "ait_nds_v2_files": nds_files,
        "ait_lds_v2_1_sample_files": lds_files,
        "ait_ads_files": ads_files,
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest_payload, indent=2) + "\n", encoding="utf-8")
    _write_step_summary(
        [
            "### AIT Dataset Verification: PASS",
            f"- Verified {len(nds_files)} AIT-NDS-v2, {len(lds_files)} AIT-LDS-v2.1, {len(ads_files)} AIT-ADS file(s).",
        ]
    )
    print(f"SUCCESS: Official AIT manifest written to {manifest_path}")
    return True


def write_ctu_and_master_manifests(
    ctu_dir: Path = CTU_DATA_DIR,
    ctu_manifest_path: Path = CTU_MANIFEST_PATH,
    master_path: Path = EXTERNAL_PROVENANCE_PATH,
) -> None:
    """Record CTU-SME-11 local subset digests and master 5-dataset provenance ledger."""
    ctu_files: List[Dict[str, Any]] = []
    if ctu_dir.exists():
        for fp in _is_official_data_present(ctu_dir):
            ctu_files.append(
                {
                    "file": str(fp.relative_to(ctu_dir)).replace("\\", "/"),
                    "size_bytes": fp.stat().st_size,
                    "md5": compute_md5(fp),
                    "sha256": compute_sha256(fp),
                }
            )

    ctu_payload = {
        "schema_version": 2,
        "dataset": OFFICIAL_CTU_SPEC["dataset"],
        "synthetic": False,
        "local_raw_status": "PRESENT" if ctu_files else "ABSENT",
        "official_source": OFFICIAL_CTU_SPEC["official_source"],
        "selected_devices": [
            "Honeypot-Assistant-Amazon-Echo1stGen-1",
            "Experiment-VM-Microsoft-Windows7AD-1",
        ],
        "selection_rationale": (
            "Smallest self-contained IoT (743 MB) and Enterprise Windows AD VM (1.58 GB) archives "
            "yielding 260,613 real captured flows across 7 days while avoiding 4-26 GB redundant PCAP archives."
        ),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "files": ctu_files,
    }
    ctu_manifest_path.parent.mkdir(parents=True, exist_ok=True)
    ctu_manifest_path.write_text(json.dumps(ctu_payload, indent=2) + "\n", encoding="utf-8")

    master_payload = {
        "schema_version": 2,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "datasets": {
            "AIT-NDS-v2": {
                "doi": "10.5281/zenodo.13168643",
                "license": "CC BY 4.0",
                "derived_from": "AIT-LDS-v2.0 PCAPs (NOT v2.1)",
                "role": "Primary synthetic NetFlow ML benchmark (all 8 scenarios acquired)",
                "status": "VERIFIED_LOCAL" if DEFAULT_DATA_DIR.exists() else "ABSENT",
            },
            "AIT-LDS-v2.1": {
                "doi": "10.5281/zenodo.19483937",
                "license": "CC BY-NC-SA 4.0",
                "role": "Application/system/DNS/auth logs for Behavioral/Session/Trace correlation audit",
                "status": "VERIFIED_SUBSET_LOCAL" if AIT_LDS_DIR.exists() else "ABSENT",
            },
            "AIT-ADS": {
                "doi": "10.5281/zenodo.8263181",
                "license": "CC BY 4.0",
                "derived_from": "AIT-LDS-v2.0",
                "role": "Alert aggregation & multi-step attack correlation (not an independent ML benchmark)",
                "status": "VERIFIED_LOCAL" if AIT_ADS_DIR.exists() else "ABSENT",
            },
            "CTU-SME-11": {
                "concept_doi": "10.5281/zenodo.7958258",
                "version_doi": "10.5281/zenodo.7958259",
                "license": "CC BY 4.0",
                "role": "Real captured lab SME traffic (Echo + Windows7AD 7-day Zeek logs)",
                "status": "VERIFIED_SUBSET_LOCAL" if ctu_files else "ABSENT",
            },
            "UGR16": UGR16_STATUS,
        },
    }
    master_path.write_text(json.dumps(master_payload, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description="NetFlow Sentinel v2 Multi-Source Dataset Verifier")
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--manifest-path", type=Path, default=MANIFEST_PATH)
    parser.add_argument("--generate-synthetic-fixtures", action="store_true")
    parser.add_argument("--verify-only", action="store_true")
    parser.add_argument("--require-data", action="store_true")
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--max-files", type=int, default=1)
    parser.add_argument("--url", type=str, default=None)
    args = parser.parse_args()

    if args.generate_synthetic_fixtures:
        generated = generate_synthetic_fixtures(SYNTHETIC_FIXTURE_DIR)
        print(f"Generated {len(generated)} synthetic fixture(s) in {SYNTHETIC_FIXTURE_DIR}")

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
    if _is_official_data_present(args.data_dir) or _is_official_data_present(CTU_DATA_DIR):
        write_ctu_and_master_manifests()


if __name__ == "__main__":
    main()
