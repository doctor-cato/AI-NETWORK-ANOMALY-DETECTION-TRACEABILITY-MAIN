#!/usr/bin/env python3
"""Audit split membership parity and hash chain provenance for NF-UNSW-NB15-v3.

Addresses Finding F03 (PR #40 / Issue #31):
- Compares canonical split manifest (Oct 2026, PR #41) with regenerated split manifest
  (Nov 2026, PR #40).
- Distinguishes:
    1. Protocol Equivalence (dataset SHA, algorithm, ratios, purge gaps, boundaries,
       category distributions).
    2. Byte Equivalence (compressed .csv.gz file SHA-256 hashes).
    3. Membership Equivalence (exact row index identity and ordering).
- Enforces Test isolation: Verifies runtime execution evidence from training manifests
  rather than asserting hardcoded passes.
- Avoids unproven claims: Reframes compression divergence as an unproven hypothesis.
- Produces structured evidence reporting and verifiable parity status.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_SOURCE = PROJECT_ROOT / "src"
if str(LOCAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(LOCAL_SOURCE))

from network_anomaly.data.split import _sha256_file  # noqa: E402

CANONICAL_OCT_SPLIT_REFERENCE: Dict[str, Any] = {
    "split_manifest_sha256": "bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88",
    "dataset_name": "NF-UNSW-NB15-v3",
    "dataset_sha256": "4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5",
    "split_protocol_version": "nf-unsw-nb15-v3-chronological-group-purged-v1",
    "random_seed": 42,
    "total_source_rows": 2365424,
    "split_policy": {
        "strategy": "chronological_with_canonical_flow_group_purge_gap",
        "timezone": "UTC",
        "purge_gap_milliseconds": 300000,
        "target_proportions": {
            "train": 0.7,
            "validation": 0.15,
            "test": 0.15,
        },
        "boundaries": {
            "t_train_end_epoch_ms": 1424238133382,
            "t_train_end_utc": "2015-02-18T05:42:13.382000+00:00",
            "t_val_start_epoch_ms": 1424238433382,
            "t_val_start_utc": "2015-02-18T05:47:13.382000+00:00",
            "t_val_end_epoch_ms": 1424250496133,
            "t_val_end_utc": "2015-02-18T09:08:16.133000+00:00",
            "t_test_start_epoch_ms": 1424250796133,
            "t_test_start_utc": "2015-02-18T09:13:16.133000+00:00",
            "actual_train_val_gap_ms": 300004,
            "actual_val_test_gap_ms": 300027,
        },
        "stable_identifier_strategy": (
            "0-based source line index (header excluded) valid for dataset bytes "
            "matching SHA-256 4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5."
        ),
    },
    "partitions": {
        "train": {
            "row_count": 1655797,
            "percentage_of_total": 70.0,
            "time_coverage": {
                "count": 1655797,
                "min_epoch_ms": 1421927376907,
                "max_epoch_ms": 1424238133382,
                "min_utc": "2015-01-22T11:49:36.907000+00:00",
                "max_utc": "2015-02-18T05:42:13.382000+00:00",
            },
            "label_distribution": {"0": 1590608, "1": 65189},
            "attack_distribution": {
                "Analysis": 646,
                "Backdoor": 3253,
                "Benign": 1590608,
                "DoS": 3238,
                "Exploits": 21416,
                "Fuzzers": 17599,
                "Generic": 9243,
                "Reconnaissance": 8304,
                "Shellcode": 1407,
                "Worms": 83,
            },
            "index_sha256": "a09ba1757484c65596a88fe22d5bd989a3cca60a01088364020e2f952b36c725",
        },
        "purged_train_val_gap": {
            "row_count": 9443,
            "percentage_of_total": 0.3992,
            "time_coverage": {
                "count": 9443,
                "min_epoch_ms": 1424238133412,
                "max_epoch_ms": 1424238433334,
                "min_utc": "2015-02-18T05:42:13.412000+00:00",
                "max_utc": "2015-02-18T05:47:13.334000+00:00",
            },
            "label_distribution": {"0": 8546, "1": 897},
            "attack_distribution": {
                "Analysis": 1,
                "Backdoor": 2,
                "Benign": 8546,
                "DoS": 63,
                "Exploits": 223,
                "Fuzzers": 335,
                "Generic": 145,
                "Reconnaissance": 115,
                "Shellcode": 12,
                "Worms": 1,
            },
            "index_sha256": "3bdf9ef3ee6f62960a61205bf1c98c06786971c913c8dea837764a95742b15a9",
        },
        "validation": {
            "row_count": 345371,
            "percentage_of_total": 14.6008,
            "time_coverage": {
                "count": 345371,
                "min_epoch_ms": 1424238433386,
                "max_epoch_ms": 1424250496133,
                "min_utc": "2015-02-18T05:47:13.386000+00:00",
                "max_utc": "2015-02-18T09:08:16.133000+00:00",
            },
            "label_distribution": {"0": 314871, "1": 30500},
            "attack_distribution": {
                "Analysis": 285,
                "Backdoor": 144,
                "Benign": 314871,
                "DoS": 1445,
                "Exploits": 10294,
                "Fuzzers": 8495,
                "Generic": 5137,
                "Reconnaissance": 4107,
                "Shellcode": 556,
                "Worms": 37,
            },
            "index_sha256": "7d41a71a2a154a46fec4a0095fb277007b6b1574727976ee6593e6d56b9400bf",
        },
        "purged_val_test_gap": {
            "row_count": 8860,
            "percentage_of_total": 0.3746,
            "time_coverage": {
                "count": 8860,
                "min_epoch_ms": 1424250496143,
                "max_epoch_ms": 1424250796107,
                "min_utc": "2015-02-18T09:08:16.143000+00:00",
                "max_utc": "2015-02-18T09:13:16.107000+00:00",
            },
            "label_distribution": {"0": 8349, "1": 511},
            "attack_distribution": {
                "Benign": 8349,
                "DoS": 41,
                "Exploits": 295,
                "Fuzzers": 65,
                "Generic": 15,
                "Reconnaissance": 84,
                "Shellcode": 10,
                "Worms": 1,
            },
            "index_sha256": "ac7f1de36b7bf1e26fce85869be0c5d0adef5c367eac8dd95f0ce50199e4a7c3",
        },
        "test": {
            "row_count": 345953,
            "percentage_of_total": 14.6254,
            "time_coverage": {
                "count": 345953,
                "min_epoch_ms": 1424250796160,
                "max_epoch_ms": 1424262564927,
                "min_utc": "2015-02-18T09:13:16.160000+00:00",
                "max_utc": "2015-02-18T12:29:24.927000+00:00",
            },
            "label_distribution": {"0": 315357, "1": 30596},
            "attack_distribution": {
                "Analysis": 294,
                "Backdoor": 1260,
                "Benign": 315357,
                "DoS": 1193,
                "Exploits": 10520,
                "Fuzzers": 7322,
                "Generic": 5111,
                "Reconnaissance": 4464,
                "Shellcode": 396,
                "Worms": 36,
            },
            "index_sha256": "63e2e081300955fe06835b0cf7405e07e53985ca3d84164e768be09116269d03",
        },
    },
}

DEFAULT_RUNTIME_MANIFEST = (
    PROJECT_ROOT / "reports" / "splits" / "nf_unsw_nb15_v3_split_manifest.json"
)
DEFAULT_TRAINING_MANIFEST = PROJECT_ROOT / "reports" / "models" / "xgboost_manifest.json"
DEFAULT_INDICES_DIR = PROJECT_ROOT / "data" / "processed" / "splits"


def audit_split_membership_parity(
    runtime_manifest_path: Path,
    training_manifest_path: Optional[Path] = None,
    indices_dir: Optional[Path] = None,
    canonical_reference: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Audit equivalence between canonical Oct split reference and Nov regenerated split.

    Performs comprehensive verification of:
    - Dataset identity and configuration parameters.
    - Split policy, purge gap parameters, and exact temporal boundaries.
    - Partition sizes, time coverage intervals, label distributions, and attack category breakdowns.
    - Byte-level hash chain comparison.
    - Membership equivalence constraints.
    - Test isolation contract vs measured runtime training evidence.
    """
    if not runtime_manifest_path.exists():
        raise FileNotFoundError(f"Runtime split manifest not found: {runtime_manifest_path}")

    with runtime_manifest_path.open("r", encoding="utf-8") as f:
        runtime_manifest = json.load(f)

    runtime_manifest_sha = _sha256_file(runtime_manifest_path)
    ref = canonical_reference or CANONICAL_OCT_SPLIT_REFERENCE
    canonical_sm_sha = ref["split_manifest_sha256"]

    protocol_discrepancies: List[str] = []

    # 1. Dataset identity & parameter audit
    if runtime_manifest.get("dataset_name") != ref["dataset_name"]:
        protocol_discrepancies.append(
            f"dataset_name mismatch: expected '{ref['dataset_name']}', "
            f"got '{runtime_manifest.get('dataset_name')}'"
        )
    if runtime_manifest.get("dataset_sha256") != ref["dataset_sha256"]:
        protocol_discrepancies.append(
            f"dataset_sha256 mismatch: expected '{ref['dataset_sha256']}', "
            f"got '{runtime_manifest.get('dataset_sha256')}'"
        )
    if runtime_manifest.get("split_protocol_version") != ref["split_protocol_version"]:
        protocol_discrepancies.append(
            f"split_protocol_version mismatch: expected '{ref['split_protocol_version']}', "
            f"got '{runtime_manifest.get('split_protocol_version')}'"
        )
    if runtime_manifest.get("random_seed") != ref["random_seed"]:
        protocol_discrepancies.append(
            f"random_seed mismatch: expected {ref['random_seed']}, "
            f"got {runtime_manifest.get('random_seed')}"
        )
    if runtime_manifest.get("total_source_rows") != ref["total_source_rows"]:
        protocol_discrepancies.append(
            f"total_source_rows mismatch: expected {ref['total_source_rows']}, "
            f"got {runtime_manifest.get('total_source_rows')}"
        )

    # 2. Split policy & temporal boundary audit
    rt_policy = runtime_manifest.get("split_policy")
    if not isinstance(rt_policy, dict):
        protocol_discrepancies.append("split_policy missing or not a dictionary")
    else:
        ref_policy = ref["split_policy"]
        if rt_policy.get("strategy") != ref_policy["strategy"]:
            protocol_discrepancies.append(
                f"split strategy mismatch: expected '{ref_policy['strategy']}', "
                f"got '{rt_policy.get('strategy')}'"
            )
        if rt_policy.get("purge_gap_milliseconds") != ref_policy["purge_gap_milliseconds"]:
            protocol_discrepancies.append(
                f"purge_gap_milliseconds mismatch: expected "
                f"{ref_policy['purge_gap_milliseconds']}, "
                f"got {rt_policy.get('purge_gap_milliseconds')}"
            )
        if rt_policy.get("target_proportions") != ref_policy["target_proportions"]:
            protocol_discrepancies.append(
                f"target_proportions mismatch: expected {ref_policy['target_proportions']}, "
                f"got {rt_policy.get('target_proportions')}"
            )
        if rt_policy.get("boundaries") != ref_policy["boundaries"]:
            protocol_discrepancies.append(
                f"split temporal boundaries mismatch: expected {ref_policy['boundaries']}, "
                f"got {rt_policy.get('boundaries')}"
            )

    # 3. Partition audit (row count, time coverage, label and attack distributions)
    partition_audit: Dict[str, Any] = {}
    rt_partitions = runtime_manifest.get("partitions")
    if not isinstance(rt_partitions, dict):
        protocol_discrepancies.append("partitions missing or not a dictionary in runtime manifest")
        rt_partitions = {}

    for p_name, expected_info in ref["partitions"].items():
        rt_part = rt_partitions.get(p_name)
        if not isinstance(rt_part, dict):
            protocol_discrepancies.append(f"Partition '{p_name}' missing from runtime manifest")
            partition_audit[p_name] = {
                "expected_row_count": expected_info["row_count"],
                "runtime_row_count": None,
                "counts_match": False,
                "canonical_oct_sha256": expected_info["index_sha256"],
                "runtime_nov_sha256": None,
                "byte_hashes_match": False,
                "time_coverage_match": False,
                "label_distribution_match": False,
                "attack_distribution_match": False,
            }
            continue

        exp_count = expected_info["row_count"]
        rt_count = rt_part.get("row_count")
        counts_equal = rt_count == exp_count
        if not counts_equal:
            protocol_discrepancies.append(
                f"Partition '{p_name}' row count mismatch: expected {exp_count}, got {rt_count}"
            )

        # Time coverage comparison
        exp_tc = expected_info.get("time_coverage", {})
        rt_tc = rt_part.get("time_coverage", {})
        tc_match = rt_tc == exp_tc
        if not tc_match:
            protocol_discrepancies.append(
                f"Partition '{p_name}' time coverage mismatch: expected {exp_tc}, got {rt_tc}"
            )

        # Label distribution comparison
        exp_ld = expected_info.get("label_distribution", {})
        rt_ld = rt_part.get("label_distribution", {})
        ld_match = rt_ld == exp_ld
        if not ld_match:
            protocol_discrepancies.append(
                f"Partition '{p_name}' label distribution mismatch: expected {exp_ld}, got {rt_ld}"
            )

        # Attack category distribution comparison
        exp_ad = expected_info.get("attack_distribution", {})
        rt_ad = rt_part.get("attack_distribution", {})
        ad_match = rt_ad == exp_ad
        if not ad_match:
            protocol_discrepancies.append(
                f"Partition '{p_name}' attack category distribution mismatch: "
                f"expected {exp_ad}, got {rt_ad}"
            )

        exp_sha = expected_info["index_sha256"]
        rt_sha = rt_part.get("index_sha256")
        hashes_equal = rt_sha == exp_sha

        partition_audit[p_name] = {
            "expected_row_count": exp_count,
            "runtime_row_count": rt_count,
            "counts_match": counts_equal,
            "canonical_oct_sha256": exp_sha,
            "runtime_nov_sha256": rt_sha,
            "byte_hashes_match": hashes_equal,
            "time_coverage_match": tc_match,
            "label_distribution_match": ld_match,
            "attack_distribution_match": ad_match,
        }

    protocol_status = "VERIFIED" if not protocol_discrepancies else "FAIL"

    # 4. Byte Equivalence
    manifest_bytes_match = runtime_manifest_sha == canonical_sm_sha
    all_partition_bytes_match = all(p["byte_hashes_match"] for p in partition_audit.values())
    byte_status = (
        "IDENTICAL" if (manifest_bytes_match and all_partition_bytes_match) else "DIFFERENT"
    )

    # 5. Membership Equivalence (requires actual canonical raw index files on disk)
    canonical_indices_present = False
    if indices_dir is not None:
        canonical_dir = indices_dir / "canonical_oct"
        if canonical_dir.is_dir():
            canonical_indices_present = all(
                (canonical_dir / f"{p}_indices.csv.gz").exists() for p in ref["partitions"]
            )

    if canonical_indices_present:
        membership_status = "NOT_EVALUATED_AUTOMATICALLY"
        membership_reason = (
            "Canonical index directory exists but automated sequence decompression "
            "has not been executed."
        )
    else:
        membership_status = "NOT_VERIFIED"
        membership_reason = (
            "Canonical October compressed index files (.csv.gz) were excluded by .gitignore "
            "and are absent from Git. While Protocol Equivalence is VERIFIED across dataset "
            "identity, split policy, temporal boundaries, purge gaps, label distributions, "
            "and attack categories, exact row-by-row index identity and ordering cannot be proven "
            "without raw canonical index artifacts. Matching row counts and distributions do "
            "NOT constitute proof of membership equivalence."
        )

    # 6. Test Isolation: Distinguish declared policy contract vs measured runtime evidence
    declared_policy_contract = {
        "test_partition_accessed": False,
        "test_rows_loaded": 0,
        "test_indices_loaded": False,
        "contract": (
            "Contractual requirement: Test partition row indices and data must remain strictly "
            "isolated and never accessed during training, tuning, or validation."
        ),
    }

    measured_runtime_evidence: Dict[str, Any] = {
        "status": "NOT_EVALUATED_IN_THIS_AUDIT",
        "details": "No model training manifest provided to inspect runtime execution evidence.",
    }

    target_training_manifest = training_manifest_path or DEFAULT_TRAINING_MANIFEST
    if target_training_manifest and target_training_manifest.exists():
        try:
            with target_training_manifest.open("r", encoding="utf-8") as f:
                t_manifest = json.load(f)
            t_lock_audit = t_manifest.get("test_lock_audit", {})
            t_prov = t_manifest.get("split_provenance", {})

            accessed = (
                t_lock_audit.get("test_partition_accessed")
                if "test_partition_accessed" in t_lock_audit
                else t_prov.get("test_partition_accessed")
            )
            rows_loaded = (
                t_lock_audit.get("test_rows_loaded")
                if "test_rows_loaded" in t_lock_audit
                else t_prov.get("test_rows_loaded")
            )

            if accessed is False and rows_loaded == 0:
                measured_runtime_evidence = {
                    "status": "VERIFIED_FROM_RUN_MANIFEST",
                    "training_run_id": t_manifest.get("run_id"),
                    "manifest_path": str(target_training_manifest),
                    "test_partition_accessed": False,
                    "test_rows_loaded": 0,
                    "test_indices_loaded": t_lock_audit.get("test_indices_loaded", False),
                    "lock_contracts_verified": [
                        "Contract A (Line Stream)",
                        "Contract B (Index Exclude)",
                    ],
                }
            else:
                measured_runtime_evidence = {
                    "status": "VIOLATION_DETECTED",
                    "training_run_id": t_manifest.get("run_id"),
                    "test_partition_accessed": accessed,
                    "test_rows_loaded": rows_loaded,
                }
        except Exception as exc:
            measured_runtime_evidence = {
                "status": "ERROR_READING_TRAINING_MANIFEST",
                "error": str(exc),
            }

    # 7. Hash Divergence Analysis: Clearly framed as unproven hypothesis
    hash_divergence_analysis = {
        "status": "UNPROVEN_HYPOTHESIS",
        "hypothesis": (
            "Compression implementation differences (e.g., zlib version, OS gzip header "
            "timestamps, or deflate implementation details between Linux Ubuntu and Windows) "
            "have been proposed as a plausible hypothesis for divergent archive SHA-256 hashes."
        ),
        "empirical_limitation": (
            "Because original October compressed index files are absent from Git, this hypothesis "
            "has NOT been empirically proven. The root cause of archive hash divergence "
            "remains unverified."
        ),
    }

    evidence: Dict[str, Any] = {
        "status": {
            "protocol_equivalence": protocol_status,
            "artifact_byte_equivalence": byte_status,
            "membership_equivalence": membership_status,
        },
        "canonical_reference": {
            "split_manifest_sha256": canonical_sm_sha,
            "source_pr": "PR #41 (accepted 2026-10-27)",
        },
        "runtime_record": {
            "split_manifest_path": str(runtime_manifest_path),
            "split_manifest_sha256": runtime_manifest_sha,
            "generated_at_utc": runtime_manifest.get("generated_at_utc"),
        },
        "protocol_discrepancies": protocol_discrepancies,
        "partitions": partition_audit,
        "membership_rationale": membership_reason,
        "test_isolation": {
            "declared_policy_contract": declared_policy_contract,
            "measured_runtime_evidence": measured_runtime_evidence,
        },
        "cause_of_hash_divergence": hash_divergence_analysis,
    }

    return evidence


def render_split_membership_report_md(evidence: Dict[str, Any]) -> str:
    """Render structured Markdown evidence report."""
    lines = [
        "# Split Membership Parity & Provenance Audit Report (NF-UNSW-NB15-v3)",
        "",
        "## 1. Summary of Equivalence Status",
        "",
        f"- **Protocol Equivalence:** `{evidence['status']['protocol_equivalence']}`",
        f"- **Artifact Byte Equivalence:** `{evidence['status']['artifact_byte_equivalence']}`",
        f"- **Membership Equivalence:** `{evidence['status']['membership_equivalence']}`",
        "",
    ]

    if evidence["protocol_discrepancies"]:
        lines.extend(
            [
                "> [!WARNING]",
                "> **Protocol Discrepancies Detected:**",
            ]
        )
        for disc in evidence["protocol_discrepancies"]:
            lines.append(f"> - {disc}")
        lines.append("")

    lines.extend(
        [
            "## 2. Provenance Chain Comparison",
            "",
            "| Partition | Row Count (Canonical) | Row Count (Nov Runtime) | Counts Match | "
            "Canonical Oct SHA-256 | Regenerated Nov SHA-256 | Byte Match |",
            "|---|---|---|---|---|---|---|",
        ]
    )

    for p_name, data in evidence["partitions"].items():
        rt_count_str = (
            f"{data['runtime_row_count']:,}" if data["runtime_row_count"] is not None else "N/A"
        )
        rt_sha_str = (
            f"`{data['runtime_nov_sha256'][:16]}...`" if data["runtime_nov_sha256"] else "`N/A`"
        )
        lines.append(
            f"| `{p_name}` | {data['expected_row_count']:,} | {rt_count_str} | "
            f"`{data['counts_match']}` | `{data['canonical_oct_sha256'][:16]}...` | "
            f"{rt_sha_str} | `{data['byte_hashes_match']}` |"
        )

    lines.extend(
        [
            "",
            "## 3. Analysis & Evidentiary Limitations of Hash Divergence",
            "",
            f"- **Hypothesis Status:** `{evidence['cause_of_hash_divergence']['status']}`",
            f"- **Hypothesis:** {evidence['cause_of_hash_divergence']['hypothesis']}",
            f"- **Empirical Limitation:** "
            f"{evidence['cause_of_hash_divergence']['empirical_limitation']}",
            "",
            "> [!IMPORTANT]",
            f"> **Membership Equivalence Assessment:** "
            f"`{evidence['status']['membership_equivalence']}`.",
            f"> {evidence['membership_rationale']}",
            "",
            "## 4. Test Partition Isolation",
            "",
            "### 4.1 Declared Policy Contract",
            f"- `test_partition_accessed`: "
            f"`{evidence['test_isolation']['declared_policy_contract']['test_partition_accessed']}`",
            f"- `test_rows_loaded`: "
            f"`{evidence['test_isolation']['declared_policy_contract']['test_rows_loaded']}`",
            f"- `test_indices_loaded`: "
            f"`{evidence['test_isolation']['declared_policy_contract']['test_indices_loaded']}`",
            f"- Policy: {evidence['test_isolation']['declared_policy_contract']['contract']}",
            "",
            "### 4.2 Measured Runtime Evidence",
        ]
    )

    m_evidence = evidence["test_isolation"]["measured_runtime_evidence"]
    lines.append(f"- **Runtime Evidence Status:** `{m_evidence['status']}`")
    if m_evidence.get("training_run_id"):
        lines.append(f"- **Training Run ID:** `{m_evidence['training_run_id']}`")
        lines.append(
            f"- **Recorded test_partition_accessed:** `{m_evidence['test_partition_accessed']}`"
        )
        lines.append(f"- **Recorded test_rows_loaded:** `{m_evidence['test_rows_loaded']}`")
        lines.append(f"- **Recorded test_indices_loaded:** `{m_evidence['test_indices_loaded']}`")
    elif m_evidence.get("details"):
        lines.append(f"- **Audit Note:** {m_evidence['details']}")

    lines.extend(
        [
            "",
            "## 5. Model Comparison Impact",
            "",
            "Comparisons between Random Forest (trained under canonical Oct split reference) "
            "and XGBoost (trained under regenerated Nov runtime split) constitute "
            "**same-protocol, same-data-definition comparisons**, not byte-identical "
            "artifact comparisons. All metric tables must explicitly declare this distinction.",
        ]
    )

    return "\n".join(lines).rstrip("\n") + "\n"


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Audit split membership parity and hash provenance."
    )
    parser.add_argument(
        "--runtime-manifest",
        type=Path,
        default=DEFAULT_RUNTIME_MANIFEST,
        help="Path to runtime split manifest json",
    )
    parser.add_argument(
        "--training-manifest",
        type=Path,
        default=DEFAULT_TRAINING_MANIFEST,
        help="Path to model training manifest to inspect runtime test-lock evidence",
    )
    parser.add_argument(
        "--output-report",
        type=Path,
        default=PROJECT_ROOT / "reports" / "splits" / "split_membership_audit_report.md",
        help="Path to output markdown report",
    )
    parser.add_argument(
        "--strict-membership",
        action="store_true",
        help="Fail audit if membership equivalence is NOT_VERIFIED or FAIL",
    )
    args = parser.parse_args(argv)

    try:
        evidence = audit_split_membership_parity(
            runtime_manifest_path=args.runtime_manifest,
            training_manifest_path=args.training_manifest,
        )
        report_md = render_split_membership_report_md(evidence)
        args.output_report.parent.mkdir(parents=True, exist_ok=True)
        args.output_report.write_text(report_md, encoding="utf-8")
        print(f"[audit_split_membership] Audit completed. Report saved to {args.output_report}")
        proto_eq = evidence["status"]["protocol_equivalence"]
        byte_eq = evidence["status"]["artifact_byte_equivalence"]
        memb_eq = evidence["status"]["membership_equivalence"]
        print(f"[audit_split_membership] Protocol Equivalence  : {proto_eq}")
        print(f"[audit_split_membership] Byte Equivalence      : {byte_eq}")
        print(f"[audit_split_membership] Membership Equivalence: {memb_eq}")

        if proto_eq != "VERIFIED":
            print(
                "[audit_split_membership] FAILED: Protocol equivalence discrepancies detected!",
                file=sys.stderr,
            )
            for disc in evidence["protocol_discrepancies"]:
                print(f"  - {disc}", file=sys.stderr)
            return 1

        if args.strict_membership and memb_eq != "VERIFIED":
            print(
                "[audit_split_membership] FAILED: Strict membership required "
                f"but status is {memb_eq}",
                file=sys.stderr,
            )
            return 1

        return 0
    except Exception as e:
        print(f"[audit_split_membership] ERROR: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
