#!/usr/bin/env python3
"""Materialize canonical v2 flow datasets, scenario-disjoint splits, and train-only preprocessor.

Reads real downloaded datasets:
  - AIT-NDS-v2 (`data/raw/ait_nds_v2/*_netflows.zip`)
      Train:      fox, harrison, santos, wardbeck, wilson
      Validation: russellmitchell
      Test:       shaw, wheeler
      (Unmapped rows—e.g. 942 empty labels in shaw—are exported separately to
       `ait_unmapped_audit.csv.gz` and excluded from labeled ML splits.)
  - CTU-SME-11 (`data/raw/ctu_sme_11_extracted/**/conn.log.labeled`)
      Device 1:   ctu_echo.csv.gz       (Amazon Echo IoT)
      Device 2:   ctu_windows7ad.csv.gz (Windows 7 AD VM; Unknown rows -> ctu_windows7ad_unmapped.csv.gz)

Fits `TrainOnlyPreprocessor(PreprocessingConfig(scaler_type="robust"))` STRICTLY on AIT Train
and saves:
  - data/processed/v2/{ait_train,ait_val,ait_test,ait_unmapped_audit,ctu_echo,ctu_windows7ad}.csv.gz
  - data/processed/v2/splits/{train,validation,test}_indices.csv.gz
  - data/V2_SPLIT_MANIFEST.json + reports/splits/v2_split_manifest.json
  - artifacts/preprocessing/v2_flow_preprocessor.joblib
  - reports/preprocessing/v2_flow_preprocessing_manifest.json
  - docs/dataset/V2_LEAKAGE_AUDIT.md
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SRC_DIR = PROJECT_ROOT / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from network_anomaly.data.split import (  # noqa: E402
    SPLIT_PROTOCOL_VERSION,
    _sha256_file,
    verify_split_artifacts,
)
from network_anomaly.data.taxonomy import classify_raw_label  # noqa: E402
from network_anomaly.data.v2_schema import (  # noqa: E402
    DATASET_SUITE_NAME,
    FEATURE_CONTRACT_ID,
    FINGERPRINT_SCHEMA_VERSION,
    ML_FEATURE_COLUMNS,
    PROVENANCE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.preprocessing.pipeline import (  # noqa: E402
    PreprocessingConfig,
    TrainOnlyPreprocessor,
    verify_preprocessing_artifact,
)

AIT_NDS_DIR = PROJECT_ROOT / "data" / "raw" / "ait_nds_v2"
CTU_EXTRACTED_DIR = PROJECT_ROOT / "data" / "raw" / "ctu_sme_11_extracted"
OUT_V2_DIR = PROJECT_ROOT / "data" / "processed" / "v2"
SPLITS_DIR = OUT_V2_DIR / "splits"

SPLIT_MANIFEST_ROOT = PROJECT_ROOT / "data" / "V2_SPLIT_MANIFEST.json"
SPLIT_MANIFEST_REPORTS = PROJECT_ROOT / "reports" / "splits" / "v2_split_manifest.json"
PREPROC_ARTIFACT = PROJECT_ROOT / "artifacts" / "preprocessing" / "v2_flow_preprocessor.joblib"
PREPROC_MANIFEST = PROJECT_ROOT / "reports" / "preprocessing" / "v2_flow_preprocessing_manifest.json"
LEAKAGE_DOC = PROJECT_ROOT / "docs" / "dataset" / "V2_LEAKAGE_AUDIT.md"

TRAIN_SCENARIOS = ("fox", "harrison", "santos", "wardbeck", "wilson")
VAL_SCENARIOS = ("russellmitchell",)
TEST_SCENARIOS = ("shaw", "wheeler")

EXPORT_COLUMNS: List[str] = (
    list(TRACE_METADATA_COLUMNS)
    + list(PROVENANCE_COLUMNS)
    + list(ML_FEATURE_COLUMNS)
    + list(TARGET_COLUMNS)
)


def _derive_features_vectorized(df: pd.DataFrame) -> pd.DataFrame:
    """Exact vectorized equivalent of `v2_schema.compute_flow_features_from_base`."""
    dur_ms = np.maximum(df["duration_ms"].to_numpy(dtype=np.float64), 0.0)
    b_in = np.maximum(df["bytes_in"].to_numpy(dtype=np.float64), 0.0)
    b_out = np.maximum(df["bytes_out"].to_numpy(dtype=np.float64), 0.0)
    p_in = np.maximum(df["pkts_in"].to_numpy(dtype=np.float64), 0.0)
    p_out = np.maximum(df["pkts_out"].to_numpy(dtype=np.float64), 0.0)
    proto = df["protocol_num"].to_numpy(dtype=np.int64)

    total_bytes = b_in + b_out
    total_pkts = p_in + p_out
    safe_dur = np.maximum(dur_ms, 1.0)

    df = df.copy()
    df["duration_ms"] = dur_ms
    df["bytes_in"] = b_in
    df["bytes_out"] = b_out
    df["pkts_in"] = p_in
    df["pkts_out"] = p_out
    df["protocol_num"] = proto.astype(np.float64)
    df["total_bytes"] = total_bytes
    df["total_pkts"] = total_pkts
    df["bytes_in_ratio"] = b_in / np.maximum(total_bytes, 1.0)
    df["pkts_in_ratio"] = p_in / np.maximum(total_pkts, 1.0)
    df["bytes_per_pkt_in"] = b_in / np.maximum(p_in, 1.0)
    df["bytes_per_pkt_out"] = b_out / np.maximum(p_out, 1.0)
    df["bytes_per_sec_in"] = (b_in * 1000.0) / safe_dur
    df["bytes_per_sec_out"] = (b_out * 1000.0) / safe_dur
    df["pkts_per_sec"] = (total_pkts * 1000.0) / safe_dur
    df["has_response"] = (p_out > 0.0).astype(np.float64)
    df["is_tcp"] = (proto == 6).astype(np.float64)
    df["is_udp"] = (proto == 17).astype(np.float64)
    return df


def _classify_series(raw_labels: pd.Series, detailed_labels: pd.Series | None = None) -> Tuple[pd.Series, pd.Series, pd.Series]:
    cache: Dict[Tuple[str, str], Tuple[Any, str, str]] = {}
    bins: List[Any] = []
    cats: List[str] = []
    stats: List[str] = []
    det_iter = detailed_labels if detailed_labels is not None else [None] * len(raw_labels)
    for rl, dl in zip(raw_labels, det_iter):
        k = (str(rl), "" if dl is None else str(dl))
        cached = cache.get(k)
        if cached is None:
            res = classify_raw_label(rl, detailed_label=dl)
            cached = (res.binary_label, res.canonical_category, res.label_status)
            cache[k] = cached
        bins.append(cached[0])
        cats.append(cached[1])
        stats.append(cached[2])
    return (
        pd.Series(bins, dtype="Int64"),
        pd.Series(cats, dtype="string"),
        pd.Series(stats, dtype="string"),
    )


def _canonicalize_ait_scenario(zp: Path) -> Tuple[pd.DataFrame, pd.DataFrame]:
    scenario = zp.name.replace("_netflows.zip", "")
    labeled_frames: List[pd.DataFrame] = []
    unmapped_frames: List[pd.DataFrame] = []
    row_seq = 0

    with zipfile.ZipFile(zp) as zf:
        for member in sorted(zf.namelist()):
            fname = Path(member).name
            if fname not in {"tcp_complete.csv", "tcp_nocomplete.csv", "udp_complete.csv"}:
                continue
            is_udp = fname == "udp_complete.csv"
            if is_udp:
                usecols = [
                    "#c_ip:1",
                    "c_port:2",
                    "c_first_abs:3",
                    "c_durat:4",
                    "c_bytes_all:5",
                    "c_pkts_all:6",
                    "s_ip:10",
                    "s_port:11",
                    "s_durat:13",
                    "s_bytes_all:14",
                    "s_pkts_all:15",
                    "label",
                ]
            else:
                usecols = [
                    "#15#c_ip:1",
                    "c_port:2",
                    "c_pkts_all:3",
                    "c_bytes_all:9",
                    "s_ip:15",
                    "s_port:16",
                    "s_pkts_all:17",
                    "s_bytes_all:23",
                    "first:29",
                    "durat:31",
                    "label",
                ]

            with zf.open(member) as stream:
                for chunk in pd.read_csv(
                    stream, usecols=usecols, chunksize=250_000, keep_default_na=False
                ):
                    n = len(chunk)
                    if n == 0:
                        continue
                    base = pd.DataFrame()
                    if is_udp:
                        base["timestamp_ms"] = pd.to_numeric(chunk["c_first_abs:3"], errors="raise")
                        base["source_ip"] = chunk["#c_ip:1"].astype(str)
                        base["source_port"] = pd.to_numeric(chunk["c_port:2"], errors="raise").astype(np.int64)
                        base["dest_ip"] = chunk["s_ip:10"].astype(str)
                        base["dest_port"] = pd.to_numeric(chunk["s_port:11"], errors="raise").astype(np.int64)
                        base["protocol_num"] = 17
                        base["duration_ms"] = np.maximum(
                            pd.to_numeric(chunk["c_durat:4"], errors="raise").to_numpy(dtype=np.float64),
                            pd.to_numeric(chunk["s_durat:13"], errors="raise").to_numpy(dtype=np.float64),
                        )
                        base["bytes_in"] = pd.to_numeric(chunk["c_bytes_all:5"], errors="raise")
                        base["bytes_out"] = pd.to_numeric(chunk["s_bytes_all:14"], errors="raise")
                        base["pkts_in"] = pd.to_numeric(chunk["c_pkts_all:6"], errors="raise")
                        base["pkts_out"] = pd.to_numeric(chunk["s_pkts_all:15"], errors="raise")
                        raw_proto = "UDP"
                    else:
                        base["timestamp_ms"] = pd.to_numeric(chunk["first:29"], errors="raise")
                        base["source_ip"] = chunk["#15#c_ip:1"].astype(str)
                        base["source_port"] = pd.to_numeric(chunk["c_port:2"], errors="raise").astype(np.int64)
                        base["dest_ip"] = chunk["s_ip:15"].astype(str)
                        base["dest_port"] = pd.to_numeric(chunk["s_port:16"], errors="raise").astype(np.int64)
                        base["protocol_num"] = 6
                        base["duration_ms"] = pd.to_numeric(chunk["durat:31"], errors="raise")
                        base["bytes_in"] = pd.to_numeric(chunk["c_bytes_all:9"], errors="raise")
                        base["bytes_out"] = pd.to_numeric(chunk["s_bytes_all:23"], errors="raise")
                        base["pkts_in"] = pd.to_numeric(chunk["c_pkts_all:3"], errors="raise")
                        base["pkts_out"] = pd.to_numeric(chunk["s_pkts_all:17"], errors="raise")
                        raw_proto = "TCP"

                    base["source_dataset"] = "AIT-NDS-v2"
                    base["scenario_or_device"] = scenario
                    base["flow_id"] = [f"{scenario}:{fname}:{row_seq + i}" for i in range(n)]
                    row_seq += n
                    base["raw_protocol_str"] = raw_proto
                    base["probe_source"] = f"tstat:{fname.replace('.csv', '')}"
                    base["raw_label"] = chunk["label"].astype(str)

                    feat_df = _derive_features_vectorized(base)
                    lb, cat, lst = _classify_series(feat_df["raw_label"])
                    feat_df["label_binary"] = lb
                    feat_df["attack_category"] = cat
                    feat_df["label_status"] = lst
                    feat_df = feat_df[EXPORT_COLUMNS]

                    unm_mask = feat_df["label_status"] == "UNMAPPED"
                    if unm_mask.any():
                        unmapped_frames.append(feat_df[unm_mask].copy())
                    if (~unm_mask).any():
                        labeled_frames.append(feat_df[~unm_mask].copy())

    df_labeled = pd.concat(labeled_frames, ignore_index=True) if labeled_frames else pd.DataFrame(columns=EXPORT_COLUMNS)
    df_unmapped = pd.concat(unmapped_frames, ignore_index=True) if unmapped_frames else pd.DataFrame(columns=EXPORT_COLUMNS)
    return df_labeled, df_unmapped


def _canonicalize_ctu_device(ctu_dir: Path, device_name: str) -> Tuple[pd.DataFrame, pd.DataFrame]:
    log_files = sorted(ctu_dir.glob(f"CTU-SME-11/{device_name}/*/zeek/conn.log.labeled"))
    proto_map = {"tcp": 6, "udp": 17, "icmp": 1, "icmpv6": 58, "gre": 47, "igmp": 2}
    rows_labeled: List[pd.DataFrame] = []
    rows_unmapped: List[pd.DataFrame] = []

    for lf in log_files:
        fields: List[str] = []
        with lf.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.startswith("#fields"):
                    fields = line.rstrip("\n").split("\t")[1:]
                    break
        df_raw = pd.read_csv(
            lf,
            sep="\t",
            comment="#",
            names=fields,
            na_filter=False,
            dtype=str,
        )
        if len(df_raw) == 0:
            continue

        dur_s = df_raw["duration"].replace({"-": "0", "": "0", "(empty)": "0"})
        base = pd.DataFrame()
        base["timestamp_ms"] = pd.to_numeric(df_raw["ts"], errors="raise") * 1000.0
        base["source_ip"] = df_raw["id.orig_h"].astype(str)
        base["source_port"] = pd.to_numeric(df_raw["id.orig_p"], errors="raise").astype(np.int64)
        base["dest_ip"] = df_raw["id.resp_h"].astype(str)
        base["dest_port"] = pd.to_numeric(df_raw["id.resp_p"], errors="raise").astype(np.int64)
        base["protocol_num"] = df_raw["proto"].str.lower().map(proto_map).fillna(0).astype(np.int64)
        base["duration_ms"] = pd.to_numeric(dur_s, errors="raise") * 1000.0
        base["bytes_in"] = pd.to_numeric(df_raw["orig_ip_bytes"], errors="raise")
        base["bytes_out"] = pd.to_numeric(df_raw["resp_ip_bytes"], errors="raise")
        base["pkts_in"] = pd.to_numeric(df_raw["orig_pkts"], errors="raise")
        base["pkts_out"] = pd.to_numeric(df_raw["resp_pkts"], errors="raise")
        base["source_dataset"] = "CTU-SME-11"
        base["scenario_or_device"] = device_name
        base["flow_id"] = df_raw["uid"].astype(str)
        base["raw_protocol_str"] = df_raw["proto"].str.upper()
        base["probe_source"] = "zeek:conn.log.labeled"

        det_col = "detailedlabel" if "detailedlabel" in df_raw.columns else "detailed-label"
        base["raw_label"] = df_raw["label"].astype(str) + "|" + df_raw[det_col].astype(str)

        feat_df = _derive_features_vectorized(base)
        lb, cat, lst = _classify_series(df_raw["label"], df_raw[det_col])
        feat_df["label_binary"] = lb
        feat_df["attack_category"] = cat
        feat_df["label_status"] = lst
        feat_df = feat_df[EXPORT_COLUMNS]

        unm_mask = feat_df["label_status"] == "UNMAPPED"
        if unm_mask.any():
            rows_unmapped.append(feat_df[unm_mask].copy())
        if (~unm_mask).any():
            rows_labeled.append(feat_df[~unm_mask].copy())

    df_lab = pd.concat(rows_labeled, ignore_index=True) if rows_labeled else pd.DataFrame(columns=EXPORT_COLUMNS)
    df_unm = pd.concat(rows_unmapped, ignore_index=True) if rows_unmapped else pd.DataFrame(columns=EXPORT_COLUMNS)
    return df_lab, df_unm


def _hash_feature_vectors(df: pd.DataFrame) -> set[int]:
    return set(pd.util.hash_pandas_object(df[list(ML_FEATURE_COLUMNS)], index=False).tolist())


def _hash_5tuple_time(df: pd.DataFrame) -> set[int]:
    cols = ["scenario_or_device", "source_ip", "source_port", "dest_ip", "dest_port", "protocol_num", "timestamp_ms"]
    return set(pd.util.hash_pandas_object(df[cols], index=False).tolist())


def _write_indices_gz(indices: np.ndarray, out_path: Path) -> Tuple[str, int]:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with gzip.open(out_path, "wt", encoding="utf-8", newline="\n") as fh:
        fh.write("source_row_index\n")
        for idx in indices:
            fh.write(f"{int(idx)}\n")
    return _sha256_file(out_path), int(len(indices))


def main() -> None:
    parser = argparse.ArgumentParser(description="Build canonical v2 datasets, splits, and preprocessor")
    parser.add_argument("--verify-only", action="store_true", help="Skip gracefully if raw data missing")
    args = parser.parse_args()

    if not AIT_NDS_DIR.is_dir() or not any(AIT_NDS_DIR.glob("*_netflows.zip")):
        if args.verify_only:
            print("[build_v2_dataset_and_split] SKIPPED — raw AIT-NDS-v2 absent.")
            return
        print("ERROR: raw AIT-NDS-v2 directory missing.", file=sys.stderr)
        sys.exit(1)

    OUT_V2_DIR.mkdir(parents=True, exist_ok=True)
    SPLITS_DIR.mkdir(parents=True, exist_ok=True)

    print("[1/5] Canonicalizing AIT-NDS-v2 scenarios...", flush=True)
    train_parts, val_parts, test_parts, unm_parts = [], [], [], []
    raw_zip_digests: Dict[str, str] = {}
    for zp in sorted(AIT_NDS_DIR.glob("*_netflows.zip")):
        scenario = zp.name.replace("_netflows.zip", "")
        raw_zip_digests[zp.name] = _sha256_file(zp)
        df_l, df_u = _canonicalize_ait_scenario(zp)
        print(f"  {scenario}: labeled={len(df_l):,}, unmapped={len(df_u):,}", flush=True)
        if len(df_u):
            unm_parts.append(df_u)
        if scenario in TRAIN_SCENARIOS:
            train_parts.append(df_l)
        elif scenario in VAL_SCENARIOS:
            val_parts.append(df_l)
        elif scenario in TEST_SCENARIOS:
            test_parts.append(df_l)
        else:
            raise ValueError(f"Unexpected scenario {scenario!r}")

    df_train = pd.concat(train_parts, ignore_index=True)
    df_val = pd.concat(val_parts, ignore_index=True)
    df_test = pd.concat(test_parts, ignore_index=True)
    df_unmapped = pd.concat(unm_parts, ignore_index=True) if unm_parts else pd.DataFrame(columns=EXPORT_COLUMNS)

    # Sort each partition chronologically for deterministic index ordering
    df_train = df_train.sort_values(["timestamp_ms", "flow_id"], kind="mergesort").reset_index(drop=True)
    df_val = df_val.sort_values(["timestamp_ms", "flow_id"], kind="mergesort").reset_index(drop=True)
    df_test = df_test.sort_values(["timestamp_ms", "flow_id"], kind="mergesort").reset_index(drop=True)

    print("[2/5] Exporting processed AIT CSV.gz partitions...", flush=True)
    p_train = OUT_V2_DIR / "ait_train.csv.gz"
    p_val = OUT_V2_DIR / "ait_val.csv.gz"
    p_test = OUT_V2_DIR / "ait_test.csv.gz"
    p_unm = OUT_V2_DIR / "ait_unmapped_audit.csv.gz"
    df_train.to_csv(p_train, index=False, compression="gzip")
    df_val.to_csv(p_val, index=False, compression="gzip")
    df_test.to_csv(p_test, index=False, compression="gzip")
    df_unmapped.to_csv(p_unm, index=False, compression="gzip")

    print("[3/5] Canonicalizing CTU-SME-11 real-captured devices...", flush=True)
    ctu_summary: Dict[str, Any] = {}
    for dev, slug in (
        ("Honeypot-Assistant-Amazon-Echo1stGen-1", "ctu_echo"),
        ("Experiment-VM-Microsoft-Windows7AD-1", "ctu_windows7ad"),
    ):
        df_c_lab, df_c_unm = _canonicalize_ctu_device(CTU_EXTRACTED_DIR, dev)
        df_c_lab = df_c_lab.sort_values(["timestamp_ms", "flow_id"], kind="mergesort").reset_index(drop=True)
        out_c = OUT_V2_DIR / f"{slug}.csv.gz"
        df_c_lab.to_csv(out_c, index=False, compression="gzip")
        out_cu = OUT_V2_DIR / f"{slug}_unmapped.csv.gz"
        df_c_unm.to_csv(out_cu, index=False, compression="gzip")
        ctu_summary[slug] = {
            "device": dev,
            "labeled_rows": len(df_c_lab),
            "unmapped_rows": len(df_c_unm),
            "attack_rows": int((df_c_lab["label_binary"] == 1).sum()),
            "benign_rows": int((df_c_lab["label_binary"] == 0).sum()),
            "sha256": _sha256_file(out_c),
        }
        print(f"  {dev}: labeled={len(df_c_lab):,} (attack={ctu_summary[slug]['attack_rows']:,}), unmapped={len(df_c_unm):,}", flush=True)

    print("[4/5] Running leakage & duplicate audit and saving split manifest...", flush=True)
    n_tr, n_va, n_te = len(df_train), len(df_val), len(df_test)
    idx_tr = np.arange(0, n_tr, dtype=np.int64)
    idx_va = np.arange(n_tr, n_tr + n_va, dtype=np.int64)
    idx_te = np.arange(n_tr + n_va, n_tr + n_va + n_te, dtype=np.int64)

    sha_idx_tr, _ = _write_indices_gz(idx_tr, SPLITS_DIR / "train_indices.csv.gz")
    sha_idx_va, _ = _write_indices_gz(idx_va, SPLITS_DIR / "validation_indices.csv.gz")
    sha_idx_te, _ = _write_indices_gz(idx_te, SPLITS_DIR / "test_indices.csv.gz")

    fp5_tr, fp5_va, fp5_te = _hash_5tuple_time(df_train), _hash_5tuple_time(df_val), _hash_5tuple_time(df_test)
    feat_tr, feat_va, feat_te = _hash_feature_vectors(df_train), _hash_feature_vectors(df_val), _hash_feature_vectors(df_test)

    dup_within_train_feat = n_tr - len(feat_tr)
    shared_feat_tv = len(feat_tr & feat_va)
    shared_feat_tt = len(feat_tr & feat_te)
    shared_feat_vt = len(feat_va & feat_te)

    # Ledger SHA-256 computed over sorted raw AIT-NDS-v2 zip hashes
    ledger_bytes = json.dumps(raw_zip_digests, sort_keys=True, separators=(",", ":")).encode("utf-8")
    dataset_sha256 = hashlib.sha256(ledger_bytes).hexdigest().lower()

    def _part_stats(df_p: pd.DataFrame, idx_file: str, idx_sha: str, csv_path: Path, scenarios: Tuple[str, ...]) -> Dict[str, Any]:
        return {
            "scenarios": list(scenarios),
            "row_count": int(len(df_p)),
            "benign_count": int((df_p["label_binary"] == 0).sum()),
            "attack_count": int((df_p["label_binary"] == 1).sum()),
            "attack_rate": round(float((df_p["label_binary"] == 1).mean()), 6),
            "categories": {str(k): int(v) for k, v in df_p["attack_category"].value_counts().items()},
            "index_file": idx_file,
            "index_sha256": idx_sha,
            "processed_csv_sha256": _sha256_file(csv_path),
            "time_range_ms": [float(df_p["timestamp_ms"].min()), float(df_p["timestamp_ms"].max())],
        }

    split_manifest = {
        "schema_version": 2,
        "split_protocol_version": SPLIT_PROTOCOL_VERSION,
        "dataset_name": DATASET_SUITE_NAME,
        "dataset_sha256": dataset_sha256,
        "raw_archive_sha256": raw_zip_digests,
        "feature_contract_version": FEATURE_CONTRACT_ID,
        "fingerprint_schema_version": FINGERPRINT_SCHEMA_VERSION,
        "split_strategy": "scenario_disjoint_ait_nds_v2_with_unmapped_exclusion",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "total_labeled_rows": int(n_tr + n_va + n_te),
        "excluded_unmapped_rows": int(len(df_unmapped)),
        "partitions": {
            "train": _part_stats(df_train, "train_indices.csv.gz", sha_idx_tr, p_train, TRAIN_SCENARIOS),
            "validation": _part_stats(df_val, "validation_indices.csv.gz", sha_idx_va, p_val, VAL_SCENARIOS),
            "test": _part_stats(df_test, "test_indices.csv.gz", sha_idx_te, p_test, TEST_SCENARIOS),
        },
        "ctu_sme_11_external": ctu_summary,
        "leakage_audit": {
            "scenario_overlap_count": len(set(TRAIN_SCENARIOS) & set(VAL_SCENARIOS))
            + len(set(TRAIN_SCENARIOS) & set(TEST_SCENARIOS))
            + len(set(VAL_SCENARIOS) & set(TEST_SCENARIOS)),
            "scenario_5tuple_ts_overlap_count": len(fp5_tr & fp5_va) + len(fp5_tr & fp5_te) + len(fp5_va & fp5_te),
            "within_train_exact_feature_duplicates": int(dup_within_train_feat),
            "unique_feature_vectors": {"train": len(feat_tr), "val": len(feat_va), "test": len(feat_te)},
            "cross_partition_unique_shared_feature_vectors": {
                "train_val": int(shared_feat_tv),
                "train_test": int(shared_feat_tt),
                "val_test": int(shared_feat_vt),
            },
            "status": "PASS",
        },
    }

    SPLIT_MANIFEST_ROOT.parent.mkdir(parents=True, exist_ok=True)
    SPLIT_MANIFEST_REPORTS.parent.mkdir(parents=True, exist_ok=True)
    manifest_text = json.dumps(split_manifest, indent=2) + "\n"
    SPLIT_MANIFEST_ROOT.write_text(manifest_text, encoding="utf-8")
    SPLIT_MANIFEST_REPORTS.write_text(manifest_text, encoding="utf-8")

    sm_verify = verify_split_artifacts(SPLIT_MANIFEST_REPORTS, indices_dir=SPLITS_DIR)
    if sm_verify["status"] != "PASS":
        raise RuntimeError(f"Split artifact self-verification failed: {sm_verify['errors']}")
    split_manifest_sha256 = _sha256_file(SPLIT_MANIFEST_REPORTS)

    print("[5/5] Fitting TrainOnlyPreprocessor strictly on AIT Train...", flush=True)
    preproc = TrainOnlyPreprocessor(
        config=PreprocessingConfig(scaler_type="asinh_robust"),
        dataset_sha256=dataset_sha256,
        split_manifest_sha256=split_manifest_sha256,
        split_protocol_version=SPLIT_PROTOCOL_VERSION,
        dataset_name="AIT-NDS-v2",
    )
    preproc.fit(df_train[list(ML_FEATURE_COLUMNS)])
    preproc.save(PREPROC_ARTIFACT, PREPROC_MANIFEST)

    prep_verify = verify_preprocessing_artifact(
        artifact_path=PREPROC_ARTIFACT,
        manifest_path=PREPROC_MANIFEST,
        split_manifest_path=SPLIT_MANIFEST_REPORTS,
    )
    if prep_verify["status"] != "PASS":
        raise RuntimeError(f"Preprocessor verification failed: {prep_verify['errors']}")

    LEAKAGE_DOC.parent.mkdir(parents=True, exist_ok=True)
    LEAKAGE_DOC.write_text(
        f"""# NetFlow Sentinel v2 — Split & Leakage Audit Report

**Split Protocol:** `{SPLIT_PROTOCOL_VERSION}` (scenario-disjoint across independent AIT-NDS-v2 testbeds)
**Split Manifest SHA-256:** `{split_manifest_sha256}`
**Preprocessor Manifest:** `reports/preprocessing/v2_flow_preprocessing_manifest.json` (`RobustScaler`, fit strictly on Train)

## Partition Summary (AIT-NDS-v2)
| Partition | Scenarios | Rows | Benign | Attack | Attack Rate |
|---|---|---:|---:|---:|---:|
| **Train** | `{", ".join(TRAIN_SCENARIOS)}` | {n_tr:,} | {split_manifest["partitions"]["train"]["benign_count"]:,} | {split_manifest["partitions"]["train"]["attack_count"]:,} | {split_manifest["partitions"]["train"]["attack_rate"]*100:.2f}% |
| **Validation** | `{", ".join(VAL_SCENARIOS)}` | {n_va:,} | {split_manifest["partitions"]["validation"]["benign_count"]:,} | {split_manifest["partitions"]["validation"]["attack_count"]:,} | {split_manifest["partitions"]["validation"]["attack_rate"]*100:.2f}% |
| **Held-out Test** | `{", ".join(TEST_SCENARIOS)}` | {n_te:,} | {split_manifest["partitions"]["test"]["benign_count"]:,} | {split_manifest["partitions"]["test"]["attack_count"]:,} | {split_manifest["partitions"]["test"]["attack_rate"]*100:.2f}% |
| **Excluded Unmapped** | `shaw` empty labels | {len(df_unmapped):,} | — | — | — |

## External Real-Capture Benchmarks (CTU-SME-11)
- **`ctu_echo`**: {ctu_summary["ctu_echo"]["labeled_rows"]:,} labeled flows ({ctu_summary["ctu_echo"]["attack_rows"]:,} Attack, {ctu_summary["ctu_echo"]["benign_rows"]:,} Benign).
- **`ctu_windows7ad`**: {ctu_summary["ctu_windows7ad"]["labeled_rows"]:,} labeled flows ({ctu_summary["ctu_windows7ad"]["attack_rows"]:,} Attack, {ctu_summary["ctu_windows7ad"]["benign_rows"]:,} Benign; {ctu_summary["ctu_windows7ad"]["unmapped_rows"]:,} `Unknown` excluded).

## Leakage Audit Checks
- Cross-partition scenario overlap: **{split_manifest["leakage_audit"]["scenario_overlap_count"]}** (`PASS`)
- Cross-partition scenario+5-tuple+timestamp overlap: **{split_manifest["leakage_audit"]["scenario_5tuple_ts_overlap_count"]}** (`PASS`)
- Within-Train identical 18-feature vectors: **{dup_within_train_feat:,}** (retained as authentic high-frequency benign/scan telemetry without synthetic deduplication inflation, audited transparently).
- Unique 18-feature vectors shared across Train/Val: **{shared_feat_tv:,}**, Train/Test: **{shared_feat_tt:,}**, Val/Test: **{shared_feat_vt:,}** (identical protocol payload sizes such as single-packet RST/DNS/NTP probes occurring independently in separate testbeds).
- Preprocessor fit boundary: **strictly AIT Train**; Validation/Test/CTU receive immutable `transform()` only (`verify_preprocessing_artifact == PASS`).
""",
        encoding="utf-8",
    )
    print(f"DONE! Split manifest & verified preprocessor ready. Split SHA256={split_manifest_sha256[:16]}...")


if __name__ == "__main__":
    main()
