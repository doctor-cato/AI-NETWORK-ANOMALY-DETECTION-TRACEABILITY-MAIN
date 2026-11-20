#!/usr/bin/env python3
"""Read-only zero-shot cross-source evaluation on UWF-ZeekData24 (CC BY 4.0, evaluation_only=true).

Does NOT retrain or calibrate thresholds on any UWF-ZeekData24 data.
Keeps UGR'16 status unchanged as BLOCKED in EXTERNAL_DATASETS_PROVENANCE.json.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
import time
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SRC_DIR = PROJECT_ROOT / "src"
_SCRIPTS_DIR = Path(__file__).resolve().parent
for p in (str(_SRC_DIR), str(_SCRIPTS_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

from _v2_train_common import (  # noqa: E402
    PREPROC_ARTIFACT_PATH,
    PREPROC_MANIFEST_PATH,
    SPLIT_MANIFEST_PATH,
    build_environment_block,
)

from network_anomaly.data.v2_schema import ML_FEATURE_COLUMNS  # noqa: E402
from network_anomaly.evaluation.test_evaluation import evaluate_v2_partition  # noqa: E402
from network_anomaly.ingestion.adapters.uwf_zeek import parse_uwf_zeek_row  # noqa: E402
from network_anomaly.models.registry import ModelRegistry  # noqa: E402
from network_anomaly.preprocessing.pipeline import TrainOnlyPreprocessor  # noqa: E402

RAW_UWF_DIR = PROJECT_ROOT / "data" / "raw" / "uwf_zeekdata24"
UWF_MANIFEST_PATH = PROJECT_ROOT / "data" / "UWF_ZEEKDATA24_MANIFEST.json"
OUT_JSON = PROJECT_ROOT / "reports" / "experiments" / "ml" / "uwf_zeekdata24_cross_source_eval.json"
OUT_MD = PROJECT_ROOT / "docs" / "experiments" / "UWF_ZEEK24_CROSS_SOURCE_EVAL.md"

UWF24_FILES: List[Tuple[str, str]] = [
    (
        "Benign",
        "https://datasets.uwf.edu/data/UWF-ZeekData24/csv/Benign/part-00000-b039213f-1208-4f1b-b71d-5e8e3a4a2939-c000.csv",
    ),
    (
        "Credential_Access",
        "https://datasets.uwf.edu/data/UWF-ZeekData24/csv/Credential_Access/part-00000-912fdc44-5727-4d42-8fd6-a0e206ba29f8-c000.csv",
    ),
    (
        "Defense_Evasion",
        "https://datasets.uwf.edu/data/UWF-ZeekData24/csv/Defense_Evasion/part-00000-de4985c7-284a-4b6e-b507-e69a2d172582-c000.csv",
    ),
    (
        "Exfiltration",
        "https://datasets.uwf.edu/data/UWF-ZeekData24/csv/Exfiltration/part-00000-6a530c25-0f6b-46a1-ba16-c6b658ef75e8-c000.csv",
    ),
    (
        "Initial_Access",
        "https://datasets.uwf.edu/data/UWF-ZeekData24/csv/Initial_Access/part-00000-9a37b839-429e-444b-82a5-a6d5e69dad7e-c000.csv",
    ),
    (
        "Persistence",
        "https://datasets.uwf.edu/data/UWF-ZeekData24/csv/Persistence/part-00000-fb5a764a-e65e-4e10-b6fb-1a189589d5e0-c000.csv",
    ),
    (
        "Privilege_Escalation",
        "https://datasets.uwf.edu/data/UWF-ZeekData24/csv/Privilege_Escalation/part-00000-d8fcf83a-aed1-4cb1-babf-581208088293-c000.csv",
    ),
    (
        "Reconnaissance",
        "https://datasets.uwf.edu/data/UWF-ZeekData24/csv/Reconnaissance/part-00000-49ed1cc6-3205-4c76-8e28-4da9abf78363-c000.csv",
    ),
]


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while chunk := fh.read(1024 * 1024):
            h.update(chunk)
    return h.hexdigest().lower()


def download_uwf24_if_needed(*, allow_download: bool) -> List[Dict[str, Any]]:
    import shutil
    import subprocess

    RAW_UWF_DIR.mkdir(parents=True, exist_ok=True)
    curl_bin = shutil.which("curl.exe") or shutil.which("curl")
    records: List[Dict[str, Any]] = []
    for folder, url in UWF24_FILES:
        dest = RAW_UWF_DIR / f"{folder}.csv"
        if not dest.is_file():
            if not allow_download:
                raise FileNotFoundError(f"Missing UWF-ZeekData24 CSV: {dest}")
            print(f"[download] Fetching UWF-ZeekData24/{folder}...", flush=True)
            tmp_dest = dest.with_suffix(".csv.part")
            if tmp_dest.exists():
                tmp_dest.unlink()
            if curl_bin:
                proc = subprocess.run(
                    [
                        curl_bin,
                        "--http1.1",
                        "--fail",
                        "--location",
                        "--silent",
                        "--show-error",
                        "--connect-timeout",
                        "20",
                        "--max-time",
                        "300",
                        "--output",
                        str(tmp_dest),
                        url,
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if proc.returncode != 0:
                    raise RuntimeError(
                        f"curl failed for {url} (rc={proc.returncode}): {proc.stderr.strip()}"
                    )
            else:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=60) as resp, tmp_dest.open("wb") as out_fh:
                    shutil.copyfileobj(resp, out_fh, length=256 * 1024)
            tmp_dest.replace(dest)
            print(f"[download] Saved {dest.name} ({dest.stat().st_size:,} bytes)", flush=True)
        records.append(
            {
                "subset": folder,
                "local_relpath": str(dest.relative_to(PROJECT_ROOT)).replace("\\", "/"),
                "source_url": url,
                "size_bytes": dest.stat().st_size,
                "sha256": _sha256_file(dest),
            }
        )
    return records


def _score_partition(
    registry: ModelRegistry,
    preproc: TrainOnlyPreprocessor,
    df_sub: pd.DataFrame,
) -> Dict[str, Any]:
    X_raw = df_sub[list(ML_FEATURE_COLUMNS)].copy()
    X_scaled = preproc.transform(X_raw, partition_name="external_uwf_zeekdata24")
    X_np = X_scaled.to_numpy(dtype=np.float64)
    y = df_sub["label_binary"].to_numpy(dtype=np.int64)
    cats = df_sub["attack_category"].to_numpy(dtype=object)
    summary = registry.summary()
    thresholds_by_key = {m["model_key"]: m["threshold"] for m in summary["models"]}
    out: Dict[str, Any] = {}
    for model_key in ("random_forest", "xgboost", "isolation_forest", "autoencoder"):
        th = float(thresholds_by_key[model_key])
        t0 = time.perf_counter()
        scores, _ = registry.score_batch(model_key, X_np)
        dt = time.perf_counter() - t0
        out[model_key] = evaluate_v2_partition(
            y_true=y,
            scores=scores,
            threshold=th,
            attack_categories=cats,
            latency_seconds=dt,
        )
    return out


def run_evaluation(*, allow_download: bool, verify_only: bool) -> int:
    if verify_only:
        missing = [
            RAW_UWF_DIR / f"{folder}.csv"
            for folder, _ in UWF24_FILES
            if not (RAW_UWF_DIR / f"{folder}.csv").is_file()
        ]
        if missing:
            print(
                f"[uwf_zeek24_eval] SKIPPED — raw UWF-ZeekData24 files absent ({len(missing)} missing)"
            )
            return 0

    file_records = download_uwf24_if_needed(allow_download=allow_download)
    manifest = {
        "schema_version": 2,
        "dataset": "UWF-ZeekData24",
        "synthetic": False,
        "evaluation_only": True,
        "role": "Supplemental Cyber Range Zeek L4-payload cross-source evaluation (does NOT replace UGR'16 ISP benchmark)",
        "official_source": {
            "publisher": "University of West Florida (Cyber Analytics Research Group)",
            "portal_url": "https://datasets.uwf.edu/",
            "csv_base_url": "https://datasets.uwf.edu/data/UWF-ZeekData24/csv/",
            "license_title": "Creative Commons Attribution 4.0 International (CC BY 4.0)",
            "license_url": "https://creativecommons.org/licenses/by/4.0/",
        },
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "files": file_records,
    }
    UWF_MANIFEST_PATH.write_text(
        json.dumps(manifest, indent=2) + "\n", encoding="utf-8", newline="\n"
    )

    preproc = TrainOnlyPreprocessor.load_verified(
        artifact_path=PREPROC_ARTIFACT_PATH,
        manifest_path=PREPROC_MANIFEST_PATH,
        split_manifest_path=SPLIT_MANIFEST_PATH,
    )
    registry = ModelRegistry()

    parsed_rows: List[Dict[str, Any]] = []
    strict_rows: List[Dict[str, Any]] = []
    parse_errors = 0
    unmapped_rows = 0
    unset_dur_count = 0
    unset_bytes_count = 0
    tactic_counts: Counter[str] = Counter()
    proto_counts: Counter[int] = Counter()
    syn_probe_bytes: List[float] = []

    for rec in file_records:
        subset = rec["subset"]
        csv_path = PROJECT_ROOT / rec["local_relpath"]
        with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
            reader = csv.DictReader(fh)
            for raw in reader:
                try:
                    row = parse_uwf_zeek_row(raw, allow_zeek_unset_zero=True, subset_name=subset)
                except Exception:
                    parse_errors += 1
                    continue
                if row["label_binary"] is None:
                    unmapped_rows += 1
                    continue
                if row["had_unset_duration"]:
                    unset_dur_count += 1
                if row["had_unset_l4_bytes"]:
                    unset_bytes_count += 1
                tactic_counts[str(row["attack_category"])] += 1
                proto_counts[int(row["protocol_num"])] += 1
                if (
                    int(row["protocol_num"]) == 6
                    and float(row["pkts_in"]) >= 1.0
                    and float(row["pkts_out"]) == 0.0
                ):
                    syn_probe_bytes.append(float(row["bytes_in"]))
                parsed_rows.append(row)
                if not row["had_unset_duration"] and not row["had_unset_l4_bytes"]:
                    strict_rows.append(row)

    df_all = pd.DataFrame(parsed_rows)
    df_strict = pd.DataFrame(strict_rows)

    syn_median = float(np.median(syn_probe_bytes)) if syn_probe_bytes else None
    syn_zero_rate = float(np.mean(np.asarray(syn_probe_bytes) == 0.0)) if syn_probe_bytes else None

    eval_all = _score_partition(registry, preproc, df_all)
    eval_strict = _score_partition(registry, preproc, df_strict)

    report = {
        "schema_version": "uwf-zeek24-cross-source-eval-v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": build_environment_block(),
        "dataset": "UWF-ZeekData24",
        "license": "CC BY 4.0",
        "evaluation_only": True,
        "ugr16_status": "BLOCKED",
        "row_accounting": {
            "total_labeled_with_zeek_unset_zero": int(len(df_all)),
            "strict_complete_rows": int(len(df_strict)),
            "zeek_unset_duration_rows": int(unset_dur_count),
            "zeek_unset_l4_bytes_rows": int(unset_bytes_count),
            "unmapped_rows_excluded": int(unmapped_rows),
            "parse_errors": int(parse_errors),
            "categories": dict(tactic_counts),
            "protocol_counts": {str(k): int(v) for k, v in proto_counts.items()},
        },
        "syn_probe_l4_audit": {
            "tcp_unanswered_probe_count": int(len(syn_probe_bytes)),
            "median_bytes_in": syn_median,
            "zero_bytes_in_rate": round(syn_zero_rate, 6) if syn_zero_rate is not None else None,
            "byte_semantics": (
                "L4_PAYLOAD_COMPATIBLE_WITH_AIT"
                if (syn_median is not None and syn_median == 0.0)
                else "CHECK_REQUIRED"
            ),
        },
        "zero_shot_eval_full_zeek_unset_zero": eval_all,
        "zero_shot_eval_strict_complete_only": eval_strict,
    }
    OUT_JSON.parent.mkdir(parents=True, exist_ok=True)
    OUT_JSON.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")

    lines = [
        "# UWF-ZeekData24 Supplemental Zero-Shot Evaluation (CC BY 4.0)",
        "",
        "- **Role:** Independent Cyber Range Zeek L4-payload cross-source check (`evaluation_only = true`). Does **not** replace `UGR'16` ISP benchmark (`BLOCKED`).",
        f"- **Rows:** Total labeled (Zeek unset `''`→`0.0`): **{len(df_all):,}** | Strict complete only (no unset fields): **{len(df_strict):,}** | Unmapped excluded: **{unmapped_rows:,}**.",
        f"- **SYN-only Probe Check (L4 vs L3):** `{len(syn_probe_bytes):,}` unanswered TCP probes, `median(bytes_in) = {syn_median}`, `zero_rate = {syn_zero_rate:.4f}` → `{report['syn_probe_l4_audit']['byte_semantics']}`.",
        "",
        "## Zero-Shot Results on Full Labeled Set (`AIT-Train E0` frozen models)",
        "",
        "| Model | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for mk in ("random_forest", "xgboost", "isolation_forest", "autoencoder"):
        m = eval_all[mk]
        lines.append(
            f"| `{mk}` | {m['precision']:.4f} | {m['recall']:.4f} | **{m['f1']:.4f}** | "
            f"{m['false_positive_rate']:.4f} | {m['roc_auc']:.4f} | {m['pr_auc']:.4f} |"
        )
    lines.extend(
        [
            "",
            "## Zero-Shot Results on Strict Complete Subset Only",
            "",
            "| Model | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC |",
            "|---|---:|---:|---:|---:|---:|---:|",
        ]
    )
    for mk in ("random_forest", "xgboost", "isolation_forest", "autoencoder"):
        m = eval_strict[mk]
        lines.append(
            f"| `{mk}` | {m['precision']:.4f} | {m['recall']:.4f} | **{m['f1']:.4f}** | "
            f"{m['false_positive_rate']:.4f} | {m['roc_auc']:.4f} | {m['pr_auc']:.4f} |"
        )
    OUT_MD.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    print(f"[+] UWF-ZeekData24 evaluation saved to {OUT_JSON} and {OUT_MD}")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(description="Run read-only UWF-ZeekData24 evaluation")
    parser.add_argument(
        "--download", action="store_true", help="Download UWF-ZeekData24 CSVs if missing"
    )
    parser.add_argument(
        "--verify-only", action="store_true", help="Exit 0 SKIPPED if raw files absent"
    )
    args = parser.parse_args()
    sys.exit(run_evaluation(allow_download=args.download, verify_only=args.verify_only))


if __name__ == "__main__":
    main()
