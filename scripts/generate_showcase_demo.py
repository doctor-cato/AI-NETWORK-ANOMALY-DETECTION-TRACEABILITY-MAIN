#!/usr/bin/env python3
"""Generate a realistic, multi-tier showcase demo CSV dataset from real v2 flows.

Samples 100% real flows (CC BY 4.0) from:
  - data/processed/v2/ait_test.csv.gz (AIT-NDS-v2)
  - data/processed/v2/ctu_windows7ad.csv.gz (CTU-SME-11)

Outputs (gitignored):
  - data/demo/showcase_demo_flows.csv
  - data/demo/showcase_demo_labels.csv

Does NOT modify data/demo/demo_flows.csv, demo_labels.csv, demo_manifest.json,
or any frozen E0 model artifact.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_LOCAL_SOURCE = PROJECT_ROOT / "src"
if str(_LOCAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(_LOCAL_SOURCE))

from network_anomaly.data.v2_schema import (  # noqa: E402
    ML_FEATURE_COLUMNS,
    TRACE_METADATA_COLUMNS,
)
from network_anomaly.ml.ood_gate import OODRejectionGate  # noqa: E402
from network_anomaly.models.registry import ModelRegistry  # noqa: E402

DEFAULT_AIT_TEST = PROJECT_ROOT / "data" / "processed" / "v2" / "ait_test.csv.gz"
DEFAULT_CTU_WIN7 = PROJECT_ROOT / "data" / "processed" / "v2" / "ctu_windows7ad.csv.gz"
DEFAULT_OOD_GATE = PROJECT_ROOT / "artifacts" / "ml" / "ood_reference_gate.json"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "data" / "demo"
DEFAULT_SEED = 42


def _score_candidates(
    df: pd.DataFrame,
    registry: ModelRegistry,
    ood_gate: OODRejectionGate,
) -> pd.DataFrame:
    """Attach OOD flag and per-model risk scores (0-100) to candidate rows."""
    feature_dicts = df[list(ML_FEATURE_COLUMNS)].to_dict(orient="records")
    ood_flags = [bool(ood_gate.evaluate_sample(fd).is_ood) for fd in feature_dicts]
    batch_scores = registry.predict_batch_all(feature_dicts)

    out = df.copy()
    out["_is_ood"] = ood_flags
    for model_name in registry.available_models:
        out[f"_score_{model_name}"] = [
            float(row_scores[model_name].normalized_score) * 100.0 for row_scores in batch_scores
        ]
    score_cols = [f"_score_{m}" for m in registry.available_models]
    out["_mean_score"] = out[score_cols].mean(axis=1)
    return out


def _sample_group(
    df: pd.DataFrame,
    n: int,
    rng: np.random.Generator,
) -> pd.DataFrame:
    """Deterministically sample up to n rows from df."""
    if len(df) == 0 or n <= 0:
        return df.iloc[0:0]
    take = min(n, len(df))
    idx = rng.choice(df.index.to_numpy(), size=take, replace=False)
    return df.loc[idx]


def generate_showcase_demo(
    *,
    ait_test_path: Path = DEFAULT_AIT_TEST,
    ctu_win7_path: Path = DEFAULT_CTU_WIN7,
    ood_gate_path: Path = DEFAULT_OOD_GATE,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    seed: int = DEFAULT_SEED,
) -> Dict[str, Any]:
    """Build showcase_demo_flows.csv and showcase_demo_labels.csv."""
    if not ait_test_path.is_file():
        raise FileNotFoundError(f"AIT test dataset not found: {ait_test_path}")
    if not ood_gate_path.is_file():
        raise FileNotFoundError(f"OOD gate artifact not found: {ood_gate_path}")

    rng = np.random.default_rng(seed)
    registry = ModelRegistry()
    if not registry.all_ready:
        raise RuntimeError(f"ModelRegistry not ready: {registry.status()}")
    ood_gate = OODRejectionGate.from_artifact(json.loads(ood_gate_path.read_text(encoding="utf-8")))

    # 1. Load candidate pool from AIT-NDS-v2 test split
    df_ait = pd.read_csv(ait_test_path, compression="gzip")
    candidate_parts: List[pd.DataFrame] = []

    benign_ait = df_ait[df_ait["label_binary"] == 0]
    candidate_parts.append(_sample_group(benign_ait, 8000, rng))

    for cat, cap in [
        ("Reconnaissance", 2500),
        ("Data_Exfiltration", 2500),
        ("Credential_Attack", 78),
        ("Post_Exploitation_Discovery", 39),
        ("Exploitation_And_C2", 5),
    ]:
        sub = df_ait[(df_ait["label_binary"] == 1) & (df_ait["attack_category"] == cat)]
        candidate_parts.append(_sample_group(sub, cap, rng))

    # 2. Load candidate pool from CTU-SME-11 Windows7AD (if present) for OOD & C2
    if ctu_win7_path.is_file():
        df_ctu = pd.read_csv(ctu_win7_path, compression="gzip")
        candidate_parts.append(_sample_group(df_ctu[df_ctu["label_binary"] == 0], 1500, rng))
        candidate_parts.append(
            _sample_group(
                df_ctu[
                    (df_ctu["label_binary"] == 1)
                    & (df_ctu["attack_category"] == "Exploitation_And_C2")
                ],
                1000,
                rng,
            )
        )

    candidates = pd.concat(candidate_parts, ignore_index=True)
    scored = _score_candidates(candidates, registry, ood_gate)

    in_dist = scored[~scored["_is_ood"]]
    ood_pool = scored[scored["_is_ood"]]

    # 3. Stratify-select 465 rows:
    #    - ~300 Benign (in-dist): ~264 LOW (<25) + ~36 borderline MEDIUM (25-49)
    ben_in = in_dist[in_dist["label_binary"] == 0]
    ben_low = ben_in[ben_in["_mean_score"] < 25.0]
    ben_med = ben_in[(ben_in["_mean_score"] >= 25.0) & (ben_in["_mean_score"] < 50.0)]
    sel_ben_low = _sample_group(ben_low, 270, rng)
    sel_ben_med = _sample_group(ben_med, 36, rng)
    if len(sel_ben_med) < 36:
        # Top up from LOW benign if fewer than 36 borderline benign rows exist
        extra = 36 - len(sel_ben_med)
        remaining_low = ben_low.drop(index=sel_ben_low.index, errors="ignore")
        sel_ben_low = pd.concat([sel_ben_low, _sample_group(remaining_low, extra, rng)])

    #    - ~150 Attack (in-dist) across all 5 categories, mixing MEDIUM/HIGH and CRITICAL
    att_in = in_dist[in_dist["label_binary"] == 1]
    att_targets = {
        "Reconnaissance": 45,
        "Data_Exfiltration": 45,
        "Credential_Attack": 26,
        "Post_Exploitation_Discovery": 18,
        "Exploitation_And_C2": 16,
    }
    att_selected_parts: List[pd.DataFrame] = []
    for cat, target_n in att_targets.items():
        cat_pool = att_in[att_in["attack_category"] == cat]
        mod_pool = cat_pool[(cat_pool["_mean_score"] >= 25.0) & (cat_pool["_mean_score"] < 80.0)]
        crit_pool = cat_pool[cat_pool["_mean_score"] >= 80.0]
        n_mod = min(len(mod_pool), max(1, target_n // 2))
        n_crit = min(len(crit_pool), target_n - n_mod)
        part = pd.concat(
            [
                _sample_group(mod_pool, n_mod, rng),
                _sample_group(crit_pool, n_crit, rng),
            ]
        )
        if len(part) < target_n:
            rem = cat_pool.drop(index=part.index, errors="ignore")
            part = pd.concat([part, _sample_group(rem, target_n - len(part), rng)])
        att_selected_parts.append(part)

    #    - ~15 OOD flows (genuinely triggering OODRejectionGate.is_ood == True)
    sel_ood = _sample_group(ood_pool, 15, rng)

    final_df = pd.concat(
        [sel_ben_low, sel_ben_med, *att_selected_parts, sel_ood],
        ignore_index=True,
    )
    # Shuffle deterministically
    final_df = final_df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    final_df.insert(0, "row_id", range(len(final_df)))

    flow_cols = ["row_id"] + list(TRACE_METADATA_COLUMNS) + list(ML_FEATURE_COLUMNS)
    label_cols = ["row_id", "label_binary", "attack_category", "raw_label"]

    output_dir.mkdir(parents=True, exist_ok=True)
    flows_path = output_dir / "showcase_demo_flows.csv"
    labels_path = output_dir / "showcase_demo_labels.csv"

    final_df[flow_cols].to_csv(flows_path, index=False, lineterminator="\n")
    final_df[label_cols].to_csv(labels_path, index=False, lineterminator="\n")

    return {
        "total_rows": int(len(final_df)),
        "benign_rows": int((final_df["label_binary"] == 0).sum()),
        "attack_rows": int((final_df["label_binary"] == 1).sum()),
        "ood_rows": int(final_df["_is_ood"].sum()),
        "attack_categories": final_df["attack_category"].value_counts().to_dict(),
        "flows_path": str(flows_path),
        "labels_path": str(labels_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    args = parser.parse_args()
    summary = generate_showcase_demo(seed=args.seed)
    print(summary)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
