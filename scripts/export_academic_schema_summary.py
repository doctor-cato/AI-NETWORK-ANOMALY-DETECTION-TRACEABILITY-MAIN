#!/usr/bin/env python3
"""Read-only schema, feature-role, and preprocessing summary exporter for academic defense.

Inspects versioned repository contracts, EDA summary, and preprocessing manifest (plus the
verified local preprocessor artifact when available) without retraining or mutating any data.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LOCAL_SOURCE = PROJECT_ROOT / "src"
if str(LOCAL_SOURCE) not in sys.path:
    sys.path.insert(0, str(LOCAL_SOURCE))

from network_anomaly.data.v2_schema import (  # noqa: E402
    ALL_CANONICAL_COLUMNS as ALL_COLUMNS,
    CATEGORICAL_CODED_COLUMNS,
    IDENTIFIER_COLUMNS,
    ML_FEATURE_COLUMNS,
    PORT_COLUMNS,
    QUANTITATIVE_ML_COLUMNS,
    TARGET_COLUMNS,
    TIMESTAMP_COLUMNS,
)
from network_anomaly.preprocessing.pipeline import TrainOnlyPreprocessor  # noqa: E402

DEFAULT_EDA_SUMMARY = PROJECT_ROOT / "reports" / "datasets" / "v2_multi_source_profile.json"
DEFAULT_PREP_MANIFEST = (
    PROJECT_ROOT / "reports" / "preprocessing" / "v2_flow_preprocessing_manifest.json"
)
DEFAULT_PREP_ARTIFACT = (
    PROJECT_ROOT / "artifacts" / "preprocessing" / "v2_flow_preprocessor.joblib"
)


def _column_role(col: str) -> str:
    if col in TARGET_COLUMNS:
        return "target"
    if col in TIMESTAMP_COLUMNS:
        return "metadata_timestamp"
    if col in IDENTIFIER_COLUMNS:
        return "metadata_ip"
    if col in PORT_COLUMNS:
        return "metadata_port"
    if col in CATEGORICAL_CODED_COLUMNS:
        return "ml_categorical_coded"
    if col in QUANTITATIVE_ML_COLUMNS:
        return "ml_quantitative"
    return "unknown"


def collect_schema_summary(
    eda_summary_path: Path = DEFAULT_EDA_SUMMARY,
    prep_manifest_path: Path = DEFAULT_PREP_MANIFEST,
    prep_artifact_path: Path = DEFAULT_PREP_ARTIFACT,
) -> Dict[str, Any]:
    """Collect read-only schema, EDA statistics, and frozen preprocessor parameters."""
    eda_data = json.loads(eda_summary_path.read_text(encoding="utf-8"))
    prep_manifest = json.loads(prep_manifest_path.read_text(encoding="utf-8"))
    numeric_stats = eda_data.get("numeric_statistics", {})
    quantiles = eda_data.get("quantiles", {})

    imputed_values: Dict[str, float] = {}
    vocab_sizes: Dict[str, int] = {}
    audit_train: Dict[str, Dict[str, int]] = {}
    preprocessor_loaded = False

    if prep_artifact_path.is_file() and prep_manifest_path.is_file():
        prep = TrainOnlyPreprocessor.load_verified(
            artifact_path=prep_artifact_path,
            manifest_path=prep_manifest_path,
        )
        imputed_values = {k: float(v) for k, v in prep.imputed_values_.items()}
        vocab_sizes = {k: len(v) for k, v in prep.category_vocabularies_.items()}
        audit_train = dict(prep.audit_counts_train_)
        preprocessor_loaded = True

    columns: List[Dict[str, Any]] = []
    for idx, col in enumerate(ALL_COLUMNS, start=1):
        role = _column_role(col)
        used_in_training = col in ML_FEATURE_COLUMNS
        ns = numeric_stats.get(col, {})
        q = quantiles.get(col, {})
        columns.append(
            {
                "index": idx,
                "name": col,
                "role": role,
                "used_in_training": used_in_training,
                "min": ns.get("minimum"),
                "p50": q.get("p50"),
                "max": ns.get("maximum"),
                "unavailable_count": ns.get("unavailable_count"),
                "train_non_finite": (
                    audit_train.get(col, {}).get("total_non_finite")
                    if preprocessor_loaded
                    else None
                ),
                "train_imputed_value": imputed_values.get(col),
                "train_vocab_size": vocab_sizes.get(col),
            }
        )

    return {
        "total_columns": len(ALL_COLUMNS),
        "ml_features_count": len(ML_FEATURE_COLUMNS),
        "categorical_coded_count": len(CATEGORICAL_CODED_COLUMNS),
        "quantitative_ml_count": len(QUANTITATIVE_ML_COLUMNS),
        "trace_metadata_count": len(TIMESTAMP_COLUMNS + IDENTIFIER_COLUMNS + PORT_COLUMNS),
        "target_count": len(TARGET_COLUMNS),
        "output_features_count": prep_manifest.get("output_features_count"),
        "scaler_type": prep_manifest.get("config", {}).get("scaler_type"),
        "handle_unknown_categories": prep_manifest.get("config", {}).get(
            "handle_unknown_categories"
        ),
        "preprocessor_artifact_loaded": preprocessor_loaded,
        "columns": columns,
    }


def _format_markdown(summary: Dict[str, Any]) -> str:
    lines = [
        "# Read-Only Schema & Preprocessing Summary",
        "",
        f"- Total columns: {summary['total_columns']}",
        f"- ML features: {summary['ml_features_count']} "
        f"({summary['categorical_coded_count']} categorical-coded + "
        f"{summary['quantitative_ml_count']} quantitative)",
        f"- Trace metadata (excluded): {summary['trace_metadata_count']}",
        f"- Targets (excluded): {summary['target_count']}",
        f"- Transformed output dims: {summary['output_features_count']}",
        f"- Scaler: {summary['scaler_type']} | Unknown categories: {summary['handle_unknown_categories']}",
        f"- Preprocessor artifact loaded locally: {summary['preprocessor_artifact_loaded']}",
        "",
        "| # | Column | Role | Train? | Min | Median (p50) | Max | Unavail (Full) | Train Imputed | Vocab Size |",
        "|---:|---|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for c in summary["columns"]:
        lines.append(
            f"| {c['index']} | `{c['name']}` | {c['role']} | "
            f"{'Yes' if c['used_in_training'] else 'No'} | "
            f"{c['min'] if c['min'] is not None else '-'} | "
            f"{c['p50'] if c['p50'] is not None else '-'} | "
            f"{c['max'] if c['max'] is not None else '-'} | "
            f"{c['unavailable_count'] if c['unavailable_count'] is not None else '-'} | "
            f"{c['train_imputed_value'] if c['train_imputed_value'] is not None else '-'} | "
            f"{c['train_vocab_size'] if c['train_vocab_size'] is not None else '-'} |"
        )
    return "\n".join(lines) + "\n"


def parse_args(argv: List[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read-only schema and preprocessing summary exporter."
    )
    parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Output format (default: markdown)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional file path to write output instead of stdout.",
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = parse_args(argv)
    summary = collect_schema_summary()
    rendered = (
        json.dumps(summary, indent=2) + "\n" if args.format == "json" else _format_markdown(summary)
    )
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
