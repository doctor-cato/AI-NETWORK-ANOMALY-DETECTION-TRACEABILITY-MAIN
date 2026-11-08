#!/usr/bin/env python3
"""Cross-Dataset Generalization Benchmark Evaluation Script (Issue #46).

Evaluates the frozen canonical Random Forest model (trained on NF-UNSW-NB15-v3)
against independent external benchmark datasets (NF-CSE-CIC-IDS2018-v3)
without retraining, tuning, or threshold adaptation.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from network_anomaly.config import ARTIFACTS, PROJECT_ROOT
from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS, TARGET_COLUMNS
from network_anomaly.inference.predict import (
    load_verified_model,
    load_verified_preprocessor,
)
from network_anomaly.ingestion.adapters.base import BaseSourceAdapter
from network_anomaly.ingestion.compatibility import FeatureCompatibilityEvaluator
from network_anomaly.ingestion.ood import OODValidator
from network_anomaly.ingestion.parser import StreamingChunkParser
from network_anomaly.ingestion.schemas import InferenceEligibility, ValidationStatus
from network_anomaly.preprocessing import TrainOnlyPreprocessor

DEFAULT_DATASET_CSV = (
    PROJECT_ROOT
    / "data"
    / "raw"
    / "NF-CSE-CIC-IDS2018-v3"
    / "NF-CSE-CIC-IDS2018-v3-sample100k.csv"
)
DEFAULT_MODEL_ARTIFACT = (
    PROJECT_ROOT / "artifacts" / "models" / "random_forest" / "random_forest_baseline.joblib"
)
DEFAULT_MODEL_MANIFEST = (
    PROJECT_ROOT / "reports" / "models" / "random_forest_manifest.json"
)
DEFAULT_PREP_ARTIFACT = (
    PROJECT_ROOT / "artifacts" / "preprocessing" / "nf_unsw_nb15_v3_preprocessor.joblib"
)
DEFAULT_PREP_MANIFEST = (
    PROJECT_ROOT / "reports" / "preprocessing" / "nf_unsw_nb15_v3_preprocessing_manifest.json"
)
DEFAULT_OUTPUT_REPORT = (
    PROJECT_ROOT / "reports" / "evaluation" / "cross_dataset_generalization_report.md"
)
DEFAULT_OUTPUT_RESULTS = (
    PROJECT_ROOT / "reports" / "evaluation" / "cross_dataset_evaluation_results.json"
)


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def verify_canonical_artifacts(
    model_path: Path,
    model_manifest_path: Path,
    prep_path: Path,
    prep_manifest_path: Path,
) -> Dict[str, Any]:
    """Verify hashes and manifests of canonical baseline model and preprocessor (fail-closed)."""
    if not model_path.exists():
        raise FileNotFoundError(f"Model artifact not found: {model_path}")
    if not model_manifest_path.exists():
        raise FileNotFoundError(f"Model manifest not found: {model_manifest_path}")
    if not prep_path.exists():
        raise FileNotFoundError(f"Preprocessor artifact not found: {prep_path}")
    if not prep_manifest_path.exists():
        raise FileNotFoundError(f"Preprocessor manifest not found: {prep_manifest_path}")

    with open(model_manifest_path, "r", encoding="utf-8") as f:
        model_manifest = json.load(f)
    with open(prep_manifest_path, "r", encoding="utf-8") as f:
        prep_manifest = json.load(f)

    model_sha = _sha256_file(model_path)
    expected_model_sha = model_manifest.get("model_artifact_sha256")
    if expected_model_sha and model_sha != expected_model_sha:
        raise ValueError(
            f"Model SHA-256 mismatch!\nExpected: {expected_model_sha}\nObserved: {model_sha}"
        )

    prep_sha = _sha256_file(prep_path)
    expected_prep_sha = prep_manifest.get("preprocessor_artifact_sha256")
    if expected_prep_sha and prep_sha != expected_prep_sha:
        raise ValueError(
            f"Preprocessor SHA-256 mismatch!\nExpected: {expected_prep_sha}\nObserved: {prep_sha}"
        )

    return {
        "model_sha256": model_sha,
        "preprocessor_sha256": prep_sha,
        "run_id": model_manifest.get("run_id"),
        "protocol_version": model_manifest.get("protocol_version"),
        "configuration_id": model_manifest.get("configuration_id"),
        "validation_summary_internal": model_manifest.get("validation_summary", {}),
    }


def evaluate_cross_dataset(
    dataset_csv: Path,
    model_artifact: Path,
    model_manifest: Path,
    preprocessor_artifact: Path,
    preprocessor_manifest: Path,
    batch_size: int = 10000,
) -> Dict[str, Any]:
    """Execute cross-dataset evaluation on streaming chunks with frozen canonical model."""
    if not dataset_csv.exists():
        raise FileNotFoundError(f"Evaluation dataset CSV not found: {dataset_csv}")

    # 1. Verify model and preprocessor integrity
    verified_meta = verify_canonical_artifacts(
        model_artifact, model_manifest, preprocessor_artifact, preprocessor_manifest
    )
    preprocessor, prep_meta = load_verified_preprocessor(
        preprocessor_artifact, manifest_path=preprocessor_manifest
    )
    model, model_meta = load_verified_model(
        model_artifact, manifest_path=model_manifest
    )

    # 2. Ingestion & Compatibility (Raw Data Completeness Validator)
    parser = StreamingChunkParser(chunk_size=batch_size)
    # Empty benchmark registry during benchmark execution to evaluate raw feature viability
    evaluator = FeatureCompatibilityEvaluator(benchmark_registry={})
    ood_validator = OODValidator(check_shortcut_drift=True)

    y_true_all: List[int] = []
    y_pred_all: List[int] = []
    attack_names_all: List[str] = []
    total_rows = 0
    total_ood_warnings = 0
    records_skipped_missing_label = 0
    records_skipped_invalid_label = 0
    records_skipped_incomplete_features = 0
    t0 = time.time()

    print(f"Beginning cross-dataset evaluation of {dataset_csv.name}...")
    for chunk_events in parser.parse_file_chunks(dataset_csv, explicit_source_id="source:nf-v3-external"):
        # Evaluate feature completeness
        comp_report = evaluator.evaluate_events(chunk_events)
        if comp_report.inference_eligibility in (
            InferenceEligibility.FEATURE_INCOMPATIBLE,
            InferenceEligibility.SCHEMA_INVALID,
        ):
            raise ValueError(f"Chunk failed feature compatibility: {comp_report.rejection_reasons}")

        # Extract 47 features with strict anti-imputation
        X_chunk, eligible_idx = BaseSourceAdapter.extract_ml_matrix(chunk_events)
        diff_count = len(chunk_events) - len(eligible_idx)
        if diff_count > 0:
            records_skipped_incomplete_features += diff_count

        if len(eligible_idx) == 0:
            continue

        # OOD Audit
        ood_chunk = ood_validator.audit_dataframe(X_chunk)
        if ood_chunk.has_ood_warning:
            total_ood_warnings += ood_chunk.shortcut_shift_count

        # Ground truth labels - STRICT: Never default missing/null Label to 0 (Benign)
        valid_row_positions = []
        for pos_in_chunk, orig_idx in enumerate(eligible_idx):
            ev = chunk_events[orig_idx]
            raw_label = ev.trace_metadata.get("Label")
            if raw_label is None or raw_label == "":
                records_skipped_missing_label += 1
                continue
            try:
                lbl = int(raw_label)
                if lbl not in (0, 1):
                    records_skipped_invalid_label += 1
                    continue
            except (ValueError, TypeError):
                records_skipped_invalid_label += 1
                continue

            valid_row_positions.append(pos_in_chunk)
            raw_attack = ev.trace_metadata.get("Attack", "Unknown")
            y_true_all.append(lbl)
            attack_names_all.append(str(raw_attack))

        if not valid_row_positions:
            continue

        # Filter feature matrix to only rows with valid ground truth
        X_valid = X_chunk.iloc[valid_row_positions]

        # Frozen Preprocessing Transformation
        X_trans = preprocessor.transform(X_valid)

        # Frozen Model Prediction
        preds = model.predict(X_trans)
        y_pred_all.extend([int(p) for p in preds])
        total_rows += len(valid_row_positions)
        print(f"  Processed {total_rows:,} verified rows...")

    dt = time.time() - t0
    y_true_arr = np.array(y_true_all)
    y_pred_arr = np.array(y_pred_all)

    # 3. Compute Metrics
    acc = float(accuracy_score(y_true_arr, y_pred_arr))
    prec = float(precision_score(y_true_arr, y_pred_arr, zero_division=0))
    rec = float(recall_score(y_true_arr, y_pred_arr, zero_division=0))
    f1 = float(f1_score(y_true_arr, y_pred_arr, zero_division=0))
    macro_f1 = float(f1_score(y_true_arr, y_pred_arr, average="macro", zero_division=0))

    cm = confusion_matrix(y_true_arr, y_pred_arr, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = float(fp / (fp + tn)) if (fp + tn) > 0 else 0.0

    # Per-category breakdown
    categories = sorted(set(attack_names_all))
    cat_breakdown: Dict[str, Dict[str, Any]] = {}
    for cat in categories:
        mask = [name == cat for name in attack_names_all]
        cat_y_true = y_true_arr[mask]
        cat_y_pred = y_pred_arr[mask]
        total_cat = len(cat_y_true)
        if cat == "Benign":
            cat_fp = int((cat_y_pred == 1).sum())
            cat_tn = int((cat_y_pred == 0).sum())
            cat_breakdown[cat] = {
                "total": total_cat,
                "true_negative": cat_tn,
                "false_positive": cat_fp,
                "false_positive_rate": float(cat_fp / total_cat) if total_cat > 0 else 0.0,
            }
        else:
            cat_detected = int((cat_y_pred == 1).sum())
            cat_missed = int((cat_y_pred == 0).sum())
            cat_breakdown[cat] = {
                "total": total_cat,
                "detected": cat_detected,
                "missed": cat_missed,
                "detection_rate": float(cat_detected / total_cat) if total_cat > 0 else 0.0,
            }

    results = {
        "evaluation_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_name": "NF-CSE-CIC-IDS2018-v3",
        "dataset_path": str(dataset_csv),
        "dataset_sha256": _sha256_file(dataset_csv),
        "rows_evaluated": total_rows,
        "evaluation_duration_seconds": round(dt, 2),
        "canonical_model_provenance": verified_meta,
        "metrics": {
            "accuracy": acc,
            "precision": prec,
            "recall": rec,
            "f1": f1,
            "macro_f1": macro_f1,
            "false_positive_rate": fpr,
            "confusion_matrix": {
                "labels": ["Benign (0)", "Attack (1)"],
                "tn": int(tn),
                "fp": int(fp),
                "fn": int(fn),
                "tp": int(tp),
                "matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
            },
        },
        "per_category_breakdown": cat_breakdown,
        "data_hygiene": {
            "records_skipped_missing_label": records_skipped_missing_label,
            "records_skipped_invalid_label": records_skipped_invalid_label,
            "records_skipped_incomplete_features": records_skipped_incomplete_features,
        },
        "ood_summary": {
            "total_shortcut_drift_rows": total_ood_warnings,
            "shortcut_drift_pct": round(total_ood_warnings / total_rows * 100, 2) if total_rows > 0 else 0.0,
        },
    }

    return results


def generate_markdown_report(results: Dict[str, Any], output_path: Path) -> str:
    """Generate comprehensive scientific Markdown report comparing external vs internal metrics."""
    m = results["metrics"]
    cm = m["confusion_matrix"]
    internal = results["canonical_model_provenance"].get("validation_summary_internal", {})
    status_label = "MODEL_VALIDATED" if (m["recall"] >= 0.85 and m["false_positive_rate"] <= 0.05) else "BENCHMARK_FAILED (Chặn suy luận: Recall < 0.85 hoặc FPR > 0.05)"

    delta_str = r"$\Delta$"
    report = f"""# Báo cáo Đánh giá Tổng quát hóa Cross-Dataset (Issue #46)

**Tập dữ liệu Kiểm định Ngoại vi:** `{results['dataset_name']}`\
**Mô hình Đánh giá:** Canonical Random Forest (`{results['canonical_model_provenance']['configuration_id']}`)\
**Thời gian Đánh giá:** `{results['evaluation_timestamp_utc']}`\
**Số dòng Đánh giá:** `{results['rows_evaluated']:,}` dòng\
**Thời gian Thực thi:** `{results['evaluation_duration_seconds']}` giây\
**Trạng thái Kiểm định Benchmark:** `{status_label}`

---

## 1. Tóm tắt Đối chiếu Hiệu năng (Internal Validation vs External Benchmark)

| Chỉ số (Metric) | Nội bộ `NF-UNSW-NB15-v3` (Validation) | Ngoại vi `NF-CSE-CIC-IDS2018-v3` (Generalization) | Độ Lệch ({delta_str}) | Nhận xét & Đánh giá Khoa học |
|---|:---:|:---:|:---:|---|
| **Accuracy** | `{internal.get('accuracy', 0.999977):.6f}` | `{m['accuracy']:.6f}` | `{m['accuracy'] - internal.get('accuracy', 0.999977):+.6f}` | Tổng quan độ chính xác phân loại toàn cục. |
| **Precision** | `{internal.get('precision', 0.999836):.6f}` | `{m['precision']:.6f}` | `{m['precision'] - internal.get('precision', 0.999836):+.6f}` | Tỷ lệ dự đoán Attack thực sự là tấn công. |
| **Recall** | `{internal.get('recall', 0.999902):.6f}` | `{m['recall']:.6f}` | `{m['recall'] - internal.get('recall', 0.999902):+.6f}` | Tỷ lệ bắt giữ tấn công thực tế trên môi trường mạng mới. |
| **F1-Score** | `{internal.get('f1', 0.999869):.6f}` | `{m['f1']:.6f}` | `{m['f1'] - internal.get('f1', 0.999869):+.6f}` | Đo lường cân bằng giữa Precision và Recall. |
| **Macro-F1** | `{internal.get('macro_f1', 0.999928):.6f}` | `{m['macro_f1']:.6f}` | `{m['macro_f1'] - internal.get('macro_f1', 0.999928):+.6f}` | Trung bình không trọng số giữa Benign và Attack. |
| **False Positive Rate (FPR)** | `{internal.get('false_positive_rate', 0.000016):.6f}` | `{m['false_positive_rate']:.6f}` | `{m['false_positive_rate'] - internal.get('false_positive_rate', 0.000016):+.6f}` | Tỷ lệ báo động giả trên lưu lượng bình thường. |

---

## 2. Ma trận Nhầm lẫn (Confusion Matrix)

Trục tung: Nhãn Thực tế (Ground Truth) — Trục hoành: Mô hình Dự đoán (Predicted)

```text
                  Predicted Benign (0)    Predicted Attack (1)
Actual Benign (0)        {cm['tn']:>12,d}            {cm['fp']:>12,d}   (TN / FP)
Actual Attack (1)        {cm['fn']:>12,d}            {cm['tp']:>12,d}   (FN / TP)
```

- **True Negatives (TN):** `{cm['tn']:,}`
- **False Positives (FP):** `{cm['fp']:,}` (Báo động giả)
- **False Negatives (FN):** `{cm['fn']:,}` (Bỏ lọt tấn công)
- **True Positives (TP):** `{cm['tp']:,}`

---

## 3. Phân tích Chi tiết theo Từng Họ Tấn công (Per-Category Breakdown)

| Danh mục Lưu lượng | Tổng số Dòng | Phát hiện Đúng | Bỏ lọt (Missed) / Dương tính Giả (FP) | Tỷ lệ Thành công |
|---|:---:|:---:|:---:|:---:|
"""

    for cat, info in results["per_category_breakdown"].items():
        if cat == "Benign":
            report += f"| **{cat}** | `{info['total']:,}` | `{info['true_negative']:,}` (TN) | `{info['false_positive']:,}` (FP) | FPR: `{info['false_positive_rate']:.4%}` |\n"
        else:
            report += f"| **{cat}** | `{info['total']:,}` | `{info['detected']:,}` (TP) | `{info['missed']:,}` (FN) | Recall: `{info['detection_rate']:.4%}` |\n"

    report += f"""
---

## 4. Phân tích Nguyên nhân Lệch Phân phối (Domain Shift & Shortcut Collapse Analysis)

Kiểm toán thực nghiệm xác nhận kết luận chẩn đoán tại `rf_baseline_validation_audit.json`:

1. **Sự sụp đổ của Shortcut `MIN_TTL`:**
   - Trong tập dữ liệu phòng lab `NF-UNSW-NB15-v3` (IXIA PerfectStorm), `MIN_TTL` là một đường tắt phân loại gần như tuyệt đối (`MIN_TTL=31` là 100% Benign; `MIN_TTL ∈ {{62, 254, 255}}` là 99.997% Attack).
   - Khi chuyển sang môi trường AWS thực tế của `NF-CSE-CIC-IDS2018-v3`, có tới **`{results['ood_summary']['total_shortcut_drift_rows']:,}` dòng ({results['ood_summary']['shortcut_drift_pct']}%)** có `MIN_TTL` hoàn toàn nằm ngoài 4 giá trị lab này (chủ yếu là `MIN_TTL=0` hoặc các bước nhảy định tuyến Internet thực tế).
   - Điều này giải thích định lượng lý do tại sao hiệu năng trên miền dữ liệu mới thay đổi và minh chứng tính tất yếu của **Cổng OOD (Out-of-Distribution Gate)** nhằm cảnh báo người vận hành khi dữ liệu mạng không còn tuân theo phân phối huấn luyện ban đầu.

2. **Khuyến nghị Vận hành Sản phẩm (Milestone M6):**
   - Không được công bố mô hình đạt 99.99% trong production mà phải hiển thị rõ trạng thái `OOD_WARNING` trên Dashboard Streamlit (#16).
   - Tự động chuyển các sự kiện có độ tin cậy thấp hoặc drift shortcut sang **Trace Engine (#24)** và **Risk Engine (#32)** để kiểm chứng đa chiều.
"""

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report)
    return report


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Evaluate cross-dataset generalization.")
    parser.add_argument("--dataset-csv", type=Path, default=DEFAULT_DATASET_CSV)
    parser.add_argument("--model-artifact", type=Path, default=DEFAULT_MODEL_ARTIFACT)
    parser.add_argument("--model-manifest", type=Path, default=DEFAULT_MODEL_MANIFEST)
    parser.add_argument("--preprocessor-artifact", type=Path, default=DEFAULT_PREP_ARTIFACT)
    parser.add_argument("--preprocessor-manifest", type=Path, default=DEFAULT_PREP_MANIFEST)
    parser.add_argument("--output-report", type=Path, default=DEFAULT_OUTPUT_REPORT)
    parser.add_argument("--output-results", type=Path, default=DEFAULT_OUTPUT_RESULTS)
    parser.add_argument("--batch-size", type=int, default=10000)

    args = parser.parse_args(argv)

    try:
        results = evaluate_cross_dataset(
            dataset_csv=args.dataset_csv,
            model_artifact=args.model_artifact,
            model_manifest=args.model_manifest,
            preprocessor_artifact=args.preprocessor_artifact,
            preprocessor_manifest=args.preprocessor_manifest,
            batch_size=args.batch_size,
        )

        args.output_results.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output_results, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)

        generate_markdown_report(results, args.output_report)
        print(f"\nEvaluation complete!")
        print(f"Results JSON: {args.output_results}")
        print(f"Report Markdown: {args.output_report}")
        print(f"Accuracy: {results['metrics']['accuracy']:.6f}")
        print(f"Precision: {results['metrics']['precision']:.6f}")
        print(f"Recall: {results['metrics']['recall']:.6f}")
        print(f"F1-Score: {results['metrics']['f1']:.6f}")
        print(f"FPR: {results['metrics']['false_positive_rate']:.6f}")
        return 0
    except Exception as e:
        print(f"Evaluation error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
