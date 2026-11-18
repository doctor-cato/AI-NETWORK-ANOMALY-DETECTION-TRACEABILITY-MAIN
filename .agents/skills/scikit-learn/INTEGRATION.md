name: scikit-learn
source_local: .agents/skills/scikit-learn/INTEGRATION.md
license: BSD-3-Clause
date_updated: 2026-11-19

trigger: xây dựng/audit `TrainOnlyPreprocessor`, `Random Forest`, `XGBoost`, `Isolation Forest`, `Autoencoder` (`MLPRegressor`), OOD gate và evaluation metrics.

repo_notes:
- Active contract: `canonical-flow-v2-18` (18 L4 flow features; `NF-UNSW-NB15-v3` đã chuyển sang `historical/`).
- Preprocessing (`src/network_anomaly/preprocessing/pipeline.py`): `TrainOnlyPreprocessor` (`asinh_robust`, `MIN_BOUNDED_SCALE_FLOOR = 0.25`) fit duy nhất trên `ait_train`; giữ bất biến cho `val`/`test`/cross-source/live.
- 4 họ mô hình `E0` (`RESEARCH_ONLY`): `RandomForest`, `XGBoost`, `IsolationForest`, `Autoencoder` (`MLPRegressor` + `score_normalization.json`). Không tự ý retrain/ghi đè `E0` `.joblib` khi chưa được giao.
- Threshold & Calibration: chọn thuần trên `ait_val` (`validation` partition); không dùng `ait_test` hay target dataset để chọn ngưỡng/hyperparameter zero-shot.
- Metrics: Precision, Recall, F1, FPR, ROC-AUC/PR-AUC (binary); Macro-F1, Weighted-F1, Balanced Accuracy, Per-class & Confusion Matrix (multiclass); kiểm soát `zero_division=0`.
- Data leakage: kiểm tra cột định danh/trace, target dẫn xuất và scenario/group overlap (`V2_SPLIT_MANIFEST.json`).

activation: luôn kết hợp `.agents/rules/ml-experiment-rules.md` và `.agents/skills/ml-experiment-audit/SKILL.md`.
