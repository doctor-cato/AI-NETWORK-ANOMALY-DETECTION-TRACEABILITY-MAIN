---
name: model-experiment
description: "Thiết kế, triển khai hoặc tái lập thí nghiệm Random Forest, XGBoost, Isolation Forest và Autoencoder có artifact/manifest/SHA-256 nhất quán. Dùng khi issue cho phép training, tuning, evaluation hoặc diagnostic; không kích hoạt training hay ghi đè E0 chỉ để kiểm tra skill."
---

# Model Experiment & Reproducibility (v2.0)

Chỉ thực hiện experiment khi task/issue hiện tại cho phép. Đọc [EXPERIMENT_PLAN.md](../../../docs/EXPERIMENT_PLAN.md), [REPRODUCIBILITY.md](../../../docs/REPRODUCIBILITY.md) và [ml-experiment-audit](../ml-experiment-audit/SKILL.md). Việc skill được kích hoạt không cấp quyền tự tải dataset hay ghi đè 4 model **`E0` baseline đang đóng băng (`RESEARCH_ONLY`)**.

## Quy tắc bảo toàn `E0` vs Thí nghiệm Bổ sung

- 4 artifacts chính thức trong `artifacts/models/{random_forest,xgboost,isolation_forest,autoencoder}` (`E0_frozen_18f_reference`) chỉ dùng **chỉ-đọc** trừ khi nhiệm vụ cho phép tái huấn luyện chính thức.
- Thí nghiệm mở rộng (ablation `WP3`, `Multi-Class 6 lớp`, `Cross-Source Calibration Diagnostic`) phải tách riêng script và báo cáo (`reports/experiments/ml/`), ghi rõ `e0_artifacts_untouched = true`.

## Supervised Models (`Random Forest`, `XGBoost`)

1. Chốt binary hay multiclass target, thứ tự lớp, `ML_FEATURE_COLUMNS` (`canonical-flow-v2-18`).
2. Dùng `TrainOnlyPreprocessor` (`asinh_robust`) đã fit thuần trên `ait_train`; **không** fit lại trên `val`/`test`/external.
3. Cố định `random_state = 42` (`config.RANDOM_SEED`); chọn cấu hình/hyperparameter bằng `ait_val` (`validation`) hoặc CV nội bộ trong `ait_train`.
4. Đánh giá 1 lần trên `ait_test` (và zero-shot trên `CTU-SME-11`, `UWF-ZeekData24` nếu thuộc phạm vi): Precision, Recall, F1, FPR, ROC-AUC/PR-AUC (hoặc Macro-F1 / Confusion Matrix cho multiclass) + per-class breakdown cho lớp hiếm.

## Unsupervised Models (`Isolation Forest`, `Autoencoder`)

- Fit không dùng nhãn (hoặc theo đúng protocol đã định trên `ait_train`); `Autoencoder` dùng `MLPRegressor` reconstruction error + sidecar `model_config.json`, `threshold.json`, `score_normalization.json`.
- Chọn hướng điểm (`higher_is_more_anomalous`) và threshold thuần trên `ait_val`; tuyệt đối không chỉnh threshold trên `ait_test` hay target dataset (chỉ được làm diagnostic riêng có dán nhãn `non-zeroshot`).

## Manifest & Provenance tối thiểu cho một run

- `run_id`, timestamp UTC, issue/requirement, commit SHA và trạng thái working tree trung thực (`git_dirty` / `DIRTY_DISCLOSED` — không giả mạo sạch);
- SHA-256 dataset/split (`V2_SPLIT_MANIFEST.json`) và preprocessor (`v2_flow_preprocessing_manifest.json`);
- full hyperparameters, random seed, dependency/Python/OS versions, lệnh tái lập;
- per-partition metrics (`ait_val`, `ait_test`, `ctu_*`, `uwf_*`), threshold provenance (`test_touched = false`), `deployment_tier` (`RESEARCH_ONLY` trừ khi vượt qua mọi cổng), và giới hạn.

## Trạng thái trung thực

- `PLANNED`: protocol/config dự kiến, chưa có code.
- `IMPLEMENTED`: code tồn tại; chưa đủ test/run.
- `TESTED`: unit/integration test đã chạy (có thể synthetic).
- `EXPERIMENTALLY VALIDATED`: run trên dữ liệu benchmark v2 thật (`AIT-NDS-v2`, `CTU-SME-11`, `UWF-ZeekData24`) có provenance, manifest, held-out evaluation và bằng chứng đầy đủ.
