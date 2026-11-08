# Kế hoạch thực nghiệm

## Giả thuyết

- H1: Random Forest là supervised baseline trên NF-UNSW-NB15-v3 sau khi quality findings được xử
  lý bằng transform fit trên train và split temporal/group-aware được audit.
- H2: Isolation Forest có thể phát hiện bất thường không cần nhãn, nhưng đánh giá cần chọn threshold và cho profile metric khác đánh giá giám sát.

## Biến số

- Độc lập: loại mô hình (RF, XGBoost, Isolation Forest hoặc Autoencoder), preprocessing,
  duplicate policy, temporal/group split và seed.
- Phụ thuộc: Precision, Recall, F1, Macro-F1, confusion matrix, FPR, per-attack-category recall.

## Baseline

- Dùng Random Forest với cấu hình baseline chuẩn hóa theo protocol `rf-baseline-nf-unsw-nb15-v3-v1`
  (chi tiết tại [RF_BASELINE_PROTOCOL.md](RF_BASELINE_PROTOCOL.md)).
- Hyperparameters khóa (`CANONICAL_BASELINE_PARAMS`, `configuration_id="rf-baseline-canonical-v1"`, `is_canonical_baseline=True`):
  `n_estimators=200`, `max_depth=16`, `min_samples_split=2`, `min_samples_leaf=1`, `criterion='gini'`,
  `max_features='sqrt'`, `class_weight=None`, `random_state=42`, `n_jobs=-1`, `bootstrap=True`.
  Mọi cấu hình tùy biến (kể cả thay đổi `n_jobs`) phải đặt `is_canonical_baseline=False` và dùng `configuration_id` riêng.
- Input matrix: Đúng 47 đặc trưng ML (`ML_FEATURE_COLUMNS`), loại trừ 6 metadata và 2 targets.
- Target: `Label` (nhị phân, Positive = `Attack` / 1, Negative = `Benign` / 0).

## Protocol & Test Lock

- Split trước rồi mới preprocessing; lưu pipeline.
- Ranh giới fit preprocessing: `train_only` (không fit trên validation hay test).
- TEST LOCK: Tập `test` bị khóa tuyệt đối, không được dùng để chọn feature, tuning siêu tham số,
  chọn threshold hay chọn mô hình. Test chỉ được đánh giá một lần duy nhất ở bước cuối cùng.
- Tuning policy: Chỉ chạy trên `train` và `validation` với search space và budget được version hóa.
- Cố định random seed (42) cho split, initialization và tuning để đảm bảo tái lập.
- Huấn luyện Random Forest baseline (Issue #10) đã đạt trạng thái `IMPLEMENTED / TESTED / EXPERIMENTALLY VALIDATED` trên dữ liệu thật `NF-UNSW-NB15-v3`:
  - Fit duy nhất trên `1.655.797` dòng `train` (`83,73s`, run manifest `rf-baseline-1794068628`), áp dụng frozen preprocessor `12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19`.
  - Model artifact: `artifacts/models/random_forest/random_forest_baseline.joblib` (`917.227` bytes, SHA-256 `801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea`).
  - Kết quả đánh giá trên tập `validation` (`345.371` dòng): `Precision = 0.999836`, `Recall = 0.999902`, `F1 = 0.999869`, `Macro-F1 = 0.999928`, `FPR = 0.000016`, Confusion Matrix `[[314866, 5], [3, 30497]]` (chi tiết tại `reports/models/random_forest_manifest.json` và `reports/models/rf_baseline_training_report.md`).
  - Kiểm toán khóa tập Test: `test_partition_accessed = false`, `test_rows_loaded = 0`, `test_indices_loaded = false`.
- Đánh giá cuối cùng trên phân vùng `test` (`345.953` dòng) thuộc phạm vi Issue #12 và vẫn giữ trạng thái `PLANNED`.

## Ghi nhận metric

- Mỗi lượt chạy lưu seed, phiên bản dataset, danh sách feature, cấu hình model, metric theo lớp và macro, confusion matrix dạng CSV/PNG, thời gian và thông tin môi trường.
- Kết quả đặt tại `reports/models/`, `reports/figures/` và `artifacts/` (không commit artifact nhị phân lớn; lưu manifest và báo cáo kiểm chứng).

Cập nhật: 2026-11-07 (hoàn thành huấn luyện thực nghiệm Random Forest baseline Issue #10 trên dữ liệu thật NF-UNSW-NB15-v3)
