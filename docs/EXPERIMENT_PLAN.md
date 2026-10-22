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
- Hyperparameters khóa: `n_estimators=200`, `max_depth=16`, `min_samples_split=2`,
  `min_samples_leaf=1`, `criterion='gini'`, `max_features='sqrt'`, `random_state=42`, `n_jobs=-1`.
- Input matrix: Đúng 47 đặc trưng ML (`ML_FEATURE_COLUMNS`), loại trừ 6 metadata và 2 targets.
- Target: `Label` (nhị phân, Positive = `Attack` / 1, Negative = `Benign` / 0).

## Protocol & Test Lock

- Split trước rồi mới preprocessing; lưu pipeline.
- Ranh giới fit preprocessing: `train_only` (không fit trên validation hay test).
- TEST LOCK: Tập `test` bị khóa tuyệt đối, không được dùng để chọn feature, tuning siêu tham số,
  chọn threshold hay chọn mô hình. Test chỉ được đánh giá một lần duy nhất ở bước cuối cùng.
- Tuning policy: Chỉ chạy trên `train` và `validation` với search space và budget được version hóa.
- Cố định random seed (42) cho split, initialization và tuning để đảm bảo tái lập.
- Chưa có experiment thật trên dữ liệu NF-UNSW-NB15-v3; việc huấn luyện thuộc Issue #10,
  đánh giá thuộc Issue #12. Mọi kết quả ML hiện tại vẫn ở trạng thái `PLANNED`.

## Ghi nhận metric

- Mỗi lượt chạy lưu seed, phiên bản dataset, danh sách feature, cấu hình model, metric theo lớp và macro, confusion matrix dạng CSV/PNG, thời gian và thông tin môi trường.
- Kết quả đặt tại `reports/figures/` và `artifacts/` (không commit nếu lớn; vẫn lưu config).

Cập nhật: 2026-10-22 (đồng bộ với Issue #9 — RF Baseline Protocol)
