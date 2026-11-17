# Kế hoạch thực nghiệm

## Giả thuyết

- H1: Random Forest là supervised baseline trên NF-UNSW-NB15-v3 sau khi quality findings được xử
  lý bằng transform fit trên train và split temporal/group-aware được audit (RQ1).
- H2: Isolation Forest và Autoencoder có thể phát hiện bất thường không cần nhãn, và duy trì khả năng phát hiện novel attacks khi áp dụng holdout protocol tốt hơn mô hình có giám sát (RQ1, RQ4).
- H3: Phân bố dữ liệu mất cân bằng cực đoan làm giảm per-class recall của tấn công hiếm; cost-sensitive weighting và calibration trên validation khắc phục được độ suy giảm này (RQ2).
- H4: Behavioral Vector chuẩn hóa cho phép liên kết các phiên kết nối của cùng thực thể tấn công độc lập với IP với độ chính xác $\ge 85\%$ (RQ3).
- H5: Adaptive Key Rotation kích hoạt theo Risk Score giảm cửa sổ phơi nhiễm khóa $>70\%$ so với Fixed 30-min rotation mà không quá tải hệ thống (RQ5).
- H6: Mã hóa AES-256-GCM trên Behavioral Vector bổ sung độ trễ $\le 0.5$ ms/sự kiện, duy trì thông lượng $\ge 5.000$ events/s (RQ6).

## Biến số

- Độc lập: loại mô hình (RF, XGBoost, Isolation Forest, Autoencoder), preprocessing,
  duplicate policy, temporal/group split, behavioral vector windowing, rotation policy (Fixed vs Adaptive), crypto mode (Plaintext vs AES-256-GCM).
- Phụ thuộc: Precision, Recall, F1, Macro-F1, confusion matrix, FPR, per-attack-category recall,
  session correlation accuracy, key exposure window, encryption latency, system throughput.

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
- Đánh giá một lần cuối cùng trên phân vùng `test` (`345.953` dòng) cho Random Forest baseline (`rf-heldout-ea330b9`, #12 CLOSED) và Isolation Forest (`if-c4-20261115T055359Z`, clean commit `bf0f3ec`, #11) đã đạt trạng thái **EXPERIMENTALLY VALIDATED**; chi tiết xem [docs/EVALUATION.md](EVALUATION.md) và `reports/experiments/isolation_forest/evaluation_report.md`. XGBoost Held-out Test và Autoencoder real-data run vẫn `NOT VERIFIED`.

## Ghi nhận metric

- Mỗi lượt chạy lưu seed, phiên bản dataset, danh sách feature, cấu hình model, metric theo lớp và macro, confusion matrix dạng CSV/PNG, thời gian và thông tin môi trường.
- Kết quả đặt tại `reports/models/`, `reports/evaluation/`, `reports/experiments/` và `artifacts/` (không commit artifact nhị phân lớn; lưu manifest và báo cáo kiểm chứng).

## Danh mục Thực nghiệm Mở rộng v2.0 (RQ1–RQ6)

- **Exp1 (4-Model Benchmark):** So sánh toàn diện 4 mô hình (RF, XGBoost, IF, AE) trên NF-UNSW-NB15-v3. (Issue #94, #95, #105).
- **Exp2 (Class Imbalance & Rare Attacks):** Đánh giá tác động mất cân bằng lớp và tối ưu hóa chi phí cho các lớp tấn công hiếm (Worms, Backdoors). (Issue #96).
- **Exp3 (IP-Independent Session Correlation):** Khảo sát năng lực liên kết phiên bất thường đa nguồn sử dụng khoảng cách Cosine trên Behavioral Vector. (Issue #101-#104).
- **Exp4 (Unknown Attack Holdout):** Giao thức giữ lại họ tấn công chưa biết trong huấn luyện để kiểm chứng tính tổng quát của Autoencoder và Isolation Forest. (Issue #98-#100).
- **Exp5 (Adaptive Key Rotation Evaluation):** So sánh cửa sổ phơi nhiễm (exposure window) giữa Fixed Rotation (30 phút) và Adaptive Rotation dưới kịch bản bùng phát tấn công. (Issue #120-#125).
- **Exp6 (Cryptographic Performance & Overhead Benchmark):** Đo lường độ trễ ($\mu s$), mức chiếm dụng CPU/RAM và thông lượng của module AES-256-GCM. (Issue #126, #147).

Cập nhật: 2026-11-17 (Mở rộng kế hoạch thực nghiệm đáp ứng chuẩn 6 Research Questions cho v2.0 — Issue #77)
