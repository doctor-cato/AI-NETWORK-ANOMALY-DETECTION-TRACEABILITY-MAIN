# NF-UNSW-NB15-v3 XGBoost Supervised Baseline Protocol

**Issue:** #31 — Triển khai XGBoost theo protocol supervised dùng chung với Random Forest (Checkpoint C3)<br>
**Status:** Protocol & Configuration: `IMPLEMENTED / TESTED` (Issue #31); Model Training: `BLOCKED` (chờ dataset raw và preprocessor artifact materialized tại môi trường cục bộ/CI); Held-out Test Evaluation: `PLANNED` (Issue #12); Real Split: `PASS (PR #41)`; Preprocessing Artifact: `PASS (PR #42)`.<br>
**Protocol Identifier:** `xgb-baseline-nf-unsw-nb15-v3-v1`<br>
**Feature Contract Version:** `nf-unsw-nb15-v3-baseline-47`<br>
**Split Protocol Reference:** `nf-unsw-nb15-v3-chronological-group-purged-v1` (PR #41)<br>
**Preprocessing Contract Reference:** `nf-unsw-nb15-v3-preproc-v1` (PR #42)

---

## 1. Mục tiêu và Phạm vi

Issue #31 triển khai mô hình **XGBoost (XGBClassifier)** có giám sát trên tập dữ liệu **NF-UNSW-NB15-v3**, hoàn toàn nhất quán về mặt giao thức, giao diện lập trình, chính sách cách ly và tiêu chuẩn đánh giá với Random Forest baseline (Issue #9, #10).

Mô hình này đóng vai trò là ứng viên cạnh tranh trực tiếp (candidate model) với Random Forest trong **Nghiên cứu Thực nghiệm #1** (Random Forest vs XGBoost) được quy định tại `docs/EXPERIMENT_PLAN.md`.

> [!IMPORTANT]
> - KHÔNG tự tạo metrics giả, prediction giả hoặc benchmark fake.
> - KHÔNG sử dụng synthetic data để mô phỏng kết quả benchmark.
> - Huấn luyện thực tế chỉ được unblock khi các artifact dữ liệu thật được nạp đầy đủ.

---

## 2. Dataset Contract & Feature Policy (Quy chuẩn 47 đặc trưng)

XGBoost tuân thủ cùng hợp đồng dữ liệu chuẩn xác như Random Forest:
- **Tập dữ liệu:** `NF-UNSW-NB15-v3` (2.365.424 flows).
- **Target chính:** `Label` (nhị phân: `0 = Benign`, `1 = Attack`).
- **Lớp dương tính (Positive Class):** `Attack` (Label = 1).
- **Lớp âm tính (Negative Class):** `Benign` (Label = 0).
- **Ma trận đầu vào X:** Đúng **47 đặc trưng NetFlow v3** (`ML_FEATURE_COLUMNS`).
- **Cột loại trừ:**
  - 6 cột `TRACE_METADATA_COLUMNS`: `FLOW_START_MILLISECONDS`, `FLOW_END_MILLISECONDS`, `IPV4_SRC_ADDR`, `IPV4_DST_ADDR`, `L4_SRC_PORT`, `L4_DST_PORT` (dành riêng cho Trace Engine).
  - 2 cột nhãn: `Label`, `Attack`.

---

## 3. Cấu hình Baseline XGBoost (`CANONICAL_BASELINE_PARAMS`)

Mô hình: `xgboost.XGBClassifier`.
Cấu hình baseline canonical được khóa cố định nhằm đảm bảo tính tái lập tuyệt đối (reproducibility):

| Tham số | Giá trị khóa | Ý nghĩa / Ghi chú |
| :--- | :--- | :--- |
| `n_estimators` | `200` | Số lượng boosting rounds (đồng bộ quy mô với RF) |
| `max_depth` | `6` | Độ sâu tối đa mỗi cây gradient boosted (chuẩn cân bằng bias/variance) |
| `learning_rate` | `0.1` | Tốc độ học (eta) |
| `subsample` | `0.8` | Tỷ lệ lấy mẫu dòng ngẫu nhiên mỗi cây để chống overfitting |
| `colsample_bytree` | `0.8` | Tỷ lệ lấy mẫu cột ngẫu nhiên mỗi cây |
| `objective` | `"binary:logistic"` | Hàm mục tiêu hồi quy logistic cho nhị phân |
| `eval_metric` | `"logloss"` | Thước đo đánh giá tối ưu nội bộ |
| `tree_method` | `"hist"` | Thuật toán xây dựng cây histogram nhanh, tối ưu cho CPU (XGBoost ≥ 2.0) |
| `random_state` | `42` | Seed cố định đồng bộ toàn repository (`RANDOM_SEED`) |
| `n_jobs` | `-1` | Khóa tối đa hóa năng lực xử lý đa nhân CPU |
| `configuration_id` | `"xgb-baseline-canonical-v1"` | Định danh cấu hình canonical baseline được khóa |
| `is_canonical_baseline` | `True` | Cờ bảo vệ ngăn chặn thay đổi tham số không kiểm soát |

---

## 4. Test Lock Policy & Tuning Isolation

- **Test Lock Policy:** Áp dụng nguyên tắc tương tự Issue #9:
  - Tập `test` (345.953 dòng) tuyệt đối **bị khóa**, không được nạp vào bộ nhớ hoặc dùng cho feature selection, tuning, threshold calibration hay fitting.
  - Test chỉ dùng đúng 1 lần cho đánh giá cuối cùng độc lập (one-shot final evaluation) ở Issue #12.
- **Tuning Policy:** Quá trình hyperparameter tuning (nếu có) chỉ được diễn ra trong ranh giới tập `train` và `validation`.

---

## 5. Kiến trúc Thành phần (Component Parity với RandomForestModel)

Class `XGBoostModel` tại `src/network_anomaly/models/xgboost_model.py` cung cấp đầy đủ các interface:
- `__init__(config=None, protocol=None)`
- `build_model()`
- `fit(X, y)`
- `predict(X)`
- `predict_proba(X)`
- `save(model_path, manifest_path=None)`
- `load(model_path)`
- `load_verified(model_path, manifest_path=None)`: kiểm tra toàn vẹn SHA-256 byte-for-byte fail-closed trước khi nạp model vào bộ nhớ.
- `classes_`: class labels known to classifier.
