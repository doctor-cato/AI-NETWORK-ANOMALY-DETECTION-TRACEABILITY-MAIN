# Báo cáo Huấn luyện Thực nghiệm Random Forest Baseline trên NF-UNSW-NB15-v3 (Issue #10)

- **Issue:** [#10 — Huấn luyện mô hình Random Forest](https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN/issues/10)
- **Pull Request:** [#43](https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN/pull/43)
- **Protocol:** `rf-baseline-nf-unsw-nb15-v3-v1` (Issue #9)
- **Configuration ID:** `rf-baseline-canonical-v1` (`is_canonical_baseline: true`)
- **Run ID:** `rf-baseline-1794068628`
- **Trained At (UTC):** `2026-11-07T16:22:20.836660+00:00`
- **Trạng thái vòng đời:** `IMPLEMENTED` / `TESTED` / `EXPERIMENTALLY VALIDATED` (huấn luyện trên dữ liệu thật `NF-UNSW-NB15-v3`; đánh giá trên tập Test vẫn giữ ở trạng thái `PLANNED` thuộc Issue #12)

---

## 1. Xác minh Prerequisites & Provenance (Fail-Closed Audit)

Toàn bộ các thành phần đầu vào chính thức từ Issue #7 (PR #41) và Issue #8 (PR #42) đã được khôi phục và xác minh SHA-256 byte-for-byte trước khi huấn luyện (`python scripts/train_random_forest.py --verify-only` -> `EXIT_CODE=0`):

| Thành phần | Đường dẫn | Kích thước / Số dòng | SHA-256 thực tế | Trạng thái |
| :--- | :--- | :--- | :--- | :--- |
| **Raw Dataset CSV** | `data/raw/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv` | `577.360.958` bytes (`2.365.424` dòng) | `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5` | **PASS** |
| **Split Manifest** | `reports/splits/nf_unsw_nb15_v3_split_manifest.json` | `nf-unsw-nb15-v3-chronological-group-purged-v1` | `bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88` | **PASS** |
| **Train Indices** | `data/processed/splits/train_indices.csv.gz` | `1.655.797` dòng | `a09ba1757484c65596a88fe22d5bd989a3cca60a01088364020e2f952b36c725` | **PASS** |
| **Purged Train-Val Gap** | `data/processed/splits/purged_train_val_gap_indices.csv.gz` | `9.443` dòng | `3bdf9ef3ee6f62960a61205bf1c98c06786971c913c8dea837764a95742b35a9` | **PASS** |
| **Validation Indices** | `data/processed/splits/validation_indices.csv.gz` | `345.371` dòng | `7d41a71a2a154a46fec4a0095fb277007b6b1574727976ee6593e6d56b9400bf` | **PASS** |
| **Purged Val-Test Gap** | `data/processed/splits/purged_val_test_gap_indices.csv.gz` | `8.860` dòng | `ac7f1de36b7bf1e26fce85869be0c5d0adef5c367eac8dd95f0ce50199e4a7c3` | **PASS** |
| **Test Indices (Locked)** | `data/processed/splits/test_indices.csv.gz` | `345.953` dòng (không nạp khi train) | `63e2e081300955fe06835b0cf7405e07e53985ca3d84164e768be09116269d03` | **PASS** |
| **Preprocessor Artifact** | `artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib` | Fit `train_only` (`1.655.797` dòng, 47 features) | `12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19` | **PASS** |
| **Preprocessor Manifest** | `reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json` | `nf-unsw-nb15-v3-preproc-v1` | `af07dc3b6c7cbc9e75426eeb5b96d52dbd191e8a09161699df2fad1bb5555441` | **PASS** |

---

## 2. Cấu hình Huấn luyện & Môi trường Thực thi

- **Lệnh thực thi:** `python scripts/run_experiments.py --step baseline` (ủy quyền trực tiếp tới `scripts/train_random_forest.py`)
- **Hyperparameters (`CANONICAL_BASELINE_PARAMS`):**
  - `model_type`: `"RandomForest"`
  - `task`: `"binary_classification"`
  - `target`: `"Label"` (`0 = Benign`, `1 = Attack`, `positive_class = "Attack"`)
  - `n_estimators`: `200`
  - `max_depth`: `16`
  - `min_samples_split`: `2`
  - `min_samples_leaf`: `1`
  - `criterion`: `"gini"`
  - `max_features`: `"sqrt"`
  - `class_weight`: `null` (`None`)
  - `random_state`: `42`
  - `n_jobs`: `-1`
  - `bootstrap`: `true`
  - `configuration_id`: `"rf-baseline-canonical-v1"`
  - `is_canonical_baseline`: `true`
- **Feature Contract:** `nf-unsw-nb15-v3-baseline-47` (đúng 47 cột `ML_FEATURE_COLUMNS` theo thứ tự canonical; loại trừ 6 cột `TRACE_METADATA_COLUMNS` và 2 cột `TARGET_COLUMNS`).
- **Môi trường & Tài nguyên:**
  - OS: `Windows-11-10.0.26200-SP0` (12 logical CPUs)
  - Python: `3.14.10` (`numpy==2.5.4`, `pandas==3.1.1`, `scikit-learn==1.9.1`, `joblib==1.6.0`)
  - Thời gian fit mô hình (`training_duration_seconds`): `83.73` giây (các lượt chạy độc lập khác: `87.73` giây và `86.12` giây)
  - Bộ nhớ đỉnh (`peak_memory_mb`): `3.863,41 MB` (~3,77 GB)

---

## 3. Model Artifact & Kiểm tra Tái lập Độc lập (Reload & Determinism Verification)

- **Đường dẫn Model Artifact:** `artifacts/models/random_forest/random_forest_baseline.joblib` (không commit vào Git theo `.gitignore`)
- **Đường dẫn Run Manifest:** `reports/models/random_forest_manifest.json` (và bản sao cục bộ `artifacts/models/random_forest/random_forest_manifest.json`)
- **Kích thước Model Artifact:** `917.227` bytes (~895,7 KB)
- **Model Artifact SHA-256:** `801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea`
- **Tính tất định qua 3 lượt chạy độc lập:**
  - Lượt chạy 1 (`python scripts/run_experiments.py --step baseline`): SHA-256 = `801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea`
  - Lượt chạy 2 (`pytest tests/unit/test_rf_training.py -k test_execute_training_real_data`): SHA-256 = `801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea`
  - Lượt chạy 3 (`python scripts/run_experiments.py --step baseline` — `rf-baseline-1794068628`): SHA-256 = `801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea`
- **Kiểm tra nạp lại (`RandomForestModel.load_verified`):**
  - Trạng thái: `PASSED`
  - Số mẫu Validation đối chiếu: `345.371` dòng
  - `predictions_identical`: `true` (`100%` dự đoán nhãn nhị phân khớp tuyệt đối)
  - `probabilities_allclose`: `true` (`atol=1e-7`, `rtol=0.0`, `max_abs_probability_diff = 2.220446049250313e-16`)
  - `estimator.classes_`: `[0, 1]`, `len(estimator.estimators_) == 200`, `len(feature_names) == 47`

---

## 4. Kết quả Đánh giá trên Tập Validation (`345.371` dòng)

> **Lưu ý phương pháp luận:** Đây là kết quả trên phân vùng **Validation** (`345.371` dòng: `314.871` Benign, `30.500` Attack) phục vụ kiểm tra mô hình sau huấn luyện theo đúng phạm vi Issue #10. Phân vùng **Test** (`345.953` dòng) hoàn toàn không được chạm tới (`test_partition_accessed: false`, `test_rows_loaded: 0`) và chỉ được đánh giá một lần ở Issue #12. Đồng thời, cần lưu ý giới hạn `ml_feature_overlap` đã được kiểm toán ở Issue #7 (`49,98%` dòng Validation chia sẻ vector 47 đặc trưng ML với tập Train do các mẫu lưu lượng giao thức lặp lại theo thời gian, với `binary_label_conflicts = 0`).

### 4.1. Chỉ số tổng hợp trên Validation

| Chỉ số (Metric) | Giá trị chính xác | Giá trị làm tròn (6 chữ số) |
| :--- | :--- | :--- |
| **Precision (Attack = 1)** | `0.9998360763228641` | `0.999836` |
| **Recall (Attack = 1)** | `0.9999016393442623` | `0.999902` |
| **F1-Score (Binary)** | `0.9998688567587948` | `0.999869` |
| **Macro-F1** | `0.9999280765516589` | `0.999928` |
| **False Positive Rate (FPR)** | `1.5879518914094977e-05` | `0.000016` |

### 4.2. Ma trận nhầm lẫn (Confusion Matrix) trên Validation

Thứ tự nhãn chuẩn `[0 = Benign, 1 = Attack]`:

| Thực tế \ Dự đoán | Dự đoán `0` (`Benign`) | Dự đoán `1` (`Attack`) | Tổng thực tế |
| :--- | ---: | ---: | ---: |
| **Thực tế `0` (`Benign`)** | `TN = 314.866` | `FP = 5` | `314.871` |
| **Thực tế `1` (`Attack`)** | `FN = 3` | `TP = 30.497` | `30.500` |
| **Tổng dự đoán** | `314.869` | `30.502` | `345.371` |

### 4.3. Phân rã theo từng họ `Attack` (Per-Category Breakdown) trên Validation

| Loại lưu lượng (`Attack`) | Tổng số dòng | Phát hiện đúng (`TP` / `TN`) | Bỏ lọt / Báo sai (`FN` / `FP`) | Tỷ lệ (`Detection Rate` / `FPR`) |
| :--- | ---: | ---: | ---: | :--- |
| **Analysis** | `285` | `285` (`detected`) | `0` (`missed`) | `1.000000` (`100,00%`) |
| **Backdoor** | `144` | `144` (`detected`) | `0` (`missed`) | `1.000000` (`100,00%`) |
| **DoS** | `1.445` | `1.444` (`detected`) | `1` (`missed`) | `0.999308` (`99,93%`) |
| **Exploits** | `10.294` | `10.293` (`detected`) | `1` (`missed`) | `0.999903` (`99,99%`) |
| **Fuzzers** | `8.495` | `8.495` (`detected`) | `0` (`missed`) | `1.000000` (`100,00%`) |
| **Generic** | `5.137` | `5.136` (`detected`) | `1` (`missed`) | `0.999805` (`99,98%`) |
| **Reconnaissance** | `4.107` | `4.107` (`detected`) | `0` (`missed`) | `1.000000` (`100,00%`) |
| **Shellcode** | `556` | `556` (`detected`) | `0` (`missed`) | `1.000000` (`100,00%`) |
| **Worms** | `37` | `37` (`detected`) | `0` (`missed`) | `1.000000` (`100,00%`) |
| **Benign (Negative Class)** | `314.871` | `314.866` (`true_negative`) | `5` (`false_positive`) | `FPR = 0.000016` (`0,0016%`) |

---

## 5. Kiểm toán Khóa Tập Test (Test Lock Audit — Contract A & Contract B)

- `test_partition_accessed`: `false`
- `test_rows_loaded`: `0`
- `test_indices_loaded`: `false`
- `training_partitions`: `["train", "validation"]`
- `train_rows_loaded`: `1.655.797`
- `val_rows_loaded`: `345.371`
- **Contract A Guarantee:** `PASSED: No Test data is used in fitting, hyperparameter tuning, threshold selection, validation, or model selection.`
- **Contract B Guarantee:** `PASSED: Zero Test partition rows are materialized or converted into DataFrames.`

---

## 6. Trạng thái Acceptance Criteria của Issue #10

| # | Acceptance Criterion (Issue #10) | Bằng chứng xác minh trên dữ liệu thật | Trạng thái |
| :--- | :--- | :--- | :--- |
| **AC1** | Train Random Forest only on the Train partition | Fit duy nhất trên `1.655.797` dòng `train` (`train_indices.csv.gz` SHA-256 `a09ba175...`) | **PASS (REAL DATA)** |
| **AC2** | Apply the fitted Train-only preprocessing pipeline | Nạp và xác minh `nf_unsw_nb15_v3_preprocessor.joblib` (`12d4360a...`), chỉ gọi `.transform()` | **PASS (REAL DATA)** |
| **AC3** | Save trained model artifact and metadata to `artifacts/` | Lưu `artifacts/models/random_forest/random_forest_baseline.joblib` (`917.227` bytes, SHA-256 `801afcbb...`) và `random_forest_manifest.json` | **PASS (REAL DATA)** |
| **AC4** | Record hyperparameters, feature list, class mapping, and random seed | Ghi đầy đủ trong `reports/models/random_forest_manifest.json` (`n_estimators=200`, `max_depth=16`, `seed=42`, `n_jobs=-1`, 47 features, `{"0": "Benign", "1": "Attack"}`) | **PASS (REAL DATA)** |
| **AC5** | Verify that reloaded model reproduces identical predictions | `RandomForestModel.load_verified()` kiểm tra trên `345.371` dòng Validation: nhãn trùng `100%`, xác suất `max_abs_probability_diff = 0.0` (`atol=1e-7`, `rtol=0`) | **PASS (REAL DATA)** |
| **AC6** | Evaluate model selection decisions only on Validation | Đánh giá duy nhất trên `345.371` dòng Validation (`F1=0.999869`, `Macro-F1=0.999928`, `FPR=0.000016`) | **PASS (REAL DATA)** |
| **AC7** | Keep the Test set untouched until final evaluation | `test_partition_accessed=false`, `test_rows_loaded=0`, `test_indices_loaded=false` | **PASS (REAL DATA)** |
