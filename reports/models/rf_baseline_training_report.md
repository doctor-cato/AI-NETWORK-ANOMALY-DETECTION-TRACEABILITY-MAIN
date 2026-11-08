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
- **Tính tất định qua 3 lượt chạy độc lập (do tác giả ghi nhận; một lượt retrain độc lập trong audit bằng `test_execute_training_real_data` cũng cho SHA-256 trùng, cùng môi trường Windows/Python 3.14.10/scikit-learn 1.9.1):**
  - Lượt chạy 1 (`python scripts/run_experiments.py --step baseline`): SHA-256 = `801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea`
  - Lượt chạy 2 (`pytest tests/unit/test_rf_training.py -k test_execute_training_real_data`): SHA-256 = `801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea`
  - Lượt chạy 3 (`python scripts/run_experiments.py --step baseline` — `rf-baseline-1794068628`): SHA-256 = `801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea`
- **Kiểm tra nạp lại (`RandomForestModel.load_verified`):**
  - Trạng thái: `PASSED`
  - Số mẫu Validation đối chiếu: `345.371` dòng
  - `predictions_identical`: `true` (`100%` dự đoán nhãn nhị phân khớp tuyệt đối)
  - `probabilities_allclose`: `true` (`atol=1e-7`, `rtol=0.0`, `max_abs_probability_diff = 2.220446049250313e-16`, khớp `reload_verification.max_abs_probability_diff` trong run manifest; giá trị khác 0 do cộng gộp xác suất đa luồng với `n_jobs=-1`, đã được tái hiện độc lập trong audit và nằm trong dung sai)
  - `estimator.classes_`: `[0, 1]`, `len(estimator.estimators_) == 200`, `len(feature_names) == 47`

---

## 4. Kết quả Đánh giá trên Tập Validation (`345.371` dòng)

> **Lưu ý phương pháp luận:** Đây là kết quả trên phân vùng **Validation** (`345.371` dòng: `314.871` Benign, `30.500` Attack) phục vụ kiểm tra mô hình sau huấn luyện theo đúng phạm vi Issue #10. Phân vùng **Test** (`345.953` dòng) hoàn toàn không được chạm tới (`test_partition_accessed: false`, `test_rows_loaded: 0`) và chỉ được đánh giá một lần ở Issue #12. Đồng thời, cần lưu ý giới hạn `ml_feature_overlap` đã được kiểm toán ở Issue #7 (`49,98%` dòng Validation chia sẻ vector 47 đặc trưng ML với tập Train do các mẫu lưu lượng giao thức lặp lại theo thời gian, với `binary_label_conflicts = 0`).

### 4.1. Chỉ số tổng hợp trên Validation

| Chỉ số (Metric) | Giá trị chính xác | Giá trị làm tròn (6 chữ số) |
| :--- | :--- | :--- |
| **Accuracy (Overall)** | `0.9999768365033543` (`345.363 / 345.371`) | `0.999977` (`99,9977%`) |
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

Bảng dưới đây lấy **nguyên văn 7 Acceptance Criteria** trong body của [Issue #10](https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN/issues/10) (đối chiếu ngày 2026-11-08). Cột "Nguồn bằng chứng" phân biệt `ĐỘC LẬP` (audit chạy lại trực tiếp trên dữ liệu/artifact thật, chỉ Train/Validation) với `MANIFEST` (chỉ dựa trên giá trị tự ghi trong run manifest, chưa tái hiện được từ bên ngoài). Chi tiết chẩn đoán ở Mục 7 và [`rf_baseline_validation_audit.json`](rf_baseline_validation_audit.json).

| # | Acceptance Criterion (nguyên văn Issue #10) | Bằng chứng thực tế | Nguồn bằng chứng | Trạng thái |
| :--- | :--- | :--- | :--- | :--- |
| **AC1** | Prerequisite check xác minh fail-closed: dừng lại ngay khi thiếu dataset hoặc preprocessor artifact. | `python scripts/train_random_forest.py --verify-only` → `EXIT=0` với đủ prerequisites (đường PASS); đường fail-closed được kiểm bằng `test_check_prerequisites_detects_missing_files`, `test_check_prerequisites_detects_hash_mismatch` và các test `check_prerequisites` khác (PASS trong full pytest). | ĐỘC LẬP (lệnh + pytest); đường fail trên dữ liệu giả lập trong test, không phá hủy dữ liệu thật | **PASS** |
| **AC2** | Preprocessor được tái sử dụng nguyên trạng từ Issue #8 (không fit lại). | `execute_training()` chỉ gọi `TrainOnlyPreprocessor.load_verified()` và `.transform()`; trong `scripts/train_random_forest.py` chỉ có `model.fit(...)`, không có `preprocessor.fit`. SHA-256 preprocessor `12d4360a…` khớp manifest; `fit_partition = train_only`; `scaler_type = none`, không có missing indicators. | ĐỘC LẬP (đọc code + nạp artifact đã xác minh) | **PASS** |
| **AC3** | Huấn luyện RF trên đúng 1.655.797 dòng tập train với đúng 47 đặc trưng ML. | Audit nạp lại `train_indices.csv.gz` (SHA-256 khớp split manifest): `1.655.797` dòng, duy nhất, rời nhau với Validation; ma trận sau transform `(1.655.797, 47)`, tên cột = `ML_FEATURE_COLUMNS` đúng thứ tự; `estimator.n_features_in_ = 47`, `feature_names_in_` và `selected_features` trong manifest cùng bằng contract. Việc "model đã được fit đúng trên các dòng này" được hỗ trợ gián tiếp: retrain độc lập cho cùng SHA-256 artifact. | ĐỘC LẬP | **PASS** |
| **AC4** | Tập test bị khóa tuyệt đối, không tham gia vào huấn luyện hay chọn mô hình. | Code: `load_partition("test")` ném `PermissionError`; `stream_partition_data` bỏ qua dòng ngoài Train/Validation ở mức text, không parse. Test `test_stream_partition_data_strict_test_isolation` PASS. Manifest: `test_partition_accessed=false`, `test_rows_loaded=0`, `test_indices_loaded=false`. Audit độc lập không mở file test indices và không đọc Test. | Code/test: ĐỘC LẬP; bộ đếm `test_*` trong manifest: MANIFEST (tự báo cáo, không chứng minh được ở runtime). Lưu ý: prerequisite check có băm SHA-256 file `test_indices.csv.gz` (không nạp chỉ số) và việc duyệt CSV vẫn đọc byte của các dòng Test để bỏ qua. | **PASS (có giới hạn)** |
| **AC5** | Model artifact được lưu kèm manifest ghi rõ SHA-256, commit, môi trường, thời gian và cấu hình. | Run manifest có `model_artifact_sha256` (`801afcbb…`, khớp SHA-256 tính lại từ file `.joblib` `917.227` bytes), `environment.git_commit = 6f50633544ccbf93fa4dd193355c1d8222360e37` (commit chứa mã huấn luyện; `git diff 6f50633 35c135d` chỉ chứa docs/report), `environment` (Python, platform, CPU, gói), `trained_at_utc`, `training_duration_seconds`, `hyperparameters`, `random_state`, class mapping, 47 features. Bản `artifacts/.../random_forest_manifest.json` và `reports/models/random_forest_manifest.json` giống hệt. | ĐỘC LẬP (tính lại hash, so khớp trường) | **PASS** |
| **AC6** | Model sau khi lưu nạp lại được và dự đoán nhất quán trên tập validation. | `RandomForestModel.load_verified()` → PASS. Audit tính lại dự đoán trên `345.371` dòng Validation từ artifact đã nạp: confusion matrix `[[314866, 5], [3, 30497]]` trùng manifest. `max_abs_probability_diff` ghi trong manifest `= 2.220446049250313e-16` (không phải `0.0`), audit tái hiện đúng độ lệch này khi gọi `predict_proba` lặp lại với `n_jobs=-1` (và `0.0` với `n_jobs=1`), trong dung sai `atol=1e-7`. So sánh model trong bộ nhớ trước khi lưu với model sau nạp lại chỉ được ghi trong manifest (MANIFEST); audit bổ sung retrain độc lập cho cùng SHA-256. | ĐỘC LẬP (load, metric, hash) + MANIFEST (so sánh trước/sau khi lưu) | **PASS** |
| **AC7** | Toàn bộ unit và integration tests PASS. | `python -m pytest tests -q` trên working tree cuối cùng: `397 passed, 2 skipped` (bao gồm 7 unit tests mới trong `tests/unit/test_audit_rf_validation_diagnostics.py`; 2 test symlink bị skip do thiếu quyền symlink trên máy Windows cục bộ; CI Ubuntu/Windows × Python 3.11/3.12 và job `audit` đều PASS). `test_execute_training_real_data` chạy thật trên dữ liệu NF-UNSW-NB15-v3. | ĐỘC LẬP | **PASS** (kèm 2 SKIPPED) |

> **Giới hạn cần đọc cùng bảng:** các AC trên xác nhận quy trình, tính toàn vẹn và khả năng tái lập của baseline; **không** xác nhận Validation Accuracy `99,9977%` phản ánh khả năng tổng quát hóa ngoài testbed. Xem Mục 7 dưới đây để đối chiếu các giả thuyết bằng dữ liệu thực. Kết quả Test (Issue #12) chưa tồn tại.

---

## 7. Kiểm toán Chẩn đoán Độc lập về Validation Accuracy 99,9977% (Train/Validation Only)

Audit độc lập được thực thi qua script [`scripts/audit_rf_validation_diagnostics.py`](../../scripts/audit_rf_validation_diagnostics.py) và xuất toàn bộ bằng chứng định lượng ra [`reports/models/rf_baseline_validation_audit.json`](rf_baseline_validation_audit.json) (tuyệt đối không mở `test_indices.csv.gz` hay truy cập phân vùng Test, và không sửa đổi canonical baseline).

### Phân biệt rõ Mô hình Canonical Baseline (200 cây) và các Mô hình Chẩn đoán (60 cây / Decision Tree)

Để tránh nhầm lẫn giữa mô hình chính thức của Issue #10 và các mô hình thử nghiệm dùng trong quá trình kiểm toán nguyên nhân đạt `99,9977%`, bảng dưới đây quy định rõ vai trò của từng nhóm mô hình trong báo cáo này:

| Nhóm mô hình | Lớp Estimator (`scikit-learn`) | Số cây (`n_estimators`) | Độ sâu tối đa (`max_depth`) | `is_canonical_baseline` | Vai trò và phạm vi sử dụng |
| :--- | :--- | ---: | ---: | :--- | :--- |
| **Canonical Random Forest Baseline (`rf-baseline-canonical-v1`)** | `RandomForestClassifier` | **`200` cây** | `16` | `True` | **Mô hình chính thức duy nhất của Issue #10**, lưu tại `artifacts/models/random_forest/random_forest_baseline.joblib` (SHA-256 `801afcbb…`). Dùng cho toàn bộ kết quả ở Mục 3, 4, 6, phân tầng overlap ở Mục 7.2, và phân tích feature importance ở Mục 7.3. |
| **Mô hình Random Forest chẩn đoán (`C0`–`C7`)** | `RandomForestClassifier` | **`60` cây** | `16` | `False` | Mô hình chẩn đoán tạm thời trong RAM (fit chỉ trên Train, chấm trên Validation) để kiểm tra độ nhạy khi loại bỏ đặc trưng (`C1`–`C5`), khử trùng lặp fingerprint (`C6`), hoặc hoán vị nhãn (`C7`). **Không phải canonical baseline** và không lưu đè artifact. |
| **Cây quyết định đơn chẩn đoán (`C8`, `C9` và Single-Feature Trees)** | `DecisionTreeClassifier` | **`1` cây** | `3` (`C8`), `8` (`C9`), `6` (đơn biến Mục 7.3) | `False` | Mô hình chẩn đoán độ phức tạp thấp để đo trực tiếp mức độ phân tách ngưỡng đơn giản của từng đặc trưng (như `MIN_TTL`, `MAX_TTL`) hoặc tổ hợp đặc trưng nông trên dữ liệu lab. |

### 7.1. Kiểm tra Feature Order, Preprocessing, Split và Label Alignment

- **Ranh giới Split & Thứ tự dòng (`PASS`):**
  - `train_indices.csv.gz` (`1.655.797` dòng, SHA-256 khớp manifest) và `validation_indices.csv.gz` (`345.371` dòng, SHA-256 khớp manifest) hoàn toàn duy nhất (`indices_unique = true`) và rời nhau tuyệt đối (`train_val_disjoint = true`).
  - Ranh giới thời gian nghiêm ngặt: `max(FLOW_END_MILLISECONDS)` trên Train = `1.424.238.197.221`, `min(FLOW_START_MILLISECONDS)` trên Validation = `1.424.238.433.386`, khoảng cách an toàn `train_end_to_validation_start_margin_ms = +236.165 ms` (~3,94 phút), `canonical_flow_group_overlap = 0`.
  - Lưu ý thực thể mạng lặp lại theo thời gian (đã loại khỏi 47 features nhưng được kiểm tra bằng metadata): `100,0%` dòng Validation có `IPV4_SRC_ADDR` từng xuất hiện trong Train, `99,999%` có cặp `(IPV4_SRC_ADDR, IPV4_DST_ADDR)` từng xuất hiện trong Train, và `86,484%` có `(IPV4_DST_ADDR, L4_DST_PORT)` từng xuất hiện trong Train — đặc trưng của mạng lab cố định số lượng máy trạm giả lập trong UNSW-NB15.
- **Label Alignment (`PASS`):**
  - Cả trên Train và Validation: `Attack == "Benign"` tương đương tuyệt đối 1-1 với `Label == 0` (`benign_iff_label_0 = true`, 0 dòng mâu thuẫn).
  - Cột `Label` và `Attack` bị loại hoàn toàn khỏi ma trận 47 đặc trưng (`excluded_targets = ["Label", "Attack"]`).
- **Feature Order & Preprocessing (`PASS`):**
  - `list(X_train.columns) == list(X_val.columns) == list(ML_FEATURE_COLUMNS) == list(model.feature_names) == list(estimator.feature_names_in_)` (47 đặc trưng đúng thứ tự).
  - Preprocessor có `scaler_type = "none"`, `add_missing_indicators = false`, `constant_features_in_train = []`; chỉ thực hiện impute bằng thống kê của Train và giữ nguyên giá trị số của 47 đặc trưng.

### 7.2. Phân tầng Validation theo ML-Feature Fingerprint trùng vs. không trùng với Train

Trên `345.371` dòng Validation, có `172.621` dòng (`49,9813%`, thuộc `61.007` fingerprint phân biệt) có vector 47 đặc trưng ML xuất hiện nguyên mẫu trong Train (`551.167` dòng Train liên quan), và `172.750` dòng (`50,0187%`) có vector 47 đặc trưng **hoàn toàn mới** (chưa từng xuất hiện trong Train):

| Tập con Validation | Số dòng (`n`) | Số dòng `Attack` | `TN` | `FP` | `FN` | `TP` | Accuracy | Precision | Recall | F1-Score | FPR | ROC-AUC |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| **Toàn bộ Validation** | `345.371` | `30.500` | `314.866` | `5` | `3` | `30.497` | `0.999977` | `0.999836` | `0.999902` | `0.999869` | `0.000016` | `1.000000` |
| **Có fingerprint trùng Train (`49,98%`)** | `172.621` | `7.853` | `164.768` | `0` | `0` | `7.853` | `1.000000` | `1.000000` | `1.000000` | `1.000000` | `0.000000` | `1.000000` |
| **Không trùng fingerprint Train (`50,02%`)** | `172.750` | `22.647` | `150.098` | `5` | `3` | `22.644` | `0.999954` | `0.999779` | `0.999868` | `0.999823` | `0.000033` | `1.000000` |

- **Nhận định từ dữ liệu thực:**
  1. Trên `172.621` dòng trùng fingerprint với Train, một bảng tra cứu thuần túy (memorisation lookup table) theo fingerprint của Train cũng đạt `Accuracy = 1.000000` vì `binary_label_conflicts = 0` (cả trong nội bộ Train trên `901.373` fingerprint phân biệt lẫn giữa Train và Validation). Do đó, việc đạt `100%` trên nửa dữ liệu trùng fingerprint không chứng minh được khả năng tổng quát hóa.
  2. Tuy nhiên, trên **`172.750` dòng Validation có vector 47 đặc trưng chưa từng xuất hiện trong Train** (bao gồm `22.647 / 30.500 = 74,25%` tổng số dòng Attack của Validation), mô hình vẫn đạt `Accuracy = 99,9954%` (`F1 = 0.999823`, chỉ sai `8` dòng: `5 FP` và `3 FN`). Toàn bộ 8 lỗi trên Validation đều nằm ở nhóm không trùng fingerprint.
  3. Như vậy, **ghi nhớ mẫu trùng (sample memorisation) chỉ giải thích sự vắng mặt của lỗi trên nửa dữ liệu trùng (`172.621` dòng), nhưng KHÔNG giải thích được tại sao `172.750` dòng có vector đặc trưng hoàn toàn mới vẫn đạt `99,9954%`**.

### 7.3. Kiểm tra Feature Importances và Đặc trưng Phân tách Mạnh của Testbed (Shortcut Features)

1. **Top Impurity Importance trong Canonical RF:**
   - `MAX_TTL` (`0.229569`), `MIN_TTL` (`0.225260`), `SHORTEST_FLOW_PKT` (`0.125933`), `MIN_IP_PKT_LEN` (`0.124349`), `DST_TO_SRC_AVG_THROUGHPUT` (`0.048880`), `NUM_PKTS_UP_TO_128_BYTES` (`0.028071`), `OUT_BYTES` (`0.020105`), `SRC_TO_DST_SECOND_BYTES` (`0.018321`), `SERVER_TCP_FLAGS` (`0.017361`), `LONGEST_FLOW_PKT` (`0.017098`).
   - Riêng 2 đặc trưng `MAX_TTL` + `MIN_TTL` chiếm **`45,48%`** tổng độ giảm bất thuần Gini; 4 đặc trưng đầu (`MAX_TTL`, `MIN_TTL`, `SHORTEST_FLOW_PKT`, `MIN_IP_PKT_LEN`) chiếm **`70,51%`**.
2. **Permutation Importance trên Validation (mẫu ngẫu nhiên cố định `60.000` dòng):**
   - Chỉ có 3 đặc trưng khi hoán vị đơn lẻ làm giảm Accuracy đáng kể: `MIN_TTL` (`-0.007567`), `SERVER_TCP_FLAGS` (`-0.006650`), `MAX_TTL` (`-0.005267`); các đặc trưng khác giảm `< 0.00002` do tính dư thừa tương quan giữa các nhóm đặc trưng lưu lượng.
3. **Cây quyết định đơn đặc trưng (Single-Feature Depth-6 Tree fit chỉ trên Train, đánh giá trên Validation):**
   - Chỉ riêng **`MIN_TTL`** đạt `Validation Accuracy = 0.999849` (`99,9849%`, `ROC-AUC = 0.999982`, so với majority baseline `91,1689%`).
   - Chỉ riêng **`MAX_TTL`** đạt `Validation Accuracy = 0.999664` (`99,9664%`, `ROC-AUC = 0.999956`).
   - Chỉ riêng **`SHORTEST_FLOW_PKT`** đạt `Validation Accuracy = 0.996256` (`ROC-AUC = 0.983039`); **`MIN_IP_PKT_LEN`** đạt `Validation Accuracy = 0.980354` (`ROC-AUC = 0.996660`).
4. **Phân phối thực nghiệm `MIN_TTL` theo nhãn (`ttl_value_vs_label`):**
   - Trong môi trường giả lập IXIA PerfectStorm của UNSW-NB15, các giao diện sinh lưu lượng bình thường (Benign) và giao diện sinh tấn công (Attack) đi qua số bước nhảy định tuyến (hop count) và ngăn xếp IP khởi tạo TTL khác nhau:
     - `MIN_TTL == 31`: Train có `1.572.911` dòng (`0` Attack = `100,00% Benign`); Validation có `308.033` dòng (`0` Attack = `100,00% Benign`, chiếm `97,83%` toàn bộ Benign của Validation).
     - `MIN_TTL in {62, 254, 255}`: Train có `65.090` dòng thì `65.087` là Attack (`99,995% Attack`, chiếm `99,84%` toàn bộ Attack của Train); Validation có `30.450` dòng thì `30.449` là Attack (`99,997% Attack`, chiếm `99,83%` toàn bộ Attack của Validation).
     - Các giá trị còn lại (`MIN_TTL == 0` có `51` Attack / `6.461` dòng trên Validation; `MIN_TTL in {1, 29, 60, 63, 64, 252}` đều `100% Benign`).
   - Đây **không phải lỗi rò rỉ dữ liệu trong pipeline code** (vì `MIN_TTL` và `MAX_TTL` là trường header IP hợp lệ trong contract 47 đặc trưng của NF-UNSW-NB15-v3), mà là **đặc tính cấu trúc của testbed tổng hợp UNSW-NB15** (synthetic lab artifact / shortcut feature).

### 7.4. Kết quả 10 Diagnostic Tests chỉ dùng Train/Validation (`C0`–`C9`) và Phân tách 3 Cơ chế

Để kiểm tra xem mô hình có phụ thuộc hoàn toàn vào TTL hoặc vào các fingerprint trùng hay không, 10 thí nghiệm chẩn đoán độc lập (tất cả đều có `is_canonical_baseline = False`, chỉ fit trên Train và đo trên Validation, tuyệt đối không thay thế canonical baseline 200 cây) đã được thực thi:

| Mã | Mô hình chẩn đoán (`is_canonical=False`) | Thiết kế chẩn đoán (Train/Validation only) | Accuracy (All Val) | F1 (All Val) | `FP` / `FN` (All Val) | Accuracy (Trùng FP) | Accuracy (Không trùng FP) | `FP` / `FN` (Không trùng FP) |
| :--- | :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: |
| **C0** | `RF (60 cây, depth=16)` | Baseline chẩn đoán (đủ 47 features, 60 cây) | `0.999980` | `0.999885` | `4 / 3` | `1.000000` | `0.999959` | `4 / 3` |
| **C1** | `RF (60 cây, depth=16)` | Loại bỏ `MIN_TTL`, `MAX_TTL` (còn 45 features) | `0.999928` | `0.999590` | `14 / 11` | `0.999988` | `0.999867` | `12 / 11` |
| **C2** | `RF (60 cây, depth=16)` | Loại bỏ Top-3 Impurity (`MAX_TTL`, `MIN_TTL`, `SHORTEST_FLOW_PKT`) | `0.999919` | `0.999541` | `14 / 14` | `0.999988` | `0.999849` | `12 / 14` |
| **C3** | `RF (60 cây, depth=16)` | Loại bỏ Top-5 Impurity (`+ MIN_IP_PKT_LEN`, `DST_TO_SRC_AVG_THROUGHPUT`) | `0.999916` | `0.999525` | `16 / 13` | `0.999988` | `0.999844` | `14 / 13` |
| **C4** | `RF (60 cây, depth=16)` | Loại bỏ `TCP_WIN_MAX_IN`, `TCP_WIN_MAX_OUT` (còn 45 features) | `0.999986` | `0.999918` | `2 / 3` | `1.000000` | `0.999971` | `2 / 3` |
| **C5** | `RF (60 cây, depth=16)` | Loại bỏ Top-10 Impurity (còn 37 features) | `0.999902` | `0.999443` | `20 / 14` | `0.999983` | `0.999821` | `18 / 13` |
| **C6** | `RF (60 cây, depth=16)` | **Khử trùng lặp xuyên tập:** Xóa toàn bộ `551.167` dòng Train có fingerprint xuất hiện trong Validation (fit trên `1.104.630` dòng Train còn lại) | `0.999699` | `0.998297` | `93 / 11` | `0.999461` | `0.999936` | `8 / 3` |
| **C7** | `RF (60 cây, depth=16)` | **Label-shuffle sanity control:** Hoán vị ngẫu nhiên `y_train` (`seed=7`) | `0.911689` | `0.000000` | `0 / 30500` | `0.954507` | `0.868903` | `0 / 22647` |
| **C8** | `DecisionTree (1 cây, depth=3)` | Một cây quyết định nông độ sâu tối đa `3` | `0.999655` | `0.998052` | `100 / 19` | `0.999861` | `0.999450` | `84 / 11` |
| **C9** | `DecisionTree (1 cây, depth=8)` | Một cây quyết định đơn độ sâu tối đa `8` | `0.999870` | `0.999263` | `41 / 4` | `0.999913` | `0.999826` | `26 / 4` |

#### Phân định rõ 3 cơ chế: Code/Pipeline Leakage vs. Fingerprint Memorisation vs. Dataset-Specific Shortcuts

1. **Rò rỉ trong mã nguồn hoặc quy trình tiền xử lý (Code / Pipeline Leakage — KHÔNG PHÁT HIỆN):**
   - Được loại trừ bằng **kiểm tra trực tiếp mã nguồn và dữ liệu ở Mục 7.1** (chứ không dựa vào `C7`): cột `Label` và `Attack` bị loại tuyệt đối khỏi 47 đặc trưng; chỉ số Train và Validation rời nhau hoàn toàn (`train_val_disjoint = true`); khoảng cách thời gian giữa dòng Train cuối cùng và dòng Validation đầu tiên là `+236.165 ms` (`canonical_flow_group_overlap = 0`); `TrainOnlyPreprocessor` chỉ fit trên Train (`scaler_type = "none"`, không tạo missing indicator); và tập Test không bị nạp (`test_partition_accessed = false`).
   - **Giới hạn diễn giải bắt buộc đối với `C7` (Label-Shuffle Control):** Khi hoán vị ngẫu nhiên `y_train` (`C7`), mô hình 60 cây dự đoán toàn bộ lớp đa số (`Benign`), `Recall = 0.0`, `F1 = 0.0`, `ROC-AUC = 0.496863`, `Accuracy = 0.911689` (đúng bằng tỷ lệ Benign của Validation). Kết quả này **chỉ xác nhận cơ chế huấn luyện/chấm điểm không đọc nhầm `y_val` và ma trận đặc trưng không chứa bản sao hậu-hoán-vị của nhãn**. **Tuyệt đối không dùng `C7` để tuyên bố đã chứng minh hoàn toàn không có data leakage** (vì label-shuffle control tự nó không thể phát hiện hiện tượng trùng lặp mẫu Train–Validation hoặc rò rỉ thống kê tiền xử lý nếu không có các bước kiểm định độc lập ở Mục 7.1, 7.2 và `C6`).
2. **Ghi nhớ mẫu trùng đặc trưng (Fingerprint Memorisation — CÓ HIỆN DIỆN TRÊN 49,98% VALIDATION NHƯNG KHÔNG PHẢI NGUYÊN NHÂN DUY NHẤT):**
   - `172.621 / 345.371` dòng Validation (`49,9813%`) có vector 47 đặc trưng trùng hệt với ít nhất một dòng trong Train (`binary_label_conflicts = 0`), nên cả canonical RF (200 cây) lẫn bảng tra cứu (lookup table) đều đạt `Accuracy = 1.000000` trên tập con này.
   - Tuy nhiên, trên **`172.750` dòng Validation có fingerprint hoàn toàn mới** (`50,0187%`, chứa `22.647 / 30.500 = 74,25%` tổng số Attack của Validation), canonical RF (200 cây) vẫn đạt `Accuracy = 0.999954` (`F1 = 0.999823`, chỉ `5 FP` và `3 FN`).
   - Hơn nữa, trong thí nghiệm **`C6`** (xóa sạch `551.167` dòng Train chia sẻ fingerprint với Validation, chỉ fit mô hình 60 cây trên `1.104.630` dòng Train còn lại), mô hình vẫn đạt `Accuracy = 0.999461` (`F1 = 0.994108`) trên chính `172.621` dòng từng trùng và `0.999699` (`F1 = 0.998297`) trên toàn bộ Validation. Do đó, ghi nhớ mẫu trùng chỉ giải thích việc không có lỗi trên nửa dữ liệu trùng, không giải thích được hiệu năng `99,9954%` trên nửa dữ liệu hoàn toàn mới.
3. **Đặc trưng lối tắt của testbed tổng hợp (Dataset-Specific Shortcuts / Synthetic Lab Separability — NGUYÊN NHÂN CHÍNH):**
   - Trong môi trường lab IXIA PerfectStorm của UNSW-NB15, kiến trúc định tuyến giữa máy phát lưu lượng bình thường và máy phát tấn công làm cho riêng `MIN_TTL` phân tách `99,9849%` Validation với một cây đơn độ sâu `6` (`MIN_TTL == 31` là `100% Benign`; `MIN_TTL in {62, 254, 255}` là `99,997% Attack`). Một cây quyết định nông 3 tầng (`C8`) cũng đạt `99,9655%`.
   - Ngay cả khi loại bỏ `MIN_TTL` & `MAX_TTL` (`C1`, `Acc = 0.999928`, `F1 = 0.999590`) hoặc loại bỏ toàn bộ 10 đặc trưng quan trọng nhất (`C5`, `Acc = 0.999902`, `F1 = 0.999443`, chỉ `20 FP` và `14 FN` trên `345.371` dòng), mô hình 60 cây vẫn vượt `99,99%` vì các luồng lưu lượng tổng hợp trong cùng ngày thu thập `2015-02-18` đồng thời tách biệt rất mạnh trên nhiều chiều kích thước gói tin (`SHORTEST_FLOW_PKT`, `MIN_IP_PKT_LEN`, `LONGEST_FLOW_PKT`), thông lượng, cờ TCP, cửa sổ TCP và IAT.

### 7.5. Phân định Bằng chứng Độc lập, Dữ kiện chỉ có trong Manifest và Giới hạn chưa thể kết luận

- **Kết quả đã được xác minh độc lập (Independently Verified):**
  - Toàn bộ chữ ký SHA-256 của raw dataset, split manifest, các tệp chỉ số phân vùng, preprocessor artifact và model artifact `.joblib` (`801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea`).
  - `RandomForestModel.load_verified()` PASS; cấu trúc estimator (200 cây, `max_depth=16`, 47 đặc trưng đúng thứ tự contract).
  - Một lượt huấn luyện lại độc lập trên dữ liệu thật (`test_execute_training_real_data`) trên cùng máy/môi trường tạo ra file `.joblib` có SHA-256 trùng khớp 100% byte-for-byte.
  - Toàn bộ chỉ số trên Validation (`345.371` dòng), ma trận nhầm lẫn `[[314866, 5], [3, 30497]]`, phân rã 10 lớp `Attack`, và độ lệch xác suất đa luồng `max_abs_probability_diff = 2.220446049250313e-16` (`n_jobs=-1`).
  - Phân tích phân tầng overlap vs. non-overlap và 10 thí nghiệm chẩn đoán `C0`–`C9` trên Train/Validation.
- **Kết quả chỉ được ghi nhận trong Run Manifest (Manifest-Recorded Only):**
  - Thời điểm chạy gốc (`trained_at_utc = 2026-11-07T16:22:20.836660+00:00`), `run_id = rf-baseline-1794068628`, thời gian huấn luyện của lượt chạy gốc (`83,73s`), bộ nhớ đỉnh (`3.863,41 MB`), và commit tại thời điểm chạy (`6f50633544ccbf93fa4dd193355c1d8222360e37`).
  - Phép đối chiếu trực tiếp giữa đối tượng model trong RAM ngay trước khi `save()` và đối tượng sau khi `load_verified()` trong cùng tiến trình của lượt chạy gốc.
  - Các cờ tự báo cáo của `PartitionAccessTracker` trong lượt chạy gốc (`test_partition_accessed: false`, `test_rows_loaded: 0`).
- **Các giới hạn chưa thể kết luận (Unresolved / Out-of-Scope Limitations):**
  - **Khả năng tổng quát hóa ngoài testbed (External Validity):** Validation Accuracy `99,9977%` chịu ảnh hưởng mạnh của cấu trúc lab tổng hợp IXIA PerfectStorm (đặc biệt là sự phân tách TTL theo nhánh định tuyến và sự lặp lại kịch bản lưu lượng trong cùng ngày `2015-02-18`). Không được diễn giải con số này là hiệu năng phát hiện xâm nhập trên mạng thực tế (production networks) hoặc giữa các môi trường mạng khác nhau.
  - **Tính tất định xuyên nền tảng (Cross-Platform Determinism):** Việc tái lập byte-for-byte SHA-256 của `.joblib` mới được chứng minh trên cùng hệ điều hành, kiến trúc CPU và phiên bản thư viện (`Windows-11`, `Python 3.14.10`, `scikit-learn 1.9.1`). Khác hệ điều hành hoặc phiên bản `scikit-learn`/`joblib` có thể tạo ra chuỗi byte `.joblib` khác nhau dù cùng cấu hình.
  - **Hiệu năng trên phân vùng Held-out Test (`345.953` dòng):** Hoàn toàn chưa được đánh giá (`NOT VERIFIED` / `PLANNED` cho Issue #12).
