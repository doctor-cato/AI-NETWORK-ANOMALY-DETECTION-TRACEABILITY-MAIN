# NF-UNSW-NB15-v3 XGBoost Supervised Baseline Protocol

**Issue:** #31 — Triển khai XGBoost theo protocol supervised dùng chung với Random Forest (Checkpoint C3)<br>
**Status:** Protocol & Configuration: `IMPLEMENTED / TESTED` (Issue #31); Model Training: `IMPLEMENTED / TESTED / EXPERIMENTALLY VALIDATED` (run `xgb-baseline-1794151507`, 2026-11-08, dữ liệu thật NF-UNSW-NB15-v3); Held-out Test Evaluation: `PLANNED` (Issue #12); Real Split: `PASS (PR #41)`; Preprocessing Artifact: `PASS (PR #42)`.<br>
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

---

## 6. Huấn luyện Thực tế (Real Training Evidence)

Trạng thái: **EXPERIMENTALLY VALIDATED** trên dữ liệu thật, không phải synthetic.

### 6.1 Lệnh tái lập

```powershell
$env:PYTHONPATH = "<repo-root>/src"
python scripts/train_xgboost.py
```

Script thực hiện 8 bước bắt buộc: (1) prereq audit fail-closed (dataset SHA-256, split manifest, preprocessor artifact và manifest, xgboost/sklearn available, artifact không tồn tại sẵn); (2) streaming load partition `train`/`validation` qua `scripts.train_random_forest` (dùng chung codebase với RF — parity); (3) transform qua preprocessor artifact đã fit train-only; (4) fit XGBClassifier canonical; (5) validation metrics dùng chung `network_anomaly.evaluation.metrics`; (6) save artifact + SHA-256; (7) `load_verified` reload fail-closed; (8) ghi markdown report.

### 6.2 Run evidence (run `xgb-baseline-1794151507`, 2026-11-08)

- **Git commit:** `7d760e0` (branch `feat/c3-xgboost-issue-31`); `git_dirty=false` — run manifest và store của run được ghi ngoài Git (`.gitignore` cho `artifacts/**`), evidence report được commit ngay sau run.
- **Provenance chain (runtime, VERIFIED):** dataset SHA `4ebb97bd…`; split manifest SHA `845d8863…` (content khớp canonical Oct, chỉ khác record timestamp); train indices `30ed493e…`, val indices `a3e4470c…`; preprocessor artifact `e1e89bde…` (fit train-only, 1.655.797 dòng).
- **Hash chain canonical vs runtime:** artifact canonical từ thời điểm accept PR #41/#42 (`bb84c1e0…` split manifest, `12d4360a…` preprocessor artifact) không thể tái sinh byte-identical vì manifest record timestamp và preprocessor joblib ngoài Git bị ghi đè ngày 2026-11-03. Run này REGENERATE artifact set bằng scripts chính thức và verify bằng runtime hash chain; canonical hashes được giữ làm `canonical_reference_hashes` trong run manifest (`reports/models/xgboost_manifest.json`).
- **Khối lượng:** Train 1.655.797 rows × 47 features; Validation 345.371 rows; fit 19.66 s; peak memory 4.422,59 MB (Python 3.13.9, xgboost 3.4.1, scikit-learn 1.9.1, pandas 3.0.6, numpy 2.5.3 — local Windows; CI matrix ubuntu/windows × Python 3.11/3.12 chỉ chạy unit/integration tests, không fit trên dataset thật).
- **Tái lập:** run thứ hai không phụ thuộc (không seed nội bộ thay đổi) cho ra metrics identical (Precision/Recall/F1/Macro-F1/FPR trùng đến 6 chữ số, CM trùng khớp); model artifact SHA khác giữa các run do joblib serialization không cố định byte (70.680 bytes cố định) — run manifest luôn ghi SHA của chính run đó.

### 6.3 Validation metrics

| Metric | Giá trị |
| :--- | :--- |
| Precision | 0.999967 |
| Recall | 1.000000 |
| F1 | 0.999984 |
| Macro-F1 | 0.999991 |
| FPR | 0.000003 |
| Confusion matrix (label order [0, 1]) | TN=314.870, FP=1, FN=0, TP=30.500 |

Đủ 10/10 category attack được phát hiện 100% (Analysis, Backdoor, DoS, Exploits, Fuzzers, Generic, Reconnaissance, Shellcode, Worms); duy nhất 1 FP trên 314.871 dòng benign.

### 6.4 Test-partition lock

- `test_partition_accessed: False`, `test_rows_loaded: 0` — Contract A/B: PASSED. Tập test (345.953 dòng) không hề được nạp; chỉ dùng 1 lần ở Issue #12.

### 6.5 So sánh với Random Forest reference (cùng protocol, cùng Validation split)

| Metric | Random Forest | XGBoost |
| :--- | :--- | :--- |
| Precision | 0.999836 | 0.999967 |
| Recall | 0.999902 | 1.000000 |
| F1 | 0.999869 | 0.999984 |
| Macro-F1 | 0.999928 | 0.999991 |
| FPR | 0.000016 | 0.000003 |
| TP / FP / FN / TN | 30.497 / 5 / 3 / 314.866 | 30.500 / 1 / 0 / 314.870 |

> [!NOTE]
> Hai run dùng **cùng dataset SHA** (`4ebb97bd…`) và cùng nội dung split, nhưng **không dùng cùng một artifact set hash**: RF reference dùng canonical Oct set (`bb84c1e0…` split manifest, `12d4360a…` preprocessor), XGBoost dùng regenerated Nov set đã verify runtime (`845d8863…` split manifest, `e1e89bde…` preprocessor). So sánh này là so sánh cùng protocol trên cùng nội dung dữ liệu, không phải so sánh trên cùng artifact bytes.

### 6.6 Artifact & reload verification

- Model artifact: `artifacts/models/xgboost/xgboost_baseline.joblib` — 70.680 bytes, SHA-256 `c70ec52fb3229ccca680f70356e0a8c44e0b16ff7988c5e6fb91da3383eabd6e` (nằm ngoài Git theo `.gitignore`; hash ghi trong run manifest).
- Reload verification qua `XGBoostModel.load_verified`: PASSED — predictions identical trên 345.371 samples, max abs probability diff 0.0.

### 6.7 Ranh giới

- Kết quả Validation không thay thế đánh giá held-out Test (Issue #12, one-shot) — vẫn `PLANNED`.
- Không có hyperparameter tuning nào được thực hiện; cấu hình canonical `xgb-baseline-canonical-v1` được dùng nguyên trạng.
