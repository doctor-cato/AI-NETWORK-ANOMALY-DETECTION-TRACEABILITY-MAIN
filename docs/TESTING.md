# Hướng dẫn Kiểm thử ML Pipeline (Testing Guide)

Tài liệu này hướng dẫn kiến trúc kiểm thử, phân loại bài kiểm thử, quy trình thực thi và cách diễn giải kết quả kiểm thử trong repository `AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN` (Issue #17 — Milestone M4).

---

## 1. Kiến trúc Kiểm thử (Test Architecture)

Hệ thống kiểm thử được tổ chức thành hai tầng riêng biệt trong thư mục `tests/`:

```text
tests/
├── unit/                        # Tầng Unit Tests: kiểm tra độc lập từng module/hàm
│   ├── test_basic.py            # Khởi tạo model, cấu hình hạt giống ngẫu nhiên, guards khi chưa fit
│   ├── test_nf_unsw_nb15_v3_*.py# Tải, split, audit và kiểm tra tính toàn vẹn dữ liệu
│   ├── test_validate_data.py    # Kiểm tra schema, kiểu dữ liệu, bounds và token auditing
│   ├── test_preprocessing_pipeline.py # 70+ test cho TrainOnlyPreprocessor, chính sách fit-on-train
│   ├── test_rf_*.py             # Protocol, cấu hình baseline, huấn luyện và chẩn đoán Random Forest
│   ├── test_inference_pipeline.py # Schema validation, CLI flags, bảo toàn row_id của Inference Pipeline
│   └── test_run_experiments.py  # Giao diện thí nghiệm baseline
│
└── integration/                 # Tầng Integration Tests: kiểm tra phối hợp các thành phần
    ├── test_inference_e2e.py    # Kiểm tra E2E CSV Inference Pipeline qua CLI và Python API
    └── test_pipeline.py         # Kiểm tra tích hợp toàn bộ pipeline: Preprocessing + RF Model + Inference
```

---

## 2. Phân biệt Unit Test và Integration Test

| Tiêu chí | Unit Tests (`tests/unit/`) | Integration Tests (`tests/integration/`) |
|---|---|---|
| **Mục tiêu** | Kiểm tra tính đúng đắn của từng class, hàm, regex hoặc logic đơn lẻ. | Kiểm tra sự tương tác và tích hợp giữa các thành phần khác nhau. |
| **Dữ liệu kiểm thử** | Minimal mock fixtures, synthetic arrays nhỏ (1-20 dòng). | Synthetic network flow DataFrame hoàn chỉnh (47 features + targets + trace metadata). |
| **Phạm vi kiểm tra** | Constructor, validate_input, tính toán metric, error guards (`NotFittedError`). | `Synthetic CSV → Schema Validation → Preprocessing → Model Prediction → Export CSV → Metadata JSON`. |
| **Thời gian chạy** | Siêu nhanh (vài millisecond mỗi test). | Nhanh, thường từ 0.1s - 2s cho toàn bộ kịch bản. |

---

## 3. Lệnh Chạy Kiểm Thử (How to Run Tests)

Tất cả lệnh chạy từ thư mục gốc của repository bằng Python environment đã kích hoạt:

### A. Chạy toàn bộ test suite
```bash
python -m pytest tests -q
```

### B. Chạy riêng tầng Unit Tests
```bash
python -m pytest tests/unit -q
```

### C. Chạy riêng tầng Integration Tests
```bash
python -m pytest tests/integration -v
```

### D. Chạy kiểm thử tích hợp pipeline cụ thể (Issue #17)
```bash
python -m pytest tests/integration/test_pipeline.py -v
```

### E. Chạy kiểm tra chất lượng code (Lint & Format)
```bash
python -m ruff check src/network_anomaly/inference/predict.py src/network_anomaly/models/random_forest.py tests/integration/test_pipeline.py tests/unit/test_basic.py
python -m black --check src/network_anomaly/inference/predict.py src/network_anomaly/models/random_forest.py tests/integration/test_pipeline.py tests/unit/test_basic.py
git diff --check
```

---

## 4. Cách Diễn Giải Trạng Thái Kiểm Thử (Interpreting Results)

Mỗi bài kiểm tra trong pytest trả về một trong các trạng thái sau:

1. **`PASS`**:
   - Thành phần đáp ứng chính xác contract và vượt qua tất cả assertions logic.
2. **`FAIL`**:
   - Vi phạm contract (sai số cột, rò rỉ dữ liệu, sai lệch SHA-256, không ném ngoại lệ khi gặp lỗi).
   - Bắt buộc phải điều tra và sửa chữa ngay.
3. **`SKIPPED`**:
   - Môi trường hiện tại thiếu artifact lớn hoặc raw dataset thực tế (như file `.joblib` bị loại trừ bởi `.gitignore`, hoặc raw dataset 577 MB không tải trên CI).
   - **Lưu ý quan trọng**: `SKIPPED` không làm fail CI, nhưng **tuyệt đối không được coi là bằng chứng kiểm chứng thành công (PASS) trên dữ liệu thật**.
   - Test suite được thiết kế **Fail-Closed**: nếu artifact thật bị thiếu, test sẽ báo rõ `SKIPPED` kèm lý do, không bao giờ âm thầm cho `PASS` giả tạo.

---

## 5. Dữ liệu Synthetic Chứng Minh Được Gì và Không Chứng Minh Được Gì?

### Những điều Synthetic Tests CHỨNG MINH ĐƯỢC:
- **Tính đúng đắn của phần mềm**: Pipeline hoạt động liền mạch từ khâu nhận file CSV, tiền xử lý đến ra quyết định dự đoán.
- **Bảo toàn Contract 47 Features**: Đúng 47 feature baseline được chọn theo đúng thứ tự chuẩn hóa NF-UNSW-NB15-v3.
- **Chống rò rỉ dữ liệu (No Leakage)**: Cột nhãn (`Label`, `Attack`) và siêu dữ liệu vết (`IPV4_SRC_ADDR`, `L4_SRC_PORT`, v.v.) bị loại bỏ hoàn toàn khỏi ma trận đầu vào mô hình $X$.
- **Bảo toàn trạng thái tiền xử lý (Frozen State)**: Quá trình inference không fit lại bất kỳ tham số nào của `TrainOnlyPreprocessor`.
- **Tính toàn vẹn Artifact (Fail-Closed Integrity)**: Phát hiện và chặn đứng các artifact bị sửa đổi, hỏng hoặc manifest không khớp mã băm SHA-256.
- **Tính xác định và Tái lập (Determinism)**: Cùng một input CSV và artifact luôn cho ra cùng một kết quả dự đoán bit-to-bit.

### Những điều Synthetic Tests KHÔNG THỂ CHỨNG MINH:
- **Độ chính xác ML (F1, Precision, Recall, AUC)**: Dữ liệu synthetic ngẫu nhiên không có ý nghĩa thống kê về lưu lượng mạng thực tế.
- **Khả năng phát hiện xâm nhập trong thực tế**: Không được dùng kết quả test synthetic để công bố benchmark mô hình. Việc đánh giá năng lực mô hình trên tập Test giữ kín là nhiệm vụ độc lập thuộc Issue #12.

---

## 6. Kiểm Chứng Trên Dữ Liệu Thật (Real-Data Verification)

Khi môi trường có sẵn các artifact thực tế:

1. **Preprocessor Artifact Thật (`artifacts/preprocessing/nf_unsw_nb15_v3_preprocessor.joblib`)**:
   - `test_real_preprocessor_artifact_verification` sẽ tự động phát hiện, đối chiếu mã SHA-256 với `reports/preprocessing/nf_unsw_nb15_v3_preprocessing_manifest.json`, xác thực 1,655,797 dòng train và báo `PASS`.
2. **Model Artifact Thật (`artifacts/models/random_forest/random_forest_baseline.joblib`)**:
   - Nếu file binary tồn tại cục bộ, `test_real_model_artifact_verification` sẽ nạp bằng `RandomForestModel.load_verified()` và kiểm tra tính toàn vẹn.
   - Nếu file binary vắng mặt (do chính sách `.gitignore` của repository), test sẽ thông báo `SKIPPED` kèm ghi chú rõ ràng về manifest đã được lưu trữ trong Git.
