# Yêu cầu — chức năng và phi chức năng

Ma trận đầy đủ Yêu cầu → Issue → Deliverable → Tiêu chí chấp nhận → Kiểm chứng nằm ở
[`TRACEABILITY_MATRIX.md`](TRACEABILITY_MATRIX.md). File này giữ danh sách yêu cầu gốc.

## Yêu cầu chức năng (core, phải hoạt động)

| ID | Yêu cầu | Kiểm chứng |
|---|---|---|
| F01 | Tải UNSW-NB15 (sau khi có dữ liệu) và kiểm tra schema | `scripts/validate_data.py` đạt với fixture; có hướng dẫn |
| F02 | Kiểm tra nhãn, phân bố lớp, bản ghi trùng, missing value | Notebook / script sinh tóm tắt |
| F03 | Preprocess không leakage: split trước, rồi fit scaler/encoder | Pipeline object; test set không tham gia fit |
| F04 | Xây dựng Random Forest classifier với hyperparameter đã ghi | `src/network_anomaly/models/random_forest.py` (hiện chỉ constructor); script train chạy được |
| F05 | Đánh giá bằng Precision, Recall, F1, Macro-F1, confusion matrix, FPR | `src/network_anomaly/evaluation/metrics.py` trả P/R/F1/Macro-F1/confusion matrix; **FPR chưa có trong module — thuộc issue #12** |
| F06 | Ghi protocol đánh giá Isolation Forest riêng (score không giám sát → threshold) | `docs/METHODOLOGY.md`; ghi chú evaluation |
| F07 | Cung cấp pipeline inference cho dữ liệu đầu vào mới | module `src/network_anomaly/inference/`; script demo |
| F08 | Cung cấp hướng dẫn chạy thực nghiệm có thể tái lập | `docs/REPRODUCIBILITY.md`; `python scripts/run_experiments.py` (hoặc tương đương) |

## Yêu cầu tùy chọn (không chặn chấp nhận core)

| ID | Requirement | Verification |
|---|---|---|
| O01 | Triển khai Isolation Forest không giám sát (ngoài phần tài liệu protocol F06) | Issue #11. Không có kết quả IF vẫn không chặn chấp nhận core; issue có thể giữ mở |
| O02 | Chạy nhiều seed và báo mean/std | Issue #12 — chỉ khi còn thời gian |
| O03 | Demo giao diện web (đề xuất Streamlit) | Issue #16 — cần issue riêng để thêm dependency; `streamlit` chưa khai trong `requirements.txt` |

## Yêu cầu phi chức năng

| ID | Yêu cầu | Kiểm chứng |
|---|---|---|
| N01 | Code tổ chức dưới `src/network_anomaly/`; logic gọi được từ notebook/script | Đã kiểm tra cấu trúc thư mục |
| N02 | Python 3.11+; giới hạn dependency tối thiểu, lưu phiên bản môi trường thực tế khi tái lập | `pyproject.toml`; `requirements.txt`; `docs/REPRODUCIBILITY.md`; CI matrix 3.11/3.12 |
| N03 | Không dùng đường dẫn tuyệt đối cố định; dùng đường dẫn tương đối hoặc config | `config.py`; tài liệu cấu hình môi trường |
| N04 | Không có secret, API key hoặc dữ liệu cá nhân trong repo | `.gitignore`; kiểm tra diff và file trước commit |
| N05 | CI kiểm tra import cơ bản và test nhẹ không cần dataset | `.github/workflows/ci.yml` |
| N06 | Repository dùng Apache-2.0; xác minh nghĩa vụ riêng của dependency/assets | `LICENSE`; `README.md` |
| N07 | Tài liệu phân biệt planned / implemented / tested / experimentally validated | `README.md`; `docs/TRACEABILITY_MATRIX.md`; mô tả milestone |

## Tiêu chí chấp nhận (theo milestone)

Mỗi yêu cầu ở trên chỉ đóng được khi có lệnh kiểm chứng chạy được và bằng chứng gắn với commit; xem cột
Kiểm chứng trong `docs/TRACEABILITY_MATRIX.md`.

- M0: Cấu trúc + tài liệu + CI pass.
- M1: Dataset đã xác minh; leakage audit đã ghi; có EDA.
- M2: Pipeline preprocessing tái lập được; Random Forest đã train; metric đã ghi.
- M3: Isolation Forest đã ghi / triển khai nếu khả thi; có protocol so sánh; hoàn tất error analysis.
  Không có kết quả Isolation Forest vẫn không chặn chấp nhận core.
- M4: Pipeline inference + demo chạy được; integration test đạt.
- M5: Dàn ý báo cáo + trình bày hoàn chỉnh; kiểm chứng cuối đạt.

Cập nhật: 2026-10-17
