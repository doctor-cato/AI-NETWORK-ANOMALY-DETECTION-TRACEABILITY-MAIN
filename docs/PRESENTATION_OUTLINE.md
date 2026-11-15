# Dàn ý trình bày — 10–12 slide (Cập nhật Phạm vi Demo Cuối kỳ)

1. **Tiêu đề** — AI-Based Network Anomaly Detection and Traceability System; nhóm (5 vai trò, để trống tên chờ điền) và bối cảnh đồ án.
2. **Bài toán & Mục tiêu Demo** — Phát hiện `Benign` / `Attack` trên NetFlow, đảm bảo không rò rỉ dữ liệu, truy vết artifact bằng SHA-256 và đóng gói ứng dụng desktop chạy offline trên Windows.
3. **Dataset & Kiểm toán Chất lượng (`NF-UNSW-NB15-v3`)** — DOI `10.48610/6E0EDA1` (phi thương mại), 2.365.424 dòng, 55 cột (47 ML features + 6 trace metadata + `Label`/`Attack`), chronological split với purge gap 5 phút (Train 1.655.797 / Val 345.371 / Test 345.953 / Purged 18.303) và các phát hiện chất lượng dữ liệu.
4. **Kiến trúc Hệ thống Mục tiêu** — **Rust / Tauri 2 + Svelte 5** (Desktop UI, file picker, lifecycle backend) giao tiếp `127.0.0.1` với **Python FastAPI + SQLite (single writer)** + `TrainOnlyPreprocessor` + 4 Verified Models (`RandomForest`, `XGBoost`, `IsolationForest`, `Autoencoder`).
5. **Chống Rò rỉ & Chiến lược 4 Mô hình AI** — Fit preprocessor chỉ trên Train; Random Forest & XGBoost (supervised); Isolation Forest & Autoencoder (unsupervised + validation threshold, hiện tại `IMPLEMENTED / TESTED` và báo `BLOCKED / NOT READY` nếu thiếu binary).
6. **Kết quả Thực nghiệm Đã Kiểm chứng** — Held-out Test Random Forest (`rf-heldout-ea330b9`: `345.953` dòng, `Accuracy=0,999974`, `F1=0,999853`, `TN=315.350, FP=7, FN=2, TP=30.594`); Validation XGBoost (`345.371` dòng, `F1=0,999984`, Held-out Test `NOT VERIFIED`).
7. **Phân tích Lỗi, TTL Shortcut & Cross-Dataset (M7)** — Hiện tượng `49,98%` duplicate vector giữa Train/Validation, cây đơn `MIN_TTL` đạt `0,999849` trên Validation và bài học domain shift khi đánh giá ngoại vi (`Issue #46` / `#48` — nghiên cứu mở rộng M7, giải thích vì sao không tuyên bố zero-day hay generalization tuyệt đối).
8. **Luồng Chuẩn bị Demo CSV & Demo Trực tiếp** — `scripts/prepare_demo_dataset.py` lấy mẫu 200 dòng cân bằng từ **Validation partition** (`0` overlap Train/Test), tách `demo_flows.csv` (không nhãn) và `demo_labels.csv` (đánh giá Confusion Matrix riêng; kết quả kiểm tra thật RF: `TN=100, FP=0, FN=0, TP=100`), trình bày luồng API/Desktop app (`#16`).
9. **Phạm vi Rút gọn & Quản trị Kỹ thuật** — Công bố trung thực các hạng mục `REDUCED`/`DEFERRED` (Behavioral/Risk/Trace đơn giản hóa theo NetFlow, hoãn AES-256-GCM keyring đầy đủ & adaptive rotation) và cơ chế fail-closed khi thiếu `.joblib`/`.pt`.
10. **Kết luận & Hướng phát triển** — Phần đã kiểm chứng (`RF` Test, `FastAPI/SQLite`, Demo CSV contract), hạng mục hoàn thiện tiếp (`Rust/Tauri 2 + Svelte 5 UI #16`, real-data benchmarks `IF`/`AE`, `M7` cross-dataset).
11. **Tài liệu tham khảo & Giấy phép** — Nguồn `NF-UNSW-NB15-v3`, `Apache-2.0` code license, `Permitted Re-Use with Commercial Use Restriction`.
12. **Phụ lục / Dự phòng Demo** — Sơ đồ OpenAPI (`/api/v1/health`, `/api/v1/analyze`), lệnh CLI dự phòng (`scripts/predict.py`), hình ảnh/JSON kết quả đã lưu.

## Chuẩn bị thuyết trình và vấn đáp dựa trên bằng chứng

- [ ] Phân vai người trình bày cho đúng 5 vai trò (tên để trống đến khi nhóm xác nhận); diễn tập có bấm giờ ít nhất 2 lần.
- [ ] Chuẩn bị kịch bản dự phòng (kết quả `data/demo/demo_predictions.csv` / `demo_predictions_meta.json` và `reports/evaluation/rf-heldout-ea330b9/`) nếu live desktop demo gặp sự cố.
- [ ] Mọi câu trả lời vấn đáp trỏ về artifact/manifest trong `reports/`, `docs/TRACEABILITY_MATRIX.md` hoặc `demo_manifest.json`. Phần chưa có kết quả thực nghiệm (`Isolation Forest` real run, `Autoencoder` real run, `XGBoost` Held-out Test, `Tauri UI #16` nếu chưa build xong lúc bảo vệ) phải trả lời rõ là **"chưa kiểm chứng / đang triển khai theo #<issue>"**, không ước lượng số liệu tại chỗ.
