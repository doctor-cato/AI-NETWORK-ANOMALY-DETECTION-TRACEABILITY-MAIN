# Phạm vi dự án — rules/project-scope.md

Bộ dữ liệu dự kiến: UNSW-NB15 (chưa tải; `data/raw/` chỉ `.gitkeep`).

Bắt buộc / ưu tiên:
- EDA + kiểm tra rò rỉ dữ liệu (leakage) trước khi chọn đặc trưng.
- Chia train/validation/test trước mọi fitting.
- Random Forest (giám sát) là baseline chính (`src/network_anomaly/models/random_forest.py`, `config.RANDOM_FOREST_DEFAULTS`).
- Metrics: Precision, Recall, F1, Macro-F1, confusion matrix, FPR (`src/network_anomaly/evaluation/metrics.py`).
- Tiền xử lý (preprocessing): phải fit trên tập train, rồi transform validation/test; lưu artifact (`docs/METHODOLOGY.md`).
- Isolation Forest chỉ nếu thời gian cho phép; đánh giá riêng biệt (score → threshold → nhãn) (`docs/EVALUATION.md`).

Không tự mở rộng:
- Autoencoder, Transformer, GNN, LSTM, mô hình chuỗi thời gian.
- Mã hóa hậu lượng tử (post-quantum), xoay khóa thích ứng (adaptive key rotation), truy vết danh tính thiết bị.
- Triển khai production, xử lý phân tán, chặn tự động.
- Phát hiện zero-day hoặc tuyên bố không có chứng cứ thực nghiệm.

Không giả mạo:
- Không bịa benchmark trên UNSW-NB15 nếu chưa chạy.
- Không ghi “pipeline hoàn chỉnh end-to-end” khi chưa có dữ liệu thật.
- Phân biệt rõ `planned` / `implemented` / `tested` / `experimentally validated` trong mọi báo cáo.

Quản lý repo:
- Không commit bộ dữ liệu gốc / bộ dữ liệu xử lý lớn / artifact không được phép.
- Không đổi `LICENSE` (Apache-2.0), không đổi sang MIT.
- Không xóa lịch sử Git, không force-push, không đóng issue/milestone.
- Chỉ sửa file trong phạm vi task; không tự mở rộng.
