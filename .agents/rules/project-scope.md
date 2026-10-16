# Phạm vi dự án — rules/project-scope.md

Dataset: UNSW-NB15 (chưa tải; `data/raw/` chỉ `.gitkeep`).

Bắt buộc / ưu tiên:
- EDA + kiểm tra leakage trước khi chọn đặc trưng.
- Train/validation/test split trước mọi fit.
- Random Forest (supervised) là baseline chính (`src/network_anomaly/models/random_forest.py`, `config.RANDOM_FOREST_DEFAULTS`).
- Metrics: Precision, Recall, F1, Macro-F1, confusion matrix, FPR (`src/network_anomaly/evaluation/metrics.py`).
- Preprocessing: phải fit trên train, transform val/test; lưu artifact (`docs/METHODOLOGY.md`).
- Isolation Forest chỉ nếu thời gian cho phép; đánh giá riêng (score → threshold → label) (`docs/EVALUATION.md`).

Không tự mở rộng:
- Autoencoder, Transformer, GNN, LSTM, sequence modeling.
- Post-quantum cryptography, adaptive key rotation, device identity tracing.
- Production deployment, distributed processing, automatic blocking.
- Zero-day detection hoặc claims không có bằng chứng thực nghiệm.

Không giả mạo:
- Không bịa benchmark trên UNSW-NB15 nếu chưa chạy.
- Không ghi “hoàn thành pipeline end-to-end” khi chưa có dataset thật.
- Phân biệt `planned` / `implemented` / `tested` / `experimentally validated` trong mọi báo cáo.

Quản lý repo:
- Không commit dataset gốc / dataset xử lý lớn / artifact không được phép.
- Không thay đổi `LICENSE` (Apache-2.0), không đổi đến MIT.
- Không xóa lịch sử Git, không force-push, không đóng issue/milestone.
- Chỉ sửa file nằm trong phạm vi task; không tự mở rộng.
