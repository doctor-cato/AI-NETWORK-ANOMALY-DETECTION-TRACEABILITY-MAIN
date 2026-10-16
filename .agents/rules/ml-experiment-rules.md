# Quy tắc thí nghiệm ML — rules/ml-experiment-rules.md

Dataset (UNSW-NB15):
- Kiểm tra nguồn, phiên bản, cấu trúc, nhãn, checksum khi có thể (`scripts/validate_data.py`).
- EDA trước chọn đặc trưng (`docs/EXPERIMENT_PLAN.md`).

Kiểm tra chất lượng:
- Missing values, duplicates, phân bố nhã, mất cân bằng lớp.
- Cột có thể gây leakage: nhãn trực tiếp, cột dẫn xuất từ nhãn, cột định danh (IP/port/time) — quyết định dựa trên mục tiêu và bằng chứng, không tự loại toàn bộ.

Chia dữ liệu:
- Train/val/test trước mọi fit preprocessing.
- Nếu dùng split có sẵn từ dataset, ghi rõ. Nếu tự chia, ghi chiến lược + seed (`RANDOM_SEED = 42`).
- Không dùng nhãn test để chọn đặc trưng / threshold / hyperparameter.

Preprocessing (`src/network_anomaly/preprocessing/` — hiện placeholder):
- Fit encoder/imputer/scaler/selector trên train; apply đã fit cho val/test.
- Lưu artifact cùng model;

Mô hình và đánh giá:
- RF (supervised): train với nhãn; đánh giá bằng Precision/Recall/F1/Macro-F1/confusion matrix/FPR.
- IF (unsupervised, nếu triển khai): score trên val/test, chọn threshold trên validation, rồi đánh giá; phải ghi rõ protocol khác RF (`docs/EVALUATION.md`).
- Báo cáo theo lớp nếu mất cân bằng ảnh hưởng.
- Không gọi kết quả synthetic là benchmark trên UNSW-NB15.

Ghi chép:
- Config, seed, cách chia, phiên bản thư viện, lệnh chạy (`docs/REPRODUCIBILITY.md`).
- Nếu chưa chạy thực nghiệm thật: ghi rõ nguyên nhân và trạng thái chưa hoàn thành.
