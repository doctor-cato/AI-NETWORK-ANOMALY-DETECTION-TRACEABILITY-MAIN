# Quy tắc thí nghiệm ML — rules/ml-experiment-rules.md

Bộ dữ liệu (UNSW-NB15):
- Kiểm tra nguồn, phiên bản, cấu trúc, nhãn, checksum khi có thể (`scripts/validate_data.py`).
- EDA trước khi chọn đặc trưng (`docs/EXPERIMENT_PLAN.md`).

Kiểm tra chất lượng:
- Missing values, duplicates, phân bố nhãn, mất cân bằng lớp.
- Cột có thể gây rò rỉ dữ liệu (leakage): nhãn trực tiếp, cột dẫn xuất từ nhãn, cột định danh (IP/port/time) — quyết định dựa trên mục tiêu và bằng chứng, không tự loại toàn bộ.

Chia dữ liệu:
- Train/val/test trước mọi fitting trước xử lý (preprocessing).
- Nếu dùng split có sẵn từ dataset, ghi rõ. Nếu tự chia, ghi chiến lược + seed (`RANDOM_SEED = 42`).
- Không dùng nhãn test để chọn đặc trưng / threshold / hyperparameter.

Tiền xử lý (`src/network_anomaly/preprocessing/` — hiện placeholder):
- Fit encoder/imputer/scaler/selector trên tập train; áp dụng phép biến đổi đã fit cho val/test.
- Lưu artifact cùng mô hình.

Mô hình và đánh giá:
- RF (giám sát): train với nhãn; đánh giá bằng Precision/Recall/F1/Macro-F1/confusion matrix/FPR.
- IF (không giám sát, nếu triển khai): score trên val/test, chọn threshold trên validation, rồi đánh giá; phải ghi rõ protocol khác RF (`docs/EVALUATION.md`).
- Báo cáo theo lớp nếu mất cân bằng ảnh hưởng.
- Không gọi kết quả synthetic là benchmark trên UNSW-NB15.

Ghi chép:
- Config, seed, cách chia, phiên bản thư viện, lệnh chạy (`docs/REPRODUCIBILITY.md`).
- Nếu chưa chạy thực nghiệm thật: ghi rõ nguyên nhân và trạng thái chưa hoàn thành.

Truy vết bằng tài liệu/metadata sẵn có, không tạo framework mới nếu chưa cần:
- `Issue → Requirements → Implementation → Tests → Verification Evidence → Experiment Results`.
- `PLANNED`: mới có kế hoạch; `IMPLEMENTED`: đã có code; `TESTED`: có test đã chạy (có thể synthetic);
  `EXPERIMENTALLY VALIDATED`: đã chạy trên UNSW-NB15 thật với provenance, split và metric có bằng chứng.
- Unit/integration test synthetic không nâng trạng thái lên `EXPERIMENTALLY VALIDATED`.
- Mỗi kết quả thực nghiệm phải truy được về commit, trạng thái working tree, dataset checksum/variant, split, feature,
  preprocessing/model config, dependency, lệnh và artifact/metric. Thiếu mắt xích thì ghi `NOT VERIFIED`.
