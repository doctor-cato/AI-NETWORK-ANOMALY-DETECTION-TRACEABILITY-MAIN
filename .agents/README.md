# .agents/ — Hướng dẫn vận hành AI agent cho dự án

Dự án: AI-Based Network Anomaly Detection (UNSW-NB15). Bài tập AI 5–6 tuần.

## Mục đích

Thư mục này là hướng dẫn cho AI coding agent khi làm việc trên repo. Không thay thế README/docs chính thức; chỉ bổ sung quy trình lập kế hoạch → triển khai → kiểm thử → review cho agent.

## Cấu trúc

- `README.md` — file này.
- `rules/project-scope.md` — phạm vi bắt buộc / không bắt buộc.
- `rules/coding-standards.md` — thực hành code, dependency, test, lỗi.
- `rules/ml-experiment-rules.md` — quy tắc thí nghiệm ML (leakage, split, metric, dữ liệu thật).
- `workflows/plan.md` → `implement.md` → `verify.md` → `review.md` — quy trình 4 bước.
- `skills/` — 4 skill tích hợp nhẹ, tham chiếu nguồn toàn cục `C:\Users\Admin\.agents\skills/`.

## Quy trình sử dụng

Plan → Implement → Verify → Review. Không sửa code trước khi đọc yêu cầu và tài liệu dự án (`README.md`, `docs/METHODOLOGY.md`, `docs/EVALUATION.md`).

Phân biệt rõ:
- `planned` = chưa triển khai / chưa có dataset.
- `implemented` = đã có module/code nhưng chưa kiểm chứng trên dữ liệu thật.
- `tested` = đã chạy test/unit/integration (có thể synthetic).
- `experimentally validated` = đã chạy trên UNSW-NB15 thật và ghi kết quả.

Không tạo thêm milestone/issue, không thêm tài liệu chỉ để tăng số file, không triển khai Autoencoder/Transformer/GNN/post-quantum.
