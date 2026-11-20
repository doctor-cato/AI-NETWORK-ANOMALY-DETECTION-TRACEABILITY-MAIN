# .agents/ — Hướng dẫn vận hành AI agent cho NetFlow Sentinel v2.0

Dự án: **NetFlow Sentinel v2.0** — *AI-Based Network Anomaly Detection and Traceability System with Secure Behavioral Vectorization and Adaptive Key Rotation* (`AIT-NDS-v2`, `CTU-SME-11`, `UWF-ZeekData24`; di sản v1 `NF-UNSW-NB15-v3` nằm trong `historical/`).

## Mục đích

Thư mục này là hướng dẫn cho AI coding agent khi làm việc trên repo. Không thay thế `README.md`/docs chính thức; chỉ bổ sung quy trình lập kế hoạch → triển khai → kiểm thử → review và các domain skill cho agent.

## Cấu trúc

- `README.md` — file này.
- `rules/project-scope.md` — phạm vi bắt buộc v2.0 (`M6.1–M6.7`), ranh giới khoa học và an toàn.
- `rules/coding-standards.md` — quy chuẩn code đa ngôn ngữ (Python / TypeScript / Rust), test, API/OpenAPI sync, và quy tắc không dấu ấn AI.
- `rules/ml-experiment-rules.md` — quy tắc thí nghiệm ML (split `AIT-NDS-v2`, `TrainOnlyPreprocessor`, OOD gate, bảo toàn `E0`, metric, provenance).
- `workflows/plan.md` → `implement.md` → `verify.md` → `review.md` — quy trình 4 bước.
- `skills/` — `repo-workflow`, 4 domain skill local và 4 tham chiếu tích hợp `INTEGRATION.md`.

## Quy trình sử dụng

Plan → Implement → Verify → Review theo phạm vi được giao. Đọc yêu cầu, `README.md` và chỉ tài liệu liên quan trước khi sửa. Chọn domain skill theo `AGENTS.md`; không tải cả bốn nếu task chỉ chạm một domain. `PLAN-only` / `REVIEW-only` không tự chuyển sang sửa file.

Phân biệt rõ:
- `PLANNED` = chưa triển khai / chưa có dữ liệu.
- `IMPLEMENTED` = đã có module/code nhưng chưa kiểm chứng trên dữ liệu thật.
- `TESTED` = đã chạy test/unit/integration (có thể synthetic).
- `EXPERIMENTALLY VALIDATED` = đã chạy trên dữ liệu benchmark v2 thật (`AIT-NDS-v2`, `CTU-SME-11`, `UWF-ZeekData24`) có manifest, split và kết quả ghi nhận.

Không tạo thêm milestone/issue ngoài phạm vi, không tự ý retrain/ghi đè `E0` `.joblib` hoặc ký `DISTRIBUTION_AUTHORIZATION.json`, và không triển khai `Transformer`/`LSTM`/`GNN`/`post-quantum`/SOAR auto-block thật.

## Dùng trong Codex / OpenCode

Codex đọc [AGENTS.md](../AGENTS.md) ở root và có thể khám phá các thư mục chứa `SKILL.md` tùy host/session. Bốn workflow ở trên vẫn dùng chung với OpenCode; không có cú pháp slash-command riêng cần mô phỏng.

Ví dụ prompt (thay phạm vi bằng task thực):

- `Dùng $repo-workflow PLAN: lên kế hoạch kiểm tra tài liệu workflow; không sửa file.`
- `Dùng $repo-workflow IMPLEMENT: thực hiện kế hoạch vừa thống nhất, rồi VERIFY và REVIEW; không commit/push.`
- `Dùng $repo-workflow VERIFY: kiểm tra thay đổi workflow hiện tại; không sửa code.`
- `Dùng $repo-workflow REVIEW: review working-tree diff và file mới; chỉ báo findings, không sửa.`

Skill chỉ đọc bước/domain cần dùng; hướng dẫn chung ở root/rules không sao chép vào mỗi skill. Validator `.agents/skills/repo-workflow/scripts/check_workflows.py` chỉ kiểm tra structure/frontmatter/link; runtime discovery và activation là kiểm chứng riêng.

Lỗi quay về `IMPLEMENT` khi được phép; lỗi tái diễn sau hai lượt sửa phải báo điều kiện tiếp tục. Reviewer subagent chỉ được gọi là độc lập khi một agent khác tự đọc diff và kiểm chứng; self-review tuần tự không phải independent review.

OpenCode đọc `.agents/workflows/*.md`, rules, domain `SKILL.md` và `INTEGRATION.md` theo đường dẫn được chỉ định. Cấu hình OpenCode toàn cục/permission không nhập vào Codex và không sửa trong repo.
