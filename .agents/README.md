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
- `skills/` — `repo-workflow`, 4 domain skill local và 4 tham chiếu tích hợp global được giữ lại.

## Quy trình sử dụng

Plan → Implement → Verify → Review theo phạm vi được giao. Đọc yêu cầu, `README.md` và chỉ tài liệu liên quan trước khi sửa. Chọn domain skill theo `AGENTS.md`; không tải cả bốn nếu task chỉ chạm một domain. PLAN-only/REVIEW-only không tự chuyển sang sửa file.

Phân biệt rõ:
- `planned` = chưa triển khai / chưa có dataset.
- `implemented` = đã có module/code nhưng chưa kiểm chứng trên dữ liệu thật.
- `tested` = đã chạy test/unit/integration (có thể synthetic).
- `experimentally validated` = đã chạy trên UNSW-NB15 thật và ghi kết quả.

Không tạo thêm milestone/issue, không thêm tài liệu chỉ để tăng số file, không triển khai Autoencoder/Transformer/GNN/post-quantum.

## Dùng trong Codex

Codex đọc [AGENTS.md](../AGENTS.md) ở root và có thể khám phá các thư mục chứa `SKILL.md` tùy host/session. Bốn workflow ở trên vẫn dùng chung với OpenCode; không có cú pháp slash-command riêng cần mô phỏng.

Ví dụ prompt (thay phạm vi bằng task thực):

- `Dùng $repo-workflow PLAN: lên kế hoạch kiểm tra tài liệu workflow; không sửa file.`
- `Dùng $repo-workflow IMPLEMENT: thực hiện kế hoạch vừa thống nhất, rồi VERIFY và REVIEW; không commit/push.`
- `Dùng $repo-workflow VERIFY: kiểm tra thay đổi workflow hiện tại; không sửa code.`
- `Dùng $repo-workflow REVIEW: review working-tree diff và file mới; chỉ báo findings, không sửa.`

Gõ prompt trực tiếp trong Codex; trong PowerShell giữ `$repo-workflow` trong chuỗi nháy đơn để tránh nội suy biến. Nếu skill chưa xuất hiện sau thay đổi, mở lại session. Có thể yêu cầu đọc trực tiếp `skills/repo-workflow/SKILL.md` trong thư mục này; đây là fallback thủ công, không phải bằng chứng auto-discovery.

Skill chỉ đọc bước/domain cần dùng; hướng dẫn chung ở root/rules không sao chép vào mỗi skill. Validator chỉ chứng minh structure/frontmatter/link. Runtime discovery và activation là hai kiểm chứng riêng; skill mới có thể cần session mới để xuất hiện.

Lỗi quay về IMPLEMENT khi được phép; lỗi tái diễn sau hai lượt sửa phải báo điều kiện tiếp tục. Reviewer subagent chỉ được gọi là độc lập khi một agent khác tự đọc diff và kiểm chứng; self-review tuần tự không phải independent review.

OpenCode tiếp tục đọc `.agents/workflows/*.md`, rules, domain `SKILL.md` và `INTEGRATION.md` theo đường dẫn được chỉ định. Cấu hình OpenCode toàn cục/permission không được nhập vào Codex và không sửa trong repo. Kiểm tra hiện tại không chứng minh OpenCode tự nạp repo-local skill; fallback được hỗ trợ là đọc trực tiếp file cần thiết, không mô phỏng cú pháp Codex.
