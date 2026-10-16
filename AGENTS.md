# Hướng dẫn làm việc với repository

- Đọc yêu cầu hiện tại và kiểm tra Git trước khi hành động; trạng thái trong tài liệu có thể là snapshot cũ. Giai đoạn hiện tại: Repository Setup & Audit. Chỉ triển khai ML khi có nhiệm vụ riêng cho phép; không tự tải UNSW-NB15, train hoặc evaluate mô hình.
- Phạm vi khoa học: UNSW-NB15, Random Forest là baseline chính; Isolation Forest tùy chọn, không chặn core. Đọc [phạm vi](.agents/rules/project-scope.md) trước khi thay đổi. Đọc [quy chuẩn code](.agents/rules/coding-standards.md) cho code/test/config và [quy tắc ML](.agents/rules/ml-experiment-rules.md) khi tác vụ liên quan dữ liệu hoặc thí nghiệm.
- Workflow dùng chung OpenCode/Codex ở [.agents/workflows](.agents/README.md). Codex dùng skill `repo-workflow`: chọn PLAN, IMPLEMENT, VERIFY hoặc REVIEW theo yêu cầu; chỉ đọc workflow đang cần. PLAN-only và REVIEW-only không sửa file. Không tự chuyển sang IMPLEMENT khi người dùng chỉ yêu cầu phân tích.
- Không ghi đè thay đổi chưa commit. Đọc file trước khi sửa; chỉ thay đổi trong phạm vi được giao. Không reset/clean mất dữ liệu, force-push hoặc rewrite history. Không tự stage, commit, push, tạo tag/release, sửa Issues/Milestones trừ khi người dùng yêu cầu rõ ràng. Quyền đã được cấp trong nhiệm vụ hiện tại không cần hỏi lại.
- Không đưa secrets, dữ liệu nhạy cảm, dataset hoặc artifact lớn vào Git. Không thay giấy phép Apache-2.0; ghi nhận nghĩa vụ của dependency/assets theo giấy phép riêng.
- Dùng lệnh Python và đường dẫn tương đối từ root. Trên Windows kiểm tra shell thực tế, dùng PowerShell hoặc Python stdlib; không giả định Bash, `make`, `source`, `&&` có sẵn. Không cài dependency/plugin/MCP nếu không cần; không thay cấu hình OpenCode cá nhân.
- Kiểm chứng theo thay đổi và CI thực tế ở [.github/workflows/ci.yml](.github/workflows/ci.yml). Lệnh nền: `python scripts/check_environment.py`, `python -m pytest tests/unit/test_basic.py tests/integration/test_pipeline.py -q`, `git diff --check`. Chỉ chạy khi phù hợp; không coi model constructor test là fit/predict hay benchmark.
- Báo từng kiểm tra bằng PASS, FAIL, SKIPPED hoặc NOT VERIFIED, kèm lệnh/bằng chứng và giới hạn. Phân biệt planned / implemented / tested / experimentally validated. Exit code 0 với thông báo bỏ qua dataset vẫn là SKIPPED.
- Trả lời tiếng Việt, giữ nguyên định danh kỹ thuật. Không bịa kết quả, đường dẫn, CI hoặc metric. Không đọc toàn bộ docs/skills nếu vài file liên quan đủ để xử lý.

## Code Review Rules

Review từ yêu cầu và diff thực tế, tự đọc code/test; kết luận của implementer chỉ là dữ kiện cần đối chiếu. Ưu tiên bug, regression, security, compatibility, data leakage và thiếu kiểm thử hành vi. Báo finding có mức độ, file:dòng, tình huống tái hiện/tác động; review-only không tự sửa. Nếu dùng cùng agent, nêu rõ đây là lượt review lại, không phải reviewer độc lập.
