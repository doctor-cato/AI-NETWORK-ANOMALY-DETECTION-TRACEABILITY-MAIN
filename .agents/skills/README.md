# .agents/skills/ — Skill tích hợp

## Codex (portable)

[repo-workflow/SKILL.md](repo-workflow/SKILL.md) là skill local cho PLAN/IMPLEMENT/VERIFY/REVIEW, không cần skill toàn cục hoặc cài thêm công cụ. Chỉ mục `name`/`description` dùng để khám phá; nội dung được đọc khi kích hoạt. Xem [hướng dẫn dùng](../README.md).

## OpenCode (giữ nguyên các tích hợp cũ)

Các thư mục bên dưới chỉ có `INTEGRATION.md`, không phải skill Codex tự khám phá. Các ghi chú ngày 2026-10-16 là snapshot lịch sử, phải xác minh lại; không phải bằng chứng test hiện tại. Đường dẫn toàn cục chỉ tồn tại trên máy tác giả; không phụ thuộc chúng để dùng Codex.

Cơ chế: `find_skill.py` (OpenCode) tìm skill ở `C:\Users\Admin\.agents\skills/` qua `skills_index.json`. Repo này không sao chép toàn bộ SKILL.md (giấy phép / kích thước) mà dùng tích hợp nhẹ.

Chọn 4 skill chất lượng, đã kiểm tra nội dung (SKILL.md) — không có lệnh cài đặt nghi ngờ, không yêu cầu gửi dữ liệu ra ngoài, không tự xóa file.

| Skill | Nguồn toàn cục | Mục đích trong repo |
|---|---|---|
| python-pro | `.agents/skills/python-pro/` | Python 3.11+, code chất lượng cho RF/IF pipeline |
| scikit-learn | `.agents/skills/scikit-learn/` | ML pipeline, preprocessing, evaluation với sklearn |
| pytest-skill | `.agents/skills/pytest-skill/` | Test fixtures cho synthetic và pipeline integration |
| git-workflow-and-versioning | `.agents/skills/git-workflow-and-versioning/` | Atomic commits, branch sạch, không force-push |

Kích hoạt: agent tham chiếu file `INTEGRATION.md` tương ứng hoặc yêu cầu đọc SKILL.md toàn cục khi cần chi tiết. Không tự động tải nội dung từ bên ngoài.
