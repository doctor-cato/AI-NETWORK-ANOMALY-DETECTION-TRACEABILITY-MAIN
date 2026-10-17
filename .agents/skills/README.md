# .agents/skills/ — Skill tích hợp

## Skills local (portable)

- [repo-workflow](repo-workflow/SKILL.md) — điều phối PLAN/IMPLEMENT/VERIFY/REVIEW.
- [network-intrusion-detection](network-intrusion-detection/SKILL.md) — semantics network flow, feature và FP/FN.
- [unsw-nb15-protocol](unsw-nb15-protocol/SKILL.md) — provenance, schema, label, split và integrity.
- [ml-experiment-audit](ml-experiment-audit/SKILL.md) — leakage/evaluation audit với PASS/FAIL criteria.
- [model-experiment](model-experiment/SKILL.md) — RF/IF experiment, artifact và reproducibility.

Chỉ mục `name`/`description` phục vụ discovery; nội dung được đọc khi skill áp dụng. Domain skill không lặp lại
workflow chung và không được nạp đồng loạt. Xem [hướng dẫn dùng](../README.md).

Phân biệt bốn trạng thái:

1. folder/SKILL.md tồn tại trong repository;
2. frontmatter/link hợp lệ theo validator;
3. runtime hiện tại khám phá skill (phụ thuộc host/session và có thể cần mở session mới);
4. skill thực sự được kích hoạt/đọc cho task (cần bằng chứng của lượt chạy).

Ba trạng thái đầu không chứng minh trạng thái sau.

## OpenCode (giữ nguyên các tích hợp cũ)

Các thư mục bên dưới chỉ có `INTEGRATION.md`, không phải skill Codex tự khám phá. Các ghi chú ngày 2026-10-16 là snapshot lịch sử, phải xác minh lại; không phải bằng chứng test hiện tại. Đường dẫn toàn cục chỉ tồn tại trên máy tác giả; không phụ thuộc chúng để dùng Codex.

Cơ chế global đã kiểm tra trên máy hiện tại: `C:\Users\Admin\.agents\scripts\find_skill.py` tìm skill ở
`C:\Users\Admin\.agents\skills\` qua `C:\Users\Admin\.agents\skills_index.json`. Repo không phụ thuộc cơ chế
machine-specific này. OpenCode không được giả định tự khám phá repo-local `SKILL.md`; khi permission/allowlist không
có tên skill, đọc file local trực tiếp theo routing trong `AGENTS.md`. Không sửa config global để ép tương thích.

Chọn 4 skill chất lượng, đã kiểm tra nội dung (SKILL.md) — không có lệnh cài đặt nghi ngờ, không yêu cầu gửi dữ liệu ra ngoài, không tự xóa file.

| Skill | Nguồn toàn cục | Mục đích trong repo |
|---|---|---|
| python-pro | `.agents/skills/python-pro/` | Python 3.11+, code chất lượng cho RF/IF pipeline |
| scikit-learn | `.agents/skills/scikit-learn/` | ML pipeline, preprocessing, evaluation với sklearn |
| pytest-skill | `.agents/skills/pytest-skill/` | Test fixtures cho synthetic và pipeline integration |
| git-workflow-and-versioning | `.agents/skills/git-workflow-and-versioning/` | Atomic commits, branch sạch, không force-push |

Kích hoạt: agent tham chiếu file `INTEGRATION.md` tương ứng hoặc yêu cầu đọc SKILL.md toàn cục khi cần chi tiết. Không tự động tải nội dung từ bên ngoài.
