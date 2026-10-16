---
name: repo-workflow
description: "Vận hành PLAN, IMPLEMENT, VERIFY và REVIEW trong repository này. Dùng khi lập kế hoạch, triển khai thay đổi đã được giao, kiểm chứng hoặc review; tôn trọng chế độ plan-only/review-only. Không kích hoạt cho hỏi đáp không liên quan repository."
---

# Workflow repository

Đọc [AGENTS.md](../../../AGENTS.md) và phạm vi nhiệm vụ hiện tại. Đây là hướng dẫn quy trình, không phải quyền sandbox hoặc quyền ghi GitHub.

## Input và chọn chế độ

Input: yêu cầu, phạm vi file/base diff, ràng buộc, kế hoạch đã thống nhất (nếu có), bằng chứng kiểm chứng trước đó. Khi thiếu base để review, dùng working-tree diff gồm staged/unstaged và đọc file mới chưa tracked; nói rõ phạm vi đã chọn.

Chỉ đọc một workflow tương ứng khi bắt đầu bước đó:

| Chế độ | Hướng dẫn | Output |
|---|---|---|
| PLAN | [plan.md](../../workflows/plan.md) | Phạm vi, dependency/rủi ro, bước thực hiện và cách kiểm chứng |
| IMPLEMENT | [implement.md](../../workflows/implement.md) | Diff tối thiểu, file thay đổi, lý do và việc còn lại |
| VERIFY | [verify.md](../../workflows/verify.md) | Bảng check, lệnh, trạng thái và bằng chứng |
| REVIEW | [review.md](../../workflows/review.md) | Findings theo mức độ, vị trí, tác động và giới hạn |

## Chuyển giao

- PLAN → IMPLEMENT khi phạm vi/kế hoạch rõ và nhiệm vụ đã cho phép thực hiện. Không yêu cầu xác nhận lại chỉ vì kết thúc PLAN. PLAN-only dừng ở kế hoạch.
- IMPLEMENT → VERIFY khi có diff cụ thể và danh sách kiểm tra tương ứng.
- VERIFY → REVIEW khi các check bắt buộc PASS; SKIPPED/NOT VERIFIED phải nêu tác động, không tự coi là PASS. Có thể review phần đã kiểm tra, nhưng giữ kết luận chưa đủ bằng chứng.
- VERIFY/REVIEW phát hiện lỗi trong phạm vi và nhiệm vụ cho phép sửa: trở lại IMPLEMENT, rồi chạy lại check bị ảnh hưởng và review lại. Review-only chỉ báo finding.
- Nếu cùng lỗi tái diễn sau hai lượt sửa, hoặc cần mở rộng scope/quyền/dữ liệu, dừng vòng tự sửa, báo bằng chứng và điều kiện để tiếp tục. Không tạo vòng lặp tự động vô hạn. Người dùng có thể yêu cầu tiếp tục.
- Không tự commit/push/cập nhật GitHub sau REVIEW. Tóm tắt kết quả và thay đổi chưa commit.

## Subagents và công cụ

Nếu runtime hỗ trợ và nhiệm vụ cho phép delegation, dùng subagent cho phần độc lập đủ phức tạp (ví dụ review riêng). Giao yêu cầu/base/file/ràng buộc; reviewer tự đọc diff trước khi xem kết luận implementer. Không giao hai writer cùng file; parent đối chiếu kết quả. Tác vụ nhỏ dùng một agent. Khi không hỗ trợ, chạy tuần tự và công khai giới hạn độc lập.

Không chuyển cú pháp agent/command/permissions của OpenCode thành lệnh Codex. MCP chỉ dùng cho công cụ bên ngoài cần thiết đã có quyền; workflow local không cần MCP hay dependency mới.

Kiểm tra cấu trúc: `python .agents/skills/repo-workflow/scripts/check_workflows.py`. Script này chỉ kiểm tra file/metadata/link; không thay thế kiểm chứng runtime discovery hoặc chất lượng review.
