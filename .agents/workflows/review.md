# Review — workflows/review.md

Review sau triển khai:

- Tự đọc yêu cầu, diff thực tế (`git diff`, staged/unstaged, untracked files), code và test trước khi đối chiếu nhận xét của implementer.
- Tìm lỗi logic, regression, leakage, fail-open bypass, xử lý nhãn sai, sai lệch metric và vấn đề tái lập.
- Kiểm tra ranh giới trọng yếu của v2:
  - Fail-closed `"deployment"` OOD policy & trusted `NETFLOW_OOD_GATE_SHA256` (không tự downgrade về `"research"`).
  - Ranh giới dữ liệu (`AIT-LDS-v2.1` `CC BY-NC-SA 4.0` cách ly khỏi ML/demo; không dùng `ait_test` hay target dataset để tune/calibrate; không fallback v1 `NF-UNSW-NB15-v3`).
  - Bảo toàn frozen `E0` artifacts (`RESEARCH_ONLY`, `production_ready=false`) và governance (`DISTRIBUTION_AUTHORIZATION.json` giữ `approved: false`).
  - Đồng bộ FastAPI schemas ↔ `reports/api/openapi.json` ↔ `desktop/src/lib/types.ts` ↔ Svelte/Tauri IPC.
  - Non-attribution (`Trace`/`Behavioral`), `executed=false` security dry-run, và không có dấu ấn/trailer AI trong code/docs/commit/PR.
- Kiểm tra test có xác minh hành vi thực tế và đường lỗi (bao gồm CI compatibility khi vắng `artifacts/`), không chỉ import/constructor.
- Phân loại findings: `BLOCKER`, `HIGH`, `MEDIUM`, `LOW`, kèm `file:dòng`, tình huống tái hiện và tác động.
- Chỉ kết luận dựa trên bằng chứng; `REVIEW-only` không tự sửa file hay cập nhật GitHub. Nếu cùng agent thực hiện kiểm tra lại, nêu rõ đây là self-review, không phải independent review.
