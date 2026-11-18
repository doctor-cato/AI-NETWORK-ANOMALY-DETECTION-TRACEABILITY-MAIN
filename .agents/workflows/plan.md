# Kế hoạch — workflows/plan.md

Khi nhận task:

1. Đọc yêu cầu; xác định kết quả cần đạt và chế độ (`PLAN-only` hay được phép `IMPLEMENT`).
2. Kiểm tra `git status --short`, branch, HEAD, remote; đọc `README.md`, [TRACEABILITY_MATRIX.md](../../docs/TRACEABILITY_MATRIX.md) và chỉ các docs/code/test/CI liên quan. Đọc file thực tế, không dùng snapshot tài liệu cũ làm trạng thái live.
3. Xác định phần đã có / chưa có / ảnh hưởng chéo giữa các lớp: Python (`src/network_anomaly/`), FastAPI/OpenAPI (`reports/api/openapi.json`), Svelte/TS (`desktop/src/`), Rust/Tauri (`desktop/src-tauri/`), companion artifacts/OOD gate (`scripts/verify_companion_artifacts.py`) và GitHub Actions (`.github/workflows/ci.yml`).
4. Xác định issue/milestone (`M6.1–M6.7`), acceptance criteria và chọn đúng domain skill trong `.agents/skills/`: `network-intrusion-detection`, `unsw-nb15-protocol` (dataset protocol v2 + v1 historical), `ml-experiment-audit`, hoặc `model-experiment`. Chỉ đọc skill thực sự cần.
5. Nếu liên quan ML/dữ liệu, xác định trạng thái dữ liệu (`absent` / `synthetic` / `real v2` / `historical v1`), ranh giới split/preprocessor/OOD gate, tách bạch `E0` đóng băng vs thí nghiệm riêng, và điều kiện để nâng `PLANNED → IMPLEMENTED → TESTED → EXPERIMENTALLY VALIDATED`.
6. Lập kế hoạch theo thứ tự ưu tiên rõ ràng, nêu danh sách file dự kiến sửa/tạo, ranh giới phạm vi/ngoài phạm vi, rủi ro và bộ lệnh kiểm chứng (`pytest -rs`, `ruff`/`black`, `npm`, `cargo`, scripts check).
7. Ưu tiên giải pháp nhỏ nhất, tái sử dụng helper hiện có, không mở rộng scope hoặc tự ý sửa `E0` / `DISTRIBUTION_AUTHORIZATION.json` / `origin/site-source`.
8. `PLAN-only` không sửa file trong repo. Chỉ chuyển `IMPLEMENT` khi đã được phép triển khai hoặc kế hoạch đã được duyệt rõ ràng.
9. Chỉ hỏi khi thiếu quyết định nghiệp vụ/ML bắt buộc (ví dụ có cho phép training lại hay chọn hướng đánh đổi); không hỏi lại dữ kiện đã đọc được trong repo.
