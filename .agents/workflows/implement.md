# Triển khai — workflows/implement.md

Khi thực hiện:

1. Làm đúng kế hoạch đã thống nhất và giữ đúng ranh giới trong [project-scope.md](../rules/project-scope.md) và [coding-standards.md](../rules/coding-standards.md).
2. Đọc file liên quan trước khi sửa (`read_file` có giới hạn dòng, kiểm tra signature/constructor thay vì đoán).
3. Không ghi đè thay đổi chưa commit của người dùng; kiểm tra `git status` trước khi sửa.
4. Không tạo placeholder hay hardcode giả lập rồi báo đã hoàn thành; mọi trạng thái `UNAVAILABLE`/`EMPTY`/`DISCONNECTED`/`BLOCKED` phải fail-closed trung thực.
5. Không sửa file ngoài phạm vi; **không** tự ý sửa/ghi đè 4 model `E0` `.joblib`, `v2_flow_preprocessor.joblib`, `ood_reference_gate.json` hoặc `DISTRIBUTION_AUTHORIZATION.json` (`approved: false`).
6. Không tự tải dataset lớn hay chạy training dài trừ khi được yêu cầu rõ; mọi nguồn mới phải kiểm tra bản quyền (`CC BY 4.0` vs `CC BY-NC-SA 4.0`) trước khi tích hợp.
7. Nếu thay đổi API schema (`src/network_anomaly/api/schemas.py` hoặc `main.py`), chạy lại `python scripts/export_openapi_spec.py` để đồng bộ `reports/api/openapi.json` & `API_CONTRACT.md`; kiểm tra `desktop/src/lib/types.ts` tương ứng.
8. Với thay đổi Python, chạy format `black` + `ruff check --fix`; với Rust, chạy `cargo fmt`. Đảm bảo test mới hoạt động được cả trên GitHub Actions CI nơi `artifacts/` và raw data bị `.gitignore`.
9. Cập nhật tài liệu/báo cáo liên quan (`docs/`, `reports/`) trung thực theo số đo thực tế; giữ traceability tối thiểu qua tài liệu/manifest hiện có, không dựng framework mới.
10. Không tự stage, commit, push, sửa/đóng GitHub Issue/PR hoặc bỏ trạng thái `Draft` trừ khi người dùng yêu cầu rõ ràng; tuyệt đối không gắn dấu ấn/trailer AI. Chuyển sang `VERIFY` ngay khi có diff hoàn chỉnh.
