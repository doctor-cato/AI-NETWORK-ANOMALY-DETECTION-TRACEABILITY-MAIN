# Dàn ý báo cáo (PDF / tài liệu bài tập)

1. Trang tiêu đề — tên dự án, tác giả, cơ sở đào tạo, ngày, license.
2. Tóm tắt — vấn đề, phương pháp, kết quả chính (bổ sung sau thực nghiệm), giới hạn.
3. Giới thiệu — động lực, phát biểu vấn đề, mục tiêu, ngoài mục tiêu.
4. Dataset — nguồn UNSW-NB15, cấu trúc, hướng dẫn tải, phiên bản, giới hạn.
5. Phương pháp — pipeline, chiến lược split, preprocessing, Random Forest, Isolation Forest (nếu triển khai), protocol đánh giá tách bạch.
6. Thiết lập thực nghiệm — môi trường, seed, hyperparameter, định nghĩa metric.
7. Kết quả — metric, confusion matrix, bảng so sánh, error analysis.
8. Thảo luận — diễn giải, false positive/negative, giới hạn dữ liệu, giá trị so sánh.
9. Kết luận — tóm tắt, phần hoạt động, giới hạn, bước tiếp theo.
10. Tài liệu tham khảo — nguồn dataset, scikit-learn, bài báo.
11. Phụ lục — file config, sơ đồ pipeline, bước tái lập.

## Gói nộp bộ (submission package)

Yêu cầu nộp bài gồm mã nguồn, tài liệu và dữ liệu. Ràng buộc bắt buộc của gói:

- **Mã nguồn:** toàn bộ repo tại commit đã ghi trong báo cáo; không cần thao tác sửa tay sau khi clone.
- **Tài liệu:** `README.md` + `docs/` (báo cáo này, dàn ý trình bày, phân công nhóm, hướng dẫn tái lập).
- **Dữ liệu:** UNSW-NB15 **không** commit và **không** phát tán lại trong gói nếu điều khoản sử dụng chưa
  cho phép. Gói chỉ ghi kèm: tên file, phiên bản, checksum và lệnh tải từ nguồn chính thức
  (`docs/DATASET.md`, `docs/REPRODUCIBILITY.md`). Nếu giảng viên yêu cầu kèm dữ liệu, phải ghi rõ điều khoản
  áp dụng trước khi đóng gói.
- **Không kèm:** secret, artifact model lớn, cache, notebook output; `.gitignore` đã chặn các nhóm này.
- Kiểm tra trước khi nộp: `python scripts/check_environment.py`, `python -m pytest tests -q`,
  `git diff --check`, và CI xanh trên đúng commit.

Cập nhật: 2026-10-17 — chỉ điền kết quả đã xác minh sau M3.
