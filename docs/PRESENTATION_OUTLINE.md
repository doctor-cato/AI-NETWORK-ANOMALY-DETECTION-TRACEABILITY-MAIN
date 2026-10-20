# Dàn ý trình bày — 10–12 slide

1. Tiêu đề — tên dự án, nhóm, cơ sở đào tạo.
2. Vấn đề — phát hiện bất thường mạng; ý nghĩa; phạm vi.
3. Dataset — NF-UNSW-NB15-v3; provenance/license, 55-column schema, quality FAIL và migration
   history của UNSW-NB15 (2015).
4. Phương pháp — sơ đồ pipeline; split; preprocessing; Random Forest; protocol Isolation Forest (đánh giá riêng).
5. Thiết kế thực nghiệm — seed; metric; khác biệt protocol.
6. Kết quả — bảng metric; trực quan confusion matrix; so sánh cùng giải thích protocol.
7. Phân tích lỗi — false positive, false negative, giới hạn.
8. Inference / demo — xử lý đầu vào mới và đầu ra mẫu.
9. Thảo luận — diễn giải; tác động chất lượng dữ liệu; giới hạn model.
10. Kết luận — phần đã đạt, phần còn lại, liên kết công việc tương lai.
11. Tài liệu tham khảo và lời cảm ơn.
12. Phụ lục / dự phòng — sơ đồ kiến trúc, config.

## Chuẩn bị thuyết trình và vấn đáp cá nhân

Yêu cầu của giảng viên gồm cả phần chuẩn bị trình bày, không chỉ dàn ý. Checklist tối thiểu:

- [ ] Phân vai người trình bày theo slide; mỗi người thuộc ít nhất 2 slide và biết cách chuyển đoạn.
- [ ] Diễn tập đủ thời lượng ít nhất 2 lần: một lần có tính giờ, một lần không dùng ghi chú.
- [ ] Chuẩn bị slide dự phòng cho trường hợp demo hoặc live prediction hỏng: dùng sẵn ảnh kết quả và
      bảng metric đã lưu.
- [ ] Danh sách câu hỏi vấn đáp dự kiến và câu trả lời: dataset lấy từ nguồn nào, checksum thế nào, vì sao
      Random Forest là baseline, split trước hay sau fitting, FPR nghĩa là gì trong confusion matrix,
      Isolation Forest khác Random Forest ở đâu, vì sao không khẳng định phát hiện zero-day, giới hạn của
      dữ liệu mất cân bằng.
- [ ] Nếu chưa có kết quả thật, trình bày dạng "planned / chưa kiểm chứng" và nêu rõ sẽ lấy bằng chứng ở
      milestone nào — không trình bày số liệu chưa chạy.

## Yêu cầu trả lời vấn đáp dựa trên bằng chứng

Mọi câu trả lời về kết quả phải trỏ về artifact hoặc `docs/TRACEABILITY_MATRIX.md`. Câu nào chưa có bằng
chứng thì trả lời "chưa kiểm chứng, sẽ bổ sung ở #<issue>", không ước lượng số liệu tại chỗ.

Cập nhật: 2026-10-20
