# Presentation Outline — 10–12 slides

1. Title — project name, team, institution
2. Problem — network anomaly detection; why it matters; scope
3. Dataset — UNSW-NB15; structure; download and verification status
4. Methodology — pipeline diagram; split; preprocessing; Random Forest; Isolation Forest protocol (separate evaluation)
5. Experimental design — seeds; metrics; protocol differences noted
6. Results — metrics table; confusion matrix visualization; comparison (with clear protocol explanation)
7. Error analysis — false positives, false negatives, limitations
8. Inference / demo — how new input is processed; sample output
9. Discussion — interpretations; data quality impact; model limits
10. Conclusion — achievements; what remains; links to future work
11. References and acknowledgments
12. Appendix / backup — architecture diagram, config

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

Updated: 2026-10-17
