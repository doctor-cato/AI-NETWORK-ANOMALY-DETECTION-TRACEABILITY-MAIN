# Kế hoạch phát triển (5–6 tuần)

| Tuần | Trọng tâm | Milestone | Deliverable chính |
|---|---|---|---|
| 1 | Repository, tài liệu, môi trường, CI | M0 | Cấu trúc; README; tài liệu; CI; label |
| 2 | Kiểm tra dữ liệu, EDA, leakage audit | M1 | Hướng dẫn dataset; script validation; EDA; tài liệu leakage audit |
| 3 | Pipeline preprocessing; Random Forest; baseline | M2 | Pipeline; model RF; metric đã ghi; ghi chú tái lập |
| 4 | Isolation Forest (nếu đủ thời gian); evaluation; so sánh; error analysis | M3 | Protocol IF; bảng so sánh; confusion matrix; phân tích |
| 5 | Inference; demo; trực quan hóa; integration test | M4 | Module inference; script demo; test; trực quan hóa |
| 6 | Tài liệu cuối; báo cáo; trình bày; kiểm chứng | M5 | Dàn ý báo cáo hoàn chỉnh; dàn ý trình bày; kiểm tra cuối |

Phụ thuộc: M2 phụ thuộc M1 vì preprocessing cần dữ liệu đã xác minh. M3 phụ thuộc M2 vì evaluation cần model đã train. M4 phụ thuộc M3 vì demo dùng kết quả. M5 phụ thuộc M4 vì kiểm chứng cuối dùng mọi đầu ra trước đó.

Cập nhật: 2026-10-17
