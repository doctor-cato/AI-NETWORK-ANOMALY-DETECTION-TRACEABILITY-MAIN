# Kiến trúc — Luồng dữ liệu và các mô-đun

```mermaid
graph LR
    A[UNSW-NB15 thô<br/>data/raw/] --> B[Kiểm tra & kiểm tra sơ bộ]
    B --> C[EDA / Kiểm tra rò rỉ dữ liệu]
    C --> D[Chia train/val/test]
    D --> E[Pipeline tiền xử lý<br/>fit trên train]
    E --> F[Huấn luyện mô hình<br/>Random Forest (bắt buộc)<br/>Isolation Forest (tùy chọn)]
    F --> G[Đánh giá<br/>metrics + confusion matrix]
    G --> H[Phân tích lỗi]
    H --> I[Pipeline suy luận<br/>dữ liệu mới -> dự đoán]
    I --> J[Demo / Báo cáo]
```

## Mô tả mô-đun

Cột "Trạng thái M0" nói rõ mô-đun đã có hành vi thật hay chỉ là khung. Mô-đun rỗng là kế hoạch cho M1–M4, không
được mô tả như đã triển khai.

| Mô-đun | Đường dẫn | Vai trò | Trạng thái M0 |
|---|---|---|---|
| Config | `src/network_anomaly/config.py` | Đường dẫn, seed, giá trị mặc định siêu tham số | implemented |
| Kiểm tra dữ liệu | `scripts/validate_data.py` | Đọc, kiểm tra schema, báo trạng thái | implemented (chỉ kiểm tra cấu trúc CSV) |
| Tiền xử lý | `src/network_anomaly/preprocessing/` | Đối tượng pipeline; mã hóa; chuẩn hóa | **placeholder** — thiết kế ở M2 (#8) |
| Đặc trưng | `src/network_anomaly/features/` | Quy tắc chọn / xây dựng đặc trưng | **placeholder** — M1 (#7) |
| Mô hình — Random Forest | `src/network_anomaly/models/random_forest.py` | Phân loại giám sát | constructor only; chưa fit/predict (M2, #10) |
| Mô hình — Isolation Forest | `src/network_anomaly/models/isolation_forest.py` | Phát hiện bất thường không giám sát | constructor only; **tùy chọn** (M3, #11) |
| Đánh giá | `src/network_anomaly/evaluation/` | Precision, Recall, F1, Macro-F1, confusion matrix | implemented; **chưa có FPR** (M3, #12) |
| Suy luận | `src/network_anomaly/inference/` | Tải artifact; dự đoán dữ liệu mới | hàm tải artifact; **chưa có entrypoint CLI** (M4, #15) |
| Trực quan hóa | `src/network_anomaly/visualization/` | Biểu đồ cho EDA, metrics, phân tích lỗi | **placeholder** — M4 (#16) |

Cập nhật: 2026-10-16
