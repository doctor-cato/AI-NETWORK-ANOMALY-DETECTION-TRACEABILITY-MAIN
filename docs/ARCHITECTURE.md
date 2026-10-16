# Kiến trúc — Luồng dữ liệu và các mô-đun

```mermaid
graph LR
    A[UNSW-NB15 thô<br/>data/raw/] --> B[Kiểm tra & kiểm tra sơ bộ]
    B --> C[EDA / Kiểm tra rò rỉ dữ liệu]
    C --> D[Chia train/val/test]
    D --> E[Pipeline tiền xử lý<br/>fit trên train]
    E --> F[Huấn luyện mô hình<br/>Random Forest / Isolation Forest]
    F --> G[Đánh giá<br/>metrics + confusion matrix]
    G --> H[Phân tích lỗi]
    H --> I[Pipeline suy luận<br/>dữ liệu mới -> dự đoán]
    I --> J[Demo / Báo cáo]
```

## Mô tả mô-đun

| Mô-đun | Đường dẫn | Vai trò |
|---|---|---|
| Config | `src/network_anomaly/config.py` | Đường dẫn, seed, giá trị mặc định siêu tham số |
| Kiểm tra dữ liệu | `scripts/validate_data.py` | Đọc, kiểm tra schema, tóm tắt |
| Tiền xử lý | `src/network_anomaly/preprocessing/` | Đối tượng pipeline; mã hóa; chuẩn hóa |
| Đặc trưng | `src/network_anomaly/features/` | Quy tắc chọn / xây dựng đặc trưng (đã ghi, không quá phức tạp) |
| Mô hình — Random Forest | `src/network_anomaly/models/random_forest.py` | Phân loại giám sát |
| Mô hình — Isolation Forest | `src/network_anomaly/models/isolation_forest.py` | Phát hiện bất thường không giám sát (nếu triển khai) |
| Đánh giá | `src/network_anomaly/evaluation/` | Metrics, confusion matrix, phân tích lỗi |
| Suy luận | `src/network_anomaly/inference/` | Tải artifact; dự đoán dữ liệu mới |
| Trực quan hóa | `src/network_anomaly/visualization/` | Biểu đồ cho EDA, metrics, phân tích lỗi |

Cập nhật: 2026-10-16
