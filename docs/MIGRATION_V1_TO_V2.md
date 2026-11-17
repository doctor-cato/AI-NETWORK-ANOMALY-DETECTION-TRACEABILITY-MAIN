# NetFlow Sentinel v1.0.0 $\to$ v2.0.0 Migration & Compatibility Guide

> **Tài liệu nâng cấp và tương thích dữ liệu (Issue #80 — Milestone M6.1)**  
> **Phiên bản:** 2.0.0-migration  
> **Script thực thi:** `scripts/migrate_v1_to_v2.py`

---

## 1. Ma trận Tương thích Artifact và Dữ liệu giữa v1.0.0 và v2.0.0

| Thành phần / Dữ liệu v1.0.0 | Trạng thái v2.0 | Hướng Xử lý / Chuyển đổi | Bằng chứng Kiểm chứng |
|---|:---:|---|---|
| **SQLite DB (`sentinel.db`)** | `CẦN UPGRADE (Idempotent)` | Nâng cấp tự động qua `scripts/migrate_v1_to_v2.py`, bảo toàn 100% dữ liệu sự kiện, phiên, và sự cố cũ. | `tests/integration/test_migration_v1_to_v2.py` PASS. |
| **Model Binaries (`artifacts/models/`)** | `DÙNG ĐƯỢC NGUYÊN TRẠNG` | Mô hình Random Forest (`.joblib`), XGBoost (`.json`), Isolation Forest và Autoencoder giữ nguyên hash SHA-256. | Preprocessor & model hash khớp manifest. |
| **Preprocessor Artifact** | `DÙNG ĐƯỢC NGUYÊN TRẠNG` | Frozen preprocessor hash `12d4360a05...` được tái sử dụng trực tiếp cho luồng suy luận NetFlow 47 features. | `tests/integration/test_pipeline.py` PASS. |
| **Offline CSV Inputs** | `DÙNG ĐƯỢC QUA ADAPTER` | Các tệp CSV định dạng v1.0.0 (55 cột) được tự động ánh xạ sang `CanonicalSecurityEvent` v2. | `tests/contract/test_canonical_security_event_v2.py` PASS. |
| **Desktop Settings / Nonce** | `TƯƠNG THÍCH HOÀN TOÀN` | Phiên bản desktop giữ nguyên giao thức loopback token `X-Sentinel-Session-Token`. | FastAPI sidecar guard test PASS. |

---

## 2. Hướng dẫn Thực hiện Nâng cấp Database (DB Migration)

### 2.1. Kiểm tra Xem trước (Dry-run Preview)
Trước khi nâng cấp cơ sở dữ liệu thực tế, chạy script ở chế độ dry-run để kiểm tra các thay đổi cấu trúc:
```bash
python scripts/migrate_v1_to_v2.py --db-path data/sentinel.db --dry-run
```

### 2.2. Nâng cấp Chính thức (Live Migration with Backup)
Chạy lệnh nâng cấp chính thức. Script sẽ tự động tạo bản sao lưu `data/sentinel_backup_<timestamp>.db` trước khi áp dụng thay đổi:
```bash
python scripts/migrate_v1_to_v2.py --db-path data/sentinel.db
```

### 2.3. Quy trình Rollback khi gặp Sự cố
Nếu quá trình nâng cấp bị gián đoạn do sự cố phần cứng hoặc lỗi I/O:
1. Đóng tiến trình NetFlow Sentinel.
2. Xóa tệp `sentinel.db` bị lỗi.
3. Đổi tên tệp sao lưu `sentinel_backup_<timestamp>.db` trở lại thành `sentinel.db`.
4. Khởi động lại hệ thống ở phiên bản v1.0.0.
