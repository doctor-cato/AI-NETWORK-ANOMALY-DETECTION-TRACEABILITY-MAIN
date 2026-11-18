# Hướng dẫn Sử dụng NetFlow Sentinel v2.0

Tài liệu này hướng dẫn vận hành giao diện Desktop **NetFlow Sentinel v2** (4 mô hình AI `canonical-flow-v2-18`, Behavioral Vector, Attack Timeline, Cryptography Dashboard và Security Dry-Run).

---

## 1. Năm Màn hình Vận hành Chính

| Màn hình | Chức năng Thực tế | Endpoint Backend |
|---|---|---|
| **Offline CSV & 4-Model Compare** | Nạp CSV 18 đặc trưng chuẩn v2 (`canonical-flow-v2-18`) hoặc mở `demo_flows.csv`, hiển thị `AI Ready 4/4` sau kiểm thực SHA-256 | `/api/v1/csv/inspect`, `/api/v1/csv/analyze` |
| **Live Telemetry & Streaming** | Giám sát event stream, backpressure ring buffer, chế độ Replay / UDP Loopback lab | `/api/v1/live/start`, `/api/v1/live/status`, `/api/v1/live/results`, `/api/v1/live/alerts`, `/api/v1/live/graph` |
| **Behavioral Analysis** | Hiển thị `Behavioral Vector` 16-D theo sliding time-window & cosine similarity score | `/api/v1/behavioral/vectors`, `/api/v1/behavioral/similarity`, `/api/v1/behavioral/correlate` |
| **Attack Timeline & Trace** | Tách biệt `OBSERVED TELEMETRY` vs `INFERRED RELATIONSHIP`, xuất investigation report kèm SHA-256 | `/api/v1/trace/timeline`, `/api/v1/trace/graph`, `/api/v1/trace/investigation/generate` |
| **Cryptography & Security Dry-Run** | Theo dõi `active_key_id`, Windows DPAPI / KEK AES-256-GCM, lịch sử xoay vòng khóa & mô phỏng phản ứng `executed=false` | `/api/v1/crypto/status`, `/api/v1/keys`, `/api/v1/rotation`, `/api/v1/security/simulate-response` |

---

## 2. Quy trình vận hành chuẩn trong Lab được cấp phép

1. **Khởi động ứng dụng & kiểm tra sẵn sàng:** Mở NetFlow Sentinel, xác nhận Backend `Online` và `AI Ready 4/4` (`Random Forest`, `XGBoost`, `Isolation Forest`, `Autoencoder` đã qua `ModelRegistry` SHA-256 verification).
2. **Phân tích luồng mạng:**
   - Với CSV: nạp tệp tuân thủ hợp đồng 18 đặc trưng `canonical-flow-v2-18` hoặc dùng `data/demo/demo_flows.csv` (200 dòng Validation của `AIT-NDS-v2`).
   - Với kịch bản UDP Lab: chạy `.venv\Scripts\python.exe scripts/run_live_lab_acceptance.py` để xác minh nhận gói tin qua UDP loopback `127.0.0.1`, mã hóa AES-256-GCM và kích hoạt Adaptive Key Rotation.
3. **Điều tra & Kiểm tra khóa:** Kiểm tra tab Behavioral / Attack Timeline và Cryptography Dashboard (`master.key` bảo vệ bởi Windows DPAPI / POSIX permissions).

---

## 3. Giới hạn an toàn & Bản quyền Dữ liệu v2

- **Chỉ giám sát mạng được cấp phép:** Không tự động chỉnh sửa tường lửa OS (`executed=false` ở Security Dry-Run).
- **Bản quyền dữ liệu v2:** Các mô hình v2 được huấn luyện và đánh giá trên `AIT-NDS-v2` (`10.5281/zenodo.13168643`) và `CTU-SME-11` (`10.5281/zenodo.7958258`) theo giấy phép **CC BY 4.0**. Nguồn `UGR'16` đang `BLOCKED` (HTTP 403) và không sử dụng.
