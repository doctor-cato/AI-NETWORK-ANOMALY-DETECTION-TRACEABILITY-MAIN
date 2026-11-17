# Hướng dẫn Sử dụng NetFlow Sentinel v2.0 (Controlled Pilot Edition)

Tài liệu này hướng dẫn người vận hành (Operator / SOC Analyst) sử dụng **NetFlow Sentinel v2.0** trong môi trường lab hoặc mạng nội bộ được cấp phép.

---

## 1. Kiến trúc tổng quan cho người vận hành

NetFlow Sentinel v2.0 kết hợp:
- **Backend FastAPI + 4-Model AI Engine (`src/network_anomaly/`)**: Thu nạp sự kiện từ NetFlow v9/IPFIX UDP collector (`NetFlowIPFIXDecoder`), file PCAP (`LocalPCAPReader`), hoặc log web/auth (`LiveLogTailer`), chuẩn hóa về `CanonicalSecurityEvent` (47 đặc trưng).
- **Behavioral & Risk Engine**: Tạo Behavioral Vector 16 chiều (chuẩn hóa L2, độc lập IP), chấm điểm rủi ro 0–100 và phát cảnh báo đã khử trùng lặp trong cửa sổ 60 giây.
- **Cryptography & Key Lifecycle**: Bảo vệ `master.key` bằng Windows DPAPI (`CryptProtectData`, fail-closed không ghi plaintext fallback), bọc khóa DEK bằng AES-256-GCM (`NETFLOW_WRAPPED_DEK_V2:` gắn AAD `key_id|domain|version`), lưu trữ vector nhạy cảm hoàn toàn ở dạng bản mã AES-256-GCM (zero plaintext in SQLite), và kích hoạt Adaptive Key Rotation khi `risk_score >= 85.0`. Hỗ trợ di trú khóa cũ có kiểm soát qua `scripts/migrate_keystore.py`.
- **Attack Traceability**: Dựng đồ thị thực thể (`EntityRelationshipGraph`), tái hiện `AttackTimeline` theo pha ATT&CK và xuất báo cáo điều tra kèm mã băm SHA-256 kiểm chứng (`InvestigationReportGenerator`).
- **Desktop UI (Tauri 2 + Svelte 5)**: Giao tiếp loopback có xác thực `X-Sentinel-Session-Token` qua Tauri IPC; phân biệt minh bạch 6 trạng thái dữ liệu (`LOADING`, `CONNECTED`, `DISCONNECTED`, `EMPTY`, `ERROR`, `DEMO`).

---

## 2. Các màn hình chức năng trên Desktop App

| Tab | Chức năng chính | API / Dữ liệu liên kết |
|---|---|---|
| **Tổng quan & CSV** | Kiểm tra sức khỏe hệ thống (`/health`), chọn/nạp CSV 47 cột, chạy 4 mô hình AI, xem cảnh báo `ABSTAINED_OOD` | `/health`, `/api/v1/models`, `/api/v1/csv/inspect`, `/api/v1/csv/analyze` |
| **Live Monitoring** | Bật/tắt UDP collector thật, theo dõi throughput/latency/queue utilization/readiness và cảnh báo thời gian thực | `/api/v1/live/status`, `/api/v1/live/start`, `/api/v1/live/stop`, `/api/v1/live/alerts`, `/api/v1/incidents` |
| **Behavioral Analysis** | Giải mã có kiểm soát vector hành vi 16 chiều (`BehavioralVectorBuilder`), đo tương đồng Cosine/Euclidean/Manhattan và phân cụm `IPSpoofingSessionCorrelator` | `/api/v1/behavioral/vectors`, `/api/v1/behavioral/vectors/{id}`, `/api/v1/behavioral/similarity`, `/api/v1/behavioral/correlate` |
| **Attack Timeline** | Chọn incident/campaign thật, tách biệt giai đoạn `OBSERVED TELEMETRY` vs `INFERRED RELATIONSHIP`, xuất báo cáo kèm SHA-256 thật | `/api/v1/trace/timeline`, `/api/v1/trace/graph`, `/api/v1/trace/investigation/generate` |
| **Cryptography Dashboard** | Giám sát `active_key_id`, chế độ bảo vệ keystore (`WINDOWS_DPAPI` / `POSIX_FILE_PERMISSIONS`), ACL, cooldown và lịch sử xoay vòng khóa thật | `/api/v1/crypto/status` |
| **Security Dry-Run** | Mô phỏng khuyến nghị phản ứng (`NO_ACTION`, `MONITOR`, `INVESTIGATE`, `ISOLATE_RECOMMENDED`) ở chế độ an toàn `executed=false` | `/api/v1/security/simulate-response` |

---

## 3. Quy trình vận hành chuẩn trong Lab được cấp phép

1. **Khởi động ứng dụng & kiểm tra sẵn sàng:** Mở NetFlow Sentinel, kiểm tra trạng thái Backend `Online` và mô hình `Random Forest (MODEL_VALIDATED)` sẵn sàng.
2. **Phân tích luồng mạng hoặc kiểm thử kịch bản Lab:**
   - Với CSV: nạp tệp theo schema 47 cột hoặc dùng dữ liệu demo chuẩn.
   - Với kịch bản UDP Lab: chạy `python scripts/run_live_lab_acceptance.py` để xác minh nhận gói tin NetFlow v9 qua socket loopback UDP (`127.0.0.1`), giải mã và kích hoạt Adaptive Key Rotation.
3. **Điều tra & Truy vết:** Chuyển sang tab **Attack Timeline** và **Behavioral Analysis** để rà soát các pha tấn công liên kết và tải Investigation Report có SHA-256.
4. **Kiểm tra khóa mật mã:** Vào **Cryptography Dashboard** để xác nhận không có khóa gốc plaintext trên đĩa (`master.key` được bảo vệ bởi Windows DPAPI, các khóa `k-*.key` được bọc KEK AES-256-GCM) và kiểm tra nhật ký xoay vòng khóa.

---

## 4. Giới hạn an toàn & phạm vi v2.0

- **Chỉ giám sát mạng được cấp phép:** Không chặn hoặc chỉnh sửa firewall hệ điều hành tự động trong chế độ mặc định (`executed=false` đối với simulation).
- **Collector v2.0:** Sử dụng `NetFlowIPFIXDecoder` bằng Python trong `src/network_anomaly/telemetry/collector.py`; phiên bản collector viết bằng Rust (#128 gốc) được hoãn ngoài phạm vi v2.0.0.
- **Giấy phép mô hình `NF-UNSW-NB15-v3`:** Các trọng số dẫn xuất từ `NF-UNSW-NB15-v3` tuân thủ điều khoản nghiên cứu/nội bộ (`UQ License ID 454104`); xem `docs/DEPLOYMENT_GUIDE_V2.md` trước khi phân phối bộ cài ra ngoài.
