# NetFlow Sentinel v2.0 — Live Telemetry Architecture & Lab Governance

**Document ID:** `ARCH-TELEMETRY-001`  
**Milestone:** `M6.6 (Real-world Network Telemetry & Live Streaming)`  
**Issue:** `#127`  
**Status:** `APPROVED & OPERATIONAL`  

---

## 1. Tổng quan Kiến trúc Giám sát Thời Gian Thực (Live Telemetry)

NetFlow Sentinel v2.0 mở rộng năng lực từ phân tích ngoại tuyến (Offline Batch) sang hệ thống giám sát dòng dữ liệu liên tục thời gian thực (Real-time Streaming Telemetry). Kiến trúc được module hóa thành các tiến trình độc lập với ranh giới rõ ràng:

```
+---------------------------------------------------------------------------------------------------+
| 1. TELEMETRY INGESTION LAYER                                                                      |
|    - NetFlow v9 / IPFIX UDP Collector (Port 2055 / 4739)                                           |
|    - Local PCAP Streamer / PCAP-to-Flow Converter                                                 |
|    - Zeek / Suricata Tailer (File descriptor persistence & log rotation handling)                 |
+---------------------------------------------------------------------------------------------------+
                                                  | (UDP Datagrams / Raw Byte Streams)
                                                  v
+---------------------------------------------------------------------------------------------------+
| 2. BUFFERING, BATCHING & BACKPRESSURE LAYER                                                       |
|    - Bounded In-Memory Ring Buffer (Capacity: 50,000 events)                                      |
|    - Backpressure Controller (Fail-closed drop counter, threshold alarms)                         |
|    - Dynamic Micro-batching (64 events or 50ms latency window)                                    |
+---------------------------------------------------------------------------------------------------+
                                                  | (CanonicalSecurityEvents v2)
                                                  v
+---------------------------------------------------------------------------------------------------+
| 3. ADAPTERS, QUALITY GATES & CANONICAL ROUTER                                                     |
|    - Strict Zero-Imputation Policy                                                                |
|    - Flow Events (18 canonical-flow-v2-18 features) -> ML Inference Pipeline                        |
|    - Non-Flow / Incomplete Events -> Route-Only (Behavioral & Trace Engine)                       |
+---------------------------------------------------------------------------------------------------+
                                                  |
                         +------------------------+------------------------+
                         |                                                 |
                         v                                                 v
+--------------------------------------------------+ +----------------------------------------------+
| 4. PARALLEL AI INFERENCE ENGINE                  | | 5. BEHAVIORAL INTELLIGENCE ENGINE            |
|    - Random Forest, XGBoost                      | |    - Sliding Window Sessionizer              |
|    - Isolation Forest, Autoencoder               | |    - 16-D Behavioral Vector Extractor        |
|    - Out-of-Distribution (OOD) Rejection Gate    | |    - AES-256-GCM Vector Encryption (M6.5)    |
+--------------------------------------------------+ +----------------------------------------------+
                         |                                                 |
                         +------------------------+------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
| 6. MULTI-CRITERIA RISK & TRACE ENGINE                                                             |
|    - Multi-Criteria Risk Scoring (0 - 100)                                                        |
|    - Threshold-based Adaptive Key Rotation Trigger (Risk >= 85 -> Cooldown-governed Key Rotation) |
|    - Entity Relationship Graph & Attack Timeline Reconstruction                                   |
+---------------------------------------------------------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
| 7. PERSISTENCE & USER PRESENTATION LAYER                                                          |
|    - Zero-Plaintext Encrypted SQLite Store                                                        |
|    - Deduplicated Real-Time Alert Hub                                                             |
|    - REST API / Server-Sent Events (SSE) / Tauri Desktop UI                                      |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Quy định & Phạm vi Môi trường Lab được Cấp phép (Authorized Lab Scope)

Hệ thống được thiết kế và kiểm thử nghiêm ngặt trong phạm vi môi trường lab an toàn được ủy quyền:
1. **Dải địa chỉ mạng được phép (Permitted Subnets):**
   - Mạng riêng nội bộ theo chuẩn RFC 1918:
     - `10.0.0.0/8` (Doanh nghiệp nội bộ).
     - `172.16.0.0/12` (Mạng lab ảo hóa / Container Docker).
     - `192.168.0.0/16` (Mạng văn phòng / Trạm làm việc thử nghiệm).
   - Loopback Adapter: `127.0.0.1/8` (Kiểm thử mô phỏng IPC nội bộ).
2. **Giao thức thu nạp được phép:**
   - NetFlow v9 (Cisco RFC 3954) qua UDP port 2055.
   - IPFIX (IETF RFC 7011) qua UDP port 4739.
   - PCAP / PCAPNG dump files thu thập từ các giao diện mạng được ủy quyền.
   - Zeek `conn.log`, `dns.log`, `http.log` và Suricata `eve.json`.
3. **Vùng cấm (Strictly Prohibited):**
   - Tuyệt đối không thu thập lưu lượng mạng công cộng hoặc can thiệp vào các dải IP định tuyến Internet ngoài phạm vi lab khi chưa có văn bản chấp thuận.
   - Không lưu trữ nội dung nhạy cảm của gói tin (Packet payload, Passwords, Session cookies, Private keys).

---

## 3. Chính sách Lưu trữ & Xóa dữ liệu (Data Retention Policy)

- **Sự kiện an ninh (Security Events):** Lưu trữ tối đa 7 ngày trong cơ sở dữ liệu mã hóa cục bộ. Các sự kiện cũ hơn 7 ngày được tự động dọn dẹp (auto-purge).
- **Cảnh báo an ninh (Security Alerts):** Lưu trữ 30 ngày phục vụ điều tra truy vết.
- **Khóa mã hóa (Cryptographic Keys):** Xoay vòng khóa định kỳ mỗi 30 phút hoặc thích ứng tức thời khi Risk Score $\ge 85$. Các khóa cũ được lưu trong Keystore mã hóa để giải mã dữ liệu lịch sử.

---

## 4. Điều kiện Nghiệm thu Hoàn thành M6.6 (Acceptance Criteria)

- **Backend-Ready:** Collector, Streaming Ring Buffer, AI Inference và Risk Engine xử lý liên tục với độ trễ dưới 50ms cho mỗi gói micro-batch.
- **Replay-Ready:** Chế độ Replay phát lại kịch bản kiểm chuẩn và cho kết quả khớp hoàn toàn với phân tích Offline.
- **Live-Ready:** Dòng telemetry thu nạp trong lab kích hoạt đầy đủ chuỗi: Phát hiện AI $\to$ Đánh giá rủi ro $\to$ Mã hóa Vector $\to$ Xoay vòng khóa thích ứng $\to$ Tái dựng Attack Timeline trên giao diện.
