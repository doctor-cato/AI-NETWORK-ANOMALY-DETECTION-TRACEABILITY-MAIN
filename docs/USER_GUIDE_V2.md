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
- **Bản quyền dữ liệu v2:** Các mô hình v2 được huấn luyện và đánh giá trên `AIT-NDS-v2` (`10.5281/zenodo.13168643`) và `CTU-SME-11` (`10.5281/zenodo.7958258`) theo giấy phép **CC BY 4.0**. Nguồn `UGR'16` đang `BLOCKED` (HTTP 403) và không sử dụng; nguồn `UWF-ZeekData24` (`CC BY 4.0`) được dùng làm kiểm chứng bổ sung chỉ-đọc (`evaluation_only = true`).

---

## 4. Kịch bản Demo Chuẩn & Thời lượng Kỳ vọng (Clean-State Verification, #150)

Bảng dưới đây mô tả đầu ra và thời lượng kỳ vọng khi chạy trên trạng thái sạch (empty SQLite DB + verified `E0` artifacts):

| Chế độ Demo | Thao tác thực hiện | Thời lượng kỳ vọng | Đầu ra / Trạng thái quan sát được |
|---|---|---:|---|
| **Offline CSV Analysis** | Chọn CSV canonical 18-feature (`Analyze Flows`) | **1–4 s** (1k–10k flows) | `CompatibilityGate = ELIGIBLE`, điểm OOD + tỷ lệ abstention, `behavioral_vectors` 16-D theo phiên, Evidence Timeline & Risk summary (`executed=false` chỉ gợi ý). |
| **Scenario Replay** | Kích hoạt Replay trên file canonical hoặc PCAP-to-flow | **2–6 s** (200–1,000 events) | `throughput_events_per_sec` đo thực tế từ `StreamingModeManager.run_replay_scenario()`, alert theo từng phase + stage timeline quan sát được (`observed_evidence`). |
| **Live Telemetry (Loopback UDP)** | `POST /api/v1/live/start` (`127.0.0.1`) + gửi gói NetFlow v9/IPFIX | **< 2 s** tới trạng thái `LIVE` | `STATE: CONNECTED`, readiness thật `ready_count/4`, ciphertexts AES-256-GCM trong `behavioral_vectors`, cảnh báo đã deduplicate theo entity/severity. |

- **Lưu ý fail-closed khi artifact vắng mặt hoặc không hợp lệ:** Nếu thiếu SHA-256 manifest, thiếu `.joblib` preprocessor hoặc dùng CSV thiếu cột contract, giao diện hiển thị `UNAVAILABLE` / HTTP `400` / `503` thay vì tạo kết quả giả.
- **Lưu ý kích hoạt `deployment` mode với Trusted OOD Anchor:** Mặc định API và Tauri desktop chạy fail-closed ở `deployment`. Để Live AI Inference chuyển từ `UNAVAILABLE` sang `4/4 READY` trong `deployment` mode, người vận hành phải cấp digest tin cậy ngoài trust boundary (`8a52bfe5ad156560a3949afd5d4860c175ce5d158c38eb47aae07342102e9825` cho `ood_reference_gate.json` hiện tại) qua biến môi trường `NETFLOW_OOD_GATE_SHA256` hoặc cờ `python scripts/run_api.py --ood-gate-sha256 <SHA256>`.
- **Lưu ý Demo Mode trên UI:** Chỉ kích hoạt khi nhấn nút `Demo Mode` trên từng panel (`STATE: DEMO`); mặc định khi mở ứng dụng mọi panel đều ở `LOADING` / `DISCONNECTED` / `EMPTY` tùy trạng thái backend thật.

### 4.1. Checklist Tái lập 2x Clean-State (`#150` Repeatability Checklist)

Thực hiện **2 lần liên tiếp** trên trạng thái sạch (xóa DB tạm / khởi động lại sidecar) với trusted OOD anchor:

```powershell
$env:NETFLOW_OOD_GATE_SHA256 = "8a52bfe5ad156560a3949afd5d4860c175ce5d158c38eb47aae07342102e9825"
.venv\Scripts\python.exe scripts/verify_clean_state_demo.py
```

1. **Offline (`data/demo/demo_flows.csv`):** Nạp `demo_flows.csv` qua tab Offline CSV & 4-Model Compare; xác nhận `AI Ready 4/4`, `CompatibilityGate = ELIGIBLE`, kết quả nhất quán giữa lần 1 và lần 2.
2. **Replay (`scripts/replay_real_netflow_udp.py` / `ModeOrchestrator.run_replay_scenario`):** Chạy replay trên `ait_test.csv.gz` (hoặc `demo_flows.csv` fallback) ở chế độ Replay (`batch_size=32`); xác nhận `throughput_events_per_sec` và timeline `observed_evidence` lặp lại ổn định.
3. **Loopback-Live (`127.0.0.1`):** Khởi động `/api/v1/live/start` (`LiveTelemetryService` trên `127.0.0.1:0`) và gửi gói UDP NetFlow v9 loopback; xác nhận `STATE: CONNECTED` (`mode == "LIVE"`), `4/4 REAL_MODELS`, `ood_gate_status == "FITTED"`, AES-256-GCM ciphertext và alert deduplication giống nhau ở cả 2 lần chạy.

#### Bằng chứng Tái lập 2x Đã Kiểm chứng (`reports/demo/clean_state_demo_verification.json`)

Kịch bản tự động `scripts/verify_clean_state_demo.py` khởi tạo **2 phiên chạy sạch độc lập** (mỗi phiên trong `tempfile.TemporaryDirectory()` riêng với SQLite DB rỗng, keystore rỗng, `runtime_mode="deployment"`, `expected_ood_gate_sha256="8a52bfe5ad156560a3949afd5d4860c175ce5d158c38eb47aae07342102e9825"`) và đạt **`repeatable_100pct = true` (`PASS`)**:

| Kịch bản Clean-State | Nguồn dữ liệu | Run 1 | Run 2 | Khớp Định tất (`Run 1 == Run 2`) |
|---|---|---|---|---|
| **1. Offline (`process_batch`)** | `data/demo/demo_flows.csv` (`200` flows) | `4/4 REAL_MODELS`, `FITTED`, `200` processed, `100` ensemble anomalies (`RF=100, XGB=100, IF=99, AE=99`), `9` alerts, `200` encrypted vectors, `0` errors | `4/4 REAL_MODELS`, `FITTED`, `200` processed, `100` ensemble anomalies (`RF=100, XGB=100, IF=99, AE=99`), `9` alerts, `200` encrypted vectors, `0` errors | **`100% MATCH` (`offline_match = true`)** |
| **2. Replay (`batch_size=32`)** | `data/processed/v2/ait_test.csv.gz` (`65` flows) | `mode=REPLAY`, `4/4 REAL_MODELS`, `65` processed, `49` anomalies, `26` alerts, `65` encrypted vectors, `0` dropped, `0` errors | `mode=REPLAY`, `4/4 REAL_MODELS`, `65` processed, `49` anomalies, `26` alerts, `65` encrypted vectors, `0` dropped, `0` errors | **`100% MATCH` (`replay_match = true`)** |
| **3. Live UDP (`127.0.0.1:0`)** | Binary NetFlow v9 UDP (`24` flows / `3` datagrams) | `mode=LIVE -> STOPPED`, `4/4 REAL_MODELS`, `FITTED`, `24/24` decoded & processed, `8` anomalies, `8` alerts, `24` persisted events & encrypted vectors, `0` errors | `mode=LIVE -> STOPPED`, `4/4 REAL_MODELS`, `FITTED`, `24/24` decoded & processed, `8` anomalies, `8` alerts, `24` persisted events & encrypted vectors, `0` errors | **`100% MATCH` (`live_udp_match = true`)** |

---

## 5. Ghi chú Loại trừ Trùng lặp Tài liệu (`#151` Deduplication Note)

- Các issue tài liệu v1 trước đây (`#18`, `#19`) đã được **thay thế hoàn toàn (superseded)** bởi bộ issue tài liệu v2: **`#151`** (User Guide & Documentation Hygiene), **`#152`** (Documentation Website `site-source`) và **`#153`** (Thesis Report, Defense Slides & Q&A).
