# NetFlow Sentinel v2.0 — Gap Analysis v1.0.0 vs Đề cương Gốc Đề tài 22

> **Tài liệu kiểm toán kỹ thuật (Issue #76 — Milestone M6.1)**  
> **Phiên bản:** 2.0.0-audit  
> **Tiêu chuẩn:** Evidence-driven Engineering / Kiểm toán dựa trên mã nguồn và artifact thực tế.

---

## 1. Bối cảnh và Mục tiêu

Đề tài 22: *"Xây dựng hệ thống AI phát hiện, phân tích và truy vết kết nối mạng bất thường kết hợp mã hóa vector hành vi và xoay vòng khóa thích ứng"* đặt ra yêu cầu xây dựng một giải pháp toàn diện bao gồm 7 trụ cột:
1. Data Collection & Multi-source Telemetry
2. Behavioral Vector Engine
3. Cryptographic Layer (AES-256-GCM & Adaptive Key Rotation)
4. AI Detection Engine (4 models & Unknown Attack Detection)
5. Attack Traceability & Evidence Graph
6. Risk Scoring & Response Engine
7. Integrated Security Desktop Dashboard

NetFlow Sentinel v1.0.0 (phát hành theo PR #72, #74 và tag `v1.0.0`) đã hoàn thành xuất sắc mục tiêu giai đoạn 1 (Desktop MVP với 4 mô hình AI trên dataset NF-UNSW-NB15-v3, offline CSV workflow, giao diện Tauri 2 + Svelte 5). Tuy nhiên, để đáp ứng đầy đủ yêu cầu bảo vệ đồ án tốt nghiệp và khôi phục toàn vẹn ý tưởng của Đề tài 22, tài liệu này tiến hành kiểm toán khoảng cách (Gap Analysis) chi tiết với bằng chứng `file:dòng` cụ thể.

---

## 2. Bảng Ma trận Kiểm toán Khoảng cách (Gap Analysis Matrix)

Các trạng thái chuẩn tắc:
- `COMPLETED`: Đã có code thực thi, kiểm thử đầy đủ, artifact hợp lệ.
- `PARTIALLY IMPLEMENTED`: Đã có khung logic hoặc hàm mô phỏng/rút gọn, cần mở rộng đầy đủ.
- `REDUCED / DEFERRED`: Đã tạm hoãn hoặc tinh giản trong phạm vi v1.0.0, bắt buộc khôi phục trong v2.0.
- `MISSING`: Chưa có mã nguồn thực tế trong repository.

| STT | Trụ cột Năng lực Đề tài 22 | Trạng thái v1.0.0 | Bằng chứng Hiện trạng trong Codebase (`file:dòng`, artifact) | Khoảng cách Kỹ thuật cần bù đắp | Ánh xạ Issue v2.0 |
|---|---|---|---|---|---|
| **1** | **Thu thập dữ liệu đa nguồn (Multi-source Ingestion)** | `PARTIALLY IMPLEMENTED` | - `src/network_anomaly/ingestion/adapters/`: chỉ nạp tĩnh từ CSV.<br>- `tests/unit/test_ingestion_adapters.py`: test chuyển đổi schema tĩnh. | - Chưa hỗ trợ streaming socket UDP/TCP NetFlow/IPFIX.<br>- Chưa có log tailing cho Zeek/Suricata.<br>- Chưa có bộ gom PCAP sang flow.<br>- Chưa có cơ chế chuẩn hóa thời gian và thực thể đa nguồn. | **#82–#93**, **#127–#130** |
| **2** | **Trích xuất & Mã hóa Vector Hành vi (Behavioral Vector)** | `REDUCED` | - `src/network_anomaly/api/desktop_csv.py:313` (`compute_netflow_behavioral_summary`): chỉ tính thống kê byte/packet cơ bản trong phiên.<br>- Chưa có package `src/network_anomaly/behavioral/`. | - Chưa có thuật toán sessionization theo time-window.<br>- Chưa có vector hành vi chuẩn hóa có phiên bản (Behavioral Vector Schema).<br>- Chưa có profiling thực thể IP-independent.<br>- Chưa có thực nghiệm độ tương đồng hành vi (RQ3). | **#101–#104**, **#106** |
| **3** | **Tầng Mật mã & Quản lý Khóa (AES-256-GCM & Rotation)** | `REDUCED` | - `src/network_anomaly/api/db.py:65` (`key_metadata` table).<br>- `src/network_anomaly/api/repositories.py` (`KeyMetadataRepository`): chỉ lưu metadata của khóa.<br>- `tests/unit/test_response_policy.py` & `tests/integration/test_security_dry_run_integration.py`: mô phỏng dry-run phản ứng và xoay khóa. | - Chưa thực hiện mã hóa ciphertext thật bằng AES-256-GCM trên payload vector và evidence.<br>- Chưa có cơ chế xoay khóa định kỳ 30 phút thực tế.<br>- Chưa có Adaptive Key Rotation kích hoạt theo Risk Score.<br>- Chưa có cơ chế giải mã dữ liệu lịch sử và chống tamper. | **#116–#126** |
| **4** | **AI Engine Đa Mô hình (4 Models)** | `COMPLETED (v1 baseline)` | - `artifacts/models/`: đầy đủ 4 model (Random Forest, XGBoost, Isolation Forest, Autoencoder).<br>- `tests/integration/test_pipeline.py`: nạp và dự đoán thành công cả 4 model.<br>- Heldout test F1 của RF đạt 0.999853. | - Cần kiểm toán shortcut TTL và data leakage.<br>- Cần giao thức đánh giá class imbalance và tấn công hiếm.<br>- Cần thí nghiệm phát hiện tấn công chưa biết (Unknown Attack Holdout - RQ4).<br>- Cần OOD rejection và hiệu chỉnh threshold trên validation. | **#94–#100**, **#105** |
| **5** | **Công cụ Truy vết & Timeline Tấn công (Trace Engine)** | `PARTIALLY IMPLEMENTED` | - `src/network_anomaly/api/desktop_csv.py:618` (`build_deterministic_evidence_timeline`): sinh timeline tuyến tính từ timestamp CSV.<br>- Chưa có package `src/network_anomaly/trace/`. | - Chưa có đồ thị liên kết thực thể (Entity Graph) liên kết đa nguồn.<br>- Chưa có suy luận chuỗi tấn công nhiều giai đoạn (Multi-stage Attack Reconstruction).<br>- Chưa có chuỗi chứng cứ số hóa (Evidence Provenance) phục vụ điều tra. | **#110–#115** |
| **6** | **Đánh giá Rủi ro & Phản ứng (Risk Engine)** | `PARTIALLY IMPLEMENTED` | - `src/network_anomaly/api/desktop_csv.py:390` (`compute_deterministic_risk_score`): tính điểm rủi ro từ trọng số cố định.<br>- `src/network_anomaly/api/main.py` (`/api/v1/security/simulate-response`): mô phỏng phản ứng an toàn `executed=false`. | - Chưa có công thức chấm điểm rủi ro đa tiêu chí chuẩn tắc 0–100.<br>- Chưa tích hợp suy luận đồng thuận từ nhiều mô hình AI.<br>- Chưa kích hoạt xoay khóa thích ứng động khi rủi ro vượt ngưỡng cảnh báo cao. | **#107–#109**, **#134** |
| **7** | **Giám sát Mạng Thời gian thực (Live Monitoring)** | `MISSING` | - Chỉ có xử lý tệp CSV tĩnh trên desktop.<br>- Chưa có tiến trình collector mạng thời gian thực. | - Chưa có Rust collector cho NetFlow v9/IPFIX.<br>- Chưa có pipeline streaming hỗ trợ backpressure và batching.<br>- Chưa có trích xuất đặc trưng và suy luận AI real-time.<br>- Chưa có chế độ Replay và Live tích hợp trên giao diện. | **#127–#137** |
| **8** | **Desktop Dashboard & Giao diện Nghiệm thu** | `PARTIALLY IMPLEMENTED` | - `desktop/src/`: Giao diện Svelte 5 + Tailwind đã có Dashboard tổng quan, phân tích CSV, cài đặt.<br>- `desktop/src-tauri/`: Cầu nối Tauri 2 giao tiếp qua HTTP sidecar. | - Chưa có Live Monitoring Dashboard hiển thị throughput và alert thời gian thực.<br>- Chưa có Behavioral Analysis Dashboard trực quan hóa vector và anomaly score.<br>- Chưa có Attack Timeline & Investigation Graph tương tác.<br>- Chưa có Cryptography & Key Rotation Dashboard hiển thị trạng thái xoay khóa. | **#139–#144** |

---

## 3. Danh sách Blocker Kế thừa Còn hiệu lực

Căn cứ đối chiếu các Issue và PR trước v2.0:
1. **Issue #73 & #71 (Windows Installer & UQ Licensing 454104):**
   - *Tình trạng:* Bộ cài `NetFlow-Sentinel-v1.0.0-windows-x64-setup.exe` đã được tạo thành công nội bộ tại `dist/issue71-verification/`. Tuy nhiên, việc phát hành public binary bị chặn do điều khoản giấy phép học thuật UQ License ID 454104 đối với dataset phái sinh.
   - *Biện pháp v2.0:* Giữ nguyên chế độ source release và installer nội bộ phục vụ bảo vệ đồ án; hoàn thiện kịch bản kiểm thử clean machine tại #148 mà không vi phạm giấy phép bản quyền.
2. **Issue #48 & PR #49 (Cross-dataset Generalization & TTL Ablation):**
   - *Tình trạng:* PR #49 đã phát hiện sự phụ thuộc quá mức vào đặc trưng TTL (shortcut learning) khi chuyển giao giữa NF-UNSW-NB15 và NF-ToN-IoT.
   - *Biện pháp v2.0:* Tích hợp thực nghiệm triệt tiêu TTL (ablation) và chuẩn hóa feature space tại #97 và #95 để đảm bảo tính đúng đắn khoa học.
3. **Issue #60 (Consolidated Audit Remediation):**
   - *Tình trạng:* Các cảnh báo về integrity hash của artifact, quản lý phiên SQLite, và loopback authentication token đã được khắc phục tại v1.0.0 nhưng cần được bảo toàn khi mở rộng sang v2.0.

---

## 4. Kết luận Đợt Kiểm toán

1. Toàn bộ 7 trụ cột năng lực của Đề tài 22 đã được nhận diện rõ ràng về mặt khoảng cách kỹ thuật.
2. Không có bất kỳ thành phần nào bị bỏ sót trong lộ trình 80 Issue của v2.0.
3. Kế hoạch lấp đầy khoảng cách sẽ được tiến hành theo chiến lược Vertical Slice: ưu tiên khôi phục Behavioral Vector và AES-256-GCM trước, tiếp nối bằng Trace Engine và Live Monitoring.
