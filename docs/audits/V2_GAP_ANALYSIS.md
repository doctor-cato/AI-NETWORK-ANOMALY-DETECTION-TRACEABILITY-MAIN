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

| STT | Trụ cột Năng lực Đề tài 22 | Trạng thái v1.0.0 | Bằng chứng Hiện trạng trong Codebase (`file:dòng`, artifact) | Khoảng cách Kỹ thuật cần bù đắp | Milestone v2.0 | Ánh xạ Issue v2.0 (Mã & Tên) |
|---|---|---|---|---|---|---|
| **1** | **Thu thập dữ liệu đa nguồn (Multi-source Ingestion)** | `PARTIALLY IMPLEMENTED` | - `src/network_anomaly/ingestion/adapters/`: chỉ nạp tĩnh từ CSV.<br>- `tests/unit/test_ingestion_adapters.py`: test chuyển đổi schema tĩnh. | - Chưa hỗ trợ streaming socket UDP/TCP NetFlow/IPFIX.<br>- Chưa có log tailing cho Zeek/Suricata.<br>- Chưa có bộ gom PCAP sang flow.<br>- Chưa có cơ chế chuẩn hóa thời gian và thực thể đa nguồn. | `M6.2`, `M6.6` | **#82–#93** (`Audit nguồn`, `Dataset downloader`, `Profiling AIT/CTU`, `Kiểm chứng liên kết AIT`, `Chuẩn hóa timestamp/entity`, `Taxonomy thống nhất`, `Adapters Flow/DNS/Web/Auth/Audit`, `Quality gate`, `Split`, `Multi-source pipeline`), **#127–#130** (`Live telemetry architecture`, `Collector`, `PCAP ingestion`, `Zeek/Suricata tail`) |
| **2** | **Trích xuất & Mã hóa Vector Hành vi (Behavioral Vector)** | `REDUCED` | - `src/network_anomaly/api/desktop_csv.py:315` (`compute_netflow_behavioral_summary`): chỉ tính thống kê byte/packet cơ bản trong phiên.<br>- Chưa có package `src/network_anomaly/behavioral/`. | - Chưa có thuật toán sessionization theo time-window.<br>- Chưa có vector hành vi chuẩn hóa có phiên bản (Behavioral Vector Schema).<br>- Chưa có profiling thực thể IP-independent.<br>- Chưa có thực nghiệm độ tương đồng hành vi (RQ3). | `M6.3` | **#101–#104** (`Sessionization`, `Behavioral Vector 16-D`, `Entity profiling & similarity`, `IP-independent correlation RQ3`), **#106** (`Tích hợp AI & Behavioral vào inference pipeline`) |
| **3** | **Tầng Mật mã & Quản lý Khóa (AES-256-GCM & Rotation)** | `REDUCED` | - `src/network_anomaly/api/db.py:95` (`key_metadata` table).<br>- `src/network_anomaly/api/repositories.py` (`KeyMetadataRepository`): chỉ lưu metadata của khóa.<br>- `tests/unit/test_response_policy.py` & `tests/integration/test_security_dry_run_integration.py`: mô phỏng dry-run phản ứng và xoay khóa. | - Chưa thực hiện mã hóa ciphertext thật bằng AES-256-GCM trên payload vector và evidence.<br>- Chưa có cơ chế xoay khóa định kỳ 30 phút thực tế.<br>- Chưa có Adaptive Key Rotation kích hoạt theo Risk Score.<br>- Chưa có cơ chế giải mã dữ liệu lịch sử và chống tamper. | `M6.5` | **#116–#126** (`Cryptographic architecture`, `AES-256-GCM AEAD`, `Mã hóa Behavioral/Evidence`, `Key lifecycle/DPAPI`, `Fixed rotation 30m`, `Adaptive rotation`, `Cooldown/rate-limit`, `Historical decryption`, `Integrity testing`, `RQ5`, `RQ6`) |
| **4** | **AI Engine Đa Mô hình (4 Models)** | `COMPLETED (v1 baseline)` | - `artifacts/historical/nf_unsw_nb15_v3/`: 4 model v1 (đã nghỉ hưu sau hard cutover v2 sang `canonical-flow-v2-18`).<br>- `tests/integration/test_pipeline.py`: nạp và dự đoán thành công cả 4 model. | - Cần kiểm toán shortcut TTL và data leakage.<br>- Cần giao thức đánh giá class imbalance và tấn công hiếm.<br>- Cần thí nghiệm phát hiện tấn công chưa biết (Unknown Attack Holdout - RQ4).<br>- Cần OOD rejection và hiệu chỉnh threshold trên validation. | `M6.3` | **#94–#100** (`Audit 4 model & shortcut TTL`, `Dataset compatibility & retrain`, `Class imbalance RQ2`, `Cross-dataset generalization`, `Unknown attack holdout RQ4`, `OOD rejection gate`, `Validation-only threshold calibration`), **#105** (`Model explainability & comparison`) |
| **5** | **Công cụ Truy vết & Timeline Tấn công (Trace Engine)** | `PARTIALLY IMPLEMENTED` | - `src/network_anomaly/api/desktop_csv.py` (`build_deterministic_evidence_timeline`): sinh timeline tuyến tính từ timestamp CSV.<br>- Chưa có package `src/network_anomaly/trace/`. | - Chưa có đồ thị liên kết thực thể (Entity Graph) liên kết đa nguồn.<br>- Chưa có suy luận chuỗi tấn công nhiều giai đoạn (Multi-stage Attack Reconstruction).<br>- Chưa có chuỗi chứng cứ số hóa (Evidence Provenance) phục vụ điều tra. | `M6.4` | **#110–#115** (`Cross-source correlation & Entity graph`, `Trace Engine v2`, `Multi-stage Attack Timeline`, `Evidence provenance & report`, `Evaluation traceability`, `Trace/Evidence REST API`) |
| **6** | **Đánh giá Rủi ro & Phản ứng (Risk Engine)** | `PARTIALLY IMPLEMENTED` | - `src/network_anomaly/api/desktop_csv.py` (`compute_deterministic_risk_score`): tính điểm rủi ro từ trọng số cố định.<br>- `src/network_anomaly/api/main.py` (`/api/v1/security/simulate-response`): mô phỏng phản ứng an toàn `executed=false`. | - Chưa có công thức chấm điểm rủi ro đa tiêu chí chuẩn tắc 0–100.<br>- Chưa tích hợp suy luận đồng thuận từ nhiều mô hình AI.<br>- Chưa kích hoạt xoay khóa thích ứng động khi rủi ro vượt ngưỡng cảnh báo cao. | `M6.4`, `M6.6` | **#107–#109** (`Unified Security Event persistence`, `Risk scoring 0–100`, `Multi-model decision aggregation`), **#134** (`Real-time Risk Engine & alert manager`) |
| **7** | **Giám sát Mạng Thời gian thực (Live Monitoring)** | `MISSING` | - Chỉ có xử lý tệp CSV tĩnh trên desktop.<br>- Chưa có tiến trình collector mạng thời gian thực. | - Chưa có collector UDP NetFlow v9/IPFIX (Rust `#128` hoãn sau v2; triển khai Python `UDPFlowCollector` ở `#131`).<br>- Chưa có pipeline streaming hỗ trợ backpressure và batching.<br>- Chưa có trích xuất đặc trưng và suy luận AI real-time.<br>- Chưa có chế độ Replay và Live tích hợp trên giao diện. | `M6.6` | **#127–#137** (`Live telemetry architecture`, `Collector #128 [DEFERRED]/#131`, `PCAP-to-flow`, `Zeek/Suricata tail`, `Streaming pipeline`, `Real-time feature extractor`, `Real-time inference`, `Live alert manager`, `Live Behavioral+Trace`, `Offline/Replay/Live modes`, `Lab acceptance`) |
| **8** | **Desktop Dashboard & Giao diện Nghiệm thu** | `PARTIALLY IMPLEMENTED` | - `desktop/src/`: Giao diện Svelte 5 + Tailwind đã có Dashboard tổng quan, phân tích CSV, cài đặt.<br>- `desktop/src-tauri/`: Cầu nối Tauri 2 giao tiếp qua HTTP sidecar. | - Chưa có Live Monitoring Dashboard hiển thị throughput và alert thời gian thực.<br>- Chưa có Behavioral Analysis Dashboard trực quan hóa vector và anomaly score.<br>- Chưa có Attack Timeline & Investigation Graph tương tác.<br>- Chưa có Cryptography & Key Rotation Dashboard hiển thị trạng thái xoay khóa. | `M6.7` | **#138–#154** (`Full E2E integration`, `Tauri 2 + Svelte 5 UI v2`, `Live/Behavioral/Timeline/Crypto/Comparison dashboards`, `RQ1–RQ6 validation`, `Security audit`, `System benchmark`, `Windows installer #148`, `Upgrade v1→v2`, `Demo scenarios`, `Docs/Website/Slides/Release #151–#154`) |

---

## 3. Danh sách Blocker Kế thừa Còn hiệu lực (Đã đối chiếu hậu Cutover v2)

Căn cứ đối chiếu các Issue và PR trong giai đoạn v2.0:
1. **Issue `#71` / `#73` → kế thừa sang `#148` (Windows Installer & Clean VM E2E):**
   - *Tình trạng:* Rào cản UQ License ID `454104` trên `NF-UNSW-NB15-v3` đã được thay thế bởi Hard Cutover sang `AIT-NDS-v2` & `CTU-SME-11` (`CC BY 4.0`) dưới cổng quản trị [`reports/governance/DISTRIBUTION_AUTHORIZATION.json`](../../reports/governance/DISTRIBUTION_AUTHORIZATION.json) (hiện giữ `approved: false`, `HOLD_FOR_MAINTAINER_SIGNOFF`).
   - *Biện pháp v2.0:* Các tiêu chí Clean Windows 10/11 VM Standard User E2E từ `#73` được kế thừa toàn phần sang `#148`.
2. **Issue `#25` / `#48` / PR `#49` → kế thừa sang `#94`, `#97`, `#145` (Cross-dataset Generalization & TTL Ablation):**
   - *Tình trạng:* Nghiên cứu `MIN_TTL` trên `NF-UNSW-NB15-v3` vs `ToN-IoT` đã lưu trữ tại `docs/historical/nf_unsw_nb15_v3/`; trong v2, thí nghiệm cross-source thực thi trên `CTU-SME-11` (`run_ctu_cross_source_eval.py`) và `WP3` (`E0–E5`).
3. **Issue `#60` → kế thừa sang `#146` (Security Audit v2.0):**
   - *Tình trạng:* Các cổng integrity SHA-256, SQLite persistence, session token và fail-closed OOD runtime policy đã được bảo toàn và mở rộng sang `#146`.

---

## 4. Kết luận Đợt Kiểm toán

1. Toàn bộ 7 trụ cột năng lực của Đề tài 22 đã được nhận diện rõ ràng về mặt khoảng cách kỹ thuật.
2. Không có bất kỳ thành phần nào bị bỏ sót trong lộ trình 80 Issue của v2.0.
3. Kế hoạch lấp đầy khoảng cách sẽ được tiến hành theo chiến lược Vertical Slice: ưu tiên khôi phục Behavioral Vector và AES-256-GCM trước, tiếp nối bằng Trace Engine và Live Monitoring.
