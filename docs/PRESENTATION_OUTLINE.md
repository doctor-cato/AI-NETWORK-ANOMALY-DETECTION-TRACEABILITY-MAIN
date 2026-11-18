# Dàn ý Trình bày Bảo vệ Đồ án — NetFlow Sentinel v2.0 (12 Chủ đề Học thuật)

> **Trạng thái Deliverable:** **`OUTLINE_ONLY — PPTX/PDF deferred (Issue #153 OPEN, 0/4 AC)`**
>
> **Phạm vi Tài liệu:** Dàn ý chi tiết 12 chủ đề phục vụ bảo vệ học thuật cho **NetFlow Sentinel v2.0** (`canonical-flow-v2-18`). Tuyệt đối **không** tạo `.pptx`, `.pdf`, slide HTML hay hình ảnh mới trong bước này; giữ nguyên Issue `#153` ở trạng thái `OPEN (0/4 AC)`.
>
> **Tài liệu liên quan:** [`docs/academic-defense/README.md`](academic-defense/README.md) · [`docs/academic-defense/EVIDENCE_INDEX.md`](academic-defense/EVIDENCE_INDEX.md) · [`docs/audits/RESEARCH_QUESTIONS_VALIDATION.md`](audits/RESEARCH_QUESTIONS_VALIDATION.md) · Hồ sơ v1 cũ tại [`docs/historical/nf_unsw_nb15_v3/academic-defense/`](historical/nf_unsw_nb15_v3/academic-defense/).

---

## Quy ước Trạng thái Bằng chứng

| Nhãn Trạng thái | Ý nghĩa Bắt buộc khi Trình bày trước Hội đồng |
|---|---|
| `VERIFIED` | Đã thực thi/đối chiếu trực tiếp trên dữ liệu thật hoặc artifact, manifest, mã nguồn và test suite hiện hành. |
| `SYNTHETIC` | Chạy trên bộ sinh tổng hợp, benchmark kịch bản có kiểm soát hoặc UDP loopback giả lập (không phải thiết bị mạng vật lý). |
| `NEGATIVE_RESULT` | Thực nghiệm hoàn tất nhưng giả thuyết đặt ra **không đạt** ngưỡng kỳ vọng (bắt buộc báo cáo trung thực). |
| `BLOCKED` | Bị chặn bởi yếu tố hạ tầng/nguồn ngoài/chứng cứ thiếu (`UGR'16` HTTP 403, AIT UID linkage `#85`, Clean VM `#73`/`#148`, physical lab `#137`, public release signoff). |
| `DEFERRED` | Chủ động hoãn ra ngoài phạm vi phát hành `v2.0` (`#128` Rust collector, OS firewall auto-containment `#27`, website `site-source` `#152`, bộ slide `.pptx`/`.pdf` `#153`). |

---

## Chủ đề 1 — Bối cảnh & Bài toán Phát hiện Xâm nhập / Bất thường NetFlow

- **Định vị Slide:** **Slide 1 — Tiêu đề, Bối cảnh & Mục tiêu Nghiên cứu (Đề tài 22)**
- **Nội dung Slide (Bullet points chính):**
  - **Bối cảnh kỹ thuật:** Lưu lượng mạng doanh nghiệp hiện đại phần lớn được mã hóa (TLS/HTTPS/QUIC), khiến Deep Packet Inspection (DPI) kém hiệu quả, tốn băng thông/CPU và dễ xâm phạm quyền riêng tư; dữ liệu **NetFlow / IPFIX / Tstat / Zeek** tóm tắt thống kê luồng L3/L4 giữ được khả năng quan sát ở quy mô lớn.
  - **Khoảng trống bài toán thực tế:**
    1. Nhiều hệ thống NIDS học thuật đạt `F1 ~ 0.99` nhờ **shortcut trong phòng lab** hoặc rò rỉ theo kịch bản/5-tuple, nhưng sụp đổ khi chuyển sang mạng thật khác nhà cung cấp/probe.
    2. Các mô hình ML đơn-flow rời rạc thiếu bối cảnh chuỗi hành vi (khi kẻ tấn công đổi IP), thiếu cơ chế chấm điểm rủi ro tổng hợp và thiếu bảo vệ bằng chứng điều tra lưu trữ at-rest.
  - **Mục tiêu NetFlow Sentinel v2.0:** Xây dựng hệ thống tích hợp gồm: **(1)** Hợp đồng luồng chuẩn hóa `canonical-flow-v2-18` chống shortcut/anti-imputation; **(2)** Ensemble 4 họ mô hình AI (Random Forest, XGBoost, Isolation Forest, Autoencoder) kèm OOD gate fail-closed; **(3)** Behavioral Vector 16-D độc lập IP + Risk Engine `[0..100]` + Trace Graph/Timeline; **(4)** Mã hóa at-rest AES-256-GCM với Adaptive Key Rotation; **(5)** Ứng dụng Desktop **Tauri 2 + Svelte 5 ↔ FastAPI Sidecar** với chính sách Security Dry-Run (`executed=false`).
- **Speaker Notes (Lời thuyết minh):**
  - Nhấn mạnh ngay từ đầu ranh giới của đề tài: NetFlow Sentinel v2.0 là một **hệ thống nghiên cứu học thuật và thử nghiệm lab có kiểm soát**, không tuyên bố là sản phẩm SOAR thương mại hay hệ thống tự động chặn lưu lượng doanh nghiệp.
  - Đặt trọng tâm vào tính **truy vết và trung thực khoa học**: mọi tuyên bố hiệu năng đều tách biệt rõ giữa in-domain (`AIT-NDS-v2`), cross-source trên capture thật (`CTU-SME-11`), mô phỏng (`RQ3`, `RQ5`) và các điểm nghẽn đang mở (`UGR'16 BLOCKED`).
- **Biểu đồ / Tham chiếu Bằng chứng:**
  - Sơ đồ kiến trúc tổng quan 3 chế độ (Offline CSV, Dataset Replay, Live Lab Monitoring) trong [`docs/ARCHITECTURE_V2.md`](ARCHITECTURE_V2.md).
  - Bảng phân định yêu cầu & lộ trình trong [`docs/REQUIREMENTS.md`](REQUIREMENTS.md) và [`docs/TRACEABILITY_MATRIX.md`](TRACEABILITY_MATRIX.md).
- **Giới hạn Trung thực (`Honest Limitations`):**
  - Phiên bản hiện tại mới đạt mức `Functional Prototype / Academic & Controlled Lab Pilot`, **không** chứng nhận `Production-Ready` hay `Public-Release-Ready`.
  - Việc phân tích chỉ dựa trên flow metadata hai chiều + log ngữ cảnh, không giải mã payload ứng dụng (TLS/encrypted C2).

---

## Chủ đề 2 — Hạn chế của Pipeline v1 (`NF-UNSW-NB15-v3`) & Lý do Hard Cutover sang v2

- **Định vị Slide:** **Slide 2 — Kiểm toán Lịch sử v1 (`NF-UNSW-NB15-v3`) & Quyết định Hard Cutover sang v2 (`canonical-flow-v2-18`)**
- **Nội dung Slide (Bullet points chính):**
  - **Ba khuyết tật nền tảng của pipeline v1 (`NF-UNSW-NB15-v3`, 55 cột / 47 ML features):**
    1. **Shortcut Learning (`MIN_TTL` / `MAX_TTL`):** Trên `NF-UNSW-NB15-v3`, `RF` đạt `F1 = 0.999886` (`MIN_TTL` importance = `0.240573`) và `XGB` đạt `F1 = 0.999984` (`MIN_TTL` importance = `0.829272`) nhờ đặc trưng topology từ máy phát IXIA; ngay cả khi bỏ `MIN_TTL` còn 46 features vẫn đạt `0.999804`/`0.999984` do `MAX_TTL` và cấu trúc testbed vẫn rò rỉ phân bố lab.
    2. **Sụp đổ Out-of-Distribution (OOD) trên tập ngoài:** Baseline `RF` v1 khi chạy trên `NF-CSE-CIC-IDS2018-v3` (100,000 mẫu) sụp đổ hoàn toàn xuống **`Recall = 0.0`**, `Precision = 0.0`, `F1 = 0.0`, `Accuracy = 0.43399`, `FPR = 0.3802` (`TP=0, FN=29,980, FP=26,621, TN=43,399`).
    3. **Bất tương thích Schema & Rào cản Giấy phép:** 47 trường vi mô của nProbe v3 không tồn tại đồng nhất trên Tstat, Zeek `conn.log` hay NetFlow v9/IPFIX chuẩn (dễ dẫn tới lỗi `NOT_MODEL_READY` hoặc ép zero-imputation); đồng thời `NF-UNSW-NB15-v3` bị ràng buộc bởi **UQ License ID `454104`** (cấm thương mại, hạn chế tái phân phối model/demo CSV).
  - **Quyết định Kiến trúc (`ADR-dataset-hard-cutover-v2.md` — `ACCEPTED`):**
    - Thực hiện **hard cutover** thay vì vá adapter kép: chuyển toàn bộ artifact, manifest, split, benchmark và script v1 sang kho lưu trữ chỉ đọc `*/historical/nf_unsw_nb15_v3/`.
    - **Cấm fallback v1:** `ModelRegistry`, `TrainOnlyPreprocessor`, `InferencePipeline`, FastAPI và Desktop UI **từ chối fail-closed** mọi CSV 55 cột / 47 features và trọng số v1.
    - Bảo toàn product core độc lập dataset (Tauri 2, Svelte 5, FastAPI, Crypto, Behavioral, Risk, Trace).
- **Speaker Notes (Lời thuyết minh):**
  - Giải thích vì sao không giữ cầu nối tương thích ngược sang v1: nếu cho phép fallback về trọng số 47 features, hệ thống sẽ tạo cảm giác "hoạt động tốt" giả tạo trên dữ liệu cũ hoặc âm thầm impute số `0` cho các trường nProbe bị thiếu, làm sai lệch hoàn toàn ý nghĩa khoa học của kết quả.
  - Làm rõ rằng benchmark v1 và v2 **không so sánh trực tiếp ngang hàng** (*non-like-for-like*) vì thay đổi cả tập dữ liệu, chiến lược chia scenario-disjoint và không gian đặc trưng (`47 -> 18`).
- **Biểu đồ / Tham chiếu Bằng chứng:**
  - Bảng ablation `MIN_TTL` (47 vs 46 features) & ma trận nhầm lẫn OOD trên `NF-CSE-CIC-IDS2018-v3` trong [`docs/historical/nf_unsw_nb15_v3/MODEL_AUDIT_TTL_ABLATION.md`](historical/nf_unsw_nb15_v3/MODEL_AUDIT_TTL_ABLATION.md).
  - Quyết định hard cutover & ghi chú migration DB trong [`docs/adr/ADR-dataset-hard-cutover-v2.md`](adr/ADR-dataset-hard-cutover-v2.md) và [`docs/MIGRATION_V1_TO_V2.md`](MIGRATION_V1_TO_V2.md).
- **Giới hạn Trung thực (`Honest Limitations`):**
  - Chạy lại ablation 46-feature cross-dataset trên file raw `NF-CSE-CIC-IDS2018-v3` hiện **`BLOCKED`** do file raw không được lưu cục bộ sau khi đóng kho v1.
  - Các con số v1 chỉ có giá trị lịch sử chứng minh nguyên nhân cutover, không dùng làm baseline hiệu năng của v2.

---

## Chủ đề 3 — Kiến trúc Hệ thống & Ranh giới An toàn

- **Định vị Slide:** **Slide 3 — Kiến trúc Hybrid Desktop-Sidecar, Live Telemetry Pipeline & 5 Hợp đồng Dữ liệu**
- **Nội dung Slide (Bullet points chính):**
  - **Mô hình Hybrid Desktop-Sidecar:**
    - **Frontend / Shell:** **Tauri 2 (`v2.0.0`) + Svelte 5** (CSP khóa chặt `default-src 'self'; connect-src 'self' http://127.0.0.1:* http://localhost:*`).
    - **Backend / Sidecar:** **Python `3.12.10` + FastAPI (`0.1.0`)** lắng nghe thuần túy trên loopback `127.0.0.1`; mọi endpoint nghiệp vụ bắt buộc header **`X-Sentinel-Session-Token`** (so sánh hằng thời gian `hmac.compare_digest`, trả HTTP `401` nếu thiếu/sai; chỉ mở `/health` và `OPTIONS`).
    - **Persistence:** SQLite single-writer tại `%LOCALAPPDATA%\NetFlowSentinel\` (nâng cấp idempotent v1→v2 qua `scripts/migrate_v1_to_v2.py`).
  - **Live Telemetry Layer (Cập nhật Kiến trúc Thực tế):**
    - Đảm nhiệm bởi **`Python UDPFlowCollector`** + **`NetFlowIPFIXDecoder`** (`src/network_anomaly/telemetry/collector.py`) và **`StreamingEventPipeline`** (`src/network_anomaly/streaming/pipeline.py`: `collections.deque` giới hạn mặc định `capacity = 10,000`, micro-batch `64`, `max_batch_latency_ms = 50.0`, chính sách backpressure `DROP_OLDEST` / `BLOCK`).
    - **Lưu ý phân tách trung thực:** Rust Collector hiệu năng cao (**Issue `#128`**) đang ở trạng thái **`DEFERRED`** hậu `v2.0.0`; hiện tại Rust chỉ đảm nhiệm shell Tauri 2, quản lý vòng đời tiến trình sidecar và IPC.
  - **Ba chế độ hoạt động & Năm hợp đồng liên module:**
    - Chế độ: **(1)** Offline CSV (`canonical-flow-v2-18`), **(2)** Dataset Replay, **(3)** Live Lab Monitoring.
    - 5 Contracts: `CanonicalSecurityEvent` (`sec-event-v2`), `MLFeatureVector` (`canonical-flow-v2-18`), `BehavioralVector` (`beh-vec-v2`), `RiskScoreResult` (`risk-res-v2`), `KeyLifecycleMetadata` (`key-meta-v2`).
- **Speaker Notes (Lời thuyết minh):**
  - Giải thích lý do chọn kiến trúc Tauri 2 + Python FastAPI Sidecar: tận dụng hệ sinh thái `scikit-learn` / `xgboost` / `cryptography` chuẩn xác của Python mà không bắt người dùng cuối cài Python/Rust khi đóng gói standalone, đồng thời cô lập giao tiếp UI↔Backend trên loopback với token ngẫu nhiên theo phiên.
  - Trình bày rành mạch khi được hỏi về Rust Collector `#128`: phần nhận UDP và giải mã NetFlow v9/IPFIX trong bản `v2.0` đã hoàn thiện và kiểm thử chạy thật bằng Python (`UDPFlowCollector`), còn việc viết lại collector bằng Rust để hướng tới tốc độ dây 1–10 Gbps được chủ động hoãn sau `v2.0`.
- **Biểu đồ / Tham chiếu Bằng chứng:**
  - Sơ đồ khối & Sequence diagram trong [`docs/ARCHITECTURE_V2.md`](ARCHITECTURE_V2.md).
  - Ranh giới bảo mật loopback & CORS tại [`src/network_anomaly/api/main.py`](../src/network_anomaly/api/main.py#L138-L174); collector/pipeline tại [`src/network_anomaly/telemetry/collector.py`](../src/network_anomaly/telemetry/collector.py) và [`src/network_anomaly/streaming/pipeline.py`](../src/network_anomaly/streaming/pipeline.py).
  - OpenAPI contract đồng bộ `3.1.0` (`reports/api/openapi.json`, `scripts/export_openapi_spec.py --check` `PASS`).
- **Giới hạn Trung thực (`Honest Limitations`):**
  - Python `UDPFlowCollector` sử dụng vòng lặp đồng thời Python và không có bộ giới hạn heap byte-level 256 MB cứng (chỉ giới hạn số lượng phần tử `capacity`).
  - `NetFlowIPFIXDecoder` giải mã template chuẩn NetFlow v9/IPFIX, nhưng các trường đặc trưng v2 đủ 18 chiều trên UDP live hiện sử dụng quy ước lab riêng (`PEN 50000` / IE `50000+i`); router thương mại chỉ xuất 5-tuple/counters tiêu chuẩn sẽ bị đánh dấu `NOT_MODEL_READY` (không suy diễn giả).

---

## Chủ đề 4 — Chiến lược Dữ liệu Đa nguồn, `UGR'16` (`BLOCKED`) & Ranh giới Liên kết AIT

- **Định vị Slide:** **Slide 4 — Dữ liệu Đa nguồn `AIT-NDS-v2`, `CTU-SME-11`, Hiện trạng `UGR'16` & Kiểm toán Ranh giới Liên kết**
- **Nội dung Slide (Bullet points chính):**
  - **Các nguồn dữ liệu đang dùng trong v2:**
    - **`AIT-NDS-v2`** (DOI `10.5281/zenodo.13168643`, **`CC BY 4.0`**, `VERIFIED_LOCAL`): Sinh bằng Tstat (`tcp_complete`, `tcp_nocomplete`, `udp_complete`) từ PCAP `AIT-LDS-v2.0` qua 8 kịch bản (`3,465,342` flows gốc = `3,464,400` labeled + `942` unmapped ở `shaw`). Chia tập **`v2-scenario-group-purged-v1`**: Train `2,097,891` (`fox, harrison, santos, wardbeck, wilson`), Val `377,704` (`russellmitchell`), Held-out Test `988,805` (`shaw, wheeler`), **0** overlap scenario và **0** overlap `(scenario, 5-tuple, timestamp)`.
    - **`CTU-SME-11`** (Concept DOI `10.5281/zenodo.7958258` / `7958259`, **`CC BY 4.0`**, `VERIFIED_SUBSET_LOCAL`): Zeek `conn.log.labeled` thu 7 ngày trên thiết bị thật SME lab (2/11 thiết bị: `CTU-Echo` `76,073` flows = `39,497` Benign / `36,576` Recon; `CTU-Win7AD` `175,146` labeled = `173,108` Benign / `2,038` Attack + `9,394` unmapped; khử trùng `45` LAN overlap với Echo còn `175,101` flows cho Exps C/D).
    - **`AIT-ADS`** (`10.5281/zenodo.8263181`, **`CC BY 4.0`**) & **`AIT-LDS-v2.1`** (`10.5281/zenodo.19483937`, **`CC BY-NC-SA 4.0`** — chỉ tải `fox_no-pcaps.zip` & `russellmitchell_no-pcaps.zip` phục vụ kiểm toán liên kết, **cách ly 100%** khỏi ML training/demo CSV).
  - **Hiện trạng `UGR'16` (`BLOCKED`) & Kiểm toán 9 Ứng viên Bổ sung:**
    - **`UGR'16`:** Giữ trạng thái **`BLOCKED`** (`https://nesg.ugr.es/nesg-ugr16/` trả `HTTP 403` / *Portal en Mantenimiento*); không dùng dữ liệu tổng hợp thay thế.
    - Khảo sát 9 ứng viên (`V2_UGR16_ALTERNATIVES_REVIEW.md`): **Không có tập nào thay thế trực tiếp (drop-in replacement)** cho lưu lượng ISP thương mại Tier-3 nhiều tháng như `UGR'16`. Khuyến nghị bổ sung phân tầng (chưa tự động nạp): **`LITNET-2020`** (`ISP_COMPARABLE` — mạng NREN thực 10 tháng, `45.49M` flows NetFlow v9, 12 attack types, bài báo `CC BY 4.0`, cần kiểm định ghép luồng hai chiều vì `opkt=0/obyt=0`, đơn vị `td`, byte L3 vs L4), **`LUFlow`** & **`CTU-13`** (`INDEPENDENT_LABELED_VALIDATION` — `CTU-13` bắt buộc tái parse `*.truncated.pcap.bz2`, cấm `.binetflow` vì thiếu `pkts_in/out`). 6 tập còn lại (`MAWI/MAWILab`, `CAIDA`, `CESNET-TimeSeries24`, `CIC-IDS2017`, `CSE-CIC-IDS2018`, `CIC-DDoS2019`) xếp **`NOT_SUITABLE`**.
  - **Ranh giới liên kết `AIT-NDS-v2 ↔ AIT-LDS-v2.0/v2.1` (`AIT_LINKAGE_FEASIBILITY.md`, Issue `#85` `OPEN 2/3 AC`):**
    - **Tier 1 — `DIRECT_UID_LINK = False` (`direct_uid_join_possible: false`):** Không có khóa ngoại chung (`uid`, `flow_id`, `conn_id`, `community_id`) giữa Tstat CSV (`AIT-NDS-v2`), Suricata/host logs + line-numbered `labels/` (`AIT-LDS-v2.1`, không có Zeek logs) và `AIT-ADS`.
    - **Tier 2 — `ENTITY_TIME_CORRELATION = HEURISTIC ONLY`:** Chỉ đồng xuất hiện thô theo `(scenario, normalized_ip_entity, utc_epoch_window)` (vd `11/11` Wazuh agent IP & `32/32` `servers.yaml` IPv4 của `fox` khớp trong `fox_netflows.zip`), nhưng gặp NAT multi-probe duplication, VPN IP aliasing và lệch cửa sổ thời gian giữa `2_label_logs.ipynb` (`else "data exfiltration"` đa ngày & bỏ sót `escalate.yaml`) với `AIT-ADS` `dnsteal` sau `service_stop`.
    - **Tier 3 — `UNVERIFIED`:** Chưa tải full PCAP `AIT-LDS-v2.0` (`10.5281/zenodo.5789064`).
- **Speaker Notes (Lời thuyết minh):**
  - Nhấn mạnh đây là điểm kiểm soát chống ngụy tạo khoa học quan trọng nhất về dữ liệu: nhóm từ chối bịa `flow_id` để ghép log với NetFlow, từ chối thay `UGR'16` bằng traffic mô phỏng, và sửa triệt để 3 lỗi dữ liệu nghiêm trọng phát hiện ở Phase 0 (`DATA-A01` khôi phục `233,185` dòng rơi ở chunk, `DATA-A02` nhân `1000.0` cho `udp_complete` từ giây sang ms, `DATA-A03` căn chỉnh Zeek L4 `orig_bytes`/`resp_bytes` với Tstat L4 `c_bytes_all`/`s_bytes_all`).
- **Biểu đồ / Tham chiếu Bằng chứng:**
  - Bảng phân bố 8 kịch bản AIT & 2 thiết bị CTU trong [`docs/dataset/AIT_PROFILE.md`](dataset/AIT_PROFILE.md), [`docs/dataset/CTU_SME_11_PROFILE.md`](dataset/CTU_SME_11_PROFILE.md), [`docs/dataset/V2_LEAKAGE_AUDIT.md`](dataset/V2_LEAKAGE_AUDIT.md).
  - Bảng so sánh 9 ứng viên theo 12 tiêu chí trong [`reports/audits/V2_UGR16_ALTERNATIVES_REVIEW.md`](../reports/audits/V2_UGR16_ALTERNATIVES_REVIEW.md).
  - Kiểm toán liên kết 3 tầng trong [`docs/dataset/AIT_LINKAGE_FEASIBILITY.md`](dataset/AIT_LINKAGE_FEASIBILITY.md) và [`data/EXTERNAL_DATASETS_PROVENANCE.json`](../data/EXTERNAL_DATASETS_PROVENANCE.json).
- **Giới hạn Trung thực (`Honest Limitations`):**
  - `AIT-NDS-v2` không chứa giao thức `ICMP` (`0` dòng) và nhiều TCP scan 1 gói `0 B` đặc thù công cụ giả lập; `CTU-SME-11` mới phản ánh 2 thiết bị SME lab (chưa đại diện mạng ISP xương sống như `UGR'16`).
  - Liên kết đa nguồn ở tầng thực nghiệm sâu (flow-to-log ground-truth pairing) vẫn **`BLOCKED`** ở `#85`.

---

## Chủ đề 5 — Feature Contract `canonical-flow-v2-18`, Anti-Shortcut & OOD Physical Invariants

- **Định vị Slide:** **Slide 5 — Hợp đồng `canonical-flow-v2-18`, Anti-Imputation, `taxonomy-v2` & OOD Fail-Closed**
- **Nội dung Slide (Bullet points chính):**
  - **Cấu trúc 18 đặc trưng chuẩn tắc (`ML_FEATURE_COLUMNS`, `src/network_anomaly/data/v2_schema.py`):**
    - **6 Base Observed Fields:** `duration_ms`, `bytes_in`, `bytes_out`, `pkts_in`, `pkts_out`, `protocol_num` (IANA `0..255`).
    - **12 Deterministic Derived Features:** `total_bytes`, `total_pkts`, `bytes_in_ratio`, `pkts_in_ratio`, `bytes_per_pkt_in`, `bytes_per_pkt_out`, `bytes_per_sec_in`, `bytes_per_sec_out`, `pkts_per_sec`, `has_response`, `is_tcp`, `is_udp`.
    - **Cách ly ma trận `X`:** Tách tuyệt đối 5 trace metadata (`timestamp_ms`, `source_ip`, `dest_ip`, `source_port`, `dest_port`), 5 provenance và 4 target columns (`label_binary`, `attack_category`, `raw_label`, `label_status`).
  - **Anti-Shortcut (`min_ttl`) & Anti-Leakage (`validate_feature_selection`):**
    - Chặn cứng các cột shortcut/rò rỉ: `MIN_TTL`, `MAX_TTL`, `role_cli`, `role_serv`, `network_cli`, `network_serv`, `uid`, `Label`, `Attack`.
    - Kết quả `shortcut_audit` trên `AIT-Val`: không có đặc trưng đơn lẻ nào đạt `abs_auc >= 0.98` (lớn nhất là `bytes_in` `0.965448`, `top2_importance_share` trên RF = `0.252695`).
  - **Anti-Imputation & Chính sách Nhãn `taxonomy-v2` (`src/network_anomaly/data/taxonomy.py`):**
    - Không điền `0`, mean hay median cho nguồn thiếu trường (`is_ml_complete = False`): NetFlow v5 / AWS VPC Flow thiếu chiều về bị gắn `FEATURE_INCOMPATIBLE`; log DNS/HTTP/Auth (`AIT-LDS-v2.1`) đi đường `route_only = True` vào Behavioral/Risk/Trace.
    - Không ép `background` / `unknown` / `""` thành `Benign` (`942` dòng AIT & `9,394` dòng `CTU-Win7AD` giữ ở `Unmapped`).
  - **Tiền xử lý Train-Only & OOD 2 Lớp:**
    - `TrainOnlyPreprocessor(asinh_robust)` (`SHA-256: 0866dec7...`) fit duy nhất trên `ait_train` (`2,097,891` dòng), có `MIN_BOUNDED_SCALE_FLOOR = 0.25` chống suy biến IQR `pkts_in_ratio`.
    - **`OODValidator`** (`src/network_anomaly/ingestion/ood.py`): bắt buộc physical invariants (`duration_ms >= 0`, counters `>= 0`, ports `[0, 65535]`, `protocol_num [0, 255]`, ratios `[0, 1]`, finite), phát hiện unseen protocol IDs (`KNOWN_PROTOCOLS`), và tách riêng `ZERO_TTL_DRIFT` nếu đầu vào có `min_ttl == 0`.
    - **`OODRejectionGate`** (`artifacts/ml/ood_reference_gate.json`, `SHA-256: 8a52bfe5...`, fit trên `2,097,891` dòng raw train, `std_margin = 4.0`, `statistical_threshold = 5.0`): kiểm chứng schema/SHA preprocessor fail-closed qua `OODRejectionGate.from_artifact()` và `validate_ood_gate_instance()`, kết hợp AE sidecar `score_normalization.json` (`d7bcb78f...`) cross-check trong `AutoencoderModel`, phát hiện `MISSING_MANDATORY_FEATURES`, `FEATURE_BOUNDS_EXTREME_BREACH`, `STATISTICAL_OUTLIER_DISTANCE` -> `ABSTAIN`; `RealtimeInferenceEngine` phân tách `runtime_mode` (`"research"` vs `"deployment"`) để cấm inject in-memory gate ở `deployment` và khóa fail-closed (`inference_mode = "UNAVAILABLE"`) khi OOD `ERROR` hoặc thiếu OOD ở `deployment`.
- **Speaker Notes (Lời thuyết minh):**
  - Giải thích sự khác biệt giữa hai lớp bảo vệ đầu vào: `OODValidator` kiểm tra các **bất biến vật lý tuyệt đối** (ví dụ duration âm hoặc tỷ lệ `bytes_in_ratio > 1.0`), còn `OODRejectionGate` kiểm tra **độ lệch thống kê đa biến** so với phân phối huấn luyện `AIT-NDS-v2`.
  - Nhấn mạnh vai trò của `MIN_BOUNDED_SCALE_FLOOR = 0.25`: ở bản audit trước, IQR của `pkts_in_ratio` bị co về `0.044269` làm luồng một chiều trên CTU bị phóng đại tới `+9.04 sigma`; floor `0.25` kéo `scaled_W1` xuống còn `0.7272`.
- **Biểu đồ / Tham chiếu Bằng chứng:**
  - `reports/schema/v2_schema_summary.json`, `reports/preprocessing/v2_flow_preprocessing_manifest.json`, `artifacts/ml/ood_reference_gate.json`.
  - [`docs/CANONICAL_SECURITY_EVENT_V2.md`](CANONICAL_SECURITY_EVENT_V2.md) và [`docs/FEATURE_COMPATIBILITY_MATRIX.md`](FEATURE_COMPATIBILITY_MATRIX.md).
  - Unit tests: `tests/unit/test_anti_imputation_and_label_integrity.py`, `tests/unit/test_ood_gate.py`, `tests/unit/test_ood_and_calibration.py`, `tests/unit/test_realtime_inference.py`, `tests/unit/test_verify_companion_artifacts.py`.
- **Giới hạn Trung thực (`Honest Limitations`):**
  - Không gian 18-D vẫn tồn tại đa cộng tuyến (`|r| >= 0.85` ở 11–16 cặp) và trùng lặp vector exact-feature gây xung đột nhãn `Benign` vs `Attack` (Bayes error: `48` vector / `126,166` dòng trong `ait_train`; `75` vector / `13,862` dòng trong `ctu_echo`).
  - `TrainOnlyPreprocessor` giữ `protocol_num` ở dạng `passthrough` chưa scale; thử nghiệm `E3a` (thay bằng one-hot `[tcp, udp, icmp, other]` 21 chiều) nâng AE `AIT-Test F1` lên `0.6496` và giảm `CTU-Echo FPR` (`0.6746 -> 0.4222`), nhưng `CTU-Win7AD FPR` vẫn cao (`0.6335`) do ngắn mạch `duration ~ 2ms` của UDP benign trên Zeek.

---

## Chủ đề 6 — Kết quả `RQ1` (4 Mô hình), Parity/OOD, Thất bại Cross-Source & 4 Cổng `RESEARCH_ONLY`

- **Định vị Slide:** **Slide 6 — Thực nghiệm `RQ1` (`AIT-Test`), Parity API/CLI, Suy giảm Cross-Source (`CTU-SME-11`) & Cơ chế 4 Cổng Sẵn sàng**
- **Nội dung Slide (Bullet points chính):**
  - **Kết quả `RQ1` trên `AIT-Test` (`N = 988,805`: `812,980` Benign / `175,825` Attack, `seed = 42`):**

| Mô hình (Protocol & Threshold trên `AIT-Val`) | Precision | Recall | F1 | Macro-F1 | FPR | ROC-AUC | PR-AUC | Latency (`us/flow`) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| **Random Forest** (`balanced_subsample, leaf=5`, `th=0.5`) | `0.9989` | `0.9911` | **`0.9950`** | `0.9969` | `0.000246` | `0.9994` | `0.9977` | `2.057` |
| **XGBoost** (`200 trees, depth=6, lr=0.1`, `th=0.5`) | `0.9989` | `0.8211` | **`0.9013`** | `0.9411` | `0.000198` | `0.9884` | `0.9728` | `0.646` |
| **Autoencoder** (`MLP 18-16-8-16-18`, Benign-only, `th=0.000467`) | `0.7860` | `0.4693` | **`0.5877`** | `0.7597` | `0.027637` | `0.5544` | `0.5664` | `0.484` |
| **Isolation Forest** (`200 trees, max_samples=512`, Benign-only, `th=0.031268`) | `0.7775` | `0.4678` | **`0.5842`** | `0.7576` | `0.028952` | `0.8330` | `0.6587` | `8.668` |

  - **OOD Fail-Closed & Parity Kiểm chứng:**
    - API `/api/v1/csv/analyze` khớp parity với CLI `InferencePipeline.predict()` sai số `<= 1e-7` trên `data/demo/demo_flows.csv` (200 flows cân bằng từ `AIT-Val`); artifact thiếu hoặc sai SHA-256 trả HTTP `503` fail-closed (không fallback); mẫu OOD trả `ABSTAINED_OOD` (`predicted_label=None, risk_score=None`); `RealtimeInferenceEngine` khóa fail-closed (`inference_mode = "UNAVAILABLE"`) ở `deployment` nếu thiếu hoặc corrupt `ood_reference_gate.json` (và từ chối ở mọi mode khi OOD `ERROR`).
    - Tách bạch `score_semantics`: `calibrated_binary_probability` (RF/XGB) vs `empirical_percentile_vs_validation_benign` (IF/AE).
  - **Thất bại Cross-Source Zero-Shot trên `CTU-SME-11` (`Exp B`) & Ablation Kiểm soát (`WP3 E0–E5`):**
    - **`CTU-Echo` (`N=76,073`):** `RF` `F1=0.0474` (`R=0.0264, FPR=0.0811, ROC=0.6137`); `XGB` `F1=0.1436` (`R=0.0832, FPR=0.0700, ROC=0.7017`); `IF` **`F1=0.8853`** (`R=0.9908, FPR=0.2292, ROC=0.9571`); `AE` `F1=0.7325` (`R=0.9990, FPR=0.6746, ROC=0.7810`).
    - **`CTU-Win7AD` (`N=175,146`):** `RF` `F1=0.0712` (`R=0.5412, FPR=0.1608, ROC=0.8392`); `XGB` `F1=0.0738` (`R=0.5623, FPR=0.1611, ROC=0.6978`); `IF` `F1=0.0464` (`R=0.9760, FPR=0.4722`); `AE` `F1=0.0326` (`R=0.9921, FPR=0.6925`).
    - **Controlled Ablation & Domain Shift (`wp3_controlled_ablation_report.json`):** `E1` (6 base features) làm `XGB Exfil` sụp `0.6128 -> 0.0803`; `E2b` (bỏ hết byte features) nâng `RF Win7AD F1` lên `0.5665` (`AUC=0.8869`) nhưng làm `AIT-Val FPR` tăng vọt lên `0.0770` và xóa sổ `CTU-Echo` (`F1=0.0067, R=0.0034`); `E4` 5-fold LOSO CV lộ `XGB Exfil=0.0230` ở fold `harrison`; `E5` xác nhận chỉ `Tier 3` (`CTU Echo late`: `RF F1=0.9634`, `RESEARCH_ONLY`) hoặc multi-source (`Tier 2`) mới cải thiện khi có dữ liệu đích. Kết luận chính thức: **`RETAIN_E0_BASELINE_ARTIFACTS`** *(quyết định bảo lưu hậu nghiệm có tham khảo holdout `AIT-Test`/`CTU`, `holdout_independent_selection = false`; không dùng holdout để fit hay calibrate threshold)*.
    - **Cảnh báo Mẫu Hiếm (`Exploitation_And_C2 N=5`):** Mức `100%` (`5/5`) trên `AIT-Test` **không** đủ ý nghĩa thống kê để kết luận tổng quát hóa `100%`.
  - **Vì sao cả 4 mô hình hiện giữ `deployment_tier = RESEARCH_ONLY` (Tách 4 Cổng trong `ModelRegistry`):**
    - `ModelRegistry` (`src/network_anomaly/models/registry.py`) tách 4 cổng độc lập:
      1. `artifact_verified` (`4/4 True` — SHA-256 + `canonical-flow-v2-18` + clean threshold + prep/split match)
      2. `in_domain_evaluated` (`4/4 True` — kết quả `ait_test` hợp lệ)
      3. `cross_source_validated` (**`0/4 False`** — yêu cầu `Recall >= 0.70` **và** `FPR <= 0.10` trên **cả** `ctu_echo` và `ctu_windows7ad` -> cả 4 đều không đạt!)
      4. `deployment_tier` (**`4/4 RESEARCH_ONLY`** — chỉ cấp `PRODUCTION_ELIGIBLE` khi đạt cả 3 cổng trên và không thuộc `RESEARCH_ONLY_MODEL_KEYS`).
    - Do đó `ai_ready = True` (`4/4 VALIDATED`) mang ngữ nghĩa tường minh: `verified_artifacts_loaded_for_scoped_inference_not_production_certified`, còn `production_ready = False` (`cross_source_validated_count = 0`).
- **Speaker Notes (Lời thuyết minh):**
  - Đây là slide chứng minh độ trung thực khoa học cao nhất: mặc dù trên `AIT-Test` RF đạt `F1=0.9950`, khi sang `CTU-SME-11` capture thực tế, ngưỡng `0.5` của RF/XGB sụp đổ do lệch kích thước/thời lượng luồng (Zeek `2.4ms` DNS vs AIT `5.1s` Benign; `ctu_echo` dùng 2-pkt SYN retry vs AIT 1-pkt scan) và `CTU-Win7AD` Trickbot chồng lấn Benign.
  - Vì cổng `cross_source_validated` được kiểm tra tự động từ manifest thực tế, hệ thống **tự hạ cấp cả 4 mô hình xuống `RESEARCH_ONLY`**, ngăn chặn mọi hành vi tự động cô lập dựa trên mô hình chưa chứng nhận đa nguồn.
- **Biểu đồ / Tham chiếu Bằng chứng:**
  - `reports/experiments/ml/model_comparison_report.json` (`RQ1`), `reports/experiments/ml/ctu_cross_source_eval.json` (Exps A–E), `reports/experiments/ml/domain_analysis/DOMAIN_SHIFT_ANALYSIS.md`.
  - Code 4 cổng & parity test: [`src/network_anomaly/models/registry.py`](../src/network_anomaly/models/registry.py#L80-L180) và [`tests/integration/test_four_model_integrity_e2e.py`](../tests/integration/test_four_model_integrity_e2e.py#L297-L442).
- **Giới hạn Trung thực (`Honest Limitations`):**
  - So sánh supervised (train Ben+Attack) và unsupervised (train Benign-only, calibrated `FPR <= 0.05` trên Val) khác giao thức huấn luyện, cần diễn giải đúng vai trò bổ trợ.
  - Throughput batch ngoại tuyến (`486k–2.06M flows/s`) chỉ phản ánh suy luận vector hóa trên CPU host, không phản ánh năng lực line-rate mạng vật lý.

---

## Chủ đề 7 — Tấn công Hiếm (`RQ2`) & Phát hiện Tấn công Chưa Biết (`RQ4`)

- **Định vị Slide:** **Slide 7 — Bài toán Mất cân bằng Lớp (`RQ2`) & Đánh giá Holdout Họ Tấn công Chưa biết (`RQ4`)**
- **Nội dung Slide (Bullet points chính):**
  - **Thực nghiệm `RQ2` — Tấn công Hiếm & Mất cân bằng (`EXP-RQ2-IMBALANCE-001`, không SMOTE trên Val/Test):**
    - Tỉ lệ mất cân bằng `AIT-Train`: `6.7121:1` (`1,825,866` Benign / `272,025` Attack). Cost-sensitive nâng overall `AIT-Test F1` từ `0.8000` (`RF_Unweighted`, `R=0.6674`) lên `0.9947` (`RF_CostSensitive`, `R=0.9907`), và `XGB_ScalePosWeight` lên `0.9727` (`R=0.9487`).
    - **Kết quả trên 3 lớp hiếm (< 0.5%) tại `AIT-Test` (`N = 988,805`):**
      - `Exploitation_And_C2` (`N = 5`, `0.0005%`): Detection Rate = **`1.0000` (`5/5`)** ở cả 5 cấu hình, nhưng one-vs-benign F1 chỉ `0.0004–0.0549` do mẫu số cực nhỏ nhạy cảm với FP Benign.
      - `Post_Exploitation_Discovery` (`N = 39`, `0.0039%`): Detection Rate = **`0.8974` (`35/39`)** với RF/XGB/IF, nhưng Autoencoder chỉ **`0.1026` (`4/39`)**.
      - `Credential_Attack` (`N = 78`, `0.0079%`): Cả `RF_Unweighted`, `RF_CostSensitive`, `XGB_ScalePosWeight` và `IF` đều dừng ở **`0.1410` (`11/78`)**, còn Autoencoder chỉ **`0.0641` (`5/78`)** -> `67/78` luồng `online_cracking` chồng lấn phân phối Benign HTTP/SSH ở cấp độ đơn-flow 18-D.
    - **Phán quyết H2:** **`h2_full_confirmed = false`** (`cost_sensitive_detection_rate_ge_0_70_all_rare = false`, `autoencoder_one_vs_benign_f1_ge_0_70_all_rare = false`).
  - **Thực nghiệm `RQ4` — Holdout Leave-Categories-Out (`EXP-RQ4-UNKNOWN-001`):**
    - Tách sạch 100% `Exploitation_And_C2` và `Post_Exploitation_Discovery` khỏi Train (`216` dòng bị loại -> còn `2,097,675`) và Val (`58` dòng bị loại -> còn `377,646`); `zero_leakage_verified = true`. Tập Test gồm `812,980` Benign, `175,781` Known Attack và **`44` Unknown Holdout**.
    - **Kết quả Recall trên `44` luồng Unknown Holdout:**
      - `Isolation Forest` (Benign-only): Unknown Recall = **`0.9091` (`40/44`)**, Unknown FPR = `0.0290`, Unknown F1 = `0.0034` (Known Recall `0.4677`).
      - `Random Forest` (Holdout-trained, `th=0.15`): Unknown Recall = **`0.9091` (`40/44`)**, Unknown FPR = `0.000357`, Unknown F1 = `0.2139` (Known Recall `0.9973`).
      - `XGBoost` (Holdout-trained, `th=0.25`): Unknown Recall = **`0.7500` (`33/44`)**, Unknown FPR = `0.000271`, Unknown F1 = `0.2222` (Known Recall `0.8216`).
      - `Autoencoder` (Benign-only): Unknown Recall = **`0.2045` (`9/44`)**, Unknown FPR = `0.0276`, Unknown F1 = `0.0008` (giảm `-56.42%` so với Known Recall `0.4693`).
    - **Phán quyết H4:** **`unsupervised_ge_0_75_both = false`** (`isolation_forest_ge_0_75 = true`, **`autoencoder_ge_0_75 = false`**).
- **Speaker Notes (Lời thuyết minh):**
  - Giải thích điểm nhấn khoa học của `RQ2`: `RandomForest_CostSensitive` giải quyết tốt khoảng trống `Data_Exfiltration` ở biên phân bố `shaw`, nhưng **không có phép gán trọng số nào cứu được `Credential_Attack` (`11/78 = 14.10%`)** vì thông tin luồng đơn lẻ 18-D không phân biệt được brute-force web/SSH ít gói với truy cập HTTP/SSH hợp lệ — đây là bằng chứng biện minh trực tiếp cho sự cần thiết của tầng Behavioral Vector theo cửa sổ phiên/host và log Auth (`AIT-LDS-v2.1`).
  - Với `RQ4`: trình bày trung thực rằng giả thuyết `H4` cho cả 2 mô hình không giám sát đều đạt `>= 0.75` là **KHÔNG đạt** vì Autoencoder chỉ đạt `20.45%` (`9/44`), dù Isolation Forest đạt `90.91%` (`40/44`). Ngoài ra, RF/XGB đạt `90.91%` và `75.00%` một phần do 2 họ holdout trong cùng testbed AIT có mẫu lưu lượng bất thường tương đồng với một số tấn công đã biết.
- **Biểu đồ / Tham chiếu Bằng chứng:**
  - `reports/experiments/imbalance/rq2_imbalance_report.json` & `reports/experiments/imbalance/rq2_imbalance_report.md`.
  - `reports/experiments/ml/rq4_unknown_attack_report.json` & [`docs/experiments/EXP4_UNKNOWN_ATTACK.md`](experiments/EXP4_UNKNOWN_ATTACK.md).
- **Giới hạn Trung thực (`Honest Limitations`):**
  - Số mẫu dương tính cực nhỏ (`N=5` cho `Exploitation_And_C2`, `N=44` tổng holdout `RQ4`) làm F1 đơn lớp bị chi phối bởi số FP trên `812,980` mẫu Benign.
  - Holdout trong nội bộ `AIT-NDS-v2` chỉ mô phỏng họ tấn công chưa thấy trong cùng testbed, **không** chứng minh khả năng phát hiện zero-day hay tấn công né tránh đối kháng ngoài thực tế.

---

## Chủ đề 8 — Behavioral Vector 16-D Độc lập IP (`RQ3`)

- **Định vị Slide:** **Slide 8 — Tương quan Phiên Hành vi 16-D Không phụ thuộc IP & Thực nghiệm `RQ3`**
- **Nội dung Slide (Bullet points chính):**
  - **Thiết kế Behavioral Vector 16-D (`src/network_anomaly/behavioral/vector.py`):**
    - Chuẩn hóa **L2 trên siêu cầu đơn vị**, băm `SHA-256`, ghi rõ `missing_feature_count`/`missing_feature_names`, hoàn toàn loại bỏ IP nguồn/đích khỏi vector đặc trưng:
      - Quy mô & tỷ lệ luồng (7): `log_duration`, `log_bytes_in`, `log_bytes_out`, `bytes_ratio_clipped`, `log_pkts_in`, `log_pkts_out`, `pkts_ratio_clipped`.
      - Đa dạng & cờ kết nối (4): `unique_ports_norm`, `unique_protocols_norm`, `syn_flag_ratio`, `rst_flag_ratio`.
      - Ngữ cảnh ứng dụng & thời gian (5): `dns_intensity`, `http_intensity`, `auth_failure_ratio`, `log_mean_iat`, `log_std_iat`.
    - Kèm **`EntityBaselineProfiler`** (cửa sổ trượt `50` phiên gần nhất theo thực thể, tính độ lệch cosine `1.0 - cos_sim`).
  - **Kết quả Thực nghiệm Track 1 — Synthetic IP-Rotation Simulation (`EXP-RQ3-CORRELATION-01`):**
    - Cấu hình: `execution_mode = "SIMULATION"`, 5 chiến dịch × 4 phiên/chiến dịch = 20 phiên (190 cặp không thứ tự: 30 positive cùng chiến dịch, 160 negative khác chiến dịch), kẻ tấn công xoay IP mỗi phiên.

| Chiến lược Liên kết | TP | FP | FN | TN | Precision | Recall | F1 | False Link Rate | Match Acc |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Strategy A:** Khớp chính xác IP | `0` | `0` | `30` | `160` | `0.0000` | `0.0000` | `0.0000` | `0.0000` | `0.8421` |
| **Strategy B:** 16-D Cosine (`>= 0.85`) | `30` | `128` | `0` | `32` | `0.1899` | `1.0000` | **`0.3191`** | `0.8000` | `0.3263` |
| **Strategy B (Strict `cos >= 0.95`)** | `30` | `48` | `0` | `112` | `0.3846` | `1.0000` | **`0.5556`** | `0.3000` | `0.7474` |

  - **Phán quyết `RQ3`:** **`simulation_hypothesis_met = false`** (mục tiêu `F1 >= 0.85` không đạt ngay cả ở ngưỡng `0.95` do va chạm cosine giữa các chiến dịch khác nhau sau khi chuẩn hóa L2).
  - **Track 2 — Thực nghiệm Đa nguồn Thực tế (`AIT`):** **`BLOCKED`** (`empirical_dataset_status = "BLOCKED"`, Issue `#85` `OPEN 2/3 AC`) do `AIT-NDS-v2 ↔ AIT-LDS-v2.1` không có khóa `UID` trực tiếp (`DIRECT_UID_LINK = False`).
- **Speaker Notes (Lời thuyết minh):**
  - Giải thích hai mặt của kết quả `RQ3`: về mặt **khả năng hồi phục khi đổi IP**, Strategy B cứu được `30/30` cặp bị mất hoàn toàn bởi IP matching (`Recall 1.0` vs `0.0`); tuy nhiên, chuẩn hóa L2 xóa bỏ quy mô tuyệt đối nên dễ gộp nhầm các chiến dịch khác nhau có hình dạng tỷ lệ gần nhau (`FalseLink = 0.80` ở `0.85`, giảm còn `0.30` ở `0.95`), khiến `F1 = 0.3191 / 0.5556 < 0.85` (`NEGATIVE_RESULT`).
  - Nêu rõ rằng Track 2 trên AIT bị chặn minh bạch chứ không ép nối bằng khóa giả.
- **Biểu đồ / Tham chiếu Bằng chứng:**
  - `reports/experiments/behavioral/rq3_session_correlation_experiment.json` & [`docs/experiments/EXP5_SESSION_CORRELATION.md`](experiments/EXP5_SESSION_CORRELATION.md).
  - Mã nguồn: [`src/network_anomaly/behavioral/vector.py`](../src/network_anomaly/behavioral/vector.py) và [`docs/dataset/AIT_LINKAGE_FEASIBILITY.md`](dataset/AIT_LINKAGE_FEASIBILITY.md).
- **Giới hạn Trung thực (`Honest Limitations`):**
  - `simulation_hypothesis_met = false`; chuẩn hóa L2 đơn thuần chưa đủ tách biệt precision giữa các chiến dịch nếu thiếu neo thời gian hoặc đặc trưng phân biệt theo loại dịch vụ.
  - Chưa có kiểm chứng thực nghiệm trên chiến dịch đa nguồn có `UID` gốc gắn kèm (Issue `#85` `OPEN`).

---

## Chủ đề 9 — Risk Engine `[0..100]`, Deduplicated Live Alerts & Security Dry-Run Policy

- **Định vị Slide:** **Slide 9 — Chấm điểm Rủi ro Đa tiêu chí, Cảnh báo Trực tiếp Gộp trùng (`#137`) & Chính sách Phản ứng Dry-Run**
- **Nội dung Slide (Bullet points chính):**
  - **Risk Engine Đa tiêu chí `[0..100]` (`src/network_anomaly/risk/scoring.py`):**
    - Tổng hợp 4 thành phần trọng số xác định: `AI Confidence` (`0–50`), `Behavioral Deviation` (`0–25`), `Sensitive Port/Protocol` (`0–15` cho `{22, 23, 88, 389, 445, 1433, 3389, 5985, 5986}`, hoặc `6.0` cho port `< 1024`), `Auth Failures` (`0–10`, `min(count * 2.5, 10)`).
    - Phân mức: `LOW (<30)`, `MEDIUM (30–69.9)`, `HIGH (>=70)`, `CRITICAL (>=85 -> trigger_adaptive_rotation)`.
    - **OOD Guard:** Nếu `is_ood = True`, trần điểm rủi ro bị khóa ở **`<= 65.0`** và `trigger_adaptive_rotation = False` để chống kích hoạt xoay khóa do báo động giả ngoài phân phối.
  - **Deduplicated Live Alert Pipeline & Nghiệm thu Synthetic UDP Loopback (`Issue #137`):**
    - `LiveAlertManager` (`src/network_anomaly/streaming/alert_manager.py`): kích hoạt cảnh báo ở ngưỡng `>= 70.0`, gộp trùng lặp theo `entity_id` trong cửa sổ **`60.0s`** (`occurrence_count`, `associated_event_ids`, lưu SQLite `live_alerts`).
    - **Kết quả Chạy Nghiệm thu Synthetic UDP Loopback (`2026-11-18T05:50:37Z`):**
      - Cổng UDP `127.0.0.1:51817`, nhận 4 datagram (NetFlow v9 template+data, v9 data-only tái sử dụng template cache, IPFIX dùng quy ước lab `PEN 50000` / IE `50000+i` float64, và 1 gói lỗi bị từ chối `malformed_packet_count = 1`).
      - `6/6` sự kiện đạt chuẩn `canonical-flow-v2-18`, `4/4 VALIDATED` (`REAL_MODELS`, `ood_gate = FITTED`, `avg_inference_latency_us = 58,625.7`), `6/6` Behavioral Vector 16-D mã hóa AES-256-GCM ciphertext (`plaintext NULL`), `trace_graph` `8` nodes / `6` relations.
      - Phát sinh **`1` cảnh báo trực tiếp hợp lệ** (`alert-d38cf1e9d645`, `host:192.0.2.10`, `risk_score = 84.035`, `HIGH`, `dest_port = 445`, `detection_latency_ms = 0.035`) và chụp màn hình GUI (`reports/acceptance/live_gui_alert_synthetic_loopback.png`).
  - **Chính sách Phản ứng Thích ứng Dry-Run (`src/network_anomaly/api/response_policy.py`, Issue `#27`):**
    - Bắt buộc `dry_run = True` (`executed = false`, `os_firewall_touched = false`, `real_key_rotated = false`).
    - **Cổng Fail-Closed Kép:** **(1)** Mọi luồng `ABSTAINED_OOD` bị cấm tuyệt đối `ISOLATE_RECOMMENDED` (hạ xuống `MONITOR`/`INVESTIGATE`); **(2)** `_evaluate_containment_authority()` kiểm tra cả provenance máy chủ lẫn trạng thái mô hình — bất kỳ model nào có `deployment_tier == "RESEARCH_ONLY"` hoặc thuộc `RESEARCH_ONLY_MODEL_KEYS` đều bị chặn ở `HOLD_RESEARCH_ONLY_MODEL`, không cho phép khuyến nghị cô lập hay escalation xoay khóa.
- **Speaker Notes (Lời thuyết minh):**
  - Giải thích tại sao trên hình ảnh nghiệm thu `live_gui_alert_synthetic_loopback.png` và `synthetic_udp_loopback_report.json` chúng ta có `1` cảnh báo mức `HIGH` (`84.035`), nhưng vẫn khẳng định Issue `#137` chỉ mới `ACCEPTED` ở mức **Synthetic UDP Loopback** và giữ trạng thái `OPEN`: vì gói tin xuất ra từ Python exporter trên `127.0.0.1` với `PEN 50000`, chưa phải router/switch vật lý ngoài lab.
  - Nhấn mạnh thiết kế phòng thủ chiều sâu ở tầng Dry-Run: dù một luồng có Risk Score `99.0`, nếu không có `server_verified_analysis` hoặc chạy trên model `RESEARCH_ONLY` (như hiện tại cả 4 model trên tầng registry), hệ thống tự động hạ cấp quyết định về `INVESTIGATE` để con người xem xét.
- **Biểu đồ / Tham chiếu Bằng chứng:**
  - [`docs/telemetry/SYNTHETIC_UDP_LOOPBACK_ACCEPTANCE.md`](telemetry/SYNTHETIC_UDP_LOOPBACK_ACCEPTANCE.md), `reports/acceptance/synthetic_udp_loopback_report.json` và ảnh giao diện `reports/acceptance/live_gui_alert_synthetic_loopback.png`.
  - Mã nguồn: [`src/network_anomaly/risk/scoring.py`](../src/network_anomaly/risk/scoring.py), [`src/network_anomaly/streaming/alert_manager.py`](../src/network_anomaly/streaming/alert_manager.py), [`src/network_anomaly/api/response_policy.py`](../src/network_anomaly/api/response_policy.py).
  - Traceability Evaluation (8-event synthetic benchmark): `reports/experiments/trace/traceability_evaluation.json` (`Trace v2` `1.0` / `1.0` vs dynamic grep `0.375` / `0.50`).
- **Giới hạn Trung thực (`Honest Limitations`):**
  - Nghiệm thu Issue `#137` là **`SYNTHETIC`** (`real_device_tested = false`, AC #4–#5 trên router/switch vật lý vẫn `BLOCKED`).
  - Thực thi firewall OS thật và xoay vòng khóa tự động ngoài môi trường dry-run vẫn **`DEFERRED`**.
  - Lưu ý kỹ thuật: trong `ModelRegistry`, cả 4 models mang `deployment_tier = "RESEARCH_ONLY"`; trong `compatibility.py` đường dẫn CSV riêng của `random_forest` đánh dấu `MODEL_VALIDATED` dựa trên chứng cứ `AIT-Test` (`test_four_model_integrity_e2e.py`), còn `xgboost`/`isolation_forest`/`autoencoder` bị chặn ở `RESEARCH_ONLY` trên cả hai tầng.

---

## Chủ đề 10 — Mã hóa AES-256-GCM At-Rest & Adaptive Key Rotation (`RQ5`, `RQ6`)

- **Định vị Slide:** **Slide 10 — Bảo vệ Bằng chứng At-Rest (`AES-256-GCM` + DPAPI) & Hiệu quả Adaptive Key Rotation (`RQ5`, `RQ6`)**
- **Nội dung Slide (Bullet points chính):**
  - **Kiến trúc Mật mã At-Rest & Vòng đời Khóa (`src/network_anomaly/crypto/`):**
    - **AEAD:** `AES-256-GCM` với nonce `96-bit` (`12 bytes` cấp phát qua `NonceRegistry` chống trùng lặp) và authentication tag `128-bit` (`16 bytes`); gắn AAD theo ngữ cảnh (`domain:behavioral|entity:<id>|win:<ts>`), cột `vector_json` trong SQLite lưu `NULL`.
    - **Key Wrapping & Bảo vệ Khóa gốc:** Trên Windows, `master.key` bắt buộc bảo vệ bằng **Windows DPAPI** (`CryptProtectData`/`CryptUnprotectData`), **fail-closed** khi DPAPI lỗi (tuyệt đối không fallback plaintext); DEK bọc bằng `NETFLOW_WRAPPED_DEK_V2` (`AAD = key_id|domain|version`), ghi atomic qua `os.replace`.
    - **Chính sách Xoay khóa Chống DoS (`KeyRotationPolicy`):** Lịch cố định `30 phút` (`1,800s`), kích hoạt khẩn cấp khi `risk_score >= 85.0`, kèm `cooldown >= 60s` và `rate_limit <= 10 rotations/hour` lưu bền vững qua restart trong SQLite `rotation_audit`.
  - **Kết quả `RQ5` — Adaptive vs Fixed Key Rotation (`EXP-RQ5-ROTATION-01`, `SIMULATION`):**
    - Kịch bản mô phỏng thời gian rời rạc 60 phút (`120` events, bước `30s`, cửa sổ tấn công tại event `20..79`, cooldown `180s`):
      - **Fixed 30-min Schedule (`1` lần xoay):** Max exposure = **`1,200.0 s` (`20.0 phút`)**, Blast radius = **`40` bản ghi tấn công / 1 khóa**, Detection-to-rotation = `1,200.0 s`.
      - **Adaptive Risk Rotation (`10` lần xoay):** Max exposure = **`150.01 s` (`2.5002 phút`)**, Blast radius = **`6` bản ghi tấn công / 1 khóa**, Detection-to-rotation = **`0.01 s`**.
      - **Cải thiện:** Giảm **`87.5%`** thời gian phơi nhiễm khóa tối đa và **`85.0%`** blast radius (`hypothesis_confirmed = true`).
  - **Kết quả `RQ6` — Chi phí Tính toán AES-256-GCM (`BM-CRYPTO-OVERHEAD-RQ6`, 200 warmup + 2,000 measured/size):**

| Kích thước Payload | Plaintext JSON P95 | Encrypt Median | Encrypt P95 | Encrypt P99 | Encrypt Throughput | Decrypt P95 | Decrypt Throughput |
|---:|---:|---:|---:|---:|---:|---:|---:|
| **256 B** | `6.6 us` | `9.2 us` | **`13.3 us`** | `33.2 us` | **`75,851.2 ops/s`** | `2.6 us` | `429,719.4 ops/s` |
| **1,024 B** | `9.8 us` | `12.2 us` | **`17.3 us`** | `52.0 us` | **`59,259.3 ops/s`** | `5.9 us` | `223,005.2 ops/s` |
| **4,096 B** | `16.2 us` | `19.7 us` | **`29.6 us`** | `78.2 us` | **`38,617.1 ops/s`** | `15.8 us` | `95,269.4 ops/s` |

  - Kết luận `H6`: Đạt biên mục tiêu (`<= 500 us` P95 và `>= 5,000 ops/s`, `hypothesis_confirmed = true`).
- **Speaker Notes (Lời thuyết minh):**
  - Chỉ ra ý nghĩa của các con số `RQ5` và `RQ6`: chi phí mã hóa AES-256-GCM cho một vector hành vi (~256–1024 B) chỉ mất ~`13.3–17.3 us` ở mức P95 — hoàn toàn không đáng kể so với chi phí suy luận 4 mô hình AI (~`58–66 ms`), nhưng mang lại tính bảo mật và chống sửa đổi (128-bit GCM tag) cho bằng chứng hành vi lưu trữ tại chỗ.
  - Nhấn mạnh `RQ5` dùng chính các đối tượng thật `KeyManager` và `KeyRotationPolicy` nhưng chạy trên **dòng thời gian mô phỏng 60 phút** (`execution_mode = "SIMULATION"`), chưa phải vận hành sản xuất nhiều tháng.
- **Biểu đồ / Tham chiếu Bằng chứng:**
  - `reports/experiments/crypto/rq5_rotation_experiment.json` & `reports/experiments/crypto/rq5_rotation_report.md`.
  - `reports/benchmarks/crypto_benchmark_report.json` & `reports/benchmarks/crypto_benchmark_report.md`.
  - Mã nguồn & test: [`src/network_anomaly/crypto/key_manager.py`](../src/network_anomaly/crypto/key_manager.py), [`src/network_anomaly/crypto/rotation.py`](../src/network_anomaly/crypto/rotation.py), `tests/unit/test_key_manager_hardening.py`, `tests/unit/test_crypto_integrity.py`.
- **Giới hạn Trung thực (`Honest Limitations`):**
  - `RQ5` là **`SIMULATION`** rời rạc 60 phút; `RQ6` là microbenchmark CPU in-process (chưa gồm chi phí SQLite disk I/O).
  - Trên nền tảng POSIX/Linux (không có Windows DPAPI), `master.key` chỉ dựa vào quyền tệp `0600` của OS, không có hardware TPM/KMS.
  - Không chống lại kẻ tấn công đã chiếm toàn quyền Administrator/Kernel đọc trực tiếp RAM của tiến trình đang chạy.

---

## Chủ đề 11 — Hiệu năng Hệ thống, Bảo mật STRIDE & Governance Phân phối

- **Định vị Slide:** **Slide 11 — Benchmark Hệ thống E2E, Mô hình Đe dọa STRIDE & Kiểm toán Pháp lý / Phân phối**
- **Nội dung Slide (Bullet points chính):**
  - **Hiệu năng Hệ thống E2E (`reports/benchmarks/system_performance_benchmark.json`):**
    - Môi trường đo: `Windows-11-10.0.26200-SP0`, `12 vCPU`, `15.27 GB RAM`, `Python 3.12.10`, chế độ `REAL_MODELS (4/4 VALIDATED)`.
    - **End-to-End Orchestrator (200 events):** **`16.38 events/s`** (`12.2108 s`), E2E Latency: Median `61,750.4 us` (`61.75 ms`), P95 `73,575.7 us`, P99 `82,525.6 us`; Replay mode: `19.43 events/s` (`10.293 s`).
    - **Ring Buffer (capacity `2,000`):** Peak utilization `10.0%`, `0` dropped events.
    - **Microbenchmarks tách biệt (P95):** `collector_decoding` `1.4 us`, `feature_contract_validation` `3.8 us`, `aes_256_gcm_encrypt` `25.9 us`, `risk_scoring_dedup` `24.3 us`, `behavioral_vector_build` `42.9 us`, **`multi_model_ai_inference` `66,242.0 us`** (Median `57,635.75 us` — nút thắt cổ chai chính trên CPU).
  - **Phân tích Bảo mật STRIDE (`docs/audits/THREAT_MODEL_V2.md`, `SECURITY_AUDIT_V2.md`):**
    - 3 ranh giới tin cậy (**TB1** Wire→Ingestion, **TB2** Desktop UI↔Loopback Sidecar, **TB3** Core Engines→Vault) và 11 yêu cầu an ninh (`SR1–SR11`): Token `X-Sentinel-Session-Token` (SR2), AES-256-GCM 128-bit tag (SR3/SR6), SHA-256 provenance & model allowlist chống pickle RCE (SR4/SR10), audit log bất biến (SR5), zero-credential logging (SR7), bounded queue `10,000` & cooldown `>=60s` (SR8/SR9).
    - Điểm mở trung thực: `SR1` (`RQ3` simulation `< 85%`, `#85` BLOCKED) và `SR11` (Standard User E2E trên Clean Windows VM đang `PENDING_CLEAN_VM` `#73`/`#148`).
  - **Governance Phân phối (`DISTRIBUTION_AUTHORIZATION.json` & `V2_DISTRIBUTION_GOVERNANCE_REVIEW.md`):**
    - **Phán quyết phát hành công khai:** `public_release_authorization.approved = false`, `status = "HOLD_FOR_MAINTAINER_SIGNOFF"`, `maintainer_approver = null`, `evidence_sha256 = null` -> cổng `verify_distribution_permission()` **chặn fail-closed (exit `1`)** mọi lệnh upload/release công khai (`public_ci_artifact`, `public_github_release`); chỉ cho phép `research-only` / `private-build-only` trên `local_offline` hoặc private repo.
    - **Cách ly tuyệt đối `CC BY-NC-SA 4.0`:** Toàn bộ 4 mô hình `.joblib`, `v2_flow_preprocessor.joblib` và `data/demo/demo_*.csv` huấn luyện/lấy mẫu **100% từ `AIT-NDS-v2` (`CC BY 4.0`)** (`CTU-SME-11` & `AIT-ADS` cũng là `CC BY 4.0`). Dữ liệu **`AIT-LDS-v2.1` (`CC BY-NC-SA 4.0`)** chỉ nằm `.gitignored` tại `data/raw/ait_lds_v2_1/` (`0%` rò rỉ vào trọng số hay demo CSV).
    - **Dirty Git Provenance:** Cả 4 model manifests đều ghi nhận trung thực `git_commit: "79ebb678b87de19cc6b664b587726983fecaf98f"`, `git_dirty: true`, `worktree_provenance: "DIRTY_DISCLOSED"` -> bắt buộc commit sạch và tái xác minh/tái huấn luyện trên `main` trước mọi phát hành công khai.
- **Speaker Notes (Lời thuyết minh):**
  - Giải thích rõ tại sao tổng các microbenchmark thành phần không cộng tuyến tính thành E2E latency: vòng lặp điều phối Python, `sessionizer` và ghi SQLite tạo thêm overhead ngoài phần suy luận từng model (`~57.6 ms` median -> `~61.75 ms` E2E median).
  - Về bản quyền và phân phối: trả lời thẳng thắn câu hỏi *"Dữ liệu log `CC BY-NC-SA 4.0` có làm lây nhiễm ShareAlike sang mô hình/bộ cài Apache-2.0 không?"* -> **Không**, vì đã chứng minh theo mã nguồn và SHA-256 rằng 4 model + preprocessor + demo CSV chỉ dùng `AIT-NDS-v2` (`CC BY 4.0`), còn bộ cài công khai hiện vẫn chủ động khóa ở `approved=false` cho đến khi hoàn tất clean commit, xóa placeholder `LICENSE:1`, kiểm tra `tauri.standalone.conf.json` và Clean VM E2E.
- **Biểu đồ / Tham chiếu Bằng chứng:**
  - `reports/benchmarks/system_performance_benchmark.json` & [`docs/benchmarks/SYSTEM_PERFORMANCE.md`](benchmarks/SYSTEM_PERFORMANCE.md).
  - [`docs/audits/THREAT_MODEL_V2.md`](audits/THREAT_MODEL_V2.md) & [`docs/audits/SECURITY_AUDIT_V2.md`](audits/SECURITY_AUDIT_V2.md).
  - `reports/governance/DISTRIBUTION_AUTHORIZATION.json` & [`reports/audits/V2_DISTRIBUTION_GOVERNANCE_REVIEW.md`](../reports/audits/V2_DISTRIBUTION_GOVERNANCE_REVIEW.md).
- **Giới hạn Trung thực (`Honest Limitations`):**
  - `16.38 events/s` trên CPU là thông lượng của pipeline suy luận 4-model thực tế trên sự kiện tuần tự, không thể chứng nhận cho băng thông mạng doanh nghiệp 1–10 Gbps.
  - Chưa thực hiện kiểm thử xâm nhập (pentest) độc lập và chưa chạy kiểm chứng trên Clean Windows 10/11 VM (`#73`, `#148`).
  - `git_dirty: true` (`79ebb678`) trên working tree hiện tại cần được đóng băng thành commit sạch để chạy CI từ xa xác nhận lại.

---

## Chủ đề 12 — Kết luận, Phạm vi Đã đạt, Hạng mục `BLOCKED`/`DEFERRED` & Hướng Phát triển

- **Định vị Slide:** **Slide 12 — Tổng kết Đóng góp, Ma trận `BLOCKED`/`DEFERRED` & Hướng Phát triển**
- **Nội dung Slide (Bullet points chính):**
  - **Phạm vi Đã đạt (`NetFlow Sentinel v2.0` — Local / Academic Lab Prototype):**
    - Hoàn thành hard cutover loại bỏ shortcut `MIN_TTL` của v1; chuẩn hóa hợp đồng `canonical-flow-v2-18` + `taxonomy-v2` + chia tập scenario-disjoint `v2-scenario-group-purged-v1` (0 overlap, `3,464,400` flows AIT).
    - Huấn luyện và xác minh SHA-256 cả 4 mô hình (`AI Ready 4/4` fail-closed trên `AIT-NDS-v2`, parity API/CLI `<= 1e-7`), kèm kiểm chứng trung thực domain shift trên `CTU-SME-11` (`CTU-Echo` & `CTU-Win7AD`) và cơ chế tự hạ cấp `deployment_tier = RESEARCH_ONLY`.
    - Triển khai đầy đủ chuỗi Behavioral 16-D, Risk Engine `[0..100]`, Trace Graph/Timeline, AES-256-GCM DPAPI + Adaptive Key Rotation (`-87.5%` exposure trong simulation), Security Dry-Run (`executed=false`), và ứng dụng Desktop Tauri 2 + Svelte 5 + FastAPI Sidecar vượt qua nghiệm thu Synthetic UDP Loopback (`#137`).
  - **Tổng hợp Hạng mục `BLOCKED` & `DEFERRED` (Minh bạch 100%):**

| Hạng mục | Issue | Trạng thái | Nguyên nhân / Phạm vi Chờ |
|---|---|---|---|
| **External ISP Benchmark `UGR'16`** | `#82`, `#83`, `#97` | **`BLOCKED`** | Portal NESG trả `HTTP 403` / *Portal en Mantenimiento*; đã rà soát `LITNET-2020`, `LUFlow`, `CTU-13` làm nguồn bổ sung tương lai. |
| **Empirical `AIT-NDS-v2 ↔ AIT-LDS-v2.1` UID Linkage** | `#85` (`OPEN 2/3 AC`) | **`BLOCKED`** | `DIRECT_UID_LINK = False`; chỉ hỗ trợ `ENTITY_TIME_CORRELATION` heuristic; thiếu full PCAP `AIT-LDS-v2.0`. |
| **Physical Router/Switch Lab Acceptance** | `#137` (`OPEN 3/5 AC`) | **`BLOCKED`** | Mới đạt `ACCEPTED` ở mức **Synthetic UDP Loopback** (`live_gui_alert_synthetic_loopback.png`); AC #4–#5 thiết bị vật lý chưa chạy. |
| **Clean Windows 10/11 VM Installer & Public Release Signoff** | `#73`, `#148`, `#154` | **`BLOCKED / NOT VERIFIED`** | Chưa chạy `vm_target_e2e.ps1` + `--sign-vm-witness` trên VM sạch; `DISTRIBUTION_AUTHORIZATION.json` giữ `approved = false`. |
| **Website Tài liệu (`site-source`)** | `#152` (`OPEN 1/4 AC`) | **`DEFERRED / OUT OF BRANCH`** | Nhánh website Astro/MDX nằm ngoài phạm vi nhánh `feat/v2-integration`. |
| **Rust High-Performance UDP Collector** | `#128` (`OPEN 0/4 AC`) | **`DEFERRED`** | Đã đáp ứng live UDP collector bằng Python (`UDPFlowCollector`); bản Rust tốc độ cao hoãn sau `v2.0.0`. |
| **OS Firewall Active Containment** | `#27` | **`DEFERRED`** | Chủ động khóa ở chế độ `Dry-Run` (`executed = false`). |
| **Slide Deck `.pptx` / `.pdf` Chính thức** | `#153` (`OPEN 0/4 AC`) | **`DEFERRED`** | Bản hiện tại là **`OUTLINE_ONLY`**; việc xuất `.pptx`/`.pdf` để mở cho bước sau khi Issue `#153` tiếp tục. |

  - **Hướng Phát triển Tiếp theo:**
    1. **Kỹ thuật đặc trưng chuỗi/phiên (Causal Window Features):** Giải nút thắt `Credential_Attack` (`14.10%` ở đơn-flow) và `Data_Exfiltration` bằng thống kê fanout/tần suất theo cửa sổ thời gian nhân quả mà không gây leakage.
    2. **Domain Adaptation & Bổ sung Nguồn Ngoài:** Chuẩn hóa bộ tiền xử lý không để `protocol_num` unscaled, kiểm chứng tích hợp có kiểm soát `LITNET-2020`, `LUFlow`, `CTU-13` (truncated PCAP) và `UGR'16` khi cổng NESG mở lại.
    3. **Hiệu năng & Hoàn thiện Phát hành:** Tối ưu tốc độ suy luận multi-model (batch vectorization / ONNX hoặc Rust collector `#128`), đóng băng commit sạch lên `main`, nghiệm thu Clean Windows VM (`#73`/`#148`) và hoàn tất signoff `#154`.
- **Speaker Notes (Lời thuyết minh):**
  - Kết thúc bài trình bày bằng thông điệp cốt lõi: giá trị của đồ án không chỉ nằm ở những con số cao trên `AIT-Test` (`RF F1 = 0.9950`), mà nằm ở **hệ thống kiểm toán trung thực** giúp phát hiện bug đơn vị, lỗi shortcut `MIN_TTL`, sụp đổ domain-shift trên `CTU-SME-11`, và thiết kế kiến trúc fail-closed không bao giờ che giấu bất ổn đằng sau fallback giả.
- **Biểu đồ / Tham chiếu Bằng chứng:**
  - [`reports/audits/V2_FINAL_AUDIT.md`](../reports/audits/V2_FINAL_AUDIT.md), [`reports/audits/V2_ISSUE_AC_AUDIT.md`](../reports/audits/V2_ISSUE_AC_AUDIT.md), [`docs/ROADMAP_FULL_SYSTEM.md`](ROADMAP_FULL_SYSTEM.md).
- **Giới hạn Trung thực (`Honest Limitations`):**
  - Tài liệu hiện tại chỉ là dàn ý văn bản (`OUTLINE_ONLY — PPTX/PDF deferred`); các thay đổi working tree cần được commit sạch và chạy lại CI GitHub Actions sau khi hoàn tất bảo vệ/review.

---

## Bảng Truy vết Bằng chứng Toàn diện (`Evidence Traceability Table`)

> **Trạng thái Deliverable:** **`OUTLINE_ONLY — PPTX/PDF deferred (Issue #153 OPEN, 0/4 AC)`**

| Chủ đề / Slide | Khẳng định / Chỉ số Trọng tâm | Đường dẫn Artifact / Bằng chứng trong Repository | Phân loại Trạng thái |
|---|---|---|---|
| **1. Bối cảnh & Mục tiêu** | Định nghĩa bài toán NetFlow NIDS v2.0, mục tiêu & phạm vi lab | `docs/ARCHITECTURE_V2.md`, `docs/REQUIREMENTS.md`, `docs/TRACEABILITY_MATRIX.md` | `VERIFIED` |
| **2. Hard Cutover v1 → v2** | `NF-UNSW-NB15-v3` `MIN_TTL` importance (`RF 0.2406`, `XGB 0.8293`); OOD `NF-CSE-CIC-IDS2018-v3` `Recall = 0.0`, `FPR = 0.3802`; UQ `454104`; Hard Cutover ADR | `docs/adr/ADR-dataset-hard-cutover-v2.md`, `docs/MIGRATION_V1_TO_V2.md`, `docs/historical/nf_unsw_nb15_v3/MODEL_AUDIT_TTL_ABLATION.md` | `VERIFIED` *(46-feat cross-dataset run `BLOCKED`)* |
| **3. Kiến trúc & Ranh giới An toàn** | Tauri 2 (`2.0.0`) + Svelte 5 + FastAPI loopback + `X-Sentinel-Session-Token`; `Python UDPFlowCollector` + `StreamingEventPipeline` (`capacity=10,000`); Rust Collector `#128` hoãn | `docs/ARCHITECTURE_V2.md`, `src/network_anomaly/api/main.py`, `src/network_anomaly/telemetry/collector.py`, `src/network_anomaly/streaming/pipeline.py`, `desktop/src-tauri/tauri.conf.json` | `VERIFIED` · `DEFERRED` (`#128`) |
| **4. Dữ liệu Đa nguồn, `UGR'16` & AIT Linkage** | `AIT-NDS-v2` (`3,464,400` + `942` unmapped), `CTU-SME-11` (`76,073` Echo + `175,146` Win7AD + `9,394` unmapped), `UGR'16` HTTP 403, ứng viên `LITNET-2020`/`LUFlow`/`CTU-13`, `DIRECT_UID_LINK=False` | `data/EXTERNAL_DATASETS_PROVENANCE.json`, `reports/splits/v2_split_manifest.json`, `docs/dataset/AIT_PROFILE.md`, `docs/dataset/CTU_SME_11_PROFILE.md`, `docs/dataset/V2_LEAKAGE_AUDIT.md`, `docs/dataset/AIT_LINKAGE_FEASIBILITY.md`, `reports/audits/V2_UGR16_ALTERNATIVES_REVIEW.md` | `VERIFIED` (`AIT`, `CTU`) · `BLOCKED` (`UGR'16`, `#85` linkage) |
| **5. Feature Contract `canonical-flow-v2-18` & OOD** | 6 base + 12 derived, anti-shortcut `min_ttl`, anti-imputation, `taxonomy-v2`, `TrainOnlyPreprocessor` (`0866dec7...`, `MIN_BOUNDED_SCALE_FLOOR=0.25`), `OODValidator` + `OODRejectionGate` (`8a52bfe5...`) + `runtime_mode` fail-closed & AE `score_normalization.json` (`d7bcb78f...`) | `src/network_anomaly/data/v2_schema.py`, `src/network_anomaly/data/taxonomy.py`, `src/network_anomaly/ingestion/ood.py`, `src/network_anomaly/ml/ood_gate.py`, `src/network_anomaly/streaming/realtime_inference.py`, `artifacts/ml/ood_reference_gate.json`, `artifacts/models/autoencoder/score_normalization.json`, `reports/schema/v2_schema_summary.json`, `reports/preprocessing/v2_flow_preprocessing_manifest.json` | `VERIFIED` *(tồn tại Bayes-error overlap đã công bố)* |
| **6. `RQ1`, `WP3 E0–E5`, Cross-Source & 4 Cổng** | `AIT-Test` (`RF 0.9950`, `XGB 0.9013`, `AE 0.5877`, `IF 0.5842`); `CTU-Echo` (`RF 0.0474`, `XGB 0.1436`, `IF 0.8853`, `AE 0.7325`); `CTU-Win7AD` (`0.0712/0.0738/0.0464/0.0326`); `WP3 E1–E5` ablation & `RETAIN_E0_BASELINE_ARTIFACTS`; 4 cổng -> `RESEARCH_ONLY`; parity `<= 1e-7` | `reports/experiments/ml/model_comparison_report.json`, `reports/experiments/ml/wp3_controlled_ablation_report.json`, `reports/experiments/ml/ctu_cross_source_eval.json`, `reports/experiments/ml/domain_analysis/DOMAIN_SHIFT_ANALYSIS.md`, `reports/models/*_manifest.json`, `src/network_anomaly/models/registry.py`, `tests/integration/test_four_model_integrity_e2e.py`, `data/demo/demo_manifest.json` | `VERIFIED` · `NEGATIVE_RESULT` (`CTU` zero-shot & `cross_source_validated=false`) |
| **7. `RQ2` Lớp hiếm & `RQ4` Holdout** | `RQ2`: `C2` N=5 (`1.0`), `PostEx` N=39 (`0.8974`), `Cred` N=78 (`0.1410` RF/XGB/IF, `0.0641` AE), `h2_full_confirmed=false`; `RQ4`: `44` holdout (`IF/RF 0.9091`, `XGB 0.7500`, `AE 0.2045`), `unsupervised_ge_0_75_both=false` | `reports/experiments/imbalance/rq2_imbalance_report.json`, `reports/experiments/imbalance/rq2_imbalance_report.md`, `reports/experiments/ml/rq4_unknown_attack_report.json`, `docs/experiments/EXP4_UNKNOWN_ATTACK.md` | `VERIFIED` · `NEGATIVE_RESULT` (`H2=False`, `AE H4=False`) |
| **8. Behavioral Vector 16-D (`RQ3`)** | Simulation 20 phiên/190 cặp: `cos>=0.85` `F1=0.3191`, `cos>=0.95` `F1=0.5556` vs IP `0.0000`, `simulation_hypothesis_met=false`; empirical AIT `#85` `BLOCKED` | `src/network_anomaly/behavioral/vector.py`, `reports/experiments/behavioral/rq3_session_correlation_experiment.json`, `docs/experiments/EXP5_SESSION_CORRELATION.md`, `docs/dataset/AIT_LINKAGE_FEASIBILITY.md` | `SYNTHETIC` · `NEGATIVE_RESULT` (`F1 < 0.85`) · `BLOCKED` (`#85` empirical) |
| **9. Risk Engine, Live Alert (`#137`) & Dry-Run** | Risk `[0..100]`, OOD cap `<= 65.0`; UDP loopback port `51817` (`6/6` flows, `1` alert `84.035` `HIGH` port `445`); Trace `1.0/1.0`; Dry-Run `executed=false` & chặn `RESEARCH_ONLY` | `src/network_anomaly/risk/scoring.py`, `src/network_anomaly/streaming/alert_manager.py`, `src/network_anomaly/api/response_policy.py`, `docs/telemetry/SYNTHETIC_UDP_LOOPBACK_ACCEPTANCE.md`, `reports/acceptance/synthetic_udp_loopback_report.json`, `reports/acceptance/live_gui_alert_synthetic_loopback.png`, `reports/experiments/trace/traceability_evaluation.json` | `SYNTHETIC` (`#137` loopback, Trace) · `BLOCKED` (`#137` router vật lý) · `DEFERRED` (OS firewall `#27`) |
| **10. AES-256-GCM & Key Rotation (`RQ5`, `RQ6`)** | DPAPI fail-closed, `NETFLOW_WRAPPED_DEK_V2`, `plaintext NULL`; `RQ5` giảm exposure `87.5%` (`1200s -> 150.01s`) & blast radius `85.0%` (`40 -> 6`); `RQ6` 256B P95 `13.3 us` (`75,851.2 ops/s`) | `src/network_anomaly/crypto/key_manager.py`, `src/network_anomaly/crypto/encrypted_storage.py`, `src/network_anomaly/crypto/rotation.py`, `reports/experiments/crypto/rq5_rotation_experiment.json`, `reports/benchmarks/crypto_benchmark_report.json` | `VERIFIED` (`RQ6` microbenchmark, unit tests) · `SYNTHETIC` (`RQ5` simulation) |
| **11. Hiệu năng, STRIDE & Governance** | E2E `16.38 events/s` (`Med 61.75ms`), inference `Med 57.64ms`; STRIDE `SR1–SR11`; `DISTRIBUTION_AUTHORIZATION.json` `approved=false`, tách `CC BY 4.0` vs `AIT-LDS-v2.1` `CC BY-NC-SA 4.0`, `git_dirty=true` (`79ebb678`) | `reports/benchmarks/system_performance_benchmark.json`, `docs/benchmarks/SYSTEM_PERFORMANCE.md`, `docs/audits/THREAT_MODEL_V2.md`, `docs/audits/SECURITY_AUDIT_V2.md`, `reports/governance/DISTRIBUTION_AUTHORIZATION.json`, `reports/audits/V2_DISTRIBUTION_GOVERNANCE_REVIEW.md` | `VERIFIED` (CPU benchmark, STRIDE code, license audit) · `BLOCKED` (Public signoff, Clean VM `#73`/`#148`) |
| **12. Kết luận, Blockers & Hướng Phát triển** | Tổng kết phạm vi `v2.0` pilot lab, các hạng mục `BLOCKED`/`DEFERRED` (`#73`, `#148`, `#137`, `#152`, `#128`, `#153`), lộ trình cải tiến | `reports/audits/V2_FINAL_AUDIT.md`, `reports/audits/V2_ISSUE_AC_AUDIT.md`, `docs/ROADMAP_FULL_SYSTEM.md`, `docs/PRESENTATION_OUTLINE.md` | `VERIFIED` (audit trạng thái) · `BLOCKED`/`DEFERRED` (`#73`, `#137`, `#148`, `#152`, `#153`, `#128`) |
