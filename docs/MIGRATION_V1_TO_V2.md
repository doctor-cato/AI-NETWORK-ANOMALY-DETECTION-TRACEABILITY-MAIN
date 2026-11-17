# NetFlow Sentinel v1.0.0 $\to$ v2.0.0 Hard Cutover & Migration Note

> **Tài liệu Migration & Nâng cấp (Issue #80 & Hard Cutover ADR)**
> **Phiên bản:** 2.0.0-hard-cutover
> **Quyết định kiến trúc:** [`docs/adr/ADR-dataset-hard-cutover-v2.md`](adr/ADR-dataset-hard-cutover-v2.md)
> **Script nâng cấp SQLite DB:** `scripts/migrate_v1_to_v2.py`

---

## 1. Vì sao Loại bỏ `NF-UNSW-NB15-v3` (v1) và Thực hiện Hard Cutover?

NetFlow Sentinel v1.0.0 dựa trên bộ dữ liệu `NF-UNSW-NB15-v3` (55 cột nProbe v3, 47 đặc trưng ML). Kiểm toán thực nghiệm trên v1 (`docs/historical/nf_unsw_nb15_v3/`) đã chứng minh ba rào cản nền tảng không thể khắc phục chỉ bằng cách thêm adapter:

1. **Học đường tắt (Shortcut Learning) & Sụp đổ ngoài miền:** Mô hình supervised v1 đạt `F1 ~ 0.9999` nhờ phụ thuộc vào đặc trưng phòng lab `MIN_TTL` / `MAX_TTL` do máy phát lưu lượng IXIA tạo ra, dẫn đến sụp đổ `Recall = 0.0`, `FPR = 38.02%` khi chạy trên hạ tầng khác (`NF-CSE-CIC-IDS2018-v3`).
2. **Bất tương thích Schema thực tế:** Phần lớn các nguồn flow chuẩn doanh nghiệp/nghiên cứu (Tstat, Zeek `conn.log`, NetFlow v9/IPFIX) không cung cấp đủ 47 trường vi mô nProbe v3, dẫn tới trạng thái bị chặn `FEATURE_INCOMPATIBLE` hoặc nguy cơ điền giá trị giả (`zero/median imputation`).
3. **Giới hạn Giấy phép Phân phối:** `NF-UNSW-NB15-v3` chịu ràng buộc giấy phép UQ `454104` (hạn chế thương mại và tái phân phối artifact phái sinh).

Do đó, **NetFlow Sentinel v2** thực hiện **hard cutover**: chuyển toàn bộ manifest, split, preprocessing, báo cáo và script v1 vào lưu trữ chỉ đọc tại `*/historical/nf_unsw_nb15_v3/` và **nghiêm cấm tái sử dụng** trọng số, preprocessor hay ngưỡng quyết định của v1.

---

## 2. Lý do Lựa chọn Nguồn Dữ liệu v2 (AIT Simulation + Real Captured Traffic)

| Nguồn dữ liệu | Vai trò trong v2 | Lý do lựa chọn & Ranh giới |
|---|---|---|
| **AIT NetFlow Data Set v2 (`AIT-NDS-v2`, DOI `10.5281/zenodo.13168643`)** | Primary synthetic NetFlow ML dataset | Sinh từ PCAP của `AIT-LDS-v2.0` trên 8 kịch bản doanh nghiệp độc lập (`fox`, `harrison`, `russellmitchell`, `santos`, `shaw`, `wardbeck`, `wheeler`, `wilson`), cho phép chia tập **scenario-disjoint** chống rò rỉ và giấy phép **CC BY 4.0**. |
| **AIT Log Data Set v2.1 (`AIT-LDS-v2.1`, DOI `10.5281/zenodo.19483937`)** | Application, system, auth, DNS, VPN & audit logs | Cung cấp ngữ cảnh đa nguồn cho Behavioral Vector, Session Correlation, Risk Engine và Trace Engine. Tách biệt phiên bản với `AIT-NDS-v2` (PCAP v2.0); không giả định join trực tiếp nếu chưa chứng minh đồng bộ khóa/timestamp. |
| **AIT Alert Data Set (`AIT-ADS`, DOI `10.5281/zenodo.8263181`)** | Alert aggregation & multi-step alert analysis | Sinh từ `AIT-LDS-v2.0`; dùng cho phân tích tương quan cảnh báo, không coi là benchmark ML độc lập. |
| **CTU-SME-11 (DOI `10.5281/zenodo.7958258`)** | Real captured SME network traffic | Traffic thu thập trên thiết bị thật trong môi trường thực nghiệm SME (11 thiết bị, 7 ngày, CC BY 4.0); cho phép đo lường trung thực mức suy giảm **synthetic-to-real domain shift** (`CTU-Echo`, `CTU-Windows7AD`). |
| **UGR'16 (`https://nesg.ugr.es/nesg-ugr16/`)** | Real ISP traffic validation | Đánh dấu **`BLOCKED`** do cổng NESG trả `HTTP 403` / *Portal en Mantenimiento*; tuyệt đối không tạo dữ liệu giả thay thế. |

---

## 3. Hợp đồng Đặc trưng Mới (`canonical-flow-v2-18`) & Huấn luyện lại 4 Mô hình

- **Hợp đồng `canonical-flow-v2-18` (`src/network_anomaly/data/v2_schema.py`):** Xây dựng thuần túy từ 6 trường luồng hai chiều thực sự tồn tại trên cả Tstat (`AIT-NDS-v2`), Zeek (`CTU-SME-11`) và NetFlow v9/IPFIX (`duration_ms`, `bytes_in`, `bytes_out`, `pkts_in`, `pkts_out`, `protocol_num`) cùng 12 đặc trưng động học luồng suy diễn xác định (`total_bytes`, `total_pkts`, `bytes_in_ratio`, `pkts_in_ratio`, `bytes_per_pkt_in`, `bytes_per_pkt_out`, `bytes_per_sec_in`, `bytes_per_sec_out`, `pkts_per_sec`, `has_response`, `is_tcp`, `is_udp`).
- **Tách biệt nhãn & `taxonomy-v2` (`src/network_anomaly/data/taxonomy.py`):** Không ép `background`/`unknown`/`-` thành `Benign` (`942` dòng unmapped trong `AIT-NDS-v2` và `9,394` dòng unmapped trong `CTU-Win7AD` bị tách khỏi ma trận $X$ và supervised metrics).
- **Retrain 100% từ đầu:** Vì không gian đặc trưng đổi từ `47` $\to$ `18` và tiền xử lý đổi sang `TrainOnlyPreprocessor(scaler_type="asinh_robust")` fit chỉ trên `ait_train` (`1,930,219` flows), cả 4 mô hình (**Random Forest**, **XGBoost**, **Isolation Forest**, **Autoencoder**) đều được huấn luyện lại mới với manifest, threshold hiệu chuẩn trên Validation và SHA-256 riêng (`AI Ready 4/4`).

---

## 4. Ma trận Tương thích & Chính sách Nâng cấp v1.0.0 $\to$ v2.0.0

| Thành phần / Dữ liệu v1.0.0 | Trạng thái v2.0 | Hướng Xử lý / Chuyển đổi | Bằng chứng Kiểm chứng |
|---|---|---|---|
| **Model Binaries & Preprocessor v1** | **`RETIRED / REJECTED`** | Lưu trữ tại `historical/nf_unsw_nb15_v3/`. `ModelRegistry` & `TrainOnlyPreprocessor` **từ chối fail-closed** bất kỳ artifact/manifest v1 nào (không fallback). | `tests/unit/test_v2_migration_guards.py` PASS |
| **CSV Input 55 cột (`NF-UNSW-NB15-v3`)** | **`REJECTED (Fail-Closed)`** | Không còn hỗ trợ suy luận AI trên schema 47 đặc trưng cũ. Người dùng chuyển sang schema `canonical-flow-v2-18` (200 dòng demo mới tại `data/demo/demo_flows.csv`). | `tests/integration/test_four_model_integrity_e2e.py` PASS |
| **SQLite DB (`sentinel.db`)** | **`UPGRADE (Idempotent)`** | Nâng cấp bảng v2 qua `scripts/migrate_v1_to_v2.py` (có sao lưu tự động), giữ nguyên dữ liệu sự cố/khóa không phụ thuộc dataset cũ. | `tests/integration/test_migration_v1_to_v2.py` PASS |
| **Product Core (Tauri 2, Svelte 5, FastAPI, Crypto, Risk, Trace, Behavioral)** | **`PRESERVED`** | Giữ nguyên kiến trúc ứng dụng, loopback auth `X-Sentinel-Session-Token`, AES-256-GCM DPAPI/POSIX keystore, Adaptive Key Rotation, Risk/Trace/Behavioral Engine và CI gates. | `pytest`, `vitest`, `cargo test --lib` PASS |

---

## 5. Hướng dẫn Nâng cấp SQLite Database (Nếu có DB từ v1.0.0)

```powershell
# 1. Xem trước thay đổi schema (dry-run)
.venv\Scripts\python.exe scripts/migrate_v1_to_v2.py --db-path data/sentinel.db --dry-run

# 2. Thực hiện nâng cấp (tự động sao lưu backup trước khi ghi)
.venv\Scripts\python.exe scripts/migrate_v1_to_v2.py --db-path data/sentinel.db
```
