# NetFlow Sentinel v2 — Nguồn dữ liệu, Acquisition, Schema & Quality Gate

> Tài liệu này mô tả hệ thống dữ liệu hiện hành của **NetFlow Sentinel v2**. Nguồn `NF-UNSW-NB15-v3` đã ngừng sử dụng trong toàn bộ active pipeline và được lưu trữ chỉ đọc tại [`docs/historical/nf_unsw_nb15_v3/`](historical/nf_unsw_nb15_v3/).

## 1. Chiến lược Multi-Source Dataset v2

| Mã nguồn | Tên chính thức & Phiên bản | DOI / URL | Vai trò | Trạng thái |
|---|---|---|---|---|
| `ait_nds_v2` | **AIT NetFlow Data Set v2** *(không gọi v2.1)* | [`10.5281/zenodo.13168643`](https://doi.org/10.5281/zenodo.13168643) | Primary synthetic NetFlow ML dataset (tạo từ PCAP của `AIT-LDS-v2.0`, 8 kịch bản, `3,465,342` flows gốc) | `VERIFIED` (CC BY 4.0) |
| `ait_lds_v2_1` | **AIT Log Data Set v2.1** | [`10.5281/zenodo.19483937`](https://doi.org/10.5281/zenodo.19483937) | Application, system, auth, DNS, VPN, audit logs & ground-truth attack steps cho Behavioral Vector, Session Correlation, Trace Engine | `VERIFIED` (CC BY 4.0); tách phiên bản với `AIT-NDS-v2`, **không** tự giả định join trực tiếp |
| `ait_ads` | **AIT Alert Data Set** | [`10.5281/zenodo.8263181`](https://doi.org/10.5281/zenodo.8263181) | Alert aggregation & multi-step alert correlation sinh từ `AIT-LDS-v2.0`; không coi là benchmark ML độc lập | `VERIFIED` (CC BY 4.0) |
| `ctu_sme_11` | **CTU-SME-11** | [`10.5281/zenodo.7958258`](https://doi.org/10.5281/zenodo.7958258) | Real captured SME testbed traffic trên thiết bị thật (`Echo1stGen-1`: `76,073` flows; `Windows7AD-1`: `175,146` labeled + `9,394` unmapped) | `VERIFIED` (CC BY 4.0) |
| `ugr16` | **UGR'16** | `https://nesg.ugr.es/nesg-ugr16/` | Real ISP traffic external validation & domain shift | **`BLOCKED`** (`HTTP 403` / Portal en Mantenimiento; không tạo dữ liệu thay thế) |

Chi tiết provenance, license và SHA-256 được ghi nhận trong [`data/EXTERNAL_DATASETS_PROVENANCE.json`](../data/EXTERNAL_DATASETS_PROVENANCE.json), [`docs/dataset/V2_SOURCE_AUDIT.md`](dataset/V2_SOURCE_AUDIT.md) và [`docs/dataset/AIT_LINKAGE_FEASIBILITY.md`](dataset/AIT_LINKAGE_FEASIBILITY.md).

---

## 2. Layout lưu trữ & Script vận hành

| Thành phần | Đường dẫn |
|---|---|
| Provenance manifest | `data/EXTERNAL_DATASETS_PROVENANCE.json` |
| Dữ liệu raw (ignored bởi Git) | `data/raw/ait_nds_v2/`, `data/raw/ait_lds_v2_1/`, `data/raw/ait_ads/`, `data/raw/ctu_sme_11/` |
| Dữ liệu chuẩn hóa v2 (ignored bởi Git) | `data/processed/v2/` (`train_indices.csv.gz`, `validation_indices.csv.gz`, `test_indices.csv.gz`, `ctu_*.csv.gz`) |
| Demo Validation (200 flows) | `data/demo/demo_flows.csv`, `data/demo/demo_labels.csv`, `data/demo/demo_manifest.json` |
| Báo cáo profile & chất lượng | `docs/dataset/AIT_PROFILE.md`, `docs/dataset/CTU_SME_11_PROFILE.md`, `docs/dataset/QUALITY_GATES.md` |
| Báo cáo split & audit | `reports/splits/v2_split_manifest.json`, `docs/dataset/MULTI_SOURCE_SPLIT_PROTOCOL.md`, `docs/dataset/V2_LEAKAGE_AUDIT.md` |
| Script acquisition & profiling | `scripts/fetch_multi_source_dataset.py`, `scripts/profile_multi_source.py` |
| Script build & split v2 | `scripts/build_v2_dataset_and_split.py`, `scripts/prepare_demo_dataset.py` |

Kiểm tra ranh giới Git (raw/processed không được commit):

```powershell
git check-ignore data/raw/ait_nds_v2 data/processed/v2
.venv\Scripts\python.exe scripts/fetch_multi_source_dataset.py --verify-only
```

---

## 3. Hợp đồng Canonical Flow v2 (`canonical-flow-v2-18`) & Label Taxonomy v2

Định nghĩa chính thức nằm tại `src/network_anomaly/data/v2_schema.py` và `src/network_anomaly/data/taxonomy.py`:

- **18 ML Features (`ML_FEATURE_COLUMNS`):**
  1. **6 Base Observed Flow Fields:** `duration_ms`, `bytes_in`, `bytes_out`, `pkts_in`, `pkts_out`, `protocol_num` (categorical IANA integer code, giữ nguyên không One-Hot Encoding).
  2. **12 Derived Flow-Dynamics Features:** `total_bytes`, `total_pkts`, `bytes_in_ratio`, `pkts_in_ratio`, `bytes_per_pkt_in`, `bytes_per_pkt_out`, `bytes_per_sec_in`, `bytes_per_sec_out`, `pkts_per_sec`, `has_response`, `is_tcp`, `is_udp`.
- **5 Trace Metadata (tách khỏi `X`, dùng cho grouping/Trace Engine):** `timestamp_ms`, `source_ip`, `dest_ip`, `source_port`, `dest_port`.
- **4 Target & Label Tracking (tuyệt đối không đi vào `X`):** `label_binary`, `attack_category`, `raw_label`, `label_status`.
- **5 Provenance Columns:** `source_dataset`, `scenario_or_device`, `flow_id`, `raw_protocol_str`, `probe_source`.
- **Nguyên tắc nhãn (`taxonomy-v2`):**
  - Không bao giờ tự động ép `background`, `unknown`, `nan` hoặc chuỗi rỗng thành `Benign`.
  - Các dòng unmapped được gắn `label_status = "unmapped"` / `attack_category = "Unmapped"` và loại khỏi supervised binary/multiclass metrics (`942` dòng trong `AIT-NDS-v2`, `9,394` dòng trong `CTU-SME-11 Windows7AD`).

---

## 4. Tóm tắt Chất lượng & Chia tập (`v2-scenario-group-purged-v1`)

- **AIT-NDS-v2 (`3,231,215` dòng có nhãn hợp lệ):**
  - **Train (`1,930,219`):** `fox`, `harrison`, `santos`, `wardbeck`, `wilson` — `1,658,795` Benign / `271,424` Attack (`Reconnaissance`: 181,843; `Data_Exfiltration`: 87,268; `Credential_Attack`: 2,104; `Post_Exploitation_Discovery`: 180; `Exploitation_And_C2`: 29).
  - **Validation (`377,704`):** `russellmitchell` — `206,676` Benign / `171,028` Attack (`Reconnaissance`: 155,181; `Data_Exfiltration`: 15,778; `Post_Exploitation_Discovery`: 56; `Credential_Attack`: 11; `Exploitation_And_C2`: 2).
  - **Test (`923,292`):** `shaw`, `wheeler` — `747,610` Benign / `175,682` Attack (`Reconnaissance`: 95,487; `Data_Exfiltration`: 80,075; `Credential_Attack`: 78; `Post_Exploitation_Discovery`: 37; `Exploitation_And_C2`: 5).
  - **Kiểm toán rò rỉ:** `scenario_overlap_count = 0`, `scenario_5tuple_ts_overlap_count = 0`, `status = "PASS"`.
