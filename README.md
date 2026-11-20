# NetFlow Sentinel v2 — AI-Based Multi-Source Network Anomaly Detection & Traceability System

**Phát hiện lưu lượng mạng bất thường đa nguồn với hợp đồng 18 đặc trưng chuẩn hóa (`canonical-flow-v2-18`), tiền xử lý chống rò rỉ train-only và truy vết SHA-256.**

**Rust / Tauri 2 + Svelte 5** Desktop ↔ **Python FastAPI / PyInstaller Sidecar + SQLite** ↔ **4 Mô hình AI v2** huấn luyện lại từ đầu trên **AIT NetFlow Data Set v2 (AIT-NDS-v2)** và đánh giá chéo trên lưu lượng thu thập thực tế **CTU-SME-11**.

[![CI](https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN/actions/workflows/ci.yml/badge.svg)](https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/Python-%3E%3D3.11-3776AB)](pyproject.toml)
[![License: Apache-2.0](https://img.shields.io/badge/code-Apache--2.0-blue)](LICENSE)

> [!IMPORTANT]
> **Hard Cutover sang NetFlow Sentinel v2 (nhánh `feat/v2-integration` / Draft PR #156):**
> - **Loại bỏ hoàn toàn `NF-UNSW-NB15-v3`** và hợp đồng 47 đặc trưng cũ khỏi active pipeline, preprocessor, model registry, API, desktop UI và CI. Toàn bộ artifact/tài liệu v1 được lưu trữ chỉ đọc tại [`data/historical/nf_unsw_nb15_v3/`](data/historical/nf_unsw_nb15_v3/), [`docs/historical/nf_unsw_nb15_v3/`](docs/historical/nf_unsw_nb15_v3/), [`scripts/historical/nf_unsw_nb15_v3/`](scripts/historical/nf_unsw_nb15_v3/), và [`reports/historical/nf_unsw_nb15_v3/`](reports/historical/nf_unsw_nb15_v3/).
> - **Không fallback về v1:** `ModelRegistry`, `InferencePipeline` và `desktop_csv` kiểm tra fail-closed `feature_contract_version == "canonical-flow-v2-18"`, `dataset_sha256`, `split_manifest_sha256` và `preprocessor_sha256`.
> - **Phân định trạng thái nguồn dữ liệu:** `AIT-NDS-v2` (CC BY 4.0) và `CTU-SME-11` (CC BY 4.0) đã tải, kiểm tra checksum và đánh giá thực tế; **`UGR'16` ở trạng thái `BLOCKED`** (cổng chính thức NESG trả `HTTP 403` / *"Portal en Mantenimiento"*) và không dùng dữ liệu thay thế giả lập.

**Điều hướng nhanh:**
- **Dữ liệu & Kiến trúc v2:** [Dataset Strategy (`docs/DATASET.md`)](docs/DATASET.md) · [Feature Contract v2 (`docs/CANONICAL_SECURITY_EVENT_V2.md`)](docs/CANONICAL_SECURITY_EVENT_V2.md) · [Kiến trúc Hệ thống (`docs/ARCHITECTURE.md`)](docs/ARCHITECTURE.md) · [Kiến trúc v2 (`docs/ARCHITECTURE_V2.md`)](docs/ARCHITECTURE_V2.md)
- **Thực nghiệm & Đánh giá:** [So sánh 4 Model (`docs/experiments/FOUR_MODEL_COMPARISON.md`)](docs/experiments/FOUR_MODEL_COMPARISON.md) · [Cross-Source CTU-SME-11 (`docs/experiments/CTU_CROSS_SOURCE_EVAL.md`)](docs/experiments/CTU_CROSS_SOURCE_EVAL.md) · [6 Câu hỏi Nghiên cứu (`docs/RESEARCH_QUESTIONS.md`)](docs/RESEARCH_QUESTIONS.md)
- **Cài đặt, Vận hành & Kiểm thử:** [Cài đặt Windows (`docs/WINDOWS_INSTALLATION.md`)](docs/WINDOWS_INSTALLATION.md) · [Reproducibility (`docs/REPRODUCIBILITY.md`)](docs/REPRODUCIBILITY.md) · [Testing (`docs/TESTING.md`)](docs/TESTING.md) · [API Contract (`reports/api/API_CONTRACT.md`)](reports/api/API_CONTRACT.md)

---

## 1. Tổng quan & Chiến lược Dữ liệu v2

NetFlow Sentinel là nền tảng nghiên cứu phát hiện bất thường mạng có khả năng kiểm toán, kết hợp **mô hình ML trên NetFlow**, **Behavioral Vector 16-D**, **Risk Engine**, **Trace Engine / Attack Timeline**, và **kho chứng cứ mã hóa AES-256-GCM với Adaptive Key Rotation**.

### Nguồn dữ liệu v2

| Nguồn | DOI / URL | Vai trò trong NetFlow Sentinel v2 | Giấy phép & Trạng thái |
|---|---|---|---|
| **AIT NetFlow Data Set v2 (`AIT-NDS-v2`)** | `10.5281/zenodo.13168643` (dẫn xuất từ PCAP `AIT-LDS-v2.0`) | Dataset huấn luyện ML chính (`3,465,342` flows gốc; `3,464,400` flows có nhãn chuẩn hóa + `942` unmapped loại riêng) | **CC BY 4.0 — VERIFIED** |
| **AIT Log Data Set v2.1 (`AIT-LDS-v2.1`)** | `10.5281/zenodo.19483937` | Application/system/auth/DNS/VPN/audit logs cho Behavioral Vector, Session Correlation, Trace Engine | **CC BY-NC-SA 4.0 — VERIFIED** (nghiên cứu cục bộ, không nhúng vào trọng số ML/demo; tách version với `AIT-NDS-v2`) |
| **AIT Alert Data Set (`AIT-ADS`)** | `10.5281/zenodo.8263181` | Alert aggregation & multi-step alert correlation tạo từ `AIT-LDS-v2.0`; **không** dùng làm benchmark ML độc lập | **CC BY 4.0 — VERIFIED** |
| **CTU-SME-11** | `10.5281/zenodo.7958258` (record `7958259`) | Lưu lượng thu thập thực tế trên thiết bị SME thật (`Honeypot-Assistant-Amazon-Echo1stGen-1`: `76,073` flows; `Experiment-VM-Microsoft-Windows7AD-1`: `175,146` flows có nhãn + `9,394` unmapped) | **CC BY 4.0 — VERIFIED** |
| **UGR'16** | `https://nesg.ugr.es/nesg-ugr16/` | Real ISP traffic external validation & domain-shift | **`BLOCKED`** (HTTP 403 / Portal en Mantenimiento; không tải được, không thay thế) |

**Ranh giới khoa học:** Đây là **đồ án nghiên cứu học thuật**, không phải enterprise SOC production hay IPS chặn tường lửa tự động. Security Dry-Run luôn chạy với `executed = false`; đánh giá zero-shot từ synthetic `AIT-NDS-v2` sang thực tế `CTU-SME-11` cho thấy suy giảm mạnh ở mô hình cây có giám sát (chi tiết bên dưới).

---

## 2. Hợp đồng Đặc trưng (`canonical-flow-v2-18`), Split & Tiền xử lý

```mermaid
flowchart LR
    A["Multi-Source Flow CSV<br/>(canonical-flow-v2-18: 18 ML Features)"] --> B["OOD, Taxonomy & Provenance Gate<br/>(unmapped/background không ép thành Benign)"]
    B --> C["TrainOnlyPreprocessor<br/>(asinh_robust + train median/mode, SHA-256 Verified)"]
    C --> D["4 Verified v2 Models (.joblib)<br/>RF · XGBoost · Isolation Forest · Autoencoder"]
    D --> E["FastAPI Sidecar (127.0.0.1)<br/>Behavioral + Risk + Trace + AES-256-GCM + SQLite"]
    E <--> F["Rust / Tauri 2 + Svelte 5<br/>Desktop UI (AI Ready 4/4)"]
```

- **18 đặc trưng ML (`canonical-flow-v2-18`):** `duration_ms`, `bytes_in`, `bytes_out`, `pkts_in`, `pkts_out`, `protocol_num`, `total_bytes`, `total_pkts`, `bytes_in_ratio`, `pkts_in_ratio`, `bytes_per_pkt_in`, `bytes_per_pkt_out`, `bytes_per_sec_in`, `bytes_per_sec_out`, `pkts_per_sec`, `has_response`, `is_tcp`, `is_udp`. Tách biệt tuyệt đối khỏi 5 cột trace metadata (`timestamp_ms`, `source_ip`, `dest_ip`, `source_port`, `dest_port`), 5 cột provenance (`source_dataset`, `scenario_or_device`, `flow_id`, `raw_protocol_str`, `probe_source`) và 4 cột target/label (`label_binary`, `attack_category`, `raw_label`, `label_status`).
- **Scenario-Disjoint Split (`v2-scenario-group-purged-v1`):**
  - **Train (`2,097,891` flows):** `fox`, `harrison`, `santos`, `wardbeck`, `wilson` (`1,825,866` Benign / `272,025` Attack).
  - **Validation (`377,704` flows):** `russellmitchell` (`206,676` Benign / `171,028` Attack).
  - **Held-out Test (`988,805` flows):** `shaw`, `wheeler` (`812,980` Benign / `175,825` Attack).
  - **Leakage audit:** `0` scenario overlap, `0` `(scenario, 5-tuple, ts_bucket)` overlap.
- **Tiền xử lý (`asinh_robust`):** Fit duy nhất trên `2,097,891` dòng Train (`0866dec7252d36d3f2bb2becddf266787cc49ddf19306a8e003ba1e951cf51a7`), biến đổi `arcsinh` + `RobustScaler` cho 17 biến định lượng (kèm `MIN_BOUNDED_SCALE_FLOOR = 0.25` cho 5 biến bounded), giữ nguyên `protocol_num` dạng số nguyên rời rạc, giữ dòng `duration_ms == 0.0`.

---

## 3. Kết quả Thực nghiệm v2 Đã Kiểm chứng

| Mô hình | Nguồn ngưỡng & Giao thức | AIT-Test (`988,805` flows) | CTU-Echo Real (`76,073` flows) | CTU-Win7AD Real (`175,146` flows) |
|---|---|---|---|---|
| **Random Forest** | Supervised (`balanced_subsample, leaf=5`, `th = 0.50`) | `F1 = 0.9950`, `P = 0.9989`, `R = 0.9911`, `FPR = 0.000246`, `ROC-AUC = 0.9994` | `F1 = 0.0474`, `R = 0.0264`, `FPR = 0.081069`, `ROC-AUC = 0.6137` | `F1 = 0.0712`, `R = 0.5412`, `FPR = 0.160755`, `ROC-AUC = 0.8392` |
| **XGBoost** | Supervised (`th = 0.50`) | `F1 = 0.9013`, `P = 0.9989`, `R = 0.8211`, `FPR = 0.000198`, `ROC-AUC = 0.9884` | `F1 = 0.1436`, `R = 0.0832`, `FPR = 0.069980`, `ROC-AUC = 0.7017` | `F1 = 0.0738`, `R = 0.5623`, `FPR = 0.161131`, `ROC-AUC = 0.6978` |
| **Isolation Forest** | Benign-only (`th = 0.031268`, Val `target_fpr = 0.05`) | `F1 = 0.5842`, `P = 0.7775`, `R = 0.4678`, `FPR = 0.028952`, `ROC-AUC = 0.8330` | `F1 = 0.8853`, `P = 0.8001`, `R = 0.9908`, `FPR = 0.229182`, `ROC-AUC = 0.9571` | `F1 = 0.0464`, `R = 0.9760`, `FPR = 0.472185`, `ROC-AUC = 0.7649` |
| **Autoencoder** | Benign-only std (`th = 0.000467`, Val `target_fpr = 0.05`) | `F1 = 0.5877`, `P = 0.7860`, `R = 0.4693`, `FPR = 0.027637`, `ROC-AUC = 0.5544` | `F1 = 0.7325`, `P = 0.5783`, `R = 0.9990`, `FPR = 0.674634`, `ROC-AUC = 0.7810` | `F1 = 0.0326`, `R = 0.9921`, `FPR = 0.692521`, `ROC-AUC = 0.7280` |

**Phát hiện quan trọng từ đánh giá thực tế `CTU-SME-11` (`reports/experiments/ml/ctu_cross_source_eval.json`):**
- Mô hình cây giám sát (`RF`, `XGBoost`) đạt `F1 = 0.9950` và `0.9013` trên kịch bản testbed mới của `AIT-NDS-v2`, cải thiện ranking zero-shot trên `CTU-SME-11` sau sửa L4 bytes/UDP ms (`CTU-Win7AD RF ROC-AUC = 0.8392`, `CTU-Echo XGB ROC-AUC = 0.7017`), nhưng `F1` zero-shot tại ngưỡng `0.50` vẫn thấp (`0.0474` / `0.1436`) do chênh lệch phân phối `duration_ms`, `bytes_in`, `bytes_out` giữa testbed mô phỏng và SME thật.
- Khi bổ sung thích nghi miền trên thiết bị khác (`AIT-Train + CTU-Echo` → unseen `CTU-Win7AD`), `RF` và `XGB` đạt `ROC-AUC` lần lượt `0.8280` và `0.8465` (recall `0.6428` / `0.6340`, FPR `0.1438` / `0.1425`) còn `Autoencoder` đạt `ROC-AUC = 0.9520`; khi huấn luyện theo trục thời gian ngay trong `CTU-Echo` (`2023-02-20..24` → `2023-02-25..26`), `RF` đạt `F1 = 0.9634` (`FPR = 0.0011`).

---

## 4. Hướng dẫn Lập trình viên (Developer Guide)

Yêu cầu: Python `>=3.11` (CI: `3.11`, `3.12`; runtime khớp `requirements-runtime.txt`), Node.js `22+`, Rust stable (`cargo`, `rustfmt`, `clippy`). Raw dataset lớn và `.joblib` model binaries nằm ngoài Git.

```powershell
# 1. Thiết lập môi trường Python
git clone https://github.com/doctor-cato/AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN.git
cd AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[dev]"

# 2. Kiểm tra nền tảng, dữ liệu v2, artifact, OpenAPI và test suite
.venv\Scripts\python.exe scripts/check_environment.py
.venv\Scripts\python.exe scripts/fetch_multi_source_dataset.py --verify-only
.venv\Scripts\python.exe scripts/verify_companion_artifacts.py
.venv\Scripts\python.exe scripts/export_openapi_spec.py --check
.venv\Scripts\python.exe scripts/check_desktop_version.py --check
.venv\Scripts\python.exe -m pytest tests -q
.venv\Scripts\python.exe -m ruff check src scripts tests
.venv\Scripts\python.exe -m black --check src scripts tests
git diff --check
```

Để tái lập pipeline dữ liệu, tiền xử lý, huấn luyện 4 model v2 và sinh toàn bộ báo cáo thực nghiệm, xem [docs/REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md) và [docs/TESTING.md](docs/TESTING.md).

---

## 5. Cấu trúc thư mục

```text
.
├── desktop/               # Rust Tauri 2 (src-tauri) + Svelte 5 UI
├── src/network_anomaly/   # data (v2_schema, taxonomy, split), preprocessing, models, behavioral, risk, trace, crypto, streaming, ingestion, inference, api
├── scripts/               # fetch_multi_source_dataset, profile_multi_source, build_v2_dataset_and_split, train_*, run_ctu_cross_source_eval, verify_companion_artifacts
├── tests/                 # unit, contract, integration + historical/nf_unsw_nb15_v3/
├── docs/                  # v2 documentation + docs/historical/nf_unsw_nb15_v3/
├── data/                  # EXTERNAL_DATASETS_PROVENANCE.json, demo/, historical/nf_unsw_nb15_v3/; raw & processed bị gitignore
├── reports/               # schema, quality, splits, preprocessing, models, experiments, benchmarks, api, governance + historical/
├── artifacts/             # .gitkeep; preprocessor & 4 model .joblib bị gitignore
└── .github/workflows/     # ci.yml, lint-audit.yml, release.yml
```

---

## 6. Giấy phép & Ghi nhận nguồn

- **Mã nguồn:** [Apache License 2.0](LICENSE) (giữ nguyên không thay đổi).
- **Datasets v2:** `AIT-NDS-v2` (`10.5281/zenodo.13168643`), `AIT-ADS` (`10.5281/zenodo.8263181`) và `CTU-SME-11` (`10.5281/zenodo.7958258`) phát hành theo **CC BY 4.0**; `AIT-LDS-v2.1` (`10.5281/zenodo.19483937`) phát hành theo **CC BY-NC-SA 4.0**. `UGR'16` ở trạng thái `BLOCKED`.
- **Kiểm kê giấy phép & Lịch sử:** Xem [`NOTICE`](NOTICE), [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md), [`reports/governance/DISTRIBUTION_AUTHORIZATION.json`](reports/governance/DISTRIBUTION_AUTHORIZATION.json), và lưu trữ v1 tại [`docs/historical/nf_unsw_nb15_v3/`](docs/historical/nf_unsw_nb15_v3/).
