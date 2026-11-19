# NetFlow Sentinel v2 — 6 Câu hỏi Nghiên cứu (RQ1–RQ6) & External Validation

> Toàn bộ thực nghiệm ML đã được chuyển sang **AIT NetFlow Data Set v2 (`AIT-NDS-v2`)** + **CTU-SME-11** dưới hợp đồng `canonical-flow-v2-18`. Các kết quả cũ trên `NF-UNSW-NB15-v3` nằm trong lưu trữ lịch sử `reports/historical/nf_unsw_nb15_v3/`.

---

## 1. Chi tiết 6 Research Questions (RQ1–RQ6)

### RQ1 — So sánh Hiệu năng Supervised vs Unsupervised trên `AIT-NDS-v2`
- **Dataset:** `AIT-NDS-v2` scenario-disjoint `test` (`shaw`, `wheeler`; `988,805` flows).
- **Trạng thái:** `EXPERIMENTALLY VALIDATED` qua `scripts/generate_model_comparison_report.py` (`reports/experiments/ml/model_comparison_report.json`).
- **Kết quả chính:** `Random Forest` đạt `F1 = 0.9950` (`P = 0.9989`, `R = 0.9911`, `ROC-AUC = 0.9994`), `XGBoost` đạt `F1 = 0.9013` (`P = 0.9989`, `R = 0.8211`, `ROC-AUC = 0.9884`), `Autoencoder` đạt `F1 = 0.5877` (`ROC-AUC = 0.5544`), `Isolation Forest` đạt `F1 = 0.5842` (`ROC-AUC = 0.8330`).

### RQ2 — Mất cân bằng Dữ liệu và Tấn công Hiếm
- **Dataset:** `AIT-NDS-v2` 3 lớp hiếm (< 0.5%): `Credential_Attack` (78 test), `Post_Exploitation_Discovery` (39 test), `Exploitation_And_C2` (5 test).
- **Trạng thái:** `EXPERIMENTALLY VALIDATED` qua `scripts/run_rq2_rare_attack_experiment.py` (`reports/experiments/imbalance/rq2_imbalance_report.json`) — **`h2_full_confirmed = false`**: dù `Post_Exploitation_Discovery` (`0.8974`) và `Exploitation_And_C2` (`1.0000`, N=5) đạt recall cao ở RF/XGB/IF, toàn bộ 5 biến thể vẫn sụt giảm mạnh trên `Credential_Attack` (`0.0641–0.1410` recall).

### RQ3 — Liên kết Phiên Độc lập IP bằng 16-D Behavioral Vector
- **Dataset:** Simulation IP-rotation (`20` phiên / `190` cặp); liên kết thực nghiệm trên `AIT NetFlow Data Set v2` + `AIT-LDS-v2.1` + `AIT-ADS`.
- **Trạng thái:** `SIMULATION` (`simulation_hypothesis_met = false`; `strict cos >= 0.95` đạt `Recall = 1.0`, `Precision = 0.3846`, `F1 = 0.5556`); **Empirical AIT campaign-linkage `BLOCKED`** do chưa có khóa đồng bộ xác minh trực tiếp giữa `AIT-NDS-v2` và `AIT-LDS-v2.1`.

### RQ4 — Phát hiện Họ Tấn công Holdout (`Exploitation_And_C2`, `Post_Exploitation_Discovery`)
- **Dataset:** `AIT-NDS-v2` holdout (loại 100% holdout families khỏi Train & Validation; `44` Test holdout rows, Benign `812,980`, Known Attack `175,781`).
- **Trạng thái:** `EXPERIMENTALLY VALIDATED` qua `scripts/run_rq4_unknown_attack_experiment.py` (`reports/experiments/ml/rq4_unknown_attack_report.json`): `Isolation Forest` đạt Unknown Recall `0.9091` (`FPR = 0.0290`), `Random Forest` đạt `0.9091` (`FPR = 0.0004`), `XGBoost` đạt `0.7500` (`FPR = 0.0003`), `Autoencoder` đạt `0.2045` (`FPR = 0.0276`). **`unsupervised_ge_0_75_both = false`**. Không tuyên bố khả năng phát hiện zero-day tổng quát.

### RQ5 — Adaptive Key Rotation vs Fixed 30-Min Rotation
- **Trạng thái:** `SIMULATION VERIFIED` qua `scripts/run_rq5_rotation_experiment.py` (`reports/experiments/crypto/rq5_rotation_experiment.json`): giảm `87.5%` cửa sổ phơi nhiễm (`20.0m -> 2.5002m`) và giảm `85.0%` blast radius (`40 -> 6` attack records/key).

### RQ6 — Cryptographic Overhead (`AES-256-GCM`) & System Throughput
- **Trạng thái:** `BENCHMARKED` qua `scripts/benchmark_crypto_overhead.py` (`reports/benchmarks/crypto_benchmark_report.json`) và `scripts/benchmark_full_system.py`:
  - `AES-256-GCM`: 256 B encrypt median `9.2 us` / P95 `13.3 us` (`75,851.2 ops/s`); 1024 B median `12.2 us` / P95 `17.3 us` (`59,259.3 ops/s`); 4096 B median `19.7 us` / P95 `29.6 us` (`38,617.1 ops/s`).
  - Full E2E pipeline `4/4 REAL_MODELS` (`runtime_mode = "deployment"`, `ood_gate_status = "FITTED"`, `explicit_expected_sha256`, `--repeats 3`) trên CPU: E2E mean **`16.75 ± 0.11 flow/s`** (`CV = 0.68%`; latest `16.78 flow/s`), median latency **`60,873.45 us`** (`60.87 ms`, `CV = 1.1%`), `dropped = 0`; Vectorized Micro-Batch (`process_batch`, `batch_size=32`) mean **`386.37 ± 12.88 flow/s`** (`CV = 3.33%`; latest `389.91 flow/s`); Replay mean **`399.44 ± 15.47 flow/s`** (`CV = 3.87%`).

---

## 2. Tổng hợp Bảng ánh xạ RQ → Issue → Dataset → Kết quả v2

| RQ | Issue triển khai / đánh giá | Dataset thực thi | Script | Trạng thái kiểm chứng |
|---|---|---|---|---|
| **RQ1** | `#77`, `#94`, `#95`, `#145` | `AIT-NDS-v2` (`ait_test`, `988,805`) | `scripts/generate_model_comparison_report.py` | `EXPERIMENTALLY VALIDATED` (`RF F1=0.9950`, `XGB F1=0.9013`, `AE F1=0.5877`, `IF F1=0.5842`) |
| **RQ2** | `#96`, `#145` | `AIT-NDS-v2` (3 rare classes) | `scripts/run_rq2_rare_attack_experiment.py` | `EXPERIMENTALLY VALIDATED` (`h2_full_confirmed=false`) |
| **RQ3** | `#85`, `#104`, `#145` | Synthetic simulation; `AIT-NDS-v2`/`AIT-LDS-v2.1` | `scripts/run_rq3_session_correlation_experiment.py` | `SIMULATION` · Empirical AIT `BLOCKED` |
| **RQ4** | `#98`, `#145` | `AIT-NDS-v2` holdout (`44` rows) | `scripts/run_rq4_unknown_attack_experiment.py` | `EXPERIMENTALLY VALIDATED` (`IF 0.9091`, `RF 0.9091`, `XGB 0.7500`, `AE 0.2045`) |
| **RQ5** | `#121`, `#125`, `#145` | 60-min discrete simulation | `scripts/run_rq5_rotation_experiment.py` | `SIMULATION VERIFIED` (`-87.5%` exposure, `-85.0%` blast radius) |
| **RQ6** | `#126`, `#145`, `#147` | In-process CPU benchmark | `scripts/benchmark_crypto_overhead.py`, `scripts/benchmark_full_system.py` | `BENCHMARKED & CONFIRMED` (`16.75 flow/s` E2E mean, `386.37 flow/s` Micro-Batch `process_batch(32)`, `399.44 flow/s` Replay, `4/4 REAL_MODELS`, 256B P95 `13.3 us`) |
| **Cross-Source** | `#97`, `#145` | `CTU-SME-11` (`Echo` + `Win7AD`) & `UGR'16` | `scripts/run_ctu_cross_source_eval.py` | `CTU VALIDATED` (`IF Echo F1=0.8853`, `Win7AD RF/XGB AUC=0.8392/0.6978`, Exps A–E) · `UGR'16 BLOCKED` |
