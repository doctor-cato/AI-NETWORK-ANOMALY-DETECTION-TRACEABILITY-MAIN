# NetFlow Sentinel v2 — 6 Câu hỏi Nghiên cứu (RQ1–RQ6) & External Validation

> Toàn bộ thực nghiệm ML đã được chuyển sang **AIT NetFlow Data Set v2 (`AIT-NDS-v2`)** + **CTU-SME-11** dưới hợp đồng `canonical-flow-v2-18`. Các kết quả cũ trên `NF-UNSW-NB15-v3` nằm trong lưu trữ lịch sử `reports/historical/nf_unsw_nb15_v3/`.

---

## 1. Chi tiết 6 Research Questions (RQ1–RQ6)

### RQ1 — So sánh Hiệu năng Supervised vs Unsupervised trên `AIT-NDS-v2`
- **Dataset:** `AIT-NDS-v2` scenario-disjoint `test` (`shaw`, `wheeler`; `923,292` flows).
- **Trạng thái:** `EXPERIMENTALLY VALIDATED` qua `scripts/generate_model_comparison_report.py` (`reports/experiments/ml/model_comparison_report.json`).
- **Kết quả chính:** `Random Forest` đạt `F1 = 0.8997` (`P = 0.9988`, `R = 0.8185`, `ROC-AUC = 0.9996`), `XGBoost` đạt `F1 = 0.8910` (`P = 0.9988`, `R = 0.8042`, `ROC-AUC = 0.9786`), `Autoencoder` đạt `F1 = 0.5788` (`ROC-AUC = 0.7886`), `Isolation Forest` đạt `F1 = 0.5766` (`ROC-AUC = 0.7753`).

### RQ2 — Mất cân bằng Dữ liệu và Tấn công Hiếm
- **Dataset:** `AIT-NDS-v2` 3 lớp hiếm (< 0.5%): `Credential_Attack` (78 test), `Post_Exploitation_Discovery` (37 test), `Exploitation_And_C2` (5 test).
- **Trạng thái:** `EXPERIMENTALLY VALIDATED` qua `scripts/run_rq2_rare_attack_experiment.py` (`reports/experiments/imbalance/rq2_imbalance_report.json`) — **`h2_full_confirmed = false`**: dù `Post_Exploitation_Discovery` (`0.9459`) và `Exploitation_And_C2` (`1.0000`, N=5) đạt recall cao ở RF/XGB/IF, toàn bộ 5 mô hình đều sụt giảm mạnh trên `Credential_Attack` (`0.0641–0.1667` recall).

### RQ3 — Liên kết Phiên Độc lập IP bằng 16-D Behavioral Vector
- **Dataset:** Simulation IP-rotation (`20` phiên / `190` cặp); liên kết thực nghiệm trên `AIT NetFlow Data Set v2` + `AIT-LDS-v2.1` + `AIT-ADS`.
- **Trạng thái:** `SIMULATION` (`simulation_hypothesis_met = false`; `strict cos >= 0.95` đạt `Recall = 1.0`, `Precision = 0.3846`, `F1 = 0.5556`); **Empirical AIT campaign-linkage `BLOCKED`** do chưa có khóa đồng bộ xác minh trực tiếp giữa `AIT-NDS-v2` và `AIT-LDS-v2.1`.

### RQ4 — Phát hiện Họ Tấn công Holdout (`Exploitation_And_C2`, `Post_Exploitation_Discovery`)
- **Dataset:** `AIT-NDS-v2` holdout (`209` Train và `58` Val rows bị loại hoàn toàn; `42` Test holdout rows).
- **Trạng thái:** `EXPERIMENTALLY VALIDATED` qua `scripts/run_rq4_unknown_attack_experiment.py` (`reports/experiments/ml/rq4_unknown_attack_report.json`): `Isolation Forest` đạt Unknown Recall `0.9524` (`40/42`, FPR `0.0376`), `RF` & `XGB` đạt `0.8333` (`35/42`), `Autoencoder` đạt `0.2143` (`9/42`). **`unsupervised_ge_0_75_both = false`**. Không tuyên bố khả năng phát hiện zero-day tổng quát.

### RQ5 — Adaptive Key Rotation vs Fixed 30-Min Rotation
- **Trạng thái:** `SIMULATION VERIFIED` qua `scripts/run_rq5_rotation_experiment.py` (`reports/experiments/crypto/rq5_rotation_experiment.json`): giảm `87.5%` cửa sổ phơi nhiễm (`20.0m -> 2.5002m`) và giảm `85.0%` blast radius (`40 -> 6` attack records/key).

### RQ6 — Cryptographic Overhead (`AES-256-GCM`) & System Throughput
- **Trạng thái:** `BENCHMARKED` qua `scripts/benchmark_crypto_overhead.py` (`reports/benchmarks/crypto_benchmark_report.json`) và `scripts/benchmark_full_system.py`:
  - `AES-256-GCM`: 256 B encrypt median `11.9 us` / P95 `38.8 us` (`43,806.2 ops/s`); 1024 B median `11.5 us` / P95 `28.0 us` (`52,903.8 ops/s`); 4096 B median `27.4 us` / P95 `54.3 us` (`26,661.0 ops/s`).
  - Full E2E pipeline 4 mô hình thật trên CPU: `10.78 events/s` (median `90.43 ms/event`, 0 dropped events).

---

## 2. Tổng hợp Bảng ánh xạ RQ → Dataset → Kết quả v2

| RQ | Dataset thực thi | Script | Trạng thái kiểm chứng |
|---|---|---|---|
| **RQ1** | `AIT-NDS-v2` (`ait_test`, `923,292`) | `scripts/generate_model_comparison_report.py` | `EXPERIMENTALLY VALIDATED` (`RF F1=0.8997`, `XGB F1=0.8910`, `AE F1=0.5788`, `IF F1=0.5766`) |
| **RQ2** | `AIT-NDS-v2` (3 rare classes) | `scripts/run_rq2_rare_attack_experiment.py` | `EXPERIMENTALLY VALIDATED` (`h2_full_confirmed=false`) |
| **RQ3** | Synthetic simulation; `AIT-NDS-v2`/`AIT-LDS-v2.1` | `scripts/run_rq3_session_correlation_experiment.py` | `SIMULATION` · Empirical AIT `BLOCKED` |
| **RQ4** | `AIT-NDS-v2` holdout (`42` rows) | `scripts/run_rq4_unknown_attack_experiment.py` | `EXPERIMENTALLY VALIDATED` (`IF 0.9524`, `RF/XGB 0.8333`, `AE 0.2143`) |
| **RQ5** | 60-min discrete simulation | `scripts/run_rq5_rotation_experiment.py` | `SIMULATION VERIFIED` (`-87.5%` exposure, `-85.0%` blast radius) |
| **RQ6** | In-process CPU benchmark | `scripts/benchmark_crypto_overhead.py` | `BENCHMARKED & CONFIRMED` |
| **Cross-Source** | `CTU-SME-11` (`Echo` + `Win7AD`) & `UGR'16` | `scripts/run_ctu_cross_source_eval.py` | `CTU VALIDATED` (`IF Echo F1=0.8527`, `RF/XGB zero-shot ~0.00`) · `UGR'16 BLOCKED` |
