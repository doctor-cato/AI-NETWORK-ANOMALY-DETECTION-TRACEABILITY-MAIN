# Báo Cáo Thẩm Định Độc Lập 6 Câu Hỏi Nghiên Cứu (RQ1–RQ6 Validation — NetFlow Sentinel v2)

**Trạng thái:** **`EMPIRICALLY EXECUTED ON AIT-NDS-V2 & CTU-SME-11 (RQ1, RQ2, RQ4, Cross-Source) · SIMULATION (RQ3, RQ5) · BENCHMARKED (RQ6) · UGR'16 & AIT CROSS-DATASET LINKAGE BLOCKED`**

---

## 1. Bảng Ma Trận Đánh Giá Thực Tế (Không suy diễn, trích từ JSON outputs)

| Mã RQ | Câu hỏi Nghiên cứu | Kết quả Kiểm chứng Thực tế (v2) | Bằng chứng Artifact |
|---|---|---|---|
| **RQ1** | So sánh 4 họ mô hình trên `canonical-flow-v2-18`? | **PARTIALLY CONFIRMED:** Supervised (`RF F1=0.9950`, `XGB F1=0.9013`) vượt unsupervised (`AE F1=0.5877`, `IF F1=0.5842`) trên `AIT-Test` (`988,805` dòng); trên `CTU-SME-11` zero-shot `RF/XGB ROC-AUC` đạt `0.6137/0.7017` (`Echo`) & `0.8392/0.6978` (`Win7AD`) nhưng F1 tại ngưỡng `0.5` vẫn thấp (`0.0474/0.1436`), trong khi `IF` đạt `F1=0.8853` trên `CTU-Echo`. | [`reports/experiments/ml/model_comparison_report.json`](../../reports/experiments/ml/model_comparison_report.json), [`reports/experiments/ml/ctu_cross_source_eval.json`](../../reports/experiments/ml/ctu_cross_source_eval.json) |
| **RQ2** | Hiệu năng trên các lớp tấn công hiếm (< 0.5%)? | **`h2_full_confirmed = false`:** `Post_Exploitation_Discovery` (39 dòng) đạt Recall `0.8974` (RF/XGB/IF) và `Exploitation_And_C2` `1.0000` (N=5), nhưng `Credential_Attack` (78 dòng test) chỉ đạt Recall `0.1410` (RF/XGB/IF), `0.0641` (AE). | [`reports/experiments/imbalance/rq2_imbalance_report.json`](../../reports/experiments/imbalance/rq2_imbalance_report.json) |
| **RQ3** | Tương quan phiên độc lập IP bằng Behavioral Vector 16-D? | **`SIMULATION ONLY` (`simulation_hypothesis_met = false`) · Empirical AIT `BLOCKED`:** Cosine `>=0.85` đạt `F1=0.3191` (`P=0.1899`, `R=1.0`, `FalseLink=0.80`); `>=0.95` đạt `F1=0.5556` (`FalseLink=0.30`). Thiếu khóa nối thực nghiệm đã xác minh giữa `AIT-NDS-v2` và `AIT-LDS-v2.1`. | [`reports/experiments/behavioral/rq3_session_correlation_experiment.json`](../../reports/experiments/behavioral/rq3_session_correlation_experiment.json) |
| **RQ4** | Phát hiện họ tấn công Holdout (`Exploitation_And_C2`, `Post_Exploitation_Discovery`)? | **`unsupervised_ge_0_75_both = false`:** Trên `44` dòng holdout Test: `IF` Recall `0.9091` (FPR `0.0290`), `RF` Recall `0.9091` (FPR `0.0004`), `XGB` Recall `0.7500` (FPR `0.0003`), `AE` Recall `0.2045` (FPR `0.0276`). Chỉ phản ánh holdout trong nội bộ `AIT-NDS-v2`. | [`reports/experiments/ml/rq4_unknown_attack_report.json`](../../reports/experiments/ml/rq4_unknown_attack_report.json) |
| **RQ5** | Giảm phơi nhiễm khóa của Adaptive Key Rotation? | **`SIMULATION VERIFIED` (`hypothesis_confirmed = true`):** Max Exposure giảm `87.5%` (`20.0m -> 2.5002m`), Blast Radius giảm `85.0%` (`40 -> 6` attack records/key). | [`reports/experiments/crypto/rq5_rotation_experiment.json`](../../reports/experiments/crypto/rq5_rotation_experiment.json) |
| **RQ6** | Chi phí AES-256-GCM & E2E Throughput? | **`BENCHMARKED & CONFIRMED`:** AES-256-GCM 256B = `72,177.2 ops/s` (median `8.8 us`, P95 `13.3 us`); 1024B P95 = `11.4 us` (`74,807.5 ops/s`); 4096B P95 = `38.4 us` (`36,351.0 ops/s`). E2E single-event (4 mô hình thật): `16.75 events/s` (median `60.55 ms`); `process_batch(32)` micro-batch: **`386.37 flow/s`**; replay mode: **`399.44 flow/s`**. | [`reports/benchmarks/crypto_benchmark_report.json`](../../reports/benchmarks/crypto_benchmark_report.json), [`reports/benchmarks/system_performance_benchmark.json`](../../reports/benchmarks/system_performance_benchmark.json) |

> **Log đối chiếu SHA-256 độc lập (`#145 AC2`):** [`reports/experiments/validation/rq_independent_rerun_log.json`](../../reports/experiments/validation/rq_independent_rerun_log.json)

---

## 2. Giới hạn Khoa học Bắt buộc

1. **Synthetic-to-Real Domain Shift (`CTU-SME-11`):** Kết quả trên `AIT-Test` không đảm bảo hiệu năng ngoài mạng thật; `RF` và `XGBoost` mất recall zero-shot trên `CTU-SME-11` do dịch chuyển phân phối `duration_ms`, `bytes_in`, `bytes_out`.
2. **`UGR'16` External ISP Validation `BLOCKED`:** Máy chủ chính thức trả `HTTP 403` / Portal en Mantenimiento.
3. **Simulation vs Empirical (`RQ3`, `RQ5`):** Các kết quả xoay vòng khóa và tương quan IP chưa thay thế kiểm thử vận hành dài hạn trên hệ thống doanh nghiệp.
