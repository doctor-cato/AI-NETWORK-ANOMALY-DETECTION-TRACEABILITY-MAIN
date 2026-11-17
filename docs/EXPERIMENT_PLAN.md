# Kế hoạch Thực nghiệm — NetFlow Sentinel v2

## 1. Giả thuyết Khoa học (H1–H6)

- **H1 (RQ1):** Trên phân vùng scenario-disjoint `AIT-Test`, mô hình giám sát (`Random Forest`, `XGBoost`) đạt F1 cao hơn mô hình không giám sát (`Isolation Forest`, `Autoencoder`), nhưng nhạy với chênh lệch phân phối khi chuyển miền sang traffic thực tế `CTU-SME-11`.
- **H2 (RQ2):** Tác động mất cân bằng lớp làm suy giảm mạnh Recall trên các lớp hiếm (`Credential_Attack`, `Post_Exploitation_Discovery`, `Exploitation_And_C2`) nếu chỉ dựa vào overall accuracy; không dùng SMOTE lên Validation/Test.
- **H3 (RQ3):** Behavioral Vector chuẩn hóa 16-D cho phép liên kết các phiên cùng thực thể khi IP xoay vòng (`SIMULATION`), tách biệt với bài toán empirical AIT linkage hiện còn `BLOCKED`.
- **H4 (RQ4):** Khi holdout hoàn toàn hai họ tấn công hiếm (`Exploitation_And_C2`, `Post_Exploitation_Discovery`) khỏi Train/Val, các mô hình được đo trung thực tỷ lệ phát hiện holdout mà không đánh đồng với zero-day thực tế.
- **H5 (RQ5):** Adaptive Key Rotation theo Risk Score ($\ge 85$) giảm $\ge 70\%$ cửa sổ phơi nhiễm khóa so với lịch cố định 30 phút.
- **H6 (RQ6):** Mã hóa AES-256-GCM đạt P95 $\le 500\,\mu s$/event và thông lượng $\ge 5.000$ ops/s trên CPU máy trạm.

---

## 2. Protocol & Test Lock

- **Feature Contract:** `canonical-flow-v2-18` (18 ML features), loại 5 trace metadata và 4 target columns khỏi `X`.
- **Split:** `v2-scenario-group-purged-v1` (Train `1,930,219` / Validation `377,704` / Test `923,292`).
- **Preprocessing:** `TrainOnlyPreprocessor(scaler_type="asinh_robust")` fit chỉ trên `ait_train`, SHA-256 `d33dfe09630687f825d7e4cfa604001c3e091560538059da2eb397b49f44bc32`.
- **Random Seed:** `42`.
- **Test Lock:** Tuyệt đối không dùng `ait_test` hay `CTU-SME-11` để fit imputer/scaler, chọn hyperparameter hay calibrate threshold.

---

## 3. Danh mục Thực nghiệm v2

| Mã | Tên thực nghiệm | Script thực thi | Báo cáo đầu ra |
|---|---|---|---|
| **Exp1 (RQ1)** | 4-Model Benchmark trên `AIT-Test` | `scripts/generate_model_comparison_report.py` | `reports/experiments/ml/model_comparison_report.json`, `docs/experiments/FOUR_MODEL_COMPARISON.md` |
| **Exp2 (RQ2)** | Class Imbalance & Rare Attacks | `scripts/run_rq2_rare_attack_experiment.py` | `reports/experiments/imbalance/rq2_imbalance_report.json`, `.md` |
| **Exp3 (RQ3)** | IP-Independent Session Correlation | `scripts/run_rq3_session_correlation_experiment.py` | `reports/experiments/behavioral/rq3_session_correlation_experiment.json`, `docs/experiments/EXP5_SESSION_CORRELATION.md` |
| **Exp4 (RQ4)** | Unknown Attack Holdout | `scripts/run_rq4_unknown_attack_experiment.py` | `reports/experiments/ml/rq4_unknown_attack_report.json`, `docs/experiments/EXP4_UNKNOWN_ATTACK.md` |
| **Exp5 (RQ5)** | Adaptive Key Rotation Simulation | `scripts/run_rq5_rotation_experiment.py` | `reports/experiments/crypto/rq5_rotation_experiment.json`, `.md` |
| **Exp6 (RQ6)** | AES-256-GCM Overhead Benchmark | `scripts/benchmark_crypto_overhead.py` | `reports/benchmarks/crypto_benchmark_report.json`, `.md` |
| **Cross-Source** | Real Capture `CTU-SME-11` & Feature Shift | `scripts/run_ctu_cross_source_eval.py` | `reports/experiments/ml/ctu_cross_source_eval.json`, `docs/experiments/CTU_CROSS_SOURCE_EVAL.md` |
| **System Perf** | Full E2E CPU Pipeline Benchmark | `scripts/benchmark_full_system.py` | `reports/benchmarks/system_performance_benchmark.json`, `docs/benchmarks/SYSTEM_PERFORMANCE.md` |
