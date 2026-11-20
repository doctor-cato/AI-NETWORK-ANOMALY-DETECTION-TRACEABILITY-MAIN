# Chỉ mục Truy vết Bằng chứng Học thuật — NetFlow Sentinel v2

Mọi khẳng định dưới đây được đối chiếu trực tiếp với mã nguồn v2, manifest và báo cáo JSON thực nghiệm trên nhánh `feat/v2-integration`. Tài liệu v1 cũ nằm tại [`docs/historical/nf_unsw_nb15_v3/academic-defense/EVIDENCE_INDEX.md`](../historical/nf_unsw_nb15_v3/academic-defense/EVIDENCE_INDEX.md).

| Hạng mục | Nguồn Code / Manifest | Báo cáo Thực nghiệm / Kiểm chứng | Trạng thái |
|---|---|---|---|
| **Acquisition & Provenance v2** | `scripts/fetch_multi_source_dataset.py`, `data/EXTERNAL_DATASETS_PROVENANCE.json` | `fetch_multi_source_dataset.py --verify-only` | `VERIFIED` (AIT & CTU CC BY 4.0) · `UGR'16 BLOCKED` |
| **Canonical Contract (`canonical-flow-v2-18`)** | `src/network_anomaly/data/v2_schema.py`, `src/network_anomaly/canonical/feature_contract.py` | `reports/schema/v2_schema_summary.json` | `IMPLEMENTED / TESTED` |
| **Taxonomy & Anti-Coercion** | `src/network_anomaly/data/taxonomy.py`, `tests/unit/test_anti_imputation_and_label_integrity.py` | `pytest tests -q` | `IMPLEMENTED / TESTED` |
| **Scenario-Disjoint Split & Leakage Audit** | `src/network_anomaly/data/split.py`, `scripts/build_v2_dataset_and_split.py` | `reports/splits/v2_split_manifest.json`, `docs/dataset/V2_LEAKAGE_AUDIT.md` | `EXPERIMENTALLY VALIDATED` (`PASS`, 0 overlap) |
| **Train-only Preprocessing (`asinh_robust`)** | `src/network_anomaly/preprocessing/pipeline.py` | `reports/preprocessing/v2_flow_preprocessing_manifest.json` (`0866dec7...`, `2,097,891` rows) | `EXPERIMENTALLY VALIDATED` |
| **4 Mô hình AI v2 (`AI Ready 4/4`)** | `scripts/train_{random_forest,xgboost,isolation_forest,autoencoder}.py` | `reports/models/*_manifest.json`, `scripts/verify_companion_artifacts.py` | `EXPERIMENTALLY VALIDATED` (`overall_status: READY`) |
| **RQ1–RQ4 & Cross-Source Real Capture** | `scripts/generate_model_comparison_report.py`, `run_rq2*`, `run_rq4*`, `run_ctu_cross_source_eval.py` | `reports/experiments/ml/{model_comparison_report,rq4_unknown_attack_report,ctu_cross_source_eval}.json`, `rq2_imbalance_report.json` | `EXPERIMENTALLY VALIDATED` (`CTU Echo/Win7AD` real capture evaluated) |
| **RQ3 Session Correlation** | `src/network_anomaly/behavioral/`, `scripts/run_rq3_session_correlation_experiment.py` | `reports/experiments/behavioral/rq3_session_correlation_experiment.json` | `SIMULATION` · Empirical AIT linkage `BLOCKED` |
| **RQ5 Key Rotation & RQ6 AES-256-GCM** | `src/network_anomaly/crypto/`, `scripts/run_rq5_rotation_experiment.py`, `benchmark_crypto_overhead.py` | `reports/experiments/crypto/rq5_rotation_experiment.json`, `reports/benchmarks/crypto_benchmark_report.json` | `SIMULATION (RQ5)` / `BENCHMARKED (RQ6)` |
| **Desktop Tauri 2 + FastAPI Sidecar** | `desktop/`, `src/network_anomaly/api/`, `scripts/verify_companion_artifacts.py` | `vitest`, `svelte-check`, `cargo test --lib`, `export_openapi_spec.py --check` | `IMPLEMENTED / TESTED` |
