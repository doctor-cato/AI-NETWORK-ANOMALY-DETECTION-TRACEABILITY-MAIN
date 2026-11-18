# NetFlow Sentinel v2 Migration — Session Checkpoint

**Checkpoint:** Checkpoint 6 — Post-Remediation Sync (Phases 0–9 Complete; Issue Sync & Final Verification Next)
**Branch:** `feat/v2-integration`
**Base Commit (`HEAD` / `origin/feat/v2-integration`):** `79ebb678b87de19cc6b664b587726983fecaf98f` (working tree contains uncommitted remediation changes across code, tests, scripts, docs, reports, and regenerated local artifacts/demo subset)
**Updated (UTC):** `2026-11-18T01:55:00Z`

---

## 1. Environment & Tooling State

- Active Python interpreter: `.venv\Scripts\python.exe` (Python `3.12.10` CPython)
- Dev linters pinned and synchronized: `ruff==0.17.5`, `black==26.10.1`
- Desktop version synchronized across `desktop/package.json`, `desktop/package-lock.json`, `desktop/src-tauri/Cargo.toml`, `desktop/src-tauri/Cargo.lock`, `desktop/src-tauri/tauri.conf.json`: **`2.0.0`**
- FastAPI Python backend contract version (`reports/api/openapi.json` / `src/network_anomaly/api/main.py`): **`0.1.0`**

---

## 2. Canonical Split & Preprocessing State (Post-DATA-A01/A02/A03/A04 Remediation)

- **Official Split Protocol:** `v2-scenario-group-purged-v1` (zero scenario / `(5-tuple, ts)` overlap across `train`, `val`, `test`)
- **AIT-NDS-v2 Preserved Labeled Total:** `3,464,400` flows (`ait_train = 2,097,891`, `ait_val = 377,704`, `ait_test = 988,805`; plus `942` unmapped flows -> `3,465,342` raw total with zero silent chunk-drop loss)
- **Unit & Byte Alignment Fixes Applied:**
  - Tstat UDP `duration_ms` scaled `* 1000.0` (`seconds -> ms`)
  - Zeek cross-source flows standardized on L4 payload (`orig_bytes`/`resp_bytes`)
  - `TrainOnlyPreprocessor` (`asinh_robust`) uses `MIN_BOUNDED_SCALE_FLOOR = 0.25`
- **LF-Normalized Split Manifest (`reports/splits/v2_split_manifest.json`) SHA-256:**
  `ed542ee80babca26f6e8ad977168b061e18e99a24be1cbe1ec8767b66d6339e8`
- **Preprocessor (`artifacts/preprocessing/v2_flow_preprocessor.joblib`) SHA-256:**
  `0866dec7252d36d3f2bb2becddf266787cc49ddf19306a8e003ba1e951cf51a7`
- **OOD Rejection Gate (`artifacts/ml/ood_reference_gate.json`):** Fitted on raw `2,097,891` `AIT-Train` flows (18 ML features) and scoped per `artifacts_dir` in `RealtimeInferenceEngine._load_ood_gate()` so isolated `tmp_path` registries still report `NOT_FITTED`.

---

## 3. Retrained 4-Model State (`AI Ready: 4/4`, Verified Reloaded)

All 4 active `.joblib` artifacts bind LF split SHA-256 `ed542ee80babca26...` and preprocessor SHA-256 `0866dec7252d36...`:

| Model | Run ID | Artifact SHA-256 (prefix) | AIT-Val F1 | AIT-Test F1 / P / R / FPR / ROC-AUC | CTU-Echo F1 (ROC-AUC) | CTU-Win7AD F1 (ROC-AUC) |
|---|---|---|---:|---:|---:|---:|
| **Random Forest** (`balanced_subsample`, `min_samples_leaf=5`) | `v2-rf-20261117T231214Z` | `b2e42f85...` | `0.999658` | `0.994967` (`P=0.998854`, `R=0.991110`, `FPR=0.000246`, `ROC=0.999372`) | `0.047418` (`0.613739`) | `0.071233` (`0.839246`) |
| **XGBoost** (canonical defaults) | `v2-xgb-20261117T231609Z` | `33d201f8...` | `0.999556` | `0.901289` (`P=0.998886`, `R=0.821066`, `FPR=0.000198`, `ROC=0.988440`) | `0.143595` (`0.701663`) | `0.073752` (`0.697827`) |
| **Isolation Forest** (`th=0.031268`) | `v2-if-20261118T020525Z` | `11b16900...` | `0.921308` | `0.584182` (`P=0.777525`, `R=0.467846`, `FPR=0.028952`, `ROC=0.833013`) | `0.885328` (`0.957148`) | `0.046382` (`0.764901`) |
| **Autoencoder** (`(16,8,16)` Benign std, `th=0.000467`) | `v2-ae-20261118T020635Z` | `e6afecef...` | `0.921513` | `0.587662` (`P=0.785970`, `R=0.469262`, `FPR=0.027637`, `ROC=0.554383`) | `0.732531` (`0.780993`) | `0.032628` (`0.728011`) |

- Companion verification report: `scripts/verify_companion_artifacts.py` (`overall_status: READY`, `4/4` models, `demo_ready: true`).
- Demo dataset hashes (`data/demo/`): `demo_flows.csv` `90b028939c36e84cf43eb9595e6d74ee9fc0f2d03c40f46d439f1886f50d01a3`, `demo_labels.csv` `9332ddd7513350f04ece64ee5ac9256948880a712e1d9741e7684d92b9daff9e`, `selected_indices_sha256` `8bf86cf116faa190b27b65bed222a203c34f85860d5c14fd1244f0a26cffc866`.

---

## 4. RQ1–RQ6 & System Verification Highlights

- **RQ1 (`reports/experiments/ml/model_comparison_report.json`):** `RandomForest` strongest supervised (`F1=0.994967`); `Autoencoder` (`F1=0.587662`) & `IsolationForest` (`F1=0.584182`) with non-empty `top_features` via validation permutation importance.
- **RQ2 (`reports/experiments/imbalance/rq2_imbalance_report.json`):** `RandomForest_CostSensitive` reaches `F1=0.994749` (`macro_f1=0.996809`, `FPR=0.000244`); `h2_full_confirmed=false` (rare `Credential_Attack` single-flow overlap limits).
- **RQ3 (`reports/experiments/behavioral/rq3_session_correlation_experiment.json`):** Executed in `SIMULATION` mode; empirical `AIT-NDS-v2 ↔ AIT-LDS-v2.1` direct UID linkage remains `BLOCKED / NOT VERIFIED`.
- **RQ4 (`reports/experiments/ml/rq4_unknown_attack_report.json`):** Holdout Val calibration enforced (`0` holdout leak); Unknown recall `RF=0.909091`, `XGB=0.750000`, `IF=0.909091`, `AE=0.204545`; `unsupervised_ge_0_75_both=false` (`IF=true, AE=false`).
- **RQ5 (`reports/experiments/crypto/rq5_rotation_experiment.json`):** `SIMULATION`, `hypothesis_confirmed=true` (max exposure reduced `1200.0 s -> 150.01 s`), plus clock injection & SQLite cooldown/rate-limit persistence added to `crypto/rotation.py`.
- **RQ6 (`reports/benchmarks/crypto_benchmark_report.json`):** `hypothesis_confirmed=true` (256B encrypt median `9.2 us`, P95 `13.3 us`, `75,851.2 ops/sec`).
- **System Performance (`reports/benchmarks/system_performance_benchmark.json`):** Synthetic in-process E2E `16.38 events/s`, Replay `19.43 events/s`, 0 dropped.
- **Loopback Acceptance (`reports/acceptance/synthetic_udp_loopback_report.json`):** `synthetic=true`, 6/6 events processed (`ood_gate=FITTED`), 4/4 `VALIDATED`.
- **Remaining External / Hardware Blockers:** `UGR'16` (HTTP `403` maintenance), `AIT-NDS-v2 ↔ AIT-LDS-v2.1` direct UID join (`NOT VERIFIED`), physical lab switch/router telemetry (`#137`), clean Windows 10/11 VM installer E2E (`#73`/`#148`), `DISTRIBUTION_AUTHORIZATION.json` maintainer signoff (`approved=false`), website `site-source` & defense slides (`#152`, `#153`).

---

## 5. Immediate Remaining Work

1. Sync GitHub Issues (`#18–#73`, `#76–#155`) checkboxes strictly per verified evidence (without closing issues or changing PR/Milestone states).
2. Update `reports/audits/V2_FINDING_REGISTER.md` and `reports/audits/V2_ISSUE_AC_AUDIT.md` post-remediation statuses.
3. Run full LF normalization, CI parity verification (`ruff`, `black`, full `pytest`, `npm` Svelte check/test/build, `cargo` fmt/clippy/test), and generate `reports/audits/V2_FINAL_AUDIT.md`.
