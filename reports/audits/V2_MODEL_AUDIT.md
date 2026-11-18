# V2 Model Baseline & Provenance Audit (`NetFlow Sentinel v2`)

- **Ngày kiểm toán:** `2026-11-18` (`+07:00`) / `2026-11-17T21:45Z`
- **Repository Snapshot:** branch `feat/v2-integration`, HEAD `79ebb678b87de19cc6b664b587726983fecaf98f` (`2026-11-18 03:39:25 +0700` = `2026-11-17T20:39:25Z`)
- **Chế độ kiểm toán:** Read-only (không chạy `train_*.py`, không ghi đè model artifacts hay manifests hiện có, không chỉnh sửa source code)
- **Phạm vi đối tượng:** `Random Forest`, `XGBoost`, `Isolation Forest`, `Autoencoder`, `TrainOnlyPreprocessor` (`v2_flow_preprocessor.joblib`), Split/Dataset manifests, `ModelRegistry`, và các báo cáo đánh giá thực nghiệm (`model_comparison_report.json`, `ctu_cross_source_eval.json`, `rq2_imbalance_report.json`, `rq4_unknown_attack_report.json`).

---

## 1. Tóm tắt điều hành (Executive Summary)

| Hạng mục kiểm toán | Trạng thái | Kết luận ngắn gọn |
|---|---|---|
| Artifact & SHA-256 Integrity (trên Windows disk hiện tại) | **PASS** | Cả 4 model `.joblib`, `v2_flow_preprocessor.joblib` và sidecar JSON khớp 100% SHA-256 trên disk; `ModelRegistry().summary()` báo `4/4 VALIDATED`, `verify_companion_artifacts()` báo `READY`. |
| Git Snapshot Traceability (`environment.git_commit`) | **FAIL** (`DIRTY_DISCLOSED`) | Cả 4 model được train trong khoảng `18:17:45Z–18:36:14Z` ngày `2026-11-17` trên working tree chưa commit (`git_commit="05240b44b2a057a9942d6297ae75f2b4cb48ea2f"`, `git_dirty=true`), trước khi commit `79ebb678` được tạo. |
| Cross-Platform Split Fingerprint (`split_manifest_sha256`) | **FAIL** | Manifest model & preprocessor ghim SHA-256 bản **CRLF** trên Windows disk (`1b7fa7ae...`), không khớp bản **LF** trong Git index (`7840d5cd...` theo `.gitattributes` `* text=auto eol=lf`). Chạy verify trên Linux CI hoặc fresh LF clone sẽ thất bại. |
| Threshold Provenance & Test Isolation | **PASS** | Không có Test leakage trong chọn ngưỡng: RF/XGB dùng ngưỡng xác suất `0.5` xác minh trên `ait_val`; IF (`0.00273631`) và AE (`0.00022800`) hiệu chuẩn bằng quantile `0.95` của `206,676` mẫu Benign `ait_val`. |
| Baseline ML Generalization & Operational Readiness | **FAIL** (`EXPERIMENTALLY VALIDATED` as weak baseline) | RF/XGB đạt `F1=0.9995/0.9996` trên `AIT-Val` nhưng tụt mạnh trên `AIT-Test` (`Credential_Attack` Recall `14.10%`, `Data_Exfiltration` Recall `60.64%/57.45%`) và **sụp đổ zero-shot trên CTU** (`F1=0.0` ở `CTU-Echo`, `F1=0.0/0.000735` ở `CTU-Win7AD`). IF/AE mù hoàn toàn trước `Data_Exfiltration` (`0.00%–0.05%` Recall) và AE bùng nổ FPR trên CTU (`0.6520` Echo, `0.8545` Win7AD). |

> **Phán quyết sẵn sàng trước khi retrain:** Đường ống inference và bộ artifact hiện tại **IMPLEMENTED & TESTED** ở mức runtime loading trên Windows disk, **EXPERIMENTALLY VALIDATED** là **baseline chưa đạt chuẩn vận hành cross-source / rare-attack**, và **CHƯA ĐẠT CHUẨN REPRODUCIBILITY SẠCH** cho tới khi khắc phục lỗi CRLF/LF `split_manifest_sha256`, clean-commit training, và các khiếm khuyết đặc trưng/hiệu chuẩn nêu ở Mục 4–5.

---

## 2. Kiểm chứng 10 tiêu chí Provenance & Integrity (Mục 4.3 `PROMPT.md`)

### 2.1 Ma trận kiểm chứng 4 baseline models

| # | Tiêu chí kiểm toán | Random Forest | XGBoost | Isolation Forest | Autoencoder |
|---|---|---|---|---|---|
| 1 | Artifact tồn tại & kích thước | **PASS** (`6,756,036` B / `6.4431 MiB`) | **PASS** (`240,643` B / `0.2295 MiB`) | **PASS** (`930,211` B / `0.8871 MiB`) | **PASS** (`25,073` B / `0.0239 MiB` + 3 sidecars) |
| 2 | SHA-256 khớp manifest (`_sha256_file`) | **PASS** (`0dd7aaaf...`) | **PASS** (`6bb5a6f2...`) | **PASS** (`aca66915...`) | **PASS** (`2032f8ca...` + config/threshold SHA) |
| 3 | Training Run IDs & Git snapshot | **PASS** Run ID (`v2-rf-20261117T181745Z`); **FAIL** clean commit (`05240b44`, `git_dirty=True`) | **PASS** Run ID (`v2-xgb-20261117T182043Z`); **FAIL** clean commit (`05240b44`, `git_dirty=True`) | **PASS** Run ID (`v2-if-20261117T183614Z`); **FAIL** clean commit (`05240b44`, `git_dirty=True`) | **PASS** Run ID (`v2-ae-20261117T183534Z`); **FAIL** clean commit (`05240b44`, `git_dirty=True`) |
| 4 | Dataset Fingerprint (`dataset_sha256`) | **PASS** (`cc7553ad...`; note: `.joblib` `protocol` có `dataset_csv_sha256=""`) | **PASS** (`cc7553ad...`) | **PASS** (`cc7553ad...`) | **PASS** (`cc7553ad...`) |
| 5 | Split Fingerprint (`split_manifest_sha256`) | **PASS** disk CRLF (`1b7fa7ae...`); **FAIL** Git LF (`7840d5cd...`) + `.joblib` internal ref `None` | **PASS** disk CRLF (`1b7fa7ae...`); **FAIL** Git LF (`7840d5cd...`) | **PASS** disk CRLF (`1b7fa7ae...`); **FAIL** Git LF (`7840d5cd...`) | **PASS** disk CRLF (`1b7fa7ae...`); **FAIL** Git LF (`7840d5cd...`) + `load_verified()` chưa check split SHA |
| 6 | Preprocessor Fingerprint | **PASS** (`d33dfe09...`); `.joblib` internal `fitted_artifact_sha256=None` | **PASS** (`d33dfe09...`) | **PASS** (`d33dfe09...`) | **PASS** (`d33dfe09...`; dùng cả `preprocessor_sha256` & `preprocessor_artifact_sha256`) |
| 7 | Feature Contract Version | **PASS** (`canonical-flow-v2-18`, 18 cols) | **PASS** (`canonical-flow-v2-18`, 18 cols) | **PASS** (`canonical-flow-v2-18`, 18 cols) | **PASS** (`canonical-flow-v2-18`, 18 cols) |
| 8 | Threshold Provenance | **PASS** (`0.5`, `validation_verified_binary_probability_0.5`, `test_touched=false`) | **PASS** (`0.5`, `validation_verified_binary_probability_0.5`, `test_touched=false`) | **PASS** (`0.002736309694079453`, `validation_benign_quantile_0.95`, `test_touched=false`; lệch nhỏ `>` vs `>=`) | **PASS** (`0.0002279976895622908`, `validation_benign_quantile_0.95`, `test_touched=false`; lệch nhỏ `>` vs `>=`) |
| 9 | Evaluation Report Consistency | **PASS** CM/Metrics; sai lệch `float32` vs `float64` AUC `~2.8e-9` | **PASS** CM/Metrics; sai lệch `float32` vs `float64` PR-AUC `1.28e-5`; còn `provenance_note` mâu thuẫn | **PASS** CM/Metrics; sai lệch AUC `~2.0e-8`; `target="Label"` legacy | **PASS** CM/Metrics; sai lệch AUC `~8.8e-10` |
| 10 | `ModelRegistry` Verification | **PASS** (`VALIDATED`, `validated=True`; cảnh báo feature names) | **PASS** (`VALIDATED`, `validated=True`) | **PASS** (`VALIDATED`, `validated=True`; cảnh báo feature names) | **PASS** (`VALIDATED`, `validated=True`; `manifest_path` trỏ `artifacts/models/...`) |

### 2.2 Chi tiết bằng chứng từng tiêu chí (Artifacts, Hashes & Runtime Checks)

#### Tiêu chí 1 & 2 — Artifact Inventory, Sizes & SHA-256 Verification
Tất cả model/preprocessing `.joblib` đều nằm dưới `artifacts/**` (được ignore bởi `.gitignore`), toàn vẹn về byte và SHA-256 so với manifest tại thời điểm kiểm toán:

- **Preprocessor (`artifacts/preprocessing/v2_flow_preprocessor.joblib`):** `1,694` bytes, SHA-256 `d33dfe09630687f825d7e4cfa604001c3e091560538059da2eb397b49f44bc32`.
- **Random Forest (`artifacts/models/random_forest/random_forest_baseline.joblib`):** `6,756,036` bytes (`6.4431 MiB`), SHA-256 `0dd7aaafa40f351986d7f977e81d9517a3c25083e6cd4525ecdb23abac38dbf0`.
- **XGBoost (`artifacts/models/xgboost/xgboost_baseline.joblib`):** `240,643` bytes (`0.2295 MiB`), SHA-256 `6bb5a6f2ac6f16fc76138c6f22c3e80cc8664d2db1ddc039819c845a97a26732`.
- **Isolation Forest (`artifacts/models/isolation_forest/isolation_forest.joblib`):** `930,211` bytes (`0.8871 MiB`), SHA-256 `aca66915e0f57433c18ebbb819f2438c75e3840a183d2e379c986f0952e1aa1c`.
- **Autoencoder (`artifacts/models/autoencoder/autoencoder_model.joblib`):** `25,073` bytes (`0.0239 MiB`), SHA-256 `2032f8caf37be27f12a91ca1348e85d32a718f332e151cd900dedcf082b71a1f`.
  - Sidecar `artifacts/models/autoencoder/model_config.json`: `327` bytes, disk CRLF SHA-256 `9cb2d69da56af7c4deb6eee8c2b5341e6263988a3636bdbab0e45e8528fe7097` (LF: `50c49dd7aaefe1671dd4d41c9177e1b61a688e617a2e6d02f8cd72364cec48da`).
  - Sidecar `artifacts/models/autoencoder/threshold.json`: `1,239` bytes, disk CRLF SHA-256 `abdb0e03940a8eedffd7f9a271316b18b1645bb4d68efd994bcf932a7d8f77ab` (LF: `9db25ee2b145cfb1f20dc7536a852199fa5109c8d20cdab19762c3a700fd80fb`).
  - Sidecar `artifacts/models/autoencoder/score_normalization.json`: `4,112` bytes, disk CRLF SHA-256 `7e4c841efcfc245ed10e42c0c7feafa340187f3e59e7353d6d40beb682bba77f` (LF: `15bd315738841e7ad1c873d349d686bef46823a60f0410054303e99a8b080177`).

Kiểm tra trùng khớp 3 bản sao JSON (`artifacts/models/<m>/*_manifest.json`, `reports/models/*_manifest.json`, `reports/evaluation/*_v2_eval.json`) cho cả 4 model xác nhận **khớp 100% theo byte**:
- `random_forest`: `15,794` bytes, CRLF SHA-256 `b90f79c7abf127933adce26f852430a168dad0fc5ad0a5fe74632fc3c45284b2` (LF: `a3937bf238cda9e2dab6b0c3514dcf1e2d6777f6d2c355f283e9a9517a8d2977`).
- `xgboost`: `16,801` bytes, CRLF SHA-256 `3593fd33ccfda28e32390c5b2ff8a8c3e9fe637be36be3debd3dbf26a6b9fefa` (LF: `78adeb8903d57785780e870728235154ac9f715f826f0618d425e576067f3e79`).
- `isolation_forest`: `26,714` bytes, CRLF SHA-256 `c51dfaaa08d5264c2b963508ff0895e43fb3bc7ef5f10cd42a659432c846ef14` (LF: `19a4d15299409a1c3a0e37a09990116f1e24170d900be3d8f60245e4a81b9eae`).
- `autoencoder`: `20,804` bytes, CRLF SHA-256 `d40aa81ed975631b9bbd41f16d4260d84e1e6f66ee88b626a331e2bedeaba9d8` (LF: `f7323fb3dbab53f0696d0af26d09d95fd2b41ff00f87822edc53aeccb582b729`).

#### Tiêu chí 3 & 4 — Training Run IDs, Git Dirty Snapshot & Dataset Ledger
- **Run IDs:** Cả 4 manifest khai báo đồng nhất `run_id == training_run_id`: `v2-rf-20261117T181745Z` (train `155.897s`), `v2-xgb-20261117T182043Z` (train `24.395s`), `v2-ae-20261117T183534Z` (train `15.497s`), `v2-if-20261117T183614Z` (train `12.644s`).
- **Git Snapshot (`FAIL` / `DIRTY_DISCLOSED`):** Cả 4 manifest ghi `environment.git_commit="05240b44b2a057a9942d6297ae75f2b4cb48ea2f"` và `git_dirty=True` (`215–275` dirty paths). Kết quả `git log` và `git diff --name-status 05240b4..79ebb67` chứng minh các model được train ngay trên working tree đang chuyển đổi v2 trước khi commit `79ebb678` (`feat(v2): complete hard dataset cutover to AIT-NDS-v2 and CTU-SME-11`) được tạo ở `2026-11-17T20:39:25Z`, do đó artifact không trỏ tới một commit sạch bất biến.
- **Dataset Ledger (`dataset_sha256`):** Giá trị `cc7553ad813ac0ee696f826a877af7afe9c7e07d3443beb34d8c9c21fbe81acf` trong cả 4 manifest khớp chính xác phép tính `sha256(json.dumps(raw_zip_digests, sort_keys=True, separators=(",", ":")))` trên 8 file `.zip` nguồn của `AIT-NDS-v2` trong `data/AIT_DATASETS_MANIFEST.json`. Các partition `.csv.gz` thực tế trên disk khớp kiểm tra:
  - `data/processed/v2/ait_train.csv.gz`: `100,272,366` B, SHA-256 `628c8e9454bdc8551d139180bcf8367bc56c47933723763b64f16e18c4fc11d0` (`N=1,930,219`; Benign `1,658,795`, Attack `271,424`)
  - `data/processed/v2/ait_val.csv.gz`: `13,969,251` B, SHA-256 `4c480ab6e25a34dd1ba83ff67682fa864370ee881ff774201c1ca24a552eba39` (`N=377,704`; Benign `206,676`, Attack `171,028`)
  - `data/processed/v2/ait_test.csv.gz`: `45,887,719` B, SHA-256 `5532fb77c35f0014f941a35386a8204eb48b5b7cbdf7480782da03d812831076` (`N=923,292`; Benign `747,610`, Attack `175,682`)
  - `data/processed/v2/ctu_echo.csv.gz`: `4,628,705` B, SHA-256 `8cdb4fb6981f6e17dc26ce1c861c0c7aa3e57d051bec393d37534c8b93d09a4d` (`N=76,073`; Benign `39,497`, Attack `36,576`)
  - `data/processed/v2/ctu_windows7ad.csv.gz`: `11,239,661` B, SHA-256 `090a454419a1d672c642b6a7d3f4d5b7451ad468f1c8339a1a9c6014b278c15c` (`N=175,146`; Benign `173,108`, Attack `2,038`; `9,394` flows unmapped bị loại)

#### Tiêu chí 5 — Split Fingerprint (`split_manifest_sha256`) & Bẫy CRLF vs LF (`FAIL`)
Kiểm tra `git ls-files --eol` cho thấy `.gitattributes` quy định `* text=auto eol=lf`, khiến Git index lưu bản **LF**, nhưng working tree Windows đang giữ bản **CRLF**:
- `reports/splits/v2_split_manifest.json` & `data/V2_SPLIT_MANIFEST.json`: `4,851` bytes trên disk (CRLF), SHA-256 = `1b7fa7aebaf3560f27b3d23ec05919a83aacd1ed6ea5448f96a6a42c7a264e0a`.
- Chuẩn LF trong Git index (`i/lf`): SHA-256 = `7840d5cdd18acb29ad222ec7d29e26e645fabb76646b62081e1d7368488eefe8`.
- **Tác động tái lập đã kiểm chứng:** Cả `v2_flow_preprocessing_manifest.json`, 4 model manifests và `data/demo/demo_manifest.json` đều ghim hash **CRLF** (`1b7fa7ae...`). Khi thử nghiệm gọi `{RF,XGB,IF}.load_verified(..., expected_split_manifest_sha256="7840d5cd...")`, cả 3 đều **FAIL** với ngoại lệ `Split manifest SHA-256 mismatch: expected 7840d5cd..., got 1b7fa7ae...`. Vì vậy, bất kỳ fresh clone theo LF hoặc pipeline Linux CI nào gọi `verify_preprocessing_artifact(..., split_manifest_path=...)` hoặc `verify_companion_artifacts()` sẽ **gãy kiểm chứng**.
- **Khiếm khuyết phụ ở tầng code model:**
  1. `train_random_forest.py` chỉ truyền `split_id`, để lại trong `random_forest_baseline.joblib` payload `protocol.split_reference` có `split_manifest_sha256=None`, `split_status="PLANNED / NOT VERIFIED"`, `ml_ready=False`, `dataset_csv_sha256=""` và `protocol.preprocessing_reference` có `fitted_artifact_sha256=None`, `preprocessing_status="PLANNED / NOT VERIFIED"`.
  2. `AutoencoderModel.load_verified()` chưa hỗ trợ kiểm tra `expected_split_manifest_sha256`.

#### Tiêu chí 6 & 7 — Preprocessor & Feature Contract
- Toàn bộ 4 model khớp `preprocessor_artifact_sha256 = d33dfe09630687f825d7e4cfa604001c3e091560538059da2eb397b49f44bc32` (`reports/preprocessing/v2_flow_preprocessing_manifest.json` đang giữ CRLF `473b5646...` trên disk vs LF `eff0c30c...`).
- `feature_contract_version = "canonical-flow-v2-18"` khớp tuyệt đối ở mọi manifest, kèm đủ 18 features chuẩn (`duration_ms`, `bytes_in`, `bytes_out`, `pkts_in`, `pkts_out`, `protocol_num`, `total_bytes`, `total_pkts`, `bytes_in_ratio`, `pkts_in_ratio`, `bytes_per_pkt_in`, `bytes_per_pkt_out`, `bytes_per_sec_in`, `bytes_per_sec_out`, `pkts_per_sec`, `has_response`, `is_tcp`, `is_udp`).
- Tuy nhiên, thiết kế `TrainOnlyPreprocessor` (`scaling_strategy="asinh_robust"`, `categorical_coded_columns=["protocol_num"]`, `handle_unknown_categories="passthrough"`, `category_vocabularies={"protocol_num": [6, 17]}`) chứa 2 khiếm khuyết hình học nghiêm trọng đối với mô hình phi giám sát (phân tích chi tiết tại Mục 4.3).

#### Tiêu chí 8 — Threshold Provenance
- **Random Forest & XGBoost:** Dùng ngưỡng cố định `0.5` (`threshold_source="validation_verified_binary_probability_0.5"`, `selected_on="validation"`, `test_touched=false`). XGBoost dùng `ait_val` làm `eval_set` để log `best_val_logloss=0.0027364170426067` ở `best_val_iteration=199` (không dùng early stopping).
- **Isolation Forest:** `threshold = 0.002736309694079453`, `threshold_source="validation_benign_quantile_0.95"`, `selected_on="validation"`, `test_touched=false`, `benign_val_count=206676`.
- **Autoencoder:** `threshold = 0.0002279976895622908`, `threshold_source="validation_benign_quantile_0.95"`, `selected_on="validation"`, `test_touched=false`, `benign_val_count=206676`.
- **Phát hiện lệch biên `>` vs `>=`:** Hàm hiệu chuẩn ghi `empirical_val_fpr = np.mean(benign_scores > threshold)` (`0.049986452` cho IF; `0.049996129` cho AE), trong khi `evaluate_v2_partition` dự đoán bằng `>= threshold` (`evaluation.ait_val.false_positive_rate` = `0.050010645` cho IF; `0.050000968` cho AE). Trên phân phối MSE nhiều giá trị trùng rời rạc gần quantile `0.95`, `>` và `>=` cho ra hai số FPR khác nhau.

#### Tiêu chí 9 — Evaluation Report & Schema Consistency
- `reports/models/*_manifest.json` vs `reports/evaluation/*_v2_eval.json` vs `artifacts/models/<m>/*_manifest.json`: **100% byte-identical**.
- `reports/experiments/ml/ctu_cross_source_eval.json` (`zero_shot_ait_models`): khớp chính xác mọi metric và Confusion Matrix với `evaluation.ctu_echo` và `evaluation.ctu_windows7ad` trong cả 4 manifests.
- `reports/experiments/ml/model_comparison_report.json` (`ait_test`): khớp 100% Confusion Matrix, Accuracy, Precision, Recall, F1, Macro-F1 và FPR cho cả 4 model; chỉ lệch vi mô ở `roc_auc` / `pr_auc` do `_v2_train_common.py` load dữ liệu bằng `np.float32` trong khi `_rq_common.py` load `float64` (`max diff` ở XGB `pr_auc`: `0.93846648` vs `0.93845370`, chênh `1.2786e-5`; RF/IF/AE chênh `8.76e-10`–`1.99e-8`). Báo cáo này cũng không ghi trường `run_id` (omitted) trong mục `models.*`.
- **Các lỗi metadata / config drift đã phát hiện:**
  1. `reports/models/xgboost_manifest.json` vẫn giữ chuỗi mâu thuẫn `"provenance_note": "Companion manifest emitted by model API without runtime provenance evidence. It is intentionally not eligible for load_verified()."` kế thừa từ `XGBoostModel.save()`.
  2. `xgboost_manifest.json` và `isolation_forest_manifest.json` lưu đường dẫn tuyệt đối theo máy Windows (`C:/Users/ASUS/Documents/GitHub/...`) ở `model_artifact_path`, trong khi `random_forest_manifest.json` dùng relative POSIX path và `autoencoder_manifest.json` dùng `"model_file": "autoencoder_model.joblib"`.
  3. `isolation_forest_manifest.json` ghi `"target": "Label"` (tên cột v1 đã nghỉ hưu) thay vì `"label_binary"`; đồng thời `train_isolation_forest.py` dùng `{n_estimators: 200, max_samples: 512, contamination: 0.05}`, lệch với `config.ISOLATION_FOREST_DEFAULTS`.
  4. `scripts/verify_companion_artifacts.py` vẫn khai báo sidecar legacy không tồn tại (`model_config.json`, `threshold.json`, `training_metadata.json`) cho Isolation Forest; `data/demo/demo_manifest.json` để `preprocessor_artifact_sha256=None`, `training_run_id=None`, `dataset_sha256=None`.

#### Tiêu chí 10 — `ModelRegistry` & Companion Verification
Kiểm chứng thực thi trực tiếp trên working copy hiện tại (`.venv\Scripts\python.exe`):
- `ModelRegistry().summary()`: `ready_count=4, validated_count=4, total_models=4, ai_ready=True, demo_heuristics_enabled=False`; cả 4 model đều mang `readiness="VALIDATED"`, `validated=True`, `threshold_source="manifest.threshold"`.
- `verify_companion_artifacts()`: `overall_status="READY"`, `ready_models=["random_forest", "xgboost", "isolation_forest", "autoencoder"]`, `demo_ready=True`.
- **Lưu ý vận hành phát hiện khi warmup:**
  1. `ModelRegistry._warmup()` và `score_batch()` truyền `np.ndarray` vào estimator của `RandomForest` và `IsolationForest` (vốn lưu `feature_names_in_` do fit trên `DataFrame`), gây cảnh báo sklearn `UserWarning: X does not have valid feature names`.
  2. Trong `ModelRegistry().summary()`, trường `manifest_path` của `autoencoder` trỏ tới `artifacts/models/autoencoder/autoencoder_manifest.json` trong khi 3 model còn lại trỏ tới `reports/models/*_manifest.json`.

---

## 3. Hiệu năng Baseline đầy đủ trên 4 Partitions (Phase 3 Baseline)

### 3.1 Bảng Metrics tổng hợp (`AIT-Val`, `AIT-Test`, `CTU-Echo`, `CTU-Win7AD`)

| Model | Partition (`N`; Benign / Attack) | Accuracy | Precision | Recall | F1 | Macro-F1 | FPR | ROC-AUC | PR-AUC | Confusion Matrix `{TN, FP, FN, TP}` | Latency (`s` / `us/row`) |
|---|---|---|---|---|---|---|---|---|---|---|---|
| **Random Forest** (`th=0.5`, `6.44 MB`, train `155.897s`) | `AIT-Val` (`377,704`; `206,676 / 171,028`) | `0.999545` | `0.999778` | `0.999217` | `0.999497` | `0.999541` | `0.000184` | `0.999931` | `0.999858` | `206,638 / 38 / 134 / 170,894` | `0.5994s` (`1.587 us`) |
| | `AIT-Test` (`923,292`; `747,610 / 175,682`) | `0.965275` | `0.998819` | `0.818473` | `0.899697` | `0.939350` | `0.000227` | `0.999561` | `0.998081` | `747,440 / 170 / 31,891 / 143,791` | `1.4545s` (`1.5753 us`) |
| | `CTU-Echo` (`76,073`; `39,497 / 36,576`) | `0.518765` | `0.000000` | `0.000000` | `0.000000` | `0.341570` | `0.000836` | `0.799629` | `0.763745` | `39,464 / 33 / 36,576 / 0` | `0.1253s` (`1.6465 us`) |
| | `CTU-Win7AD` (`175,146`; `173,108 / 2,038`) | `0.975369` | `0.000000` | `0.000000` | `0.000000` | `0.493765` | `0.013148` | `0.688774` | `0.119936` | `170,832 / 2,276 / 2,038 / 0` | `0.2649s` (`1.5124 us`) |
| **XGBoost** (`th=0.5`, `0.23 MB`, train `24.395s`) | `AIT-Val` (`377,704`; `206,676 / 171,028`) | `0.999637` | `0.999801` | `0.999398` | `0.999599` | `0.999634` | `0.000165` | `0.999948` | `0.999885` | `206,642 / 34 / 103 / 170,925` | `0.1832s` (`0.485 us`) |
| | `AIT-Test` (`923,292`; `747,610 / 175,682`) | `0.962555` | `0.998812` | `0.804163` | `0.890981` | `0.934188` | `0.000225` | `0.978618` | `0.938454` | `747,442 / 168 / 34,405 / 141,277` | `0.4837s` (`0.5239 us`) |
| | `CTU-Echo` (`76,073`; `39,497 / 36,576`) | `0.494919` | `0.000000` | `0.000000` | `0.000000` | `0.331068` | `0.046763` | `0.037340` | `0.393081` | `37,650 / 1,847 / 36,576 / 0` | `0.0536s` (`0.704 us`) |
| | `CTU-Win7AD` (`175,146`; `173,108 / 2,038`) | `0.984482` | `0.001466` | `0.000491` | `0.000735` | `0.496458` | `0.003934` | `0.159882` | `0.007887` | `172,427 / 681 / 2,037 / 1` | `0.1167s` (`0.6663 us`) |
| **Isolation Forest** (`th=0.002736`, `0.89 MB`, train `12.644s`) | `AIT-Val` (`377,704`; `206,676 / 171,028`) | `0.929937` | `0.937447` | `0.905705` | `0.921303` | `0.929084` | `0.050011` | `0.965929` | `0.967958` | `196,340 / 10,336 / 16,127 / 154,901` | `1.9881s` (`5.2636 us`) |
| | `AIT-Test` (`923,292`; `747,610 / 175,682`) | `0.868704` | `0.746120` | `0.469849` | `0.576600` | `0.749452` | `0.037569` | `0.775284` | `0.635323` | `719,523 / 28,087 / 93,138 / 82,544` | `5.6102s` (`6.0763 us`) |
| | `CTU-Echo` (`76,073`; `39,497 / 36,576`) | `0.848764` | `0.801675` | `0.910761` | `0.852744` | `0.848653` | `0.208649` | `0.784484` | `0.678162` | `31,256 / 8,241 / 3,264 / 33,312` | `0.3205s` (`4.2125 us`) |
| | `CTU-Win7AD` (`175,146`; `173,108 / 2,038`) | `0.560030` | `0.000093` | `0.003435` | `0.000182` | `0.359070` | `0.433417` | `0.306737` | `0.009282` | `98,080 / 75,028 / 2,031 / 7` | `1.0567s` (`6.0333 us`) |
| **Autoencoder** (`th=0.000228`, `0.024 MB`, train `15.497s`) | `AIT-Val` (`377,704`; `206,676 / 171,028`) | `0.929813` | `0.937440` | `0.905419` | `0.921151` | `0.928956` | `0.050001` | `0.961504` | `0.965826` | `196,342 / 10,334 / 16,176 / 154,852` | `0.1194s` (`0.3162 us`) |
| | `AIT-Test` (`923,292`; `747,610 / 175,682`) | `0.870373` | `0.758089` | `0.468130` | `0.578827` | `0.751112` | `0.035104` | `0.788561` | `0.641065` | `721,366 / 26,244 / 93,440 / 82,242` | `0.3038s` (`0.3291 us`) |
| | `CTU-Echo` (`76,073`; `39,497 / 36,576`) | `0.621850` | `0.565827` | `0.917596` | `0.700003` | `0.594318` | `0.652024` | `0.758762` | `0.654693` | `13,744 / 25,753 / 3,014 / 33,562` | `0.0219s` (`0.2885 us`) |
| | `CTU-Win7AD` (`175,146`; `173,108 / 2,038`) | `0.154477` | `0.012445` | `0.914622` | `0.024556` | `0.139206` | `0.854472` | `0.781298` | `0.031960` | `25,192 / 147,916 / 174 / 1,864` | `0.0576s` (`0.3288 us`) |

### 3.2 Per-Attack Category Detection Rates (`Detected / Total`)

| Partition | Attack Category | Total | Random Forest | XGBoost | Isolation Forest | Autoencoder |
|---|---|---|---|---|---|---|
| `AIT-Val` | `Credential_Attack` | `11` | `9/11` (`81.82%`) | `10/11` (`90.91%`) | `11/11` (`100.00%`) | `3/11` (`27.27%`) |
| `AIT-Val` | `Data_Exfiltration` | `15,778` | `15,776/15,778` (`99.99%`) | `15,753/15,778` (`99.84%`) | `0/15,778` (`0.00%`) | `1/15,778` (`0.0063%`) |
| `AIT-Val` | `Exploitation_And_C2` | `2` | `2/2` (`100.00%`) | `2/2` (`100.00%`) | `2/2` (`100.00%`) | `2/2` (`100.00%`) |
| `AIT-Val` | `Post_Exploitation_Discovery` | `56` | `56/56` (`100.00%`) | `56/56` (`100.00%`) | `56/56` (`100.00%`) | `1/56` (`1.79%`) |
| `AIT-Val` | `Reconnaissance` | `155,181` | `155,051/155,181` (`99.92%`) | `155,104/155,181` (`99.95%`) | `154,832/155,181` (`99.78%`) | `154,845/155,181` (`99.78%`) |
| `AIT-Test` | `Credential_Attack` | `78` | **`11/78` (`14.10%`)** | **`11/78` (`14.10%`)** | **`13/78` (`16.67%`)** | **`5/78` (`6.41%`)** |
| `AIT-Test` | `Data_Exfiltration` | `80,075` | **`48,559/80,075` (`60.64%`)** | **`46,007/80,075` (`57.45%`)** | **`0/80,075` (`0.00%`)** | **`37/80,075` (`0.046%`)** |
| `AIT-Test` | `Exploitation_And_C2` | `5` | `5/5` (`100.00%`) | `5/5` (`100.00%`) | `5/5` (`100.00%`) | `5/5` (`100.00%`) |
| `AIT-Test` | `Post_Exploitation_Discovery` | `37` | `35/37` (`94.59%`) | `35/37` (`94.59%`) | `35/37` (`94.59%`) | `4/37` (`10.81%`) |
| `AIT-Test` | `Reconnaissance` | `95,487` | `95,181/95,487` (`99.68%`) | `95,219/95,487` (`99.72%`) | `82,491/95,487` (`86.39%`) | `82,191/95,487` (`86.08%`) |
| `CTU-Echo` | `Reconnaissance` | `36,576` | **`0/36,576` (`0.00%`)** | **`0/36,576` (`0.00%`)** | `33,312/36,576` (`91.08%`) | `33,562/36,576` (`91.76%`) |
| `CTU-Win7AD` | `Exploitation_And_C2` | `2,036` | **`0/2,036` (`0.00%`)** | **`1/2,036` (`0.049%`)** | `6/2,036` (`0.29%`) | `1,863/2,036` (`91.50%` at `FPR=0.8545`) |
| `CTU-Win7AD` | `Malware_And_DoS` | `2` | `0/2` (`0.00%`) | `0/2` (`0.00%`) | `1/2` (`50.00%`) | `1/2` (`50.00%`) |

### 3.3 Tham chiếu các thí nghiệm chẩn đoán hiện có (`RQ2`, `RQ4`, `CTU-CrossSource`)
- **`rq2_imbalance_report.json` (`EXP-RQ2-IMBALANCE-001`):** Tỷ lệ mất cân bằng `AIT-Train` là `6.1115:1` (`1,658,795` Benign vs `271,424` Attack). Khi huấn luyện `RandomForest_CostSensitive` (`class_weight="balanced_subsample"`), Recall tổng trên `AIT-Test` tăng vọt từ `0.6678` (unweighted default trong RQ2) / `0.8185` (baseline manifest) lên **`0.99135`** (`F1=0.99510`, `Macro-F1=0.99698`, `FPR=0.000262`). Với `XGBoost_ScalePosWeight` (`6.1115`), Recall tăng nhẹ lên `0.82288` (`F1=0.90206`). **Tuy nhiên**, cả `RandomForest_CostSensitive` lẫn `XGBoost_ScalePosWeight` đều giữ nguyên điểm phát hiện `Credential_Attack` ở **`11/78` (`14.10%`)**.
- **`rq4_unknown_attack_report.json` (`EXP-RQ4-UNKNOWN-001`):** Khi loại `Exploitation_And_C2` + `Post_Exploitation_Discovery` (`42` mẫu test) khỏi Train: `IsolationForest` đạt unknown recall **`95.24%` (`40/42`)** ở `FPR=3.76%`, còn `Autoencoder` chỉ đạt **`21.43%` (`9/42`)** (`PR-AUC=0.000716`), chủ yếu bỏ sót `Post_Exploitation_Discovery` (chỉ `4/37 = 10.81%` trên baseline `AIT-Test`).
- **`ctu_cross_source_eval.json`:**
  - Khi đánh giá **CTU temporal** (train `AIT + CTU early days`, test `CTU late days`): `RF` đạt `F1=0.9600` (`Recall=0.9245, FPR=0.0020`), `XGB` đạt `F1=0.9521` (`Recall=0.9098, FPR=0.0018`) trên `ctu_echo_late_days`.
  - Khi đánh giá **Device-disjoint** (train `AIT + CTU-Echo`, test `CTU-Win7AD` chưa từng thấy): `RF` chỉ đạt `Recall=0.5074, FPR=0.1700, F1=0.0636`; `XGB` đạt `Recall=0.5039, FPR=0.1938, F1=0.0561`; `IF` gần như vô hiệu (`Recall=0.0044, FPR=0.4573, F1=0.00022`).

---

## 4. Chẩn đoán kỹ thuật nguyên nhân gốc rễ (Root-Cause Analysis)

### 4.1 Nguyên nhân RF & XGB sụp đổ zero-shot trên CTU (`CTU-Echo` F1=0.0, `CTU-Win7AD` F1=0.0 / 0.000735)

1. **Bất tương thích cách đếm byte giữa Tstat (AIT) và Zeek (CTU) — *Probe Accounting Mismatch*:**
   - Trong `AIT-NDS-v2` (xuất từ Tstat), `bytes_in` / `bytes_out` đo **TCP/UDP payload bytes**. Các flow quét cổng SYN/RST rỗng (`Reconnaissance`) có `bytes_in = 0, bytes_out = 0`.
   - Trong `CTU-SME-11` (xuất từ Zeek), trường `orig_ip_bytes` / `resp_ip_bytes` đo **tổng byte gói IP (bao gồm IP + TCP/UDP headers)**. Do đó, các probe TCP SYN scan 2 gói trên `CTU-Echo` (`duration_ms=0.0, pkts_in=2, pkts_out=0`) có median `bytes_in = 88.0, bytes_out = 0.0`, và tỷ lệ flow có `bytes_in == 0` là **`0.0000`**.
2. **Phụ thuộc quá mức vào shortcut byte tuyệt đối & Sụp đổ xác suất dưới ngưỡng `0.5`:**
   - Rút trích `feature_importances_` trực tiếp từ artifact `.joblib`:
     - **XGBoost:** `bytes_in = 0.354245`, `bytes_per_sec_in = 0.199612` (`top2 = 0.553857`), tiếp theo là `total_bytes = 0.083642`, `bytes_in_ratio = 0.083348`, `bytes_per_pkt_out = 0.080892`, `bytes_per_sec_out = 0.079616`.
     - **Random Forest:** `bytes_in_ratio = 0.188487`, `total_bytes = 0.140971`, `bytes_in = 0.140442` (`top2 = 0.329458`), `bytes_per_pkt_in = 0.116124`, `bytes_per_sec_in = 0.092993`.
   - Trên `AIT-Val`, riêng đặc trưng đơn `bytes_in` đã có `auc_symmetric = 0.965448` (`shortcut_audit`). Khi gặp `CTU-Echo` (`Reconnaissance` có `bytes_in = 88 > 0` và Benign có tới `20%` flow `bytes_out == 0`), **XGBoost đảo ngược phân hạng hoàn toàn** (`Attack p50 = 1.77e-5`, `Benign p95 = 0.470`, **ROC-AUC = `0.037340`**). Trong khi đó, **Random Forest vẫn giữ phân hạng tương đối (`ROC-AUC = 0.799629`)**, nhưng toàn bộ xác suất Attack bị nén dưới `0.5` (`Attack p50 = 0.090, max = 0.325` → `0/36,576` ở `th=0.5`; kiểm tra threshold sweep ở `0.05` thu hồi được `TPR = 0.8822` với `FPR = 0.1864`).
3. **Shift hạ tầng & trùng chéo hành vi trên `CTU-Win7AD` + Unseen ICMP:**
   - Nhóm `Exploitation_And_C2` trong `CTU-Win7AD` (`N=2,036` Trickbot/human) là các flow TCP ngắn, kích thước nhỏ (`median duration_ms=2.641, bytes_in=178.0, bytes_out=100.0, pkts_in=3.0, pkts_out=2.0`), trùng khít với `CTU-Win7AD Benign` (`median duration_ms=2.417, bytes_in=164.0, bytes_out=93.0, pkts_in=2.0, pkts_out=1.0`) và hoàn toàn đối lập với `AIT Exploitation_And_C2` (`N=5` reverse-shell/RCE: `median bytes_in=506,585, bytes_out=53,889..62,085, duration_ms=2.7–4.2s`).
   - Đồng thời CTU chứa `protocol_num=1` (ICMP: `6,371` Echo, `4,698` Win7AD) không hề có trong `AIT-Train` (`category_vocabularies={"protocol_num": [6, 17]}`).

### 4.2 Nguyên nhân `Credential_Attack` (`14.10%`) và `Data_Exfiltration` (`57.45%–60.64%` / `0%–0.05%`) có Recall thấp trên `AIT-Test`

1. **`Data_Exfiltration` (`N=80,075` trên `AIT-Test`, 100% UDP DNS tunneling `dnsteal`):**
   - Toàn bộ `Data_Exfiltration` là cặp gói UDP đơn lẻ (`duration_ms=0.0, pkts_in=1, pkts_out=1, protocol_num=17`).
   - **Tại sao Supervised bị gãy theo scenario & vách biên byte:** Trong `AIT-Train`, mỗi scenario DNS tunneling mang chữ ký byte rất hẹp (`harrison` med `189/208 B`, `wilson` `226/245 B`, `fox` `248/267 B`, `wardbeck` `251/269 B`, `santos` `266/284 B`). Sang `AIT-Test`:
     - `wheeler` (`n=19,177`, `bytes_in=231, bytes_out=250`) nằm lọt trong vùng Train → RF đạt `99.97%`, XGB đạt `99.73%`.
     - `shaw` (`n=60,898`) bị chẻ đôi đúng rìa quyết định: nhóm `bytes_in=248, bytes_out=265` thoát ngưỡng vừa đủ ở RF (`29,387` flows, `48.26%`, `RF_p50=0.5049`), còn nhóm `bytes_in=246, bytes_out=263` (`31,511` flows) rơi vào khoảng trống giữa `wilson` (`226/245`) và `fox` (`248/267`) nên sụp đổ xuống `RF_p50=0.4256` và `XGB_p50=0.0063`. Kết quả `RandomForest_CostSensitive` trong RQ2 nâng Recall tổng lên `0.9914` (`FPR=0.000262`) chứng tỏ khi triệt tiêu thiên lệch prior `6.11:1`, RF phủ được khe hở byte này, còn unweighted baseline bị lệch mạnh về Benign.
   - **Tại sao IF (`0/80,075 = 0.00%`) và AE (`37/80,075 = 0.046%`) mù hoàn toàn:** Vì cặp gói `1/1 pkt, dur=0.0, UDP 231–265 B` nằm lọt giữa đám đông mật độ cao của Benign UDP DNS (`shaw Benign UDP` median `45/87 B, 1/1 pkt, dur=0.0`), điểm bất thường của `Data_Exfiltration` (`IF_p50 = -0.1934`, `AE_p50 = 0.000035`) thậm chí còn **"bình thường hơn" Benign UDP** (`IF_p50 = -0.1917`, `AE_p50 = 0.000041`). Không thể tách `dnsteal` bằng distance/reconstruction đơn-flow nếu không có feature DNS payload hoặc thống kê theo phiên/host.
2. **`Credential_Attack` (`N=78` ở `shaw`, TCP `online_cracking`):**
   - Chỉ `11/78` (`14.10%`) flows có burst response khổng lồ (`median bytes_in=910, bytes_out=506,759, pkts_in=141, pkts_out=437`) được cả RF & XGB phát hiện.
   - `67/78` (`85.90%`) flows bị bỏ sót (`median duration_ms=54.8s, bytes_in=1,833, bytes_out=3,115, pkts_in=15, pkts_out=15, bytes_in_ratio=0.16`) chồng lấn trực tiếp lên phân phối Benign HTTP/SSH (`median duration_ms=5.1s, bytes_in=1,354, bytes_out=1,944, pkts_in=10, pkts_out=9`). Ngay cả `RandomForest_CostSensitive` & `XGBoost_ScalePosWeight` trong RQ2 vẫn dừng ở **`11/78` (`14.10%`)**, khẳng định đây là **nút thắt thông tin đơn-flow**, không thể giải quyết nếu chỉ tune weight/threshold.

### 4.3 Nguyên nhân Autoencoder bùng nổ FPR trên CTU (`0.6520` Echo, `0.8545` Win7AD) & IF FPR (`0.2086` / `0.4334`)

Kiểm tra `fitted_state` của `v2_flow_preprocessor.joblib` và đo đạc lỗi tái tạo từng feature chứng minh **3 cơ chế cộng hưởng**:

1. **`protocol_num` đi thô (unscaled passthrough) trực tiếp vào hàm MSE:**
   - `TrainOnlyPreprocessor` giữ `protocol_num` ngoài bước `asinh_robust` (`categorical_coded_columns=["protocol_num"]`, `handle_unknown_categories="passthrough"`). Trong khi 17 feature khác được nén về biên độ $O(1)$, `protocol_num` giữ nguyên giá trị `{1, 6, 17}`.
   - Trên `AIT-Train`/`AIT-Val` chỉ có `{6, 17}`, AE dễ dàng thuộc lòng mối tương quan giữa `protocol_num` và `is_tcp`/`is_udp` (`sq_err ~ 2.4e-5`). Khi gặp **ICMP (`protocol_num=1`)** trên CTU, dự đoán sai giao thức tạo squared error khổng lồ: **`7.58`** trên `CTU-Echo` Benign ICMP (`n=6,101`, `43.8%` tổng MSE nhóm này, **`FPR = 100.0%`**, `med_mse = 1.2355`) và **`10.06`** trên `CTU-Win7AD` Benign ICMP (`n=4,698`, `42.4%` tổng MSE nhóm này, **`FPR = 100.0%`**, `med_mse = 1.3292`). Tính trên toàn bộ tập Benign, riêng `protocol_num` đóng góp **`39.9%` mean Benign MSE trên `CTU-Echo` (`1.18281`)** và **`37.7%` trên `CTU-Win7AD` (`0.27382`)**.
2. **`pkts_in_ratio` suy biến IQR (`scale = 0.044269`) gây bùng nổ độ lệch khi `has_response = 0`:**
   - Trong `v2_flow_preprocessor.joblib`, `pkts_in_ratio` có `center = 0.481212` (`arcsinh(0.5)`) và **`scale = 0.044269`** — nhỏ hơn **`~6x–250x`** so với các feature liên tục khác (như `bytes_in_ratio scale = 0.266264`, `duration_ms scale = 11.050218`).
   - Nguyên nhân: hơn 50% flows `AIT-Train` có `pkts_in_ratio ~ 0.5`, ép IQR về gần `0.044`. Sang CTU, tỷ lệ flow Benign không có chiều phản hồi (`has_response = 0`, `pkts_in_ratio = 1.0`) chiếm tới `20.0%` (`CTU-Echo`) và `45.6%` (`CTU-Win7AD`), bị phóng đại thành `(arcsinh(1.0) - 0.481212) / 0.044269 = +9.039` (`+10.87` ở cực đại). Do đó, `pkts_in_ratio` gây **`21.8%` mean Benign MSE trên `CTU-Echo` (`0.64752`, chiếm `35.8%` trên Benign TCP)** và **`20.5%` trên `CTU-Win7AD` (`0.14868`, chiếm `44.0%` trên Benign TCP)**.
   - **Tổng hợp 2 lỗi preprocessing này (`protocol_num` + `pkts_in_ratio`) tạo ra `61.7%` (CTU-Echo) và `58.2%` (CTU-Win7AD) toàn bộ Benign MSE.**
3. **Ngưỡng quantile `0.95` siêu hẹp (`0.000228`) vs nhiễu rate-feature của Zeek Benign UDP (`~2ms`):**
   - `MLPRegressor(hidden_layer_sizes=[16, 8, 16], max_iter=50)` dừng ở `n_iter=31` với `final_loss = 8.177e-5`, khiến Benign `AIT-Val` có `med_mse = 3.487e-5` và ngưỡng p95 tụt xuống **`0.0002280`**.
   - Trong khi đó, `CTU-Echo` Benign UDP (`n=16,311`, chiếm `41.3%` Echo Benign) và `CTU-Win7AD` Benign UDP (`n=158,089`, chiếm `91.3%` Win7AD Benign) chủ yếu là các Zeek DNS flows siêu ngắn (`median duration_ms ~ 2.09–2.19ms`, ngắn hơn **`~2,500x`** so với AIT Benign median `~5.1–5.2s`), làm tăng `bytes_per_sec_out` (`~0.00814` sq_err) và `duration_ms` (`~0.00317` sq_err), đẩy **`AE FPR` trên Benign UDP lên `0.9920` (`CTU-Echo`, `med_mse=0.000361`) và `0.8898` (`CTU-Win7AD`, `med_mse=0.000383`)**! Đáng chú ý, ngay trong `artifacts/models/autoencoder/threshold.json`, ở quantile `0.99` (`threshold=0.0022274`), `AIT-Val` Recall gần như không đổi (`0.90516` vs `0.90542`) trong khi `Val FPR` giảm 5 lần (`0.01000` vs `0.05000`) và `Val F1` tăng từ `0.92115` lên `0.94423`.
   - Với **Isolation Forest**, `protocol_num=1` (`Benign proto=1 FPR = 0.6758` ở Echo và `0.9998` ở Win7AD) cùng nhóm UDP `2ms` + `has_response=0` (`Benign proto=17 FPR = 0.4404` trên Win7AD) là nguyên nhân trực tiếp đẩy FPR lên `0.2086` (`CTU-Echo`) và `0.4334` (`CTU-Win7AD`).

---

## 5. Model Improvement Plan trước khi Retrain

### 5.0 Hạ tầng & Provenance Prerequisites (Phải hoàn tất trước khi retrain)

1. **Khắc phục triệt để lỗi LF vs CRLF `split_manifest_sha256`:**
   - Chuẩn hóa EOL thành LF (`\n`) cho `data/V2_SPLIT_MANIFEST.json`, `reports/splits/v2_split_manifest.json`, `reports/preprocessing/v2_flow_preprocessing_manifest.json` (khớp `.gitattributes` `* text=auto eol=lf`), hoặc thay cách hash file thô bằng canonical JSON SHA-256 (`json.dumps(..., sort_keys=True)`) tại tầng verify để loại bỏ phụ thuộc OS EOL.
2. **Đảm bảo Clean-Commit Reproducibility & Đồng nhất Schema:**
   - Commit code/pipeline fix trước khi chạy retrain để `environment.git_commit` trỏ tới commit sạch (`git_dirty=false`).
   - Sửa `train_random_forest.py` truyền đủ `dataset_sha256`, `split_manifest_sha256`, `preprocessor_artifact_sha256` vào `RandomForestProtocol`; sửa `XGBoostModel.save()` / `train_xgboost.py` để xóa `provenance_note` mâu thuẫn khi lưu bản verified; dùng relative POSIX path cho `model_artifact_path`; sửa `IsolationForestModel` `"target": "label_binary"` và đồng bộ `config.py`; bổ sung kiểm tra `expected_split_manifest_sha256` vào `AutoencoderModel.load_verified()`; thống nhất logic `>` vs `>=` giữa calibration và evaluation; đồng bộ `ModelRegistry` truyền đúng feature columns để bỏ cảnh báo `UserWarning` và trỏ thống nhất `reports/models/*_manifest.json`.

### 5.1 Kế hoạch cho Agent E (Supervised Models: Random Forest & XGBoost)

1. **`P0` — Cân bằng lớp & Calibration ngưỡng trên Validation (không chạm Test):**
   - Áp dụng `class_weight="balanced_subsample"` cho Random Forest (kết hợp tuning `max_depth`, `min_samples_leaf`) và `scale_pos_weight` tuning (`[1.0, 3.0, 6.11, sqrt(6.11)]` kèm `max_depth`, `min_child_weight`, `reg_lambda`) cho XGBoost dựa trên **Macro-F1 / PR-AUC của `AIT-Val`**.
   - Bỏ ngưỡng cứng `0.5` mặc định: thực hiện probability calibration (`CalibratedClassifierCV` hoặc Isotonic/Platt trên `AIT-Val` cross-fit) và chọn decision threshold tối ưu theo chi phí FN/FP trên `AIT-Val` (để loại bỏ hiện tượng "vách biên" như `shaw Data_Exfiltration` `RF_p50=0.4256` hay `CTU-Echo` RF bị nén dưới `0.5`).
2. **`P0` — Ablation loại bỏ Shortcut Byte tuyệt đối & Chuẩn hóa Header-Offset Cross-Source:**
   - Thực hiện feature ablation kiểm soát `bytes_in` / `total_bytes` / `bytes_per_sec_in` thô vốn gắn chặt với Tstat L4 payload `0 B` vs Zeek L3 IP bytes `88 B`:
     - Bổ sung feature chuẩn hóa header-offset (ví dụ `est_payload_bytes_in = max(0, bytes_in - k_hdr * pkts_in)` trong adapter hoặc học trên phân phối đối chiếu `bytes_per_pkt_in <= 60` + `has_response`, `bytes_per_pkt_ratio`, `asinh` packet-symmetry).
     - Kiểm thử khả năng giữ ranking của RF (`ROC-AUC=0.7996` trên `CTU-Echo`) và khắc phục hiện tượng inverted ranking của XGBoost (`ROC-AUC=0.0373`).
3. **`P1` — Multi-Source Domain Randomization & Unseen-Host Evaluation:**
   - Tách rõ hai chế độ báo cáo: **(a) Zero-shot AIT-only** (đo trung thực khoảng cách cross-source) và **(b) Multi-source adaptation** (`AIT-Train + CTU-Echo early days` có kiểm soát header jitter / domain-invariant augmentation, đánh giá trên `AIT-Test`, `CTU-Echo late days` và unseen-host `CTU-Win7AD`).
   - Sử dụng scenario-grouped CV ngay trong `AIT-Train` để tune hyperparameters thay vì dựa vào duy nhất 1 scenario `AIT-Val` (`russellmitchell`).
4. **`P1` — Feature Ngữ cảnh Causal Window cho `Credential_Attack` & `Data_Exfiltration`:**
   - Vì `67/78` mẫu `Credential_Attack` trùng khít phân phối Benign đơn-flow ngay cả khi bật cost-sensitive weights, phối hợp bổ sung causal sliding-window features theo host/flow-key (`src_dst_flow_rate`, `dst_port_fanout`, `small_tcp_conn_burst`, `fixed_size_udp_repeat_ratio` chỉ dùng quá khứ trong cùng capture) mà không tạo data leakage giữa các partition.

- **Tiêu chí nghiệm thu (Agent E):** Zero-shot hoặc Multi-source model giữ `AIT-Val`/`AIT-Test` `FPR <= 0.002`, nâng `Data_Exfiltration` Recall từ `~57–61%` lên `>= 95%`, nâng `Credential_Attack` Recall vượt mốc `14.10%` bằng window features nếu được phép mở rộng contract, và kéo `CTU-Echo` / `CTU-Win7AD` khỏi sụp đổ `F1=0.0`.

### 5.2 Kế hoạch cho Agent F (Unsupervised Models: Isolation Forest & Autoencoder)

1. **`P0` — Sửa triệt để `TrainOnlyPreprocessor` cho Không gian Khoảng cách / MSE (bắt buộc trước khi retrain IF & AE):**
   - **Loại `protocol_num` raw passthrough:** Tách biến giao thức thành vector one-hot chuẩn hóa `[is_tcp, is_udp, is_icmp_or_other]` có biên độ bounded $[0, 1]$ và **loại `protocol_num` nguyên thủy** khỏi vector đầu vào tính khoảng cách/MSE của AE & IF, triệt tiêu hoàn toàn cú nổ `sq_err = 7.58–10.06` khi gặp ICMP (`proto=1`).
   - **Xử lý suy biến IQR ở `pkts_in_ratio` (`scale=0.044269`) & bất đối xứng `has_response=0`:** Áp dụng `min_scale_floor >= 0.25` (hoặc thay sang `StandardScaler` / `MinMaxScaler` / `QuantileTransformer(output_distribution="normal")` trên miền `asinh`, kèm clipping biến đã scale vào $[-5, +5]$) để flow Benign có `has_response=0` không bị phóng đại `+9.04 sigma` và chiếm `20.5%–21.8%` tổng MSE CTU.
2. **`P0` — Tái thiết kế Autoencoder Loss, Kiến trúc & Per-Feature Score Normalization:**
   - Thay `MLPRegressor(MSE)` nhạy outlier bằng mô hình **Huber / $L_1$ (hoặc Smooth-L1) reconstruction loss** có regularization (Denoising / Dropout hoặc L2 penalty hợp lý) và bottleneck tránh memorize tương quan tầm thường.
   - Chuẩn hóa reconstruction error **theo từng feature** (chia residual $|x_j - \hat{x}_j|$ cho median/MAD trên `AIT-Val Benign`, hoặc trim top-1/top-2 feature spikes / Winsorize error) trước khi tổng hợp điểm bất thường, ngăn `bytes_per_sec_out` của các UDP DNS flow ngắn (`2ms`) áp đảo toàn bộ ngưỡng.
3. **`P0/P1` — Calibration Ngưỡng & OOD Gating theo Giao thức:**
   - Mở rộng tìm kiếm ngưỡng trên `AIT-Val Benign` từ `p95` sang `p97–p99.5` (hoặc phân tầng theo protocol `TCP` / `UDP` / `Other`, vì ngay trên bản hiện tại `p99=0.0022274` giữ `Val Recall = 0.9052` mà giảm `Val FPR` 5 lần và nâng `Val F1` lên `0.9442`), kết hợp **OOD gate** khi dữ liệu test chứa giao thức chưa gặp (`protocol_num=1`) hoặc tốc độ/duration lệch khỏi `AIT-Val` nhiều bậc độ lớn.
   - Với **Isolation Forest:** Tinh chỉnh `max_samples`, `n_estimators`, stratified Benign sampling theo từng scenario của `AIT-Train` (tránh thiên lệch scenario lớn), và thực hiện ablation loại bỏ hoặc nén các rate features nhạy duration `2ms` (`bytes_per_sec_out`, `pkts_per_sec`) để giảm `CTU-Win7AD` Benign UDP FPR từ `44.04%` xuống mức kiểm soát được.
4. **`P1` — Cải thiện phát hiện `Post_Exploitation_Discovery` & `Data_Exfiltration`:**
   - Khắc phục thất bại của AE trên unknown holdout trong RQ4 (`21.43%` so với IF `95.24%`) thông qua tái thiết kế scaler + Huber/L1 + per-feature standardized residual.
   - Lưu ý giới hạn khoa học trung thực: với `Data_Exfiltration` (`dnsteal` `1/1 pkt, dur=0, UDP 231–265 B`), mọi mô hình **phi giám sát đơn-flow** đều bị chặn bởi giao thoa mật độ với Benign UDP DNS; cần bổ sung behavioral/DNS-burst window features nếu đặt mục tiêu phát hiện nhóm này ở chế độ không nhãn.

- **Tiêu chí nghiệm thu (Agent F):** Giảm `CTU-Echo` / `CTU-Win7AD` Benign FPR từ `0.6520 / 0.8545` (AE) và `0.2086 / 0.4334` (IF) xuống mức tiệm cận mục tiêu kiểm soát (`<= 0.05–0.10`), giữ `AIT-Val/Test` FPR `<= 0.05` (ưu tiên `~0.01–0.03`), nâng unknown-attack recall của AE trên bài toán kiểu RQ4 lên `>= 0.75`, và đảm bảo `protocol_num=1` không còn tạo FPR `100%`.

---

## 6. Kết quả Post-Remediation & Controlled Experiments (`2026-11-18`)

Sau khi khắc phục `DATA-A01..A04` (phục hồi đủ `3,464,400` flows có nhãn từ chunk boundary, sửa `udp_complete` `* 1000.0 ms`, chuẩn hóa CTU Zeek sang L4 payload `orig_bytes`/`resp_bytes`, áp `MIN_BOUNDED_SCALE_FLOOR = 0.25` cho biến bounded trong `asinh_robust`, và chuẩn hóa LF `ed542ee80babca26...`), toàn bộ 4 mô hình đã được thử nghiệm có kiểm soát trên `AIT-Val` (không chạm `AIT-Test`) trong `reports/experiments/ml/model_improvement_summary.json` và retrain bản chính thức:

### 6.1. Provenance & Verification Status (`verify_companion_artifacts.py`: `READY 4/4`)

| Thành phần | Artifact SHA-256 | Run ID / Contract | Ghi chú khắc phục |
|---|---|---|---|
| `TrainOnlyPreprocessor` | `0866dec7252d36d3f2bb2becddf266787cc49ddf19306a8e003ba1e951cf51a7` | Split `ed542ee80babca26f6e8ad977168b061e18e99a24be1cbe1ec8767b66d6339e8` (LF) | `MIN_BOUNDED_SCALE_FLOOR = 0.25`; fit strictly on `ait_train` (`2,097,891`) |
| `Random Forest` | `b2e42f85f2625f5bf04902a032a4db734f4c4e744d45f4fef3ddffd05a694f2f` | `v2-rf-20261117T231214Z` (`balanced_subsample`, `min_samples_leaf=5`) | Đã điền đủ `SplitReference` & `PreprocessingReference` (`VERIFIED`) |
| `XGBoost` | `33d201f8f3d842c0b71547532c74f3d107bd402d8a65e20241ff5f407723aa48` | `v2-xgb-20261117T231609Z` | Sửa `provenance_note` verified, relative POSIX path |
| `Isolation Forest` | `11b1690088bca1984df9280b3c5662fbb13a76ca31e55258b9de43d6a10a6885` | `v2-if-20261118T020525Z` (`th=0.031268`, `>=` FPR `0.049991`) | Đổi `target="label_binary"`, thêm `top_features` permutation importance |
| `Autoencoder` | `e6afecefdc939a09e3c7fedd3e994a10c404f74e9b52c9ab95dfd984aae0cd4f` | `v2-ae-20261118T020635Z` (`(16,8,16)` Benign std, `th=0.000467`, FPR `0.049996`) | Thêm per-feature Benign standardization, check `expected_split_manifest_sha256`, `top_features` |
| `OODRejectionGate` | `8a52bfe5ad156560a3949afd5d4860c175ce5d158c38eb47aae07342102e9825` | `artifacts/ml/ood_reference_gate.json` (`2,097,891` raw train rows) | Khớp không gian raw `feature_dict`; kiểm chứng cả persisted artifact (`verify_ood_gate_artifact`) lẫn injected gate (`validate_ood_gate_instance`: schema, finite arrays, provenance, preprocessor SHA); `deployment` mode cấm inject in-memory gate và khóa fail-closed |
| `AE score_normalization.json` | `d7bcb78f7439930ee61b53e6e970ff1535d52ad10f2a025ad4877629a7478847` | `artifacts/models/autoencoder/score_normalization.json` | Sidecar chuẩn hóa điểm AE; cross-checked lúc load (`_validate_ae_contract_before_deserialize`) & stage standalone |

### 6.2. So sánh Thực nghiệm Trước vs Sau Khắc phục (Cohort Đầy đủ `AIT-Test = 988,805`)

| Mô hình | Baseline `AIT-Test` F1 | Post-Fix `AIT-Test` F1 | Delta `AIT-Test` | Baseline `CTU-Echo` F1 | Post-Fix `CTU-Echo` F1 | Post-Fix `CTU-Win7AD` F1 / ROC-AUC |
|---|---:|---:|---:|---:|---:|---:|
| **Random Forest** | `0.8997` | **`0.9950`** (`ROC=0.9994`) | **`+0.0953`** | `0.0000` | **`0.0474`** (`AUC=0.6137`) | **`0.0712`** / `0.8392` |
| **XGBoost** | `0.8910` | **`0.9013`** (`ROC=0.9884`) | **`+0.0103`** | `0.0000` | **`0.1436`** (`AUC=0.7017`) | **`0.0738`** / `0.6978` |
| **Isolation Forest** | `0.5766` | **`0.5842`** (`ROC=0.8330`, `FPR=0.0290`) | **`+0.0076`** | `0.8527` | **`0.8853`** | `0.0464` (`FPR=0.4722`) |
| **Autoencoder** | `0.5788` | **`0.5877`** (`FPR=0.0276`) | **`+0.0089`** | `0.7000` | **`0.7325`** | `0.0326` (`FPR=0.6925` vs `0.8545`) |

- **Ghi chú trung thực về giới hạn còn lại:** Mặc dù `CTU-Echo` và `AIT-Test` đều cải thiện rõ trên cả 4 mô hình (và `XGB CTU-Echo ROC-AUC` hết bị đảo dấu `0.0373 -> 0.7017`), `supervised zero-shot` trên `CTU-SME-11` vẫn suy giảm mạnh về Recall tuyệt đối tại ngưỡng `0.5` do chênh lệch lưu lượng nền, nên `random_forest`/`xgboost` chỉ hợp lệ cho phân tích in-domain hoặc multi-source domain-adapted, còn `isolation_forest`/`autoencoder` giữ `deployment_tier = "RESEARCH_ONLY"`.

---

### 6.3. Đối chiếu Toàn diện Baseline `E0` trên Toàn Bộ Chỉ số & Nhóm Tấn công Hiếm (`wp3_controlled_ablation_report.json`)

Bảng đối chiếu đầy đủ trích xuất trực tiếp từ 4 model manifest và `reports/experiments/ml/wp3_controlled_ablation_report.json` (`canonical-flow-v2-18`, `split_manifest_sha256 = ed542ee80babca26f6e8ad977168b061e18e99a24be1cbe1ec8767b66d6339e8`, `preprocessor_sha256 = 0866dec7252d36d3f2bb2becddf266787cc49ddf19306a8e003ba1e951cf51a7`):

| Mô hình / Split | Precision | Recall | F1 | Macro-F1 | ROC-AUC | PR-AUC | FPR | Confusion Matrix (`tn, fp, fn, tp`) | Latency (`s` / `us/flow`) |
|---|---:|---:|---:|---:|---:|---:|---:|---|---|
| **RF** (`AIT-Val`) | `0.9998` | `0.9996` | `0.9997` | `0.9997` | `0.9999` | `0.9999` | `0.0002` | `206635 / 41 / 76 / 170952` | `0.5992s` / `1.5865us` |
| **RF** (`AIT-Test`) | `0.9989` | `0.9911` | `0.9950` | `0.9969` | `0.9994` | `0.9977` | `0.0002` | `812780 / 200 / 1563 / 174262` | `1.8561s` / `1.8771us` |
| **RF** (`CTU-Echo`) | `0.2318` | `0.0264` | `0.0474` | `0.3495` | `0.6137` | `0.6180` | `0.0811` | `36295 / 3202 / 35610 / 966` | `0.1499s` / `1.9709us` |
| **RF** (`CTU-Win7AD`) | `0.0381` | `0.5412` | `0.0712` | `0.4906` | `0.8392` | `0.4948` | `0.1608` | `145280 / 27828 / 935 / 1103` | `0.2682s` / `1.5311us` |
| **XGB** (`AIT-Val`) | `0.9998` | `0.9993` | `0.9996` | `0.9996` | `0.9999` | `0.9999` | `0.0002` | `206643 / 33 / 119 / 170909` | `0.1844s` / `0.4882us` |
| **XGB** (`AIT-Test`) | `0.9989` | `0.8211` | `0.9013` | `0.9411` | `0.9884` | `0.9728` | `0.0002` | `812819 / 161 / 31461 / 144364` | `0.4992s` / `0.5048us` |
| **XGB** (`CTU-Echo`) | `0.5240` | `0.0832` | `0.1436` | `0.4065` | `0.7017` | `0.6747` | `0.0700` | `36733 / 2764 / 33533 / 3043` | `0.0413s` / `0.5424us` |
| **XGB** (`CTU-Win7AD`) | `0.0395` | `0.5623` | `0.0738` | `0.4918` | `0.6978` | `0.4774` | `0.1611` | `145215 / 27893 / 892 / 1146` | `0.0905s` / `0.5170us` |
| **IF** (`AIT-Val`) | `0.9375` | `0.9057` | `0.9213` | `0.9291` | `0.9705` | `0.9718` | `0.0500` | `196344 / 10332 / 16129 / 154899` | `2.6781s` / `7.0904us` |
| **IF** (`AIT-Test`) | `0.7775` | `0.4678` | `0.5842` | `0.7576` | `0.8330` | `0.6587` | `0.0290` | `789443 / 23537 / 93566 / 82259` | `8.4309s` / `8.5264us` |
| **IF** (`CTU-Echo`) | `0.8001` | `0.9908` | `0.8853` | `0.8759` | `0.9571` | `0.9237` | `0.2292` | `30445 / 9052 / 336 / 36240` | `0.3866s` / `5.0816us` |
| **IF** (`CTU-Win7AD`) | `0.0238` | `0.9760` | `0.0464` | `0.3686` | `0.7649` | `0.1002` | `0.4722` | `91369 / 81739 / 49 / 1989` | `1.4767s` / `8.4314us` |
| **AE** (`AIT-Val`) | `0.9375` | `0.9061` | `0.9215` | `0.9293` | `0.9192` | `0.9501` | `0.0500` | `196343 / 10333 / 16064 / 154964` | `0.1558s` / `0.4126us` |
| **AE** (`AIT-Test`) | `0.7860` | `0.4693` | `0.5877` | `0.7597` | `0.5544` | `0.5664` | `0.0276` | `790512 / 22468 / 93317 / 82508` | `0.4961s` / `0.5017us` |
| **AE** (`CTU-Echo`) | `0.5783` | `0.9990` | `0.7325` | `0.6116` | `0.7810` | `0.7146` | `0.6746` | `12851 / 26646 / 37 / 36539` | `0.0294s` / `0.3869us` |
| **AE** (`CTU-Win7AD`) | `0.0166` | `0.9921` | `0.0326` | `0.2515` | `0.7280` | `0.0204` | `0.6925` | `53227 / 119881 / 16 / 2022` | `0.0819s` / `0.4678us` |

- **Per-attack Recall trên `AIT-Test` (`N = 988,805`):**
  - `Reconnaissance` (`N = 95,628`): RF `0.9962`, XGB `0.9960`, IF `0.8597`, AE `0.8623`.
  - `Data_Exfiltration` (`N = 80,075` — `wheeler` + `shaw` DNS tunneling): RF `0.9860`, XGB `0.6128`, IF `0.0000`, AE `0.0005` *(IF/AE hoàn toàn mù với slow DNS tunneling ở mức flow đơn lẻ; XGB sụt mạnh trên `wheeler`/`shaw` chưa thấy)*.
  - `Credential_Attack` (`N = 78` — mẫu hiếm): RF `0.1410`, XGB `0.1410`, IF `0.1410`, AE `0.0641` *(nút thắt single-flow overlap với benign HTTPS/SSH)*.
  - `Post_Exploitation_Discovery` (`N = 39` — mẫu rất hiếm): RF `0.8974`, XGB `0.8974`, IF `0.8974`, AE `0.1026`.
  - `Exploitation_And_C2` (**`N = 5` — không đủ lực thống kê**): Cả 4 mô hình đạt `1.0000` (`5/5`), **KHÔNG được phép diễn giải thành khả năng tổng quát hóa `100%`**.

---

### 6.4. Thí nghiệm Kiểm soát WP3 (`E1`–`E5`), Ranh giới Leakage & Quyết định Lựa chọn Candidate (`RETAIN_E0_BASELINE_ARTIFACTS`)

Toàn bộ thí nghiệm được thực thi bằng [`scripts/run_wp3_controlled_ablation.py`](../../scripts/run_wp3_controlled_ablation.py) (tổng thời gian `986.03s`, kết quả tại [`reports/experiments/ml/wp3_controlled_ablation_report.json`](../experiments/ml/wp3_controlled_ablation_report.json)). **Phân tách trung thực ranh giới sử dụng từng split (`leakage_policy`):**
- **Model fitting & Feature transform fitting (`E0`–`E3b`):** Chỉ sử dụng `ait_train` (`2,097,891` flows; IF/AE fit trên Benign `ait_train`). Thí nghiệm `E4` chạy 5-fold LOSO CV hoàn toàn bên trong `ait_train` (`4` kịch bản train / `1` kịch bản held-out). Trong `E5` Tiers 2–3 (`RESEARCH_ONLY`, tách riêng khỏi zero-shot), `CTU-Echo` / early-days CTU chỉ được dùng trong các cấu hình adaptation có gắn nhãn `RESEARCH_ONLY`.
- **Threshold calibration & Hyperparameter tuning (`E0`–`E3b`):** RF & XGB giữ ngưỡng xác suất nhị phân cố định `0.5`; IF & AE hiệu chuẩn quantile `target_fpr=0.05` trên `ait_val` (`russellmitchell`); IF trong `E4` dùng quantile `0.95` của train-fold Benign (`ait_train`). Do đó `ait_test_used_for_training = false`, `ait_test_used_for_feature_transform_fitting = false`, `ait_test_used_for_threshold_calibration = false`, `ait_test_used_for_hyperparameter_tuning = false`, và `ctu_used_for_training_in_zero_shot_experiments = false`.
- **Post-hoc evaluation & Quyết định giữ `E0` (`selection_recommendation`):** Các tập `ait_val`, `ait_test`, `ctu_echo`, `ctu_windows7ad` đều được đánh giá hậu nghiệm (`posthoc_evaluation`). Khối `selection_recommendation` (`RETAIN_E0_BASELINE_ARTIFACTS`) trực tiếp trích dẫn kết quả hậu nghiệm của `AIT-Test Data_Exfiltration`, `CTU-Win7AD`, `CTU-Echo` cùng `AIT-Val FPR`, `E4` và `E5` để biện minh giữ nguyên 4 artifact `E0`; vì vậy đây là **quyết định bảo lưu hậu nghiệm có tham khảo holdout** (`selection_type = "posthoc_holdout_informed_retention_decision"`, `ait_test_used_for_posthoc_candidate_selection = true`, `ctu_used_for_posthoc_candidate_selection = true`, `holdout_independent_selection = false`), **không** phải kết quả lựa chọn candidate độc lập hoàn toàn với holdout. Không có trọng số, ngưỡng hay feature nào của `E0` bị tối ưu lại hoặc thay thế theo `AIT-Test`/`CTU`.

| Thí nghiệm | Thiết lập đặc trưng / Split | Phát hiện định lượng chính | Kết luận kiểm soát |
|---|---|---|---|
| **E1 (6 base features)** | `duration_ms, bytes_in, bytes_out, pkts_in, pkts_out, protocol_num` | RF Test `F1=0.9184` (`Exfil=0.7081`), Val `FPR=0.0031`; XGB Test `F1=0.7324` (`Exfil=0.0803`), Win7AD `F1=0.3632 / FPR=0.0176`; IF Test `0.5921` (Echo `FPR=0.3328`); AE Test `0.5914` (`Exploit=0.0`, `PostEx=0.0`, Win7AD `FPR=0.5999`) | Bỏ 12 engineered features làm sụp đổ `Data_Exfiltration` của XGB (`0.6128 -> 0.0803`) và AE/RF recall; XGB Win7AD cải thiện nhẹ nhưng vẫn bất ổn giữa Echo/AIT |
| **E2 (12 non-byte/rate features)** | Bỏ `bytes_in, bytes_out, total_bytes, bytes_per_sec_in, bytes_per_sec_out, pkts_per_sec` | RF Test `F1=0.9944` (`Exfil=0.9837`), Win7AD `F1=0.0707 / FPR=0.1599`; XGB Test `F1=0.7989` (`Exfil=0.2722`), Echo `F1=0.1473`; IF Test `0.5756`, Echo `0.8845`; AE Test `0.5679`, Win7AD `FPR=0.8308` | Cắt 6 biến byte/rate thô chưa đủ triệt tiêu shift `CTU-Win7AD` vì `bytes_per_pkt_{in,out}` vẫn giữ shortcut phân bố payload (`RF` giữ `AIT` tốt nhưng Win7AD FPR vẫn `0.1599`) |
| **E2b (10 pure non-byte features)** | Bỏ thêm `bytes_per_pkt_{in,out}` | RF Win7AD nhảy vọt **`F1=0.5665, P=0.6709, R=0.4902, FPR=0.0028, AUC=0.8869`**, NHƯNG RF AIT-Val `FPR` tăng 388x (`0.0002 -> 0.0770`), Test `Exfil` giảm (`0.9380`), và CTU-Echo sụp xuống **`F1=0.0067 (R=0.0034)`**; XGB Test `0.7862`, Win7AD `0.0723` | **Bằng chứng nhân quả:** `bytes_per_pkt_{in,out}` và byte counts chính là nguồn phát sinh Win7AD FP cho RF, nhưng loại bỏ hoàn toàn byte features đánh đổi quá nặng: phá vỡ `AIT-Val FPR` (`0.0770`) và xóa sổ recall trên `CTU-Echo` |
| **E3a (Protocol semantic one-hot, IF & AE)** | Thay ordinal `protocol_num` bằng `[proto_is_tcp, proto_is_udp, proto_is_icmp, proto_is_other]` (`21` dims) | AE AIT-Test `F1` tăng `0.5877 -> 0.6496` (`AUC 0.5544 -> 0.6357`), CTU-Echo `F1` tăng `0.7325 -> 0.8134` (`FPR 0.6746 -> 0.4222`), CTU-Win7AD `AUC 0.7280 -> 0.8075` (`FPR 0.6925 -> 0.6335`). IF ổn định (`Test 0.5845`, `Echo 0.8815`, `Win7AD 0.0479`) | Mã hóa ngữ nghĩa protocol cải thiện rõ AE (triệt tiêu giả định khoảng cách tuyến tính `protocol_num=1`) và cắt `-0.2524` FPR ở `CTU-Echo`, nhưng FPR trên `CTU-Win7AD` (`0.6335`) vẫn quá cao do mismatch `duration ~ 2ms` trên UDP benign của Zeek |
| **E3b (Semantic one-hot + `floor=0.25`)** | One-hot protocol + `min_scale_floor=0.25` trên ratio/flag `[0,1]` | AE AIT-Test `F1=0.5920` (`AUC=0.8080`, `FPR=0.0245`), Echo `F1=0.7912` (`FPR=0.4866`), nhưng Win7AD `FPR=0.8395` | Cắt bớt trọng số bất thường trên `protocol` khiến AE nhạy quá mức với biến lệch duration/bytes ở Win7AD |
| **E4 (5-fold LOSO CV trong `AIT-Train`)** | GroupKFold theo 5 scenario `{fox, harrison, santos, wardbeck, wilson}` | RF: `F1 = 0.9876 ± 0.0062` (`[0.9782 wardbeck, 0.9956 fox]`, `FPR mean=0.00035`, `Exfil min=0.9977`); XGB: `F1 = 0.9224 ± 0.0900` (`min=0.7585 harrison`, `Exfil min=0.0230 harrison`); IF: `F1 = 0.5179 ± 0.2361` (`[0.2072 wardbeck, 0.7971 harrison]`, `Exfil mean=0.0003`) | Khẳng định phương sai liên-kịch bản rất lớn ở XGB (`Exfil 0.023` khi hold-out `harrison`) và IF; đánh giá trên một scenario `AIT-Val` duy nhất (`russellmitchell`) không đại diện hết phương sai `AIT` |
| **E5 (Domain Adaptation 3 tầng)** | Tier 1 (`Zero-Shot`), Tier 2 (`AIT+Echo -> unseen Win7AD`, `RESEARCH_ONLY`), Tier 3 (`CTU Early->Late`, `RESEARCH_ONLY`) | Tier 2 Win7AD: RF `F1=0.0928 / AUC=0.8280` (nhưng AIT-Test tụt `0.9950 -> 0.7904`), XGB `0.0923 / AUC=0.8465`, AE `AUC=0.9520` (`FPR=0.4688`). Tier 3 `CTU-Echo late`: RF `0.9634`, XGB `0.9589`, IF `0.9132`, AE `0.2875` (`Win7AD late`: không còn attack sau ngày cắt, `FPR RF=0.0005 / AE=0.0413`) | Chỉ **adaptation cùng nguồn/thiết bị (`Tier 3`)** mới đạt FPR thấp & F1 > 0.95 trên Zeek; fine-tuning hay thay ngưỡng không biến `AIT-only` thành `production_ready` cross-source |

- **Quyết định Bảo lưu Candidate Hậu nghiệm (`RETAIN_E0_BASELINE_ARTIFACTS` — `posthoc_holdout_informed_retention_decision`):** Giữ nguyên 4 artifact E0 đã ký SHA-256 trên hợp đồng `canonical-flow-v2-18` và preprocessor `0866dec7...`, toàn bộ giữ `deployment_tier = "RESEARCH_ONLY"` và `cross_source_validated = false`. Lý do dựa trên đối chiếu tổng hợp `AIT-Val`, `E4` LOSO CV và đánh giá hậu nghiệm holdout: (i) `E1/E2/E2b` làm suy giảm in-domain FPR (`AIT-Val`) hoặc sụp đổ recall ở nguồn còn lại (`AIT-Test Data_Exfiltration` / `CTU-Echo`); (ii) `E3a/E3b` đổi vector schema từ `18` sang `21` chiều mà không giảm được FPR `CTU-Win7AD` xuống vùng vận hành (`<= 0.05`); (iii) `E5 Tiers 2–3` yêu cầu telemetry/nhãn từ môi trường đích nên không hợp lệ cho `zero-shot` baseline của PR `#156`. Lưu ý đây là quyết định phân tích hậu nghiệm có tham khảo holdout (`holdout_independent_selection = false`), không sửa/retrain `E0`.

---

### 6.5. Tách bạch Ba Trạng thái Provenance (WP4)

| Trục Provenance | Phán quyết | Bằng chứng & Lý do |
|---|---|---|
| `artifact_integrity_verified` | **`PASS`** | Toàn bộ 4 model `.joblib`/`.pt`, `v2_flow_preprocessor.joblib` (`0866dec7...`), `V2_SPLIT_MANIFEST.json` (`ed542ee8...`), `ood_reference_gate.json` (`8a52bfe5...`) và AE `score_normalization.json` (`d7bcb78f...`) đều khớp SHA-256 trong `verify_companion_artifacts.py`. |
| `dataset_provenance_verified` | **`PASS`** *(AIT & CTU)* / **`BLOCKED`** *(UGR'16)* | `fetch_multi_source_dataset.py --verify-only` xác nhận 10 archive `AIT-NDS-v2`, 2 `AIT-LDS-v2.1` (cách ly không trộn vào weights/demo), 2 `AIT-ADS`, 4 `CTU-SME-11`; `UGR'16` trả `HTTP 403` nên giữ `BLOCKED`. |
| `source_reproducibility_verified` | **`DIRTY_DISCLOSED`** | 4 model manifest ghi trung thực `training_git_commit = 79ebb678b87de19cc6b664b587726983fecaf98f` và `git_dirty = true`. Theo nguyên tắc kiểm toán, không sửa giả `git_dirty = false`; tái huấn luyện từ clean commit thuộc `#154` sau khi chốt mã nguồn PR `#156`. |

