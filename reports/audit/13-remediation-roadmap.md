# Report 13 — Remediation Roadmap

## 1. Nguyên tắc

1. **Không sửa hash cho khớp**; phải tái sinh artifact từ canonical input.
2. **Không đóng issue bằng manifest/checkbox**; phải có artifact + test + verification command.
3. **Không trộn run**: mỗi run có `run_id`, evidence riêng, không ghi đè.
4. **Không credit working tree chưa commit**.
5. **Không merge PR khi review `CHANGES_REQUESTED`**.
6. Ưu tiên P0 security/integrity trước khi làm feature mới.

## 2. Phase 0 — Chốt sự thật và đóng băng trạng thái (0,5 ngày)

### Hành động

- Tạo audit baseline mới sau mỗi thay đổi; lưu `git rev-parse HEAD`.
- Mở lại (hoặc tạo follow-up) cho #15, #17, #31 nếu chưa đạt.
- Đánh dấu M2 là “reopened/incomplete” hoặc ghi rõ lý do trên milestone.
- Ghi rõ PR #51/#47/#49/#52 là branch-only, không tính vào main.

### Acceptance

- Issue state phản ánh đúng Report 04.
- Milestone M2 không còn được coi là hoàn thành.
- Không có thay đổi source trong phase này.

## 3. Phase 1 — Canonical provenance (P0, 1–2 ngày)

### Vấn đề

- split `main` `1ba6b2ef…`;
- RF `bb84c1e0…`;
- XGB/prep `845d8863…`;
- hardcode `bb84…` tại `scripts/train_random_forest.py:71`;
- EOL CRLF/LF làm hash đổi.

### Hành động

1. Chọn **một** canonical split:
   - Option A: tái sinh split từ raw data với protocol hiện tại;
   - Option B: dùng external split `bb84…` và commit index `.csv.gz` (hoặc manifest chứa hash do tool tính).
2. Bảo đảm `.gitattributes` `eol=lf` và mọi hash được tính trên byte LF.
3. Bỏ hardcode `EXPECTED_SPLIT_MANIFEST_SHA256`, `EXPECTED_PREPROCESSOR_*`; đọc từ manifest canonical.
4. Ghi `split_manifest_sha256` thật vào preprocessor/RF/XGB manifest.
5. Tạo `reports/provenance/chain.json`:

```json
{
  "dataset_sha256": "...",
  "split_manifest_sha256": "...",
  "preprocessor_artifact_sha256": "...",
  "rf_model_sha256": "...",
  "xgb_model_sha256": "...",
  "run_ids": {"preprocessing": "...", "rf": "...", "xgb": "..."}
}
```

### Acceptance

```text
python scripts/preprocess_nf_unsw_nb15_v3.py --verify-only
# exit 0, hash chain PASS

python scripts/train_random_forest.py --verify-only
# exit 0, split/preprocessor/model PASS
```

- Clean clone (`git clone` + `git checkout <commit>`) cho cùng hash.
- Không còn hash hardcode trong script.

## 4. Phase 2 — Fail-closed loaders (P0, 1 ngày)

### Hành động

1. `src/network_anomaly/inference/predict.py`:
   - `manifest_path` **bắt buộc**;
   - bắt buộc `model_artifact_sha256`, `feature_contract_version`, `preprocessor_artifact_sha256`;
   - bắt buộc `class_mapping`/classes;
   - không `except Exception: pass`;
   - gọi `RandomForestModel.load_verified`/`XGBoostModel.load_verified` thay vì `joblib.load` trần.
2. `src/network_anomaly/inference/pipeline.py`:
   - xóa hoặc đánh dấu private `predict_from_artifact`;
   - nếu giữ, phải yêu cầu manifest + hash.
3. `RandomForestModel.load_verified`:
   - chỉ chấp nhận `provenance_status == "VERIFIED"`;
   - yêu cầu `environment.git_commit` hợp lệ.
4. Thêm test âm:

```text
test_load_model_without_manifest_fails
test_load_model_with_empty_manifest_fails
test_load_model_with_unverified_provenance_fails
test_load_model_with_wrong_hash_fails
test_load_model_with_wrong_feature_contract_fails
```

### Acceptance

- Các test trên **FAIL đúng cách** (raise), không load.
- `INFERENCE_NO_MANIFEST`, `INFERENCE_EMPTY_MANIFEST`, `RF_UNVERIFIED_PROVENANCE` không còn accepted.
- Không còn `joblib.load` trần trong inference path.

## 5. Phase 3 — Tái sinh artifact (P0/P1, 2–4 ngày)

### 5.1. RF

```text
python scripts/train_random_forest.py
python scripts/train_random_forest.py --verify-only
```

Lưu:

- `artifacts/models/random_forest/random_forest_baseline.joblib`
- `reports/models/random_forest_manifest.json`
- validation predictions + metric
- `run_id`, git commit, env, split hash, preprocessor hash

### 5.2. XGBoost

```text
python scripts/train_xgboost.py
python scripts/run_experiments.py --step xgboost
```

Lưu artifact + manifest + validation metric. Thêm `--model xgboost` vào `scripts/predict.py`.

### 5.3. IF (nếu trong scope)

```text
python scripts/train_isolation_forest.py
```

Lưu:

- `model.joblib`
- `threshold.json`
- `manifest.json` có threshold, score direction, class mapping
- `threshold_calibration.json`

### Acceptance

- Mỗi model có `.joblib` + manifest + metric.
- `load_verified()` PASS với artifact thật.
- CLI predict chạy cho RF/XGB/IF.
- Không còn “manifest without artifact”.

## 6. Phase 4 — Test evaluation (P1, 1–2 ngày)

### Hành động

1. Chạy **một lần** trên test 345.953 dòng:
   - RF;
   - XGB (nếu có artifact).
2. Lưu:
   - predictions CSV có `row_id`;
   - confusion matrix + precision/recall/F1/FPR;
   - per-category breakdown;
   - `run_manifest.json` trỏ đúng model/split/preprocessor.
3. Cập nhật #12/#13; đóng chỉ khi metric + prediction + manifest khớp.

### Acceptance

```text
python scripts/run_experiments.py --step evaluate
# exit 0, sinh reports/evaluation/test_metrics.json
```

- Confusion matrix tổng đúng số test rows.
- Metric truy được về đúng run.
- Không dùng test để tune.

## 7. Phase 5 — Khoa học và leakage (P1/P2, 2–3 ngày)

### Hành động

1. **TTL ablation**:
   - RF có/không `MIN_TTL`/`MAX_TTL`;
   - DecisionTree 1 feature;
   - báo rõ metric thay đổi.
2. **Duplicate audit**:
   - exact/ML-feature/group overlap trên index thật;
   - quyết định dedup/không dedup có lý do.
3. **Temporal audit**:
   - boundary/purge gap;
   - distribution shift.
4. **Calibration**:
   - reliability curve/Brier nếu có probability.
5. **Cross-dataset**:
   - chỉ sau khi #47/#49 rebase và pass audit.

### Acceptance

- Báo cáo có bảng metric có/không TTL.
- Không còn claim “99,99%” mà không nêu TTL shortcut.
- Leakage audit có hash/index thật.

## 8. Phase 6 — Governance, CI, docs (P1/P2, 1–2 ngày)

### Hành động

1. CI:
   - thêm `push` cho lint-audit;
   - gate Ruff/Black cho file thay đổi;
   - thêm `xgboost` vào `check_environment.py`;
   - thêm job load artifact thật (nếu có artifact trong CI cache);
   - pin dependency + lockfile, pin Actions theo SHA, thêm `pip-audit`/SBOM (F-16).
2. Docs:
   - cập nhật README status matrix;
   - ARCHITECTURE ghi rõ “target vs implemented”;
   - thêm status matrix phân biệt IMPLEMENTED / TESTED / EXPERIMENTALLY VALIDATED;
   - sửa #31 49-feature → 47.
3. Milestone:
   - M2 reopen/incomplete;
   - M4 chỉ đóng khi E2E gate pass.

### Acceptance

- `lint-audit` chạy trên push `main`.
- README/ARCHITECTURE không còn claim lệch.
- Milestone state khớp Report 05.

## 9. Phase 7 — Hợp nhất PR branch-only (P2, 3–5 ngày)

Thứ tự:

1. **#50** (RF test eval) — rebase, sửa test index checksum/disjointness; merge sau #12.
2. **#47** (ingestion) — rebase, tích hợp `InferenceEligibilityGate`, sửa UUID hash.
3. **#49** (cross-dataset) — rebase trên #47, sửa E0 contamination.
4. **#52** (API) — rebase, dùng verified pipeline, audit auth/security.
5. **#51** (autoencoder) — rebase, artifact + real eval; chỉ merge khi #29 AC đạt.

### Acceptance

- Mỗi PR có CI + review approve + test mới.
- Không merge PR `CONFLICTING`/`CHANGES_REQUESTED`.
- Không credit branch-only trước merge.

## 10. Phase 8 — Delivery (P2/P3, theo scope)

- #19 PDF/slides/demo/handoff.
- #25 bảy experiments.
- #18 license/provenance.
- #20 final verification.

Chỉ bắt đầu sau Phase 1–6.

## 11. Thứ tự tổng

```text
Phase 0 (truth)
  → Phase 1 (provenance)
  → Phase 2 (fail-closed)
  → Phase 3 (artifacts)
  → Phase 4 (test eval)
  → Phase 5 (science)
  → Phase 6 (governance/CI/docs)
  → Phase 7 (branch PRs)
  → Phase 8 (delivery)
```

## 12. Bằng chứng nghiệm thu tối thiểu

| Check | Command | Kỳ vọng |
|---|---|---|
| Provenance | `python scripts/preprocess_nf_unsw_nb15_v3.py --verify-only` | exit 0 |
| RF verify | `python scripts/train_random_forest.py --verify-only` | exit 0 |
| Test suite | `python -m pytest tests -q -rs` | 0 failed; skip có lý do |
| RF inference | `python scripts/predict.py --model random_forest --input <csv> --output <csv>` | CSV + metadata |
| XGB inference | `python scripts/predict.py --model xgboost --input <csv> --output <csv>` | CSV + metadata |
| Fail-closed | test model không manifest/`{}`/`UNVERIFIED` | raise |
| Test metric | `python scripts/run_experiments.py --step evaluate` | exit 0 + metric |
| IF threshold | predict IF | `0/1`, không raw `-1/1` |
| Git hygiene | `git diff --check` | PASS |

## 13. Điều kiện dừng

Chỉ tuyên bố “remediation hoàn tất” khi:

1. Tất cả P0 đóng bằng test + artifact;
2. RF/XGB có test metric;
3. Không còn issue đóng sai;
4. CI gate chạy trên `main`;
5. Báo cáo mới thay thế Report 12 với verdict **READY** có bằng chứng.

Nếu thiếu bất kỳ điều nào, giữ verdict **NOT READY**.
