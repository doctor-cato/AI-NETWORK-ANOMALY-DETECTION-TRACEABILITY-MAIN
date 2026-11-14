# Report 09 — Security, Integrity & Supply Chain Audit

## 1. Phạm vi

- Audit static + dynamic trên snapshot `b14dfee`.
- Không có service/API trong `main`, nên không có bề mặt auth/network để kiểm thử.
- Các PR #52/#47/#49 không được tính là bề mặt của `main`.
- Không đọc file secrets; không tìm thấy secrets trong tracked files.

## 2. CWE-502 — Unsafe deserialization

### 2.1. Đường legacy

`src/network_anomaly/inference/pipeline.py:44`:

```python
model = joblib.load(path)
```

- Không kiểm tra hash.
- Không kiểm tra manifest.
- Không kiểm tra loại object trước khi deserialize.
- `joblib.load` có thể thực thi arbitrary code qua pickle.

**Mức**: P0 nếu đường này được gọi với artifact không tin cậy.

### 2.2. Đường inference mới

`src/network_anomaly/inference/predict.py:363`:

```python
loaded_obj = joblib.load(model_path)
```

Trước đó:

- `manifest_path` là optional (`283-301`);
- nếu không tìm thấy manifest, **vẫn load**;
- nếu manifest `{}`, tất cả check `if expected_sha`, `if feat_contract`, `if prep_sha` đều bị bỏ qua;
- chỉ raise nếu hash **có mặt và sai**.

Reproducer đã chạy:

```text
INFERENCE_NO_MANIFEST ACCEPTED
INFERENCE_EMPTY_MANIFEST ACCEPTED
```

**Mức**: P0. Đây là fail-open thực sự, không phải lý thuyết.

### 2.3. Model wrapper

- `RandomForestModel.load()` (`random_forest.py:219-246`) gọi `joblib.load` trực tiếp.
- `XGBoostModel.load()` (`xgboost_model.py:438-460`) gọi `joblib.load` trực tiếp.
- Hai hàm này không có “verified” trong tên, nhưng vẫn là public API và có thể bị dùng nhầm.
- `RandomForestModel.load_verified()` kiểm tra hash trước khi load, nhưng **chấp nhận `provenance_status: "UNVERIFIED"`** (`405-411`).
- `XGBoostModel.load_verified()` strict hơn: yêu cầu `VERIFIED`, git commit, 47 features, classes `[0,1]`.

**Mức**: P0 cho RF `UNVERIFIED`; P2 cho public `load()` nếu tài liệu không cảnh báo.

## 3. Integrity — chuỗi hash bị đứt

### 3.1. Hash không nhất quán

| Thành phần | Hash được ghi | Hash thực tế trên `main` |
|---|---|---|
| Split manifest | RF: `bb84c1e0…`; XGB/prep: `845d8863…` | `1ba6b2ef…` |
| RF preprocessor artifact | `12d4360a…` | không có trong Git |
| XGB preprocessor artifact | `e1e89bde…` | không có trong Git |
| Preprocessing manifest | XGB: `666a7aae…` | `666a7aae…` (khớp file) |

- `845d8863…` là biến thể **CRLF** của cùng nội dung split manifest `1ba6b2ef…` (đã tái lập bằng đổi LF→CRLF); `.gitattributes` buộc `eol=lf`, nên checkout sạch luôn cho `1ba6…`.
- Vì vậy `verify_preprocessing_artifact()` báo:
  - `Companion manifest split_manifest_sha256 (845d…) does not match current split manifest hash (1ba6…)`.
- `scripts/train_random_forest.py:71` hardcode `EXPECTED_SPLIT_MANIFEST_SHA256 = bb84…`, nên `--verify-only` fail trên clean HEAD.

**Mức**: P0. Đây là lỗi integrity, không chỉ là “cosmetic hash mismatch”.

### 3.2. Hash không phải chữ ký

Ngay cả khi hash khớp, cơ chế hiện tại chỉ là **integrity**, không phải **authenticity**:

- kẻ tấn công có quyền ghi artifact có thể thay cả model và manifest;
- không có chữ ký số/trust root;
- không có HMAC/key management.

**Mức**: P2 (thiết kế), nhưng trở thành P0 nếu model được tải từ nguồn không tin cậy.

### 3.3. Test lock không được chứng minh toàn cục

- RF manifest ghi `test_partition_accessed: false` cho **training**.
- Preprocessing evidence lại ghi test `row_count`, `all_finite`, `zero_duration` — test đã được materialize ở bước preprocessing.
- Không có audit trail chứng minh test không được dùng để chọn feature/hyperparameter **trong toàn bộ vòng đời**.

**Mức**: P1 về governance/integrity.

## 4. Path và input validation

- `load_verified_model` nhận path từ CLI; không có path traversal guard nhưng đây là CLI local, không phải remote service.
- `scripts/predict.py` kiểm tra file tồn tại; không kiểm tra quyền file.
- `InferencePipeline.run()` kiểm tra output không trùng input; ghi atomic qua temp file.
- `validate_inference_input()` kiểm tra schema/order/feature; đây là điểm tốt.
- IF inference không kiểm tra threshold; output raw `-1/1` có thể bị hiểu sai.

## 5. Supply chain

| Rủi ro | Bằng chứng | Mức |
|---|---|---|
| Dependency không pin | `pyproject.toml` dùng `pandas>=2.2`, `numpy>=1.26`, `scikit-learn>=1.5`, `xgboost>=2.0`, `joblib>=1.3` | P2 |
| Không lockfile | Không có `requirements.lock`/`poetry.lock`/`uv.lock` | P2 |
| CI cài bản mới nhất | `pip install -e .` không `--require-hashes` | P2 |
| Actions dùng tag, không SHA | `actions/checkout@v4`, `setup-python@v5`, `upload-artifact@v4` | P2 |
| Không pip-audit/SBOM | Không có workflow | P2 |
| Artifact build khác CI | RF manifest: Python 3.14.10, sklearn 1.9.1, numpy 2.5.4; CI: 3.11/3.12 | P2 (reproducibility) |
| Raw data ngoài Git | `.gitignore`; hash verification | **PASS** |
| Secrets | Không tìm thấy trong tracked files | **PASS** |

## 6. Những gì không phải lỗi

- Không có API trong `main` → không có auth bypass để báo cáo.
- Không có SQLite trong `main` → không có SQL injection.
- Không có AES/key lifecycle trong `main` → không có key management vulnerability.
- PR #52 có API nhưng **branch-only**; không được coi là đã triển khai. Nếu merge, phải audit lại.

## 7. Kết luận

| ID | Severity | Finding |
|---|---|---|
| F-01 | **P0** | Inference loader fail-open: không manifest/`{}` vẫn load và predict |
| F-02 | **P0** | RF `load_verified` chấp nhận `UNVERIFIED` |
| F-03 | **P0** | Chuỗi hash split/preprocessor/model không nhất quán; hardcode hash |
| F-05 | **P1** | Test partition bị materialize trước evaluation; không có audit toàn cục |
| F-16 | **P2** | Supply chain không pin/lock/audit |
| F-21 | **P3** | Trainer tạo manifest `git_commit=UNKNOWN` ngoài Git → reload fail |

**Không được tuyên bố “verified inference”** khi F-01/F-02 còn tồn tại.
