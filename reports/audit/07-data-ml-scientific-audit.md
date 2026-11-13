# Report 07 — Data & ML Scientific Audit

## 1. Nguồn dữ liệu

| Thuộc tính | Giá trị | Bằng chứng |
|---|---|---|
| Dataset | NF-UNSW-NB15-v3 | manifest, README |
| File | `data/raw/NF-UNSW-NB15-v3/data/NF-UNSW-NB15-v3.csv` (ngoài Git) | external |
| Kích thước | 577.360.958 byte | BagIt + SHA-256 |
| SHA-256 | `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5` | khớp mọi manifest |
| SHA-1 | `2cba4879ead17c51e3268a01c06af41186cd90e4` | khớp BagIt |
| Số dòng dữ liệu | 2.365.424 | đọc thực tế |
| Số cột | 55 = 53 NetFlow + `Label` + `Attack` | header thực tế |
| Nhãn | 2.237.731 benign / 127.693 attack (17,52:1) | EDA report |

**Kết luận**: nguồn và byte dữ liệu **PASS**. Không có dấu hiệu file bị thay thế.

## 2. Split và preprocessing

### 2.1. Split được công bố

| Partition | Số dòng | Index hash (main manifest) | Index hash (external thật) |
|---|---|---|---|
| Train | 1.655.797 | `30ed493e…` | `a09ba175…` |
| Validation | 345.371 | `a3e4470c…` | `7d41a71a…` |
| Test | 345.953 | `90219f75…` | `63e2e081…` |
| Purged | 18.303 | — | — |
| Tổng | 2.365.424 | — | — |

Hai bộ hash **không khớp**, nhưng row count và label distribution của cả ba partition **giống hệt**:

- external manifest `bb84c1e0…` sinh `2026-10-27T10:46:58Z` — bản RF artifact dùng;
- main manifest `1ba6b2ef…` sinh `2026-11-08T14:45:31Z` — bản hiện tại trên `main`.

Có hai khả năng: cùng membership nhưng serialize khác thứ tự/encoding, hoặc membership khác nhưng trùng row count và phân bố nhãn. Không có index `.csv.gz` trong Git nên không thể phân biệt; hash chain vẫn **NOT VERIFIED**. Đây là lý do trực tiếp khiến RF artifact (`bb84…`) không verify được với `main` (`1ba6…`).

### 2.2. Preprocessing

`reports/preprocessing/execution_evidence.json` ghi:

- `git_commit`: `89c32fa8a5d19c1e00016d033724cf034ae4dc4e` (commit XGB, không phải RF);
- `split_manifest_sha256`: `845d8863…`;
- `artifact_sha256`: `e1e89bde…`;
- train 1.655.797 dòng, validation 345.371, **test 345.953** — tất cả `all_finite: true`;
- `purged_rows`: 18.303.

Điểm quan trọng:

- `845d8863…` **không phải split khác**: đó là SHA-256 của cùng nội dung `1ba6…` sau khi đổi LF→CRLF. `.gitattributes` buộc `eol=lf`, nên checkout sạch luôn cho `1ba6…`; vì vậy mọi manifest ghi `845d…` sẽ fail verify trên checkout sạch.
- Evidence này **không phải** của RF run (`6f506335…`) mà là của run XGB/preprocessing sau đó.
- Nó chứng minh **test partition đã được materialize và transform** trong preprocessing, trước khi evaluation.
- Việc transform test không tự động là leakage nếu transformer chỉ fit trên train; nhưng nó **phá vỡ tuyên bố “test bị khóa tuyệt đối”** nếu tuyên bố đó bao gồm cả preprocessing.
- `test_lock_audit` trong RF manifest chỉ nói training không load test; nó không chứng minh preprocessing chưa từng chạm test.

## 3. Random Forest — kết quả validation thật

### 3.1. Cách tái lập

Dùng external clone lịch sử:

- split indices thật khớp hash `bb84…` của RF manifest;
- preprocessor artifact `12d4360a…`;
- RF artifact `801afcbb…`;
- validation 345.371 dòng.

Kết quả tái lập **khớp 100%** với `reports/models/random_forest_manifest.json`.

### 3.2. Metric

| Metric | Giá trị |
|---|---|
| Confusion | `tn=314.866`, `fp=5`, `fn=3`, `tp=30.497` |
| Accuracy | `0,9999768365033543` |
| Precision | `0,9998360763228641` |
| Recall | `0,9999016393442623` |
| F1 | `0,9998688567587948` |
| FPR | `1,5879518914094977e-05` |
| Macro-F1 | `0,9999280765516589` |

**Đây là kết quả thật**, không phải synthetic. Nhưng chỉ trên **validation**, không phải test.

### 3.3. Ý nghĩa khoa học

Với 30.500 attack và 314.871 benign, mô hình chỉ sai 8/345.371 mẫu. Đây là mức gần như hoàn hảo — quá tốt để coi là bằng chứng generalization. Cần kiểm tra shortcut (mục 4) trước khi kết luận.

## 4. Shortcut learning trên TTL

### 4.1. Bằng chứng

- `MIN_TTL` + `MAX_TTL` chiếm **45,48%** tổng feature importance của RF.
- Một `DecisionTree` chỉ dùng **duy nhất `MIN_TTL`**, depth 3, đạt accuracy **0,9998494372718033** trên validation.
- Phân bố điều kiện:

| `MIN_TTL` | Số dòng validation | Attack rate |
|---|---|---|
| 31 | 308.033 | 0,0 |
| 62 | 7.820 | 1,0 |
| 254 | 22.629 | 0,9999558 |

### 4.2. Diễn giải

TTL trong UNSW-NB15 phản ánh **hop count/topology của lab IXIA CyberRange**, không phải hành vi tấn công nội tại. Mô hình đang học:

```text
MIN_TTL = 31  → gần như chắc chắn benign
MIN_TTL = 62  → gần như chắc chắn attack
```

Đây là **shortcut learning**, không phải phát hiện hành vi. Hệ quả:

- metric 99,99% **không chứng minh** mô hình phát hiện tấn công tốt;
- mô hình có thể sụp đổ trên mạng thật nơi TTL khác;
- mọi claim “state-of-the-art” hoặc “gần hoàn hảo” là **false confidence**.

### 4.3. Khuyến nghị khoa học

- Báo cáo metric có và không có `MIN_TTL`/`MAX_TTL`;
- thêm ablation theo nhóm feature;
- thử cross-dataset (PR #47/#49) để đo generalization;
- không dùng TTL làm feature mặc định nếu mục tiêu là phát hiện hành vi.

## 5. Leakage và validity

| Rủi ro | Trạng thái | Ghi chú |
|---|---|---|
| Target leakage (`Label`, `Attack`) | **PASS** | Bị loại khỏi X bằng contract/test |
| Metadata leakage (IP/port/timestamp) | **PASS** | 6 cột bị loại khỏi X baseline |
| Fit trên validation/test | **PASS (theo evidence)** | Preprocessor fit train-only; test transform |
| Test bị materialize trước evaluation | **FAIL (strict isolation)** | Evidence có test row_count/all_finite |
| Duplicate leakage | **NOT VERIFIED** | 14.815 exact; 1.134.553 ML-equivalent; không dedup |
| Group leakage | **NOT VERIFIED** | 1.270 nhóm mixed-category; group-aware split chưa audit byte-level |
| Temporal leakage | **NOT VERIFIED** | Traffic tập trung 3 ngày trong 27 ngày; boundary chưa kiểm chứng |
| Threshold tuning trên test | **PASS** | IF script calibrate trên validation, test frozen |
| Calibration | **NOT DONE** | Không có calibration curve/Brier/reliability |
| Test evaluation | **BLOCKED** | Không có metric test cho RF/XGB |

## 6. XGBoost

`reports/models/xgboost_manifest.json` ghi:

- artifact `c70ec52fb3229ccca680f70356e0a8c44e0b16ff7988c5e6fb91da3383eabd6e`;
- split `845d8863…`;
- preprocessor `e1e89bde…`;
- validation: precision `0,9999672142`, recall `1,0`, F1 `0,9999836068`, FPR `3,1759e-06`, confusion `[[314870,1],[0,30500]]`.

Nhưng:

- **không có file** `artifacts/models/xgboost/xgboost_baseline.joblib`;
- split `845d…` là biến thể CRLF của split `main` `1ba6…`, không tái lập trên checkout sạch;
- không có test metric;
- CLI không nhận `--model xgboost`.

**Verdict**: metric trong manifest là **historical claim**, không phải kết quả có thể tái lập tại HEAD. **NOT VERIFIED**.

## 7. Isolation Forest

### 7.1. Điểm tốt

`scripts/train_isolation_forest.py` có protocol đúng:

- fit benign-only;
- `calibrate_threshold()` trên validation;
- unknown attack categories không dùng để chọn threshold;
- test evaluation sau khi threshold frozen;
- `anomaly_scores()` = `-decision_function` (score cao = bất thường).

### 7.2. Điểm lỗi

- Không có artifact/model thật trên `main`.
- Inference chung (`inference/predict.py`) gọi `model.predict()` → raw `-1/1`; không áp threshold.
- `decision_function` được ghi thành `decision_score` mà không đảo dấu; score cao = bình thường.
- Không có `threshold.json` trong package inference.
- `scripts/predict.py --model isolation_forest` có thể chạy nhưng output semantics sai.

**Verdict**: **PARTIAL** về training protocol; **FAIL** về inference semantics.

## 8. Autoencoder

- Chỉ có trong PR #51 (branch-only), 3 commit, +3.390/−5, 13 file.
- CI 5/5 pass.
- Không có artifact, không có real-data metric, không có unknown-attack evaluation trong `main`.

**Verdict**: **NOT VERIFIED / NOT MERGED**.

## 9. Kết luận khoa học

| Câu hỏi | Kết luận |
|---|---|
| Dữ liệu thật? | **Có** — hash/rows khớp |
| RF train thật? | **Có, lịch sử** — artifact ngoài main |
| RF metric thật? | **Có, validation** — tái lập 100% |
| RF test metric? | **Không** — chưa evaluate |
| XGB thật? | **Không đủ** — manifest không artifact |
| IF thật? | **Chưa** — không artifact, inference sai |
| AE thật? | **Không** — branch-only |
| Leakage? | **Không có target leakage rõ ràng**, nhưng duplicate/group/temporal chưa verify |
| Shortcut? | **Có, nghiêm trọng** — TTL |
| False confidence? | **Có** — 99,99% validation bị diễn giải quá mức |

**Verdict tổng**: RF đạt **EXPERIMENTALLY VALIDATED trên validation với artifact lịch sử**; toàn bộ hệ thống chưa đạt **TESTED trên test**, chưa **REPRODUCED từ main**, và chưa **VALIDATED ngoài phân phối lab**.
