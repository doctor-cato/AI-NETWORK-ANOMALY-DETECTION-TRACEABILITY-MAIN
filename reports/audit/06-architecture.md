# Report 06 — Architecture Audit

## 1. Kiến trúc mục tiêu (theo `docs/ARCHITECTURE.md`)

```text
Network events
  → Validation/Preprocessing
  → Behavioral Vector
  → Correlation / Risk Engine
  → Trace Engine
  → AES-GCM Storage
  → SQLite Repositories
  → FastAPI
  → Streamlit Dashboard
```

Tài liệu này mô tả **kiến trúc Phương án B**, không phải trạng thái triển khai. Bảng module ghi “Package dự kiến” và checkpoint C1–C11.

## 2. Những gì thực sự có trong `src/` tại HEAD

```text
src/network_anomaly/
├── config.py
├── data/
│   ├── nf_unsw_nb15_v3.py
│   └── split.py
├── eda/
│   ├── evidence.py
│   ├── figures.py
│   ├── profiling.py
│   └── report.py
├── evaluation/
│   └── metrics.py
├── features/
├── inference/
│   ├── pipeline.py
│   └── predict.py
├── models/
│   ├── isolation_forest.py
│   ├── random_forest.py
│   ├── random_forest_protocol.py
│   ├── xgboost_model.py
│   └── xgboost_protocol.py
├── preprocessing/
│   └── pipeline.py
└── visualization/
    └── plots.py
```

**Không có** package `api`, `storage`, `security`, `behavioral`, `risk`, `trace`, `dashboard`, `response`, `experiments`.

## 3. Trạng thái từng lớp

| Lớp | Mục tiêu | Trạng thái HEAD | Bằng chứng |
|---|---|---|---|
| Data acquisition | Tải/verify NF-UNSW-NB15-v3 | **IMPLEMENTED/TESTED** | `scripts/fetch_nf_unsw_nb15_v3.py`, manifest, EDA tests |
| Schema/quality | 55 cột, nhãn, missing/duplicate | **IMPLEMENTED/TESTED** | validation report; `ML_READY: BLOCKED` |
| Split | chronological/group/purged | **PARTIAL** | manifest/report; index thật không có trong Git |
| Preprocessing | train-only fit, transform | **PARTIAL** | code/test; artifact external; hash chain lệch |
| RF | train/evaluate/inference | **PARTIAL** | artifact lịch sử; validation metric; test chưa eval |
| XGBoost | train/evaluate/inference | **FAIL** | code + manifest; không có artifact; CLI không hỗ trợ |
| Isolation Forest | fit/score/threshold | **PARTIAL** | code + train script; không artifact; inference sai semantics |
| Autoencoder | fit/score/unknown attack | **NOT MERGED** | chỉ PR #51 branch-only |
| Inference CSV | verified load + export | **FAIL (fail-open)** | `predict.py` chấp nhận manifest rỗng/không manifest |
| Evaluation | metric + test evaluation | **PARTIAL** | `evaluation/metrics.py` đúng; chưa có test evaluation |
| API | FastAPI | **ABSENT** | không có `src/network_anomaly/api` |
| Storage | SQLite | **ABSENT** | không có repository/storage module |
| Security | AES-GCM/key lifecycle | **ABSENT** | không có code |
| Dashboard | Streamlit | **ABSENT** | không có code |
| Trace/Risk/Behavioral | correlation/risk/timeline | **ABSENT** | không có code |

## 4. Luồng dữ liệu thực tế

### 4.1. Training

```text
raw CSV (ngoài Git)
  → split manifest + index .csv.gz (ngoài Git)
  → TrainOnlyPreprocessor.fit(train)
  → transform(train/validation)
  → RandomForestModel.fit / XGBoostModel.fit
  → model .joblib + manifest .json
```

Vấn đề:

- index `.csv.gz` không có trong Git;
- preprocessor artifact không có trong Git;
- model artifact RF/XGB không có trong Git;
- manifest tham chiếu hash không tái lập được.

### 4.2. Inference

Có **hai đường**:

1. `InferencePipeline` trong `src/network_anomaly/inference/predict.py`:
   - `load_verified_preprocessor()` → bắt buộc manifest;
   - `load_verified_model()` → **manifest optional**;
   - `predict()` → `model.predict`, optional `predict_proba`, optional `decision_function`.
2. `predict_from_artifact()` trong `src/network_anomaly/inference/pipeline.py`:
   - `joblib.load(path)` trực tiếp, **không manifest/hash**.

Đường 1 là entrypoint mới; đường 2 là legacy vẫn còn trong package. Sự tồn tại song song tạo **bypass**.

### 4.3. CLI

| Lệnh | Trạng thái |
|---|---|
| `python scripts/predict.py --model random_forest` | Chạy nếu có artifact + manifest |
| `python scripts/predict.py --model isolation_forest` | Chạy nếu có artifact; nhưng output raw `-1/1` |
| `python scripts/predict.py --model xgboost` | **FAIL**: coi `xgboost` là path → `Model artifact not found at 'xgboost'` |
| `python scripts/run_experiments.py --step baseline` | Delegate RF training |
| `python scripts/run_experiments.py --step xgboost` | Delegate XGB training |
| `python scripts/run_experiments.py --step evaluate` | **Exit 3 — NOT IMPLEMENTED** |
| `python scripts/run_experiments.py --step inference` | **Exit 3 — NOT IMPLEMENTED** |

## 5. Đối chiếu tài liệu

- `README.md:23-24` ghi real split và model training là **PLANNED / NOT VERIFIED**. Điều này **trung thực so với trạng thái tái lập**, nhưng đã lỗi thời so với code/XGB/IF đã merge — theo hướng **thận trọng**, không phải false claim.
- `README.md:139` ghi “Model training, FastAPI, Streamlit, AES-GCM... are not implemented by this dataset migration” — đúng cho migration, nhưng không còn đúng cho model training sau #38/#40.
- `docs/ARCHITECTURE.md` là **target architecture**, không phải “as-built”.
- Không có file tracked nào ở HEAD ghi “60 Issues”; con số đó chỉ xuất hiện trong checkpoint/untracked của workspace audit và đã được đính chính ở Report 00.
- Không có tài liệu nào chứng minh FastAPI/Streamlit/SQLite/AES đã được triển khai.

## 6. Kết luận

- Hệ thống hiện tại là **ML research pipeline**, không phải hệ thống traceability/backend hoàn chỉnh.
- Kiến trúc tài liệu và kiến trúc thực tế **lệch pha lớn**; đây là “paper architecture” cho các lớp C5–C9.
- Ngay trong phần ML, integration cũng chưa hoàn chỉnh: hai loader song song, CLI thiếu XGB, `run_experiments` thiếu evaluate/inference.
- Không được dùng `docs/ARCHITECTURE.md` để trả lời “hệ thống đã có chức năng X”.
