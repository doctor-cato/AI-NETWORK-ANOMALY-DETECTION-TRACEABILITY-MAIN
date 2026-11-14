# Report 14 — Nội dung sẵn sàng đăng GitHub

> Có thể đăng như comment tổng hợp trên issue audit hoặc PR. Không có trailer/tên công cụ.

---

## Bản chính — Audit summary

### Forensic audit: `b212377..b14dfee`

**Phạm vi**: 38 commit, 49 file (+13.469/−158), 19 PR, 41 issue, 8 milestone. Snapshot kiểm toán: `b14dfeed9e7cbb07201cfb0ac8ce69c951434be1`. Chế độ read-only; không sửa source, không merge.

### Kết luận

Repository có **code ML thật** và **một artifact Random Forest lịch sử** đạt metric rất cao trên validation, nhưng **chưa sẵn sàng end-to-end** và **không thể tái lập từ `main`**.

### Bằng chứng đã xác minh

- Raw dataset: 2.365.424 dòng, 55 cột, SHA-256 `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5`, khớp BagIt.
- RF validation (345.371 dòng): `tn=314866`, `fp=5`, `fn=3`, `tp=30497`; accuracy `0,9999768365`; precision `0,9998360763`; recall `0,9999016393`; F1 `0,9998688568`; FPR `1,5879518914e-05`.
- TTL shortcut: `MIN_TTL` + `MAX_TTL` = `45,48%` importance; cây chỉ dùng `MIN_TTL` đạt accuracy `0,9998494373`.
- Test suite: `739 passed, 10 skipped` tại HEAD (clone có `.git`).
- PR #51: OPEN, `REVIEW_REQUIRED`, head `8a75e375…`, CI 5/5, **branch-only**.

### Findings chặn nghiệm thu

| ID | Mức | Finding |
|---|---|---|
| F-01 | P0 | Inference loader fail-open: model không manifest hoặc manifest `{}` vẫn được load/predict. |
| F-02 | P0 | `RandomForestModel.load_verified()` chấp nhận `provenance_status: "UNVERIFIED"`. |
| F-03 | P0 | Chuỗi hash split → preprocessor → model không nhất quán; hardcode `bb84…` trong `train_random_forest.py`. |
| F-04 | P1 | XGBoost không có artifact `.joblib`; CLI `--model xgboost` fail; issue #31 đóng khi 0/4 AC. |
| F-05 | P1 | Test partition bị materialize trong preprocessing trước evaluation; chưa có test metric. |
| F-06 | P1 | TTL shortcut tạo false confidence. |
| F-07 | P1 | Isolation Forest inference trả raw `-1/1`, không áp threshold calibrated. |
| F-08 | P1 | #15, #17, #31 đóng sớm; #7/#8/#10 thiếu tái lập. |
| F-09 | P1 | M2 đóng sai; M4 có 0 open nhưng không đóng. |

### Trạng thái theo năng lực

| Năng lực | Trạng thái |
|---|---|
| Data acquisition/validation | PASS |
| EDA | PASS |
| Split/preprocessing | PARTIAL — index/artifact ngoài Git, hash lệch |
| RF validation | EXPERIMENTALLY VALIDATED (historical artifact) |
| RF test evaluation | BLOCKED |
| XGBoost | FAIL — manifest không artifact |
| Isolation Forest | FAIL/PARTIAL — chưa artifact, inference sai |
| Autoencoder | NOT VERIFIED — PR #51 branch-only |
| Inference verification | FAIL — fail-open |
| API/DB/dashboard/security | ABSENT trong `main` |
| Delivery | ABSENT |

### Hành động bắt buộc

1. Chốt canonical split và tái sinh preprocessor + RF + XGB; bỏ hash hardcode.
2. Fail-closed toàn bộ loader; manifest/hash/feature/class bắt buộc; xóa `except Exception: pass`.
3. Sinh XGBoost artifact thật hoặc mở lại #31.
4. Chạy test evaluation đúng một lần; lưu prediction + metric + manifest.
5. Sửa IF inference dùng `anomaly_scores` + threshold.
6. Mở lại issue/milestone chưa đạt; không đóng bằng checkbox.

### Không được tuyên bố

- “End-to-end reproducible từ `main`”.
- “XGBoost hoàn thành Issue #31”.
- “99,99% chứng minh mô hình tốt” — TTL shortcut.
- “CI xanh chứng minh ML pipeline chạy thật” — 10 skip do thiếu dữ liệu/artifact.
- “PR #51 là năng lực của `main`” — chưa merge.

---

## Bản ngắn — comment cho PR #51

> PR này đang OPEN, `REVIEW_REQUIRED`, branch-only; chưa được tính vào năng lực của `main`.
>
> CI 5/5 pass chỉ chứng minh test synthetic. Chưa có artifact Autoencoder, chưa có real-data unknown-attack evaluation, chưa chứng minh threshold chỉ chọn trên validation với holdout class tách khỏi fit.
>
> Đề nghị: rebase trên `main` sau khi xử lý P0 provenance/loader; bổ sung artifact + threshold + metric detection rate/FPR + split identifiers; chỉ merge khi #29 AC đạt.

---

## Bản ngắn — comment cho PR #40 / issue #31

> Issue #31 đang closed nhưng 0/4 AC và không có `artifacts/models/xgboost/xgboost_baseline.joblib`. Manifest `reports/models/xgboost_manifest.json` tham chiếu artifact `c70ec52f…` không tồn tại; CLI `python scripts/predict.py --model xgboost` trả `Model artifact not found at 'xgboost'`.
>
> Đề nghị mở lại #31 và chỉ đóng khi có artifact + load/predict + test metric + reproduction command.

---

## Bản ngắn — comment cho milestone M2

> M2 đang closed nhưng #31 không đạt: không artifact, 0/4 AC, CLI không hỗ trợ. Đề nghị reopen M2 hoặc ghi rõ “closed with exception” kèm danh sách thiếu; không dùng M2 làm bằng chứng baseline hoàn thành.
