# Report 01 — Executive Summary

## 1. Kết luận điều hành

Repository là một **research prototype có code ML thật**, không phải hệ thống end-to-end hoàn chỉnh. Trong 38 commit sau baseline, nhóm đã hợp nhất được:

- pipeline đọc/kiểm định NF-UNSW-NB15-v3;
- split protocol và train-only preprocessing;
- Random Forest baseline có manifest và artifact lịch sử;
- XGBoost và Isolation Forest ở mức code;
- inference CSV và bộ test lớn.

Tuy nhiên, **chuỗi bằng chứng từ `main` bị đứt**:

- split manifest trên `main` có SHA-256 `1ba6b2ef…`, trong khi model RF và preprocessor manifest lại tham chiếu `bb84c1e0…`/`845d8863…`;
- commit tạo artifact RF `6f506335…` không nằm trên `main`;
- XGBoost manifest tồn tại nhưng **không có file model `.joblib`**;
- loader inference chấp nhận model không có manifest và bỏ qua kiểm tra nếu field thiếu;
- test partition chưa từng được đánh giá cho RF/XGB, nên toàn bộ metric công bố chỉ là **validation**.

Vì vậy, câu trả lời trung thực cho câu hỏi “repo đã sẵn sàng chưa?” là:

> **Chưa sẵn sàng end-to-end.** Random Forest được **EXPERIMENTALLY VALIDATED trên validation** với artifact lịch sử; không được coi là validated trên `main`, trên test, hay trong production.

## 2. Score card

| Khu vực | Trạng thái | Bằng chứng chính |
|---|---|---|
| Nguồn và byte dữ liệu thô | **PASS** | 2.365.424 dòng; 55 cột; SHA-256 `4ebb97bd…` khớp BagIt |
| Schema/nhãn/chất lượng dữ liệu | **PASS có giới hạn** | 122.493 dòng zero-duration/non-finite; 14.815 exact duplicate; `ML_READY: BLOCKED` |
| Split protocol | **PARTIAL** | Manifest có trên `main`; index `.csv.gz` không có trong Git; hash index `main` khác external |
| Train-only preprocessing | **PARTIAL** | Code + test + artifact lịch sử; hash chain không tái lập; execution evidence bị ghi đè bởi run XGB; Test partition vẫn bị materialize (F-05) |
| Random Forest training | **PARTIAL** | Artifact thật `801afcbb…`; metric validation tái lập 100%; không tái lập được từ `main` |
| Random Forest test evaluation | **BLOCKED** | Chưa có metric trên 345.953 dòng test; issue #12/#13 còn open |
| XGBoost | **FAIL** | Artifact được khai báo `c70ec52f…` nhưng file vắng mặt; CLI không nhận `--model xgboost`; issue #31 đóng khi 0/4 AC |
| Isolation Forest | **PARTIAL** | Code + training script + threshold protocol; chưa có artifact thật; inference trả raw `-1/1` |
| Autoencoder | **NOT VERIFIED** | Chỉ có trên PR #51 branch-only; chưa merge, chưa có artifact |
| Inference CSV | **FAIL (fail-open)** | `load_verified_model()` chấp nhận model không manifest/`{}`; `except Exception: pass` |
| Test suite | **PASS (synthetic)** | 739 passed, 10 skipped; 6 skip do thiếu dữ liệu/artifact thật, 2 symlink, 1 split manifest, 1 XGB blocked |
| CI | **PARTIAL** | Matrix 4 job xanh; lint-audit không chạy trên push `main`; không có real-data gate |
| Security/integrity | **FAIL** | CWE-502 `joblib.load`; RF `load_verified` chấp nhận `UNVERIFIED`; dependency không pin |
| Documentation truthfulness | **PARTIAL** | README vẫn ghi model training “PLANNED” sau khi IF/XGB/inference đã merge (thận trọng nhưng lỗi thời); ARCHITECTURE chỉ là target, không có status as-built |
| Milestone/issue governance | **FAIL** | #15/#17/#31 đóng sớm; M2 đóng dù #31 0/4 AC; M4 0 open nhưng vẫn open |

## 3. Các phát hiện nghiêm trọng nhất

| ID | Mức | Phát hiện | Bằng chứng |
|---|---|---|---|
| F-01 | **P0** | Inference loader fail-open: model không manifest hoặc manifest `{}` vẫn được nạp và dự đoán | `src/network_anomaly/inference/predict.py:283-363`; reproducer `INFERENCE_NO_MANIFEST ACCEPTED`, `INFERENCE_EMPTY_MANIFEST ACCEPTED` |
| F-02 | **P0** | `RandomForestModel.load_verified()` chấp nhận `provenance_status: "UNVERIFIED"` | `src/network_anomaly/models/random_forest.py:405-411`; reproducer `RF_UNVERIFIED_PROVENANCE ACCEPTED` |
| F-03 | **P0** | Chuỗi hash split → preprocessing → model không nhất quán; hardcode hash trong training script | split `main` `1ba6…`; RF `bb84…`; XGB `845d…`; `scripts/train_random_forest.py:71` |
| F-04 | **P1** | XGBoost không có artifact; CLI `--model xgboost` fail; issue #31 đóng khi 0/4 AC | `reports/models/xgboost_manifest.json`; `scripts/predict.py:50-67`; exit 1 |
| F-05 | **P1** | Test partition bị materialize trong preprocessing evidence trước evaluation | `reports/preprocessing/execution_evidence.json:52-59`; `test_lock_audit` chỉ áp dụng cho training |
| F-06 | **P1** | Shortcut learning trên TTL: 45,48% importance; 1 feature đạt 99,98% accuracy | real-data reproduction; `MIN_TTL`/`MAX_TTL` |
| F-07 | **P1** | Isolation Forest inference trả raw `-1/1`, không dùng threshold calibrated; `decision_score` ngược dấu | `inference/predict.py:467, 494-498`; threshold chỉ có trong training script |
| F-08 | **P1** | Đóng issue sớm: #15, #17, #31; #7/#8/#10 có bằng chứng không tái lập từ `main` | mục Report 04 |
| F-09 | **P1** | M2 đóng dù #31 không đạt; M4 có 0 open/2 closed nhưng vẫn open | GitHub milestone data |
| F-11 | **P2** | CI/lint gate bỏ sót RF, IF, inference; không chạy lint trên push `main` | `.github/workflows/lint-audit.yml:7-17`; scoped list 44-79 |
| F-12 | **P2** | `run_experiments.py --step inference` trả exit 3 `NOT IMPLEMENTED` | `scripts/run_experiments.py:14, 33-35, 79-84` |
| F-13 | **P2** | Không có evaluation test cho #12/#13; metric cao chỉ từ validation | `reports/models/random_forest_manifest.json:157-241` |

## 4. Những gì thực sự đã được chứng minh

1. **Dữ liệu thô là thật và khớp manifest**: 577.360.958 byte, SHA-256 `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5`, 2.365.424 dòng dữ liệu, 55 cột.
2. **RF validation metric tái lập được** với artifact lịch sử bên ngoài `main`: confusion `tn=314866, fp=5, fn=3, tp=30497`; accuracy `0.9999768365`; precision `0.9998360763`; recall `0.9999016393`; F1 `0.9998688568`; FPR `1.5879518914e-05`.
3. **TTL shortcut tái lập được**: `MIN_TTL` + `MAX_TTL` chiếm `45,48%` importance; cây chỉ dùng `MIN_TTL` đạt accuracy `0.9998494373`.
4. **Test suite xanh trên synthetic fixtures**: 739 passed, 10 skipped; không có real benchmark trong CI.
5. **Inference E2E chỉ chạy với artifact lịch sử**: 1.000 dòng → 829 benign/171 attack khi dùng split `bb84…`; fail với split `main` `1ba6…`.

## 5. Những gì không được phép tuyên bố

- “Pipeline tái lập end-to-end từ `main`” — **SAI**.
- “XGBoost đã hoàn thành Issue #31” — **SAI**: không có artifact, 0/4 AC.
- “Isolation Forest/Autoencoder đã được đánh giá unknown attack” — **SAI/CHƯA CÓ**.
- “Kết quả 99,99% chứng minh mô hình tốt” — **SAI về mặt khoa học**: TTL là shortcut của lab topology.
- “CI xanh chứng minh ML pipeline chạy thật” — **SAI**: 10 skip do thiếu dữ liệu/artifact.
- “PR #51 là năng lực của `main`” — **SAI**: PR đang OPEN, `REVIEW_REQUIRED`.

## 6. Hành động bắt buộc trước khi nghiệm thu

1. **Đóng băng provenance**: chọn một split manifest chuẩn, tái sinh preprocessor + RF + XGB từ đúng split đó trên `main`, bỏ hardcode hash.
2. **Fail-closed toàn bộ loader**: manifest bắt buộc; hash/contract/feature/class bắt buộc; xóa `except Exception: pass`.
3. **Sinh XGBoost artifact thật** hoặc hạ issue #31 về open và xóa claim hoàn thành.
4. **Chạy đánh giá test đúng một lần** cho RF (và XGB nếu có), lưu metric + prediction + run manifest.
5. **Sửa IF inference**: dùng `anomaly_scores` + threshold calibrated, map `score >= threshold` → `1`, không xuất raw `-1/1`.
6. **Đóng lại issue/milestone chưa đạt**; không dùng checkbox hoặc CI xanh thay cho evidence.

Chi tiết thứ tự và cách chứng minh ở Report 13.
