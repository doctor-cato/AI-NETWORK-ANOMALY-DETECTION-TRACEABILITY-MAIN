# Quy tắc thí nghiệm ML — rules/ml-experiment-rules.md

## Bộ dữ liệu & Provenance (`canonical-flow-v2-18`)

- **Active v2:** `AIT-NDS-v2` (`10.5281/zenodo.13168643`, `CC BY 4.0`), `CTU-SME-11` (`10.5281/zenodo.7958258`, `CC BY 4.0`), và nguồn kiểm chứng bổ sung `UWF-ZeekData24` (`CC BY 4.0`, `evaluation_only = true`).
- **Ranh giới dữ liệu:** `AIT-LDS-v2.1` (`CC BY-NC-SA 4.0`) cách ly 100% khỏi ML weights và `data/demo/`; `UGR'16` giữ trạng thái `BLOCKED` (`HTTP 403`). `NF-UNSW-NB15-v3` đã chuyển sang `historical/` và bị cấm ở active pipeline (`scripts/fetch_multi_source_dataset.py --verify-only`, `scripts/verify_companion_artifacts.py`).
- **Tài liệu thiết kế:** Đối chiếu [docs/DATASET.md](../../docs/DATASET.md), [docs/EXPERIMENT_PLAN.md](../../docs/EXPERIMENT_PLAN.md), [docs/dataset/V2_SOURCE_AUDIT.md](../../docs/dataset/V2_SOURCE_AUDIT.md) và [docs/REPRODUCIBILITY.md](../../docs/REPRODUCIBILITY.md).

## Kiểm tra chất lượng & Leakage

- Kiểm tra missing values, finite numeric bounds, duplicates, class imbalance và non-canonical protocol/port values trước khi vào model (`OODValidator`, `OODRejectionGate`).
- Cột định danh & trace (`timestamp_ms`, `source_ip`, `dest_ip`, `source_port`, `dest_port`), target dẫn xuất và TTL shortcut bị loại nghiêm ngặt khỏi 18 ML features trong `canonical-flow-v2-18`.

## Chia dữ liệu & Tiền xử lý (`src/network_anomaly/preprocessing/pipeline.py`)

- Tách **Scenario/Host-grouped split** (`data/V2_SPLIT_MANIFEST.json`, zero scenario & `(scenario, 5-tuple, ts)` overlap) trước mọi bước fitting; seed cố định `RANDOM_SEED = 42`.
- `TrainOnlyPreprocessor` (`asinh_robust`, `MIN_BOUNDED_SCALE_FLOOR = 0.25`) fit duy nhất trên `ait_train`, lưu kèm manifest SHA-256 (`reports/preprocessing/v2_flow_preprocessing_manifest.json`) và dùng ở mode bất biến cho `ait_val`, `ait_test`, `CTU-SME-11`, `UWF-ZeekData24` và live inference.
- **Nghiêm cấm:** Dùng `ait_test` hoặc target cross-source để chọn đặc trưng, tune hyperparameter hoặc hiệu chỉnh threshold zero-shot. Nếu tham chiếu hậu nghiệm (như `WP3`), phải khai báo rõ `ait_test_used_for_posthoc_candidate_selection = true`, `holdout_independent_selection = false`.

## Mô hình, Đánh giá & Bảo lưu `E0`

- **Supervised (`Random Forest`, `XGBoost`):** Báo cáo Precision, Recall, F1, FPR, ROC-AUC, PR-AUC; với phân loại đa lớp báo cáo đủ Macro-F1, Weighted-F1, Balanced Accuracy, Per-class metrics và Confusion Matrix có rõ support lớp hiếm.
- **Unsupervised (`Isolation Forest`, `Autoencoder`):** Fit theo đúng protocol đã định, gắn kèm `score_normalization.json` và calibrate threshold thuần trên `ait_val` (`validation` partition), không dùng nhãn test chọn ngưỡng.
- **Bảo toàn `E0`:** 4 baseline `.joblib` hiện hành giữ tier `RESEARCH_ONLY`; mọi thí nghiệm phụ (multi-class, diagnostic, ablation) phải tách riêng khỏi `E0` trừ khi có nhiệm vụ tái huấn luyện được phê duyệt.

## Ghi chép & Truy vết

- Chuỗi bắt buộc: `Issue → Requirements → Implementation → Tests → Verification Evidence → Experiment Results`.
- `PLANNED`: mới có kế hoạch; `IMPLEMENTED`: đã có code; `TESTED`: đã chạy test (có thể synthetic); `EXPERIMENTALLY VALIDATED`: đã chạy trên dữ liệu benchmark v2 thật (`AIT-NDS-v2`, `CTU-SME-11`, `UWF-ZeekData24`) có split, checksum, environment metadata, commit/working-tree provenance và metric đầy đủ. Thiếu mắt xích thì ghi `NOT VERIFIED`.
