---
name: ml-experiment-audit
description: "Audit ranh giới split, preprocessing, feature selection, tuning, threshold, OOD gate và metric để phát hiện leakage hoặc evaluation sai. Dùng khi review pipeline/thí nghiệm ML hoặc xác minh claim leakage-safe; không coi tài liệu là bằng chứng runtime."
---

# ML Leakage & Evaluation Audit (v2.0)

Audit từ code, config, manifest SHA-256, test và log thực thi. Đọc [quy tắc thí nghiệm](../../rules/ml-experiment-rules.md) và protocol dữ liệu/model liên quan; không xác nhận `leakage-safe` chỉ vì tài liệu mô tả đúng.

## Checklist leakage & trust boundary

| Rủi ro | PASS khi | FAIL khi |
|---|---|---|
| Target & shortcut leakage | target, TTL shortcut và cột trace bị loại khỏi `ML_FEATURE_COLUMNS` (18 cột) | target/proxy/trace lọt vào `X` |
| Train/test contamination | `ait_test`, `CTU-SME-11`, `UWF-ZeekData24` cô lập tới evaluation; post-hoc selection khai báo rõ (`WP3`) | test/external tham gia fit, tuning hoặc giấu post-hoc reference |
| Preprocessing leakage | `TrainOnlyPreprocessor` (`asinh_robust`) fit chỉ trên `ait_train` với `MIN_BOUNDED_SCALE_FLOOR` | fit trước split hoặc trên val/test |
| Feature-selection leakage | ablation/selection chạy trên `ait_train`/`ait_val` hoặc CV trong `ait_train` | dùng thống kê `ait_test` chọn feature |
| Tuning / threshold leakage | hyperparameter & `IF`/`AE` threshold (kèm `score_normalization.json`) chọn thuần trên `ait_val` (`validation`) | dùng `test` label chọn cấu hình/threshold |
| Duplicate / scenario leakage | split theo scenario/host (`V2_SPLIT_MANIFEST.json`, `0` `(scenario, 5-tuple, ts)` overlap) | cùng scenario/flow đi qua split không kiểm soát |
| OOD deployment bypass | `deployment` mode mặc định fail-closed, bắt buộc trusted `NETFLOW_OOD_GATE_SHA256` ngoài `artifacts/` | tự downgrade `deployment -> research` hoặc tin unsigned manifest cùng boundary |

Không có code/log đủ quan sát thì ghi `NOT VERIFIED`.

## Audit evaluation

- Chốt rõ **Binary (`Benign`/`Attack`)** vs **Multiclass (6 lớp)**, positive class, label order, support (cảnh báo lớp hiếm `N <= 78`) và `deployment_tier` (`RESEARCH_ONLY` vs `PRODUCTION_ELIGIBLE`).
- Binary: kiểm tra Precision, Recall, F1, `FPR = FP/(FP+TN)`, `ROC-AUC`, `PR-AUC`, confusion matrix đúng thứ tự nhãn.
- Multiclass: dùng per-class metrics và `Macro-F1`/`Weighted-F1`, không dùng `average="binary"`.
- Tách riêng **in-domain (`AIT-Test`)**, **zero-shot cross-source (`CTU-SME-11`, `UWF-ZeekData24` @ threshold cố định hoặc `AIT-Val` threshold)**, và **target-benign diagnostic** (tuyệt đối không gắn nhãn zero-shot cho target quantile).
- Khi so sánh 4 model (`Random Forest`, `XGBoost`, `Isolation Forest`, `Autoencoder`): giữ đúng `score_semantics` (`calibrated_binary_probability` cho RF/XGB vs `empirical_percentile_vs_validation_benign` cho IF/AE).

## Bằng chứng và kết luận

Ghi từng check `PASS / FAIL / SKIPPED / NOT VERIFIED`, lệnh/exit code, SHA-256 artifact/log và giới hạn. Map về `Issue → Requirements → Implementation → Tests → Verification Evidence → Experiment Results`. Một `FAIL` về contamination, threshold leakage, OOD trust-boundary bypass hoặc sai metric/label semantics làm mất hiệu lực claim liên quan cho đến khi sửa và chạy lại.
