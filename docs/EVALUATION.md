# Đánh giá — Metric, Giải thích, Phân tích lỗi

## Protocol đánh giá theo mô hình

### Random Forest (giám sát — Baseline chính)

- Huấn luyện trên tập `train` có nhãn theo protocol `rf-baseline-nf-unsw-nb15-v3-v1`
  (chi tiết tại [RF_BASELINE_PROTOCOL.md](RF_BASELINE_PROTOCOL.md)).
- Split NF-UNSW-NB15-v3 theo chronological/group-purged contract (`nf-unsw-nb15-v3-chronological-group-purged-v1`, PR #41);
  tuyệt đối không dùng `test` để chọn feature, imputation, threshold hoặc hyperparameter.
- Dự đoán trên validation và test bằng pipeline đã fit (fit `train_only`).
- Lớp dương tính (Positive Class): `Attack` (Label = 1).
- Lớp âm tính (Negative Class): `Benign` (Label = 0).
- Tính các chỉ số chính:
  - Precision: $TP / (TP + FP)$ (average="binary", zero_division=0)
  - Recall: $TP / (TP + FN)$ (average="binary", zero_division=0)
  - F1-Score: $2 \cdot P \cdot R / (P + R)$
  - Macro-F1: trung bình F1 giữa lớp Benign và Attack
  - False Positive Rate (FPR): $FP / (FP + TN)$
  - Confusion Matrix: trục có nhãn thứ tự rõ ràng `[0, 1]` tương ứng `[Benign, Attack]`
- Phân tích lỗi (Error Analysis): phân rã chi tiết False Negatives (bỏ lọt tấn công) theo từng
  họ `Attack` cụ thể trong 9 loại tấn công (`Exploits`, `Fuzzers`, `Generic`, `Reconnaissance`,
  `DoS`, `Backdoor`, `Shellcode`, `Analysis`, `Worms`).

### Isolation Forest (không giám sát — C4 / Issue #11)

- Hướng score đã được ghim trong code: `network_anomaly.models.isolation_forest.anomaly_scores` trả
  về điểm mà **lớn hơn = bất thường hơn** (đảo dấu `decision_function` của scikit-learn, vốn dùng chiều
  ngược). Dùng helper này để tránh đảo chiều âm thầm; helper không áp ngưỡng.
- **Huấn luyện benign-only**: Chỉ huấn luyện mô hình trên các mẫu lưu lượng bình thường (`Label == 0`) từ
  phân vùng Train. Không truyền `Label` hoặc `Attack` vào hàm huấn luyện của mô hình.
- **Hiệu chuẩn ngưỡng trên Validation (Threshold Calibration)**:
  - Điểm bất thường được sinh trên tập Validation.
  - Các nhóm tấn công chưa biết được đăng ký trước (pre-registered: `UNKNOWN_ATTACK_CATEGORIES` gồm `Worms` và `Backdoor`)
    và **hoàn toàn loại trừ** khỏi việc lựa chọn ngưỡng hoặc tinh chỉnh siêu tham số trên Validation.
  - Ngưỡng được lựa chọn dựa trên sự đánh đổi giữa FPR và detection rate (chính sách tối đa hóa F1 trên các nhóm
    tấn công đã biết hoặc thỏa mãn mục tiêu FPR định trước).
- **Đóng băng ngưỡng trước khi đánh giá Test**:
  - Ngưỡng đã chọn được đóng băng cố định (`frozen threshold`).
  - Không sử dụng nhãn hay điểm của tập Test để chọn hoặc điều chỉnh ngưỡng.
- **Đánh giá trên tập Test**:
  - Bắt buộc tính toán đầy đủ: TP, TN, FP, FN, Accuracy, Precision, Recall / Detection Rate, F1, FPR, ROC-AUC, PR-AUC.
  - Đánh giá phân rã: tỷ lệ phát hiện tấn công đã biết (known attack detection rate), tỷ lệ phát hiện tấn công
    chưa biết (unknown attack detection rate), và ma trận nhầm lẫn có nhãn rõ ràng.
  - Phân tích tỷ lệ phát hiện trên từng loại tấn công cụ thể (`per-attack category detection rate`).
  - Phân biệt rõ khả năng phát hiện bất thường nhị phân với khả năng tổng quát hóa trên các nhóm tấn công chưa thấy;
    không tuyên bố phát hiện zero-day chỉ vì mô hình phát hiện được các nhóm bị loại khỏi validation.
- Entrypoint thực thi: `scripts/train_isolation_forest.py`. Pipeline tuân thủ nguyên tắc fail-closed (dừng ngay và báo
  `BLOCKED` nếu thiếu dữ liệu thật, sai lệch SHA-256, thiếu split manifest, lỗi schema đặc trưng hoặc phát hiện rò rỉ).

## Định nghĩa metric (lặp lại từ METHODOLOGY cho rõ ràng)

- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2 * P * R / (P + R)
- Macro-F1 = trung bình F1 theo từng lớp
- False Positive Rate (FPR) = FP / (FP + TN)
- Confusion matrix: trục phải ghi rõ nhãn `[0, 1]` tương ứng `[Benign, Attack]`

## Phân tích lỗi

- Dương tính giả (False Positive - FP): kết nối bình thường (`Benign`) bị đánh dấu bất thường;
  mô tả nguyên nhân có thể (đặc trưng tương tự bất thường; vấn đề mã hóa đặc trưng; chồng chéo lớp).
- Âm tính giả (False Negative - FN): bất thường (`Attack`) bị bỏ sót và đoán là bình thường;
  mô tả nguyên nhân có thể (loại bất thường thiếu dữ liệu như Worms/Analysis; chưa bắt được đặc trưng;
  ngưỡng quá bảo thủ).
- Hạn chế dữ liệu: mất cân bằng lớp (Attack chỉ chiếm ~5,4%), giá trị thiếu/vô hạn ở throughput fields,
  và sự lặp lại mẫu đặc trưng ML giữa các phân vùng thời gian (`ml_feature_overlap` ở trạng thái `REVIEWED_AND_JUSTIFIED`:
  `61.007` fingerprints giữa train/validation ~ `49,98%` dòng validation; `59.966` fingerprints giữa train/test ~ `53,21%` dòng test;
  `24.143` fingerprints giữa validation/test ~ `33,13%` dòng test; `binary_label_conflicts: 0`, trong khi `exact_full_row_overlap = 0`,
  `source_feature_overlap = 0`, `canonical_flow_group_overlap = 0`, `temporal_boundary_violations = 0`).
  Các mẫu đánh giá chia sẻ vector 47 đặc trưng với tập `train` không hoàn toàn độc lập trong không gian đặc trưng (non-i.i.d. feature space).
- Báo cáo riêng theo 10 giá trị `Attack`; không che rare-class failure bằng accuracy tổng.
- Hạn chế mô hình: Random Forest có thể overfit nếu độ sâu không giới hạn (khóa `max_depth=16`);
  Isolation Forest giả định dữ liệu bình thường phân cụm khác với bất thường; không tuyên bố phát hiện
  zero-day không có chứng cứ.

## Bảng metric thực nghiệm M3 & trạng thái kiểm chứng

Phân biệt rõ trạng thái: `PLANNED`, `IMPLEMENTED`, `TESTED`, `EXPERIMENTALLY VALIDATED`, `REPRODUCED`, `BLOCKED / NOT VERIFIED`.

- **Random Forest (Baseline chính — #9, #10, #12, #13):** **EXPERIMENTALLY VALIDATED** & **REPRODUCED** (Validation) + **EXPERIMENTALLY VALIDATED** (Held-out Test `rf-heldout-ea330b9`).
  - Artifact: `artifacts/models/random_forest/random_forest_baseline.joblib` (SHA-256 `801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea`, `917.227` bytes), manifest `reports/models/random_forest_manifest.json` (`rf-baseline-1794068628`).
  - Validation (`345.371` dòng): `Precision = 0.999836`, `Recall = 0.999902`, `F1 = 0.999869`, `Macro-F1 = 0.999928`, `FPR = 0.000016`, `CM = [[314866, 5], [3, 30497]]`. Tái lập sạch trong venv Python `3.12.10` đạt sai khác **0** trên toàn bộ metric và confusion matrix.
  - Held-out Test (`rf-heldout-ea330b9`, `345.953` dòng): `Accuracy = 0.999974`, `Precision = 0.999771`, `Recall = 0.999935`, `F1 = 0.999853`, `Macro-F1 = 0.999919`, `FPR = 0.0000222`, `CM = [[315350, 7], [2, 30594]]` (xem `reports/evaluation/rf-heldout-ea330b9/verified_summary.json`).
- **XGBoost (#31 & M7):** **EXPERIMENTALLY VALIDATED** & **REPRODUCED** trên Validation (`345.371` dòng) và **EXPERIMENTALLY VALIDATED** trên Held-out Test (`xgb-baseline-1794755807`, `345.953` dòng — xem [`reports/evaluation/xgboost/metrics.json`](../reports/evaluation/xgboost/metrics.json)).
  - Validation (`xgb-baseline-1794151507` / `xgb-baseline-1794755807`): `Precision = 0.999967`, `Recall = 1.000000`, `F1 = 0.999984`, `Macro-F1 = 0.999991`, `FPR = 0.000003`, `CM = [[314870, 1], [0, 30500]]`.
  - Held-out Test (`xgb-baseline-1794755807`, `345.953` dòng): `Accuracy = 0.999997`, `Precision = 0.999967`, `Recall = 1.000000`, `F1 = 0.999984`, `Macro-F1 = 0.999991`, `FPR = 0.00000317`, `ROC-AUC = 1.0`, `CM = [[315356, 1], [0, 30596]]` (xem [`reports/models/xgboost_manifest.json`](../reports/models/xgboost_manifest.json)).
  - Trạng thái vận hành Desktop: `RESEARCH_ONLY` (khi có artifact `.joblib` cục bộ hoặc được đóng gói vào standalone installer ở bước build-time; chưa có benchmark sign-off `MODEL_VALIDATED` độc lập trong `DEFAULT_BENCHMARK_REGISTRY`).
- **Isolation Forest (C4 — #11):** **EXPERIMENTALLY VALIDATED** & **REPRODUCED** trên dữ liệu thật `NF-UNSW-NB15-v3` (`if-c4-20261115T055359Z`, clean commit `bf0f3ec`, `git_dirty=false`, Python `3.12.10`).
  - Huấn luyện **benign-only** trên `1.590.608` mẫu `Label == 0` thuộc Train (loại bỏ `65.189` mẫu Attack), seed `42`, `n_estimators = 100`, `max_samples = "auto"`, `contamination = 0.1`.
  - Hiệu chuẩn ngưỡng trên Validation (`314.871` Benign + `30.319` Known Attack; loại trừ `181` Unknown `{Backdoor, Worms}`): policy `max-F1-on-known-attacks` (quét `74.421` ngưỡng ứng viên) chọn ngưỡng đóng băng `-0.033526858092757406` (`Validation`: `Precision = 0.327973`, `Recall = 0.887892`, `F1 = 0.479008`, `FPR = 0.175183`; quan sát `Unknown` trên Validation `154/181 = 0.8508`).
  - Held-out Test (`345.953` dòng = `315.357` Benign + `29.300` Known + `1.296` Unknown `{Backdoor: 1260, Worms: 36}`):
    - **Tổng thể:** `TP = 27.528`, `TN = 264.755`, `FP = 50.602`, `FN = 3.068`, `Accuracy = 0.844863`, `Precision = 0.352336`, `Recall = 0.899725`, `F1 = 0.506374`, `FPR = 0.160459`, `ROC-AUC = 0.893730`, `PR-AUC = 0.288753` (`reports/experiments/isolation_forest/metrics.json`, `confusion_matrix.csv`, `confusion_matrix.png`).
    - **Known Attacks vs Benign:** `26.406 / 29.300` (`Recall = 0.901229`, `Precision = 0.342899`, `F1 = 0.496783`, `ROC-AUC = 0.893996`).
    - **Unknown Attacks (`Backdoor`, `Worms`) vs Benign:** `1.122 / 1.296` (`Recall = 0.865741`, `ROC-AUC = 0.887713`; riêng `Backdoor: 1093/1260 = 0.8675`, `Worms: 29/36 = 0.8056`).
  - Cảnh báo: tỷ lệ phát hiện Unknown trên split holdout này phản ánh tổng quát hóa trong cùng testbed IXIA PerfectStorm, **không** chứng minh phát hiện zero-day ngoài thực tế; điểm bất thường cũng chịu tác động của `ml_feature_overlap` và shortcut `MIN_TTL` (`Validation benign_median = 31.0` so với `attack_median = 254.0`, `benign_zero_fraction = 0.0204` so với `attack_zero_fraction = 0.0017`).
- **Autoencoder (#29 & M7):** **EXPERIMENTALLY VALIDATED** trên dữ liệu thật `NF-UNSW-NB15-v3` (`ae_fpr_constrained_20261115T163000Z`, `sklearn.neural_network.MLPRegressor` kiến trúc `(32, 16, 32)`, seed `42`, `reports/models/autoencoder_manifest.json` & `reports/evaluation/autoencoder/metrics.json`).
  - Huấn luyện **benign-only** trên `1.590.608` mẫu `Label == 0` thuộc Train; hiệu chuẩn ngưỡng theo chính sách `fpr_constrained <= 0.05` trên Validation (`345.371` dòng) → ngưỡng đóng băng `17234985.792476` (`Val FPR = 0.049998`, `Val F1 = 0.1430`, `Val Recall = 0.1168`).
  - Held-out Test (`345.953` dòng): `Precision = 0.1804`, `Recall = 0.1093`, `F1 = 0.1361`, `FPR = 0.0482`, `ROC-AUC = 0.6303`, `PR-AUC = 0.1615`, `CM = [[300169, 15188], [27253, 3343]]`, Unknown `{Backdoor, Worms}` `Recall = 0.0625` (`81/1296`). Chi tiết phân tích nguyên nhân (không chuẩn hóa đầu vào `scaler_type="none"` gây chi phối MSE bởi cột byte/pkt lớn) xem tại [`docs/academic-defense/07_MODEL_RESULTS_AND_LIMITATIONS.md`](academic-defense/07_MODEL_RESULTS_AND_LIMITATIONS.md).

Cập nhật: 2026-11-17 (M7 — đồng bộ thực nghiệm 4 mô hình và bộ tài liệu [`docs/academic-defense/`](academic-defense/README.md))
