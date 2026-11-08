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

### Isolation Forest (không giám sát — nếu triển khai)

- Chọn rõ normal-only novelty setup hoặc mixed/unlabeled outlier setup trước khi fit. Nếu label chỉ được dùng để lọc
  normal-only, ghi rõ bước này; không truyền target vào mô hình.
- Tạo điểm bất thường trên tập validation.
- Chọn ngưỡng (ghi rõ phương pháp: contamination/quantile đã định trước, hoặc tối ưu bằng validation labels và ghi
  rõ đây là supervised calibration).
- Dự đoán trên test với ngưỡng đã chọn.
- Tính các metric giống trên; ghi rõ quá trình chọn ngưỡng.
- Lưu ý: các metric chỉ so sánh được khi cả hai protocol đã được ghi rõ.

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

## Không tuyên bố benchmark chưa kiểm chứng

- Repo này không tuyên bố độ chính xác, F1 cụ thể, hoặc kết quả benchmark cho đến khi thực nghiệm thật
  hoàn thành và kết quả được ghi cùng seed/phiên bản.
- Mọi kết quả phải ghi rõ: `PLANNED / IMPLEMENTED / TESTED / EXPERIMENTALLY VALIDATED`.
- Hiện tại protocol đánh giá là `IMPLEMENTED / TESTED` (bằng code contracts và unit tests).
- Huấn luyện Random Forest baseline và đánh giá trên phân vùng **Validation** (`345.371` dòng) thuộc Issue #10 đã đạt trạng thái `IMPLEMENTED / TESTED / EXPERIMENTALLY VALIDATED` trên dữ liệu thật `NF-UNSW-NB15-v3` (`reports/models/random_forest_manifest.json`, `reports/models/rf_baseline_training_report.md`):
  - Model artifact SHA-256: `801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea` (`917.227` bytes, tái lập 100% byte-for-byte).
  - Validation metrics (`345.371` dòng): `Precision = 0.999836`, `Recall = 0.999902`, `F1 = 0.999869`, `Macro-F1 = 0.999928`, `FPR = 0.000016`, Confusion Matrix `[[314866, 5], [3, 30497]]` (`TN = 314.866`, `FP = 5`, `FN = 3`, `TP = 30.497`), cùng phân rã đầy đủ 10 lớp cột `Attack`.
  - Kiểm toán khóa tập Test: `test_partition_accessed = false`, `test_rows_loaded = 0`, `test_indices_loaded = false`.
- Đánh giá một lần cuối cùng (one-shot final evaluation) trên phân vùng **Test** (`345.953` dòng) thuộc phạm vi Issue #12 và vẫn giữ trạng thái `PLANNED`.

Cập nhật: 2026-11-07 (cập nhật kết quả huấn luyện và đánh giá Validation thực nghiệm của Random Forest baseline Issue #10; giữ khóa tập Test cho Issue #12)
