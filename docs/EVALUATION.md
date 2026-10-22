# Đánh giá — Metric, Giải thích, Phân tích lỗi

## Protocol đánh giá theo mô hình

### Random Forest (giám sát — Baseline chính)

- Huấn luyện trên tập `train` có nhãn theo protocol `rf-baseline-nf-unsw-nb15-v3-v1`
  (chi tiết tại [RF_BASELINE_PROTOCOL.md](RF_BASELINE_PROTOCOL.md)).
- Split NF-UNSW-NB15-v3 theo temporal/group-aware contract (`nf-unsw-nb15-v3-temporal-group-v1`);
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
  bản ghi trùng lặp luồng, rò rỉ định danh.
- Báo cáo riêng theo 10 giá trị `Attack`; không che rare-class failure bằng accuracy tổng.
- Hạn chế mô hình: Random Forest có thể overfit nếu độ sâu không giới hạn (khóa `max_depth=16`);
  Isolation Forest giả định dữ liệu bình thường phân cụm khác với bất thường; không tuyên bố phát hiện
  zero-day không có chứng cứ.

## Không tuyên bố benchmark chưa kiểm chứng

- Repo này không tuyên bố độ chính xác, F1 cụ thể, hoặc kết quả benchmark cho đến khi thực nghiệm thật
  hoàn thành và kết quả được ghi cùng seed/phiên bản.
- Mọi kết quả phải ghi rõ: `PLANNED / IMPLEMENTED / TESTED / EXPERIMENTALLY VALIDATED`.
- Hiện tại ở Issue #9, protocol đánh giá là `IMPLEMENTED / TESTED` (bằng code contracts và unit tests);
  kết quả thực nghiệm trên dữ liệu thật vẫn là `PLANNED` và thuộc phạm vi Issue #12.

Cập nhật: 2026-10-22 (đồng bộ với Issue #9 — RF Baseline Protocol)
