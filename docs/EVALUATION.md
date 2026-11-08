# Đánh giá — Metric, Giải thích, Phân tích lỗi

## Protocol đánh giá theo mô hình

### Random Forest (giám sát)

- Huấn luyện trên tập train có nhãn.
- Split NF-UNSW-NB15-v3 theo temporal/group-aware contract; không dùng test để chọn feature,
  imputation, threshold hoặc hyperparameter.
- Dự đoán trên validation và test bằng pipeline đã fit.
- Tính: Precision, Recall, F1 (nhị phân hoặc theo lớp), Macro-F1, confusion matrix, FPR.
- Confusion matrix phải có nhãn trục rõ ràng.

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
- Confusion matrix: trục phải ghi rõ nhãn
- FPR = FP / (FP + TN) — báo cáo khi có ý nghĩa

## Phân tích lỗi

- Dương tính giả: kết nối bình thường bị đánh dấu bất thường; mô tả nguyên nhân có thể (đặc trưng tương tự bất thường; vấn đề mã hóa đặc trưng; chồng chéo lớp).
- Âm tính giả: bất thường bị bỏ sót; mô tả nguyên nhân có thể (loại bất thường thiếu dữ liệu; chưa bắt được đặc trưng; ngưỡng quá bảo thủ).
- Hạn chế dữ liệu: mất cân bằng, giá trị thiếu, bản ghi trùng, rò rỉ định danh.
- Báo cáo riêng theo 10 giá trị `Attack`; không che rare-class failure bằng accuracy tổng.
- Hạn chế mô hình: Random Forest có thể overfit nếu độ sâu không giới hạn; Isolation Forest giả định dữ liệu bình thường phân cụm khác với bất thường; không tuyên bố phát hiện zero-day không có chứng cứ.

## Không tuyên bố benchmark chưa kiểm chứng

- Repo này không tuyên bố độ chính xác, F1 cụ thể, hoặc kết quả benchmark cho đến khi thực nghiệm thật hoàn thành và kết quả được ghi cùng seed/phiên bản.
- Mọi kết quả phải ghi rõ: `PLANNED / IMPLEMENTED / TESTED / EXPERIMENTALLY VALIDATED`.

Cập nhật: 2026-11-03 (Isolation Forest C4 protocol & pipeline evaluation)
