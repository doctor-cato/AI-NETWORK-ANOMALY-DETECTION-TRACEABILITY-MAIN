# Phương pháp mô hình — Phương án B

## Luồng tổng thể

1. Đọc dữ liệu (sau khi tải về `data/raw/`)
2. Kiểm tra schema / nhãn (`scripts/validate_data.py`)
3. Khám phá (EDA tái lập được — `scripts/eda_nf_unsw_nb15_v3.py`, báo cáo
   `docs/dataset/NF_UNSW_NB15_V3_EDA.md`): phân bố lớp, giá trị thiếu, bản ghi trùng, kiểm tra
   rò rỉ dữ liệu. EDA chỉ mô tả population đã xác minh, không chọn feature, không fit
   transformer, không xóa dòng và không tạo split; mọi khuyến nghị phụ thuộc train ở trạng
   thái `PENDING ISSUE #7`.
4. Tạo split mới cho NF-UNSW-NB15-v3: temporal ordering, versioned duplicate/equivalence audit và
   bidirectional 5-tuple/time-bucket grouping; không kế thừa split UNSW-NB15 (2015) và không tự
   động loại behavioral-equivalent rows.
5. Tiền xử lý (fit chỉ trên train): mã hóa, chuẩn hóa, chọn đặc trưng; lưu pipeline
6. Huấn luyện mô hình: Random Forest/XGBoost theo supervised protocol; Isolation Forest
   và Autoencoder theo anomaly protocol riêng của C4.
7. Đánh giá (protocol khác nhau theo mô hình; xem bên dưới)
8. Phân tích lỗi (dương tính giả / âm tính giả; ghi rõ hạn chế)
9. Suy luận (tải pipeline + mô hình; áp dụng cho dữ liệu mới)

## Random Forest (baseline bắt buộc)

- Loại: phân loại giám sát (nhị phân hoặc đa lớp tùy mục tiêu)
- Huấn luyện: tập huấn luyện có nhãn; siêu tham số đã ghi (`n_estimators`, `max_depth`, `random_state`)
- Đánh giá: các metric giám sát chuẩn — Precision, Recall, F1 per class, Macro-F1, confusion matrix, False Positive Rate (FPR) khi có ý nghĩa
- Giải thích confusion matrix: âm tính đúng / dương tính giả (bình thường bị phân loại nhầm là bất thường) / âm tính giả (bất thường bị bỏ sót) / dương tính đúng
- Ngăn rò rỉ dữ liệu: không tạo đặc trưng từ nhãn; chia trước mọi fitting; kiểm tra cột định danh và xử lý cẩn thận

## Isolation Forest (phát hiện bất thường không giám sát — bắt buộc ở C4)

- Loại: không giám sát; học phân phối dữ liệu bình thường; chấm điểm độ lệch
- Dữ liệu fit phải được chọn và ghi trước: normal-only cho novelty detection, hoặc mixed/unlabeled training population
  cho outlier detection. Nếu dùng nhãn để lọc normal-only thì phải công khai bước lọc; target không được truyền như
  feature hay đối số fit của mô hình.
- Protocol đánh giá (phải ghi riêng biệt với đánh giá giám sát):
  - Tạo điểm bất thường cho tập validation/test
  - Chọn ngưỡng trên tập validation (ví dụ: contamination/quantile đã định trước, hoặc tối ưu bằng validation labels
    và ghi rõ đây là supervised calibration)
  - Áp dụng ngưỡng cho tập test để có nhãn dự đoán
  - So sánh dự đoán với nhãn thực tế bằng Precision, Recall, F1, Macro-F1, FPR
  - Ghi rõ phương pháp chọn ngưỡng và tác động đến metric
- Quan trọng: so sánh trực tiếp với Random Forest cần giải thích rõ vì RF dùng nhãn khi huấn luyện và đánh giá theo protocol giám sát, trong khi IF dùng chấm điểm và chọn ngưỡng rồi đánh giá. Các metric chỉ so sánh được khi cả hai protocol được mô tả rõ ràng.

## Autoencoder (phát hiện bất thường dựa trên lỗi tái tạo — bắt buộc ở C4 / Issue #29)

- Loại: mạng nơ-ron không giám sát (MLP Autoencoder); học biểu diễn và phân phối lưu lượng lành tính (benign); chấm điểm bất thường dựa trên sai số tái tạo (reconstruction error MSE).
- Kiến trúc: `Input (47) → Encoder (Dense 32, ReLU) → Latent (Dense 16, ReLU) → Decoder (Dense 32, ReLU) → Output (Dense 47, Linear/Identity)`.
- Hàm mất mát và điểm bất thường: Mean Squared Error $\text{MSE}(x, \hat{x}) = \frac{1}{d} \sum_{j=1}^d (x_j - \hat{x}_j)^2$. Chiều điểm chuẩn hóa: điểm lỗi tái tạo càng cao thì càng bất thường (higher reconstruction error = more anomalous).
- Dữ liệu fit: thuần lành tính (benign-only, `Label == 0` từ partition Train). Nhãn chỉ dùng để lọc quần thể huấn luyện trước khi fit; tuyệt đối không đưa `Label`, `Attack` hay metadata vào ma trận $X$. Quá trình tối ưu gradient hoàn toàn không giám sát.
- Protocol unknown attack (pre-registered holdout):
  - Danh mục tấn công chưa biết được đăng ký trước: `Worms` và `Backdoor` (tương thích tuyệt đối với Issue #11).
  - Danh mục unknown tuyệt đối không tham gia fit mô hình, không tham gia cập nhật gradient, không tham gia early stopping, không tham gia hyperparameter tuning và không tham gia hiệu chuẩn ngưỡng (threshold calibration).
  - Unknown attack chỉ được đánh giá ở pha đánh giá cuối cùng để đo lường năng lực phát hiện dạng tấn công chưa từng gặp.
- Hiệu chuẩn ngưỡng (Validation-only threshold calibration):
  - Ngưỡng bất thường $\tau$ chỉ được xác định trên partition Validation, tuyệt đối không dùng Test hay unknown attacks.
  - Các phương pháp hiệu chuẩn được hỗ trợ: ràng buộc FPR mục tiêu trên mẫu lành tính validation (ví dụ FPR $\le 0.05$ hoặc quantile $1 - \text{target\_fpr}$), hoặc tối ưu ngưỡng trên validation lành tính và known attacks (khai báo rõ ràng là supervised calibration).
  - Quyết định phân loại: $\text{anomaly} = 1$ khi $\text{reconstruction\_error} \ge \tau$, ngược lại $0$.
  - Sau khi chọn xong trên Validation, ngưỡng $\tau$ được đóng băng (frozen) vĩnh viễn trước khi đánh giá bất kỳ mẫu nào khác.
- Bảo vệ khóa tập kiểm thử (Held-out Test Lock):
  - Tập Test hoàn toàn không được nạp hay truy cập trong suốt quá trình fit, early stopping và hiệu chuẩn ngưỡng.
  - Chỉ được đánh giá khi có cờ `--evaluate-test` sau khi mô hình và ngưỡng đã đóng băng.
- Giới hạn khoa học bắt buộc:
  - Unknown-attack holdout là protocol kiểm chuẩn trong môi trường kiểm soát (controlled benchmark), không phải bằng chứng phát hiện tấn công zero-day thực tế.
  - Đặc trưng NetFlow v3 có giới hạn tóm lược theo flow, không có payload, có thể gặp hiện tượng lặp lại mẫu hành vi hoặc ghi nhớ phân phối.

## Quy tắc tiền xử lý (tránh rò rỉ)

- Chia train / val / test trước mọi fitting tiền xử lý.
- Fit imputer/encoder/scaler/selector chỉ trên train.
- Transform val/test bằng đối tượng đã fit.
- Lưu đối tượng đã fit cùng artifact mô hình.
- Ghi rõ cột nào được bao gồm / loại bỏ và lý do (kết quả kiểm tra rò rỉ).
- Baseline `X` có 47 fields. `Label`, `Attack`, IP identifier, hai L4 port và absolute timestamp
  không thuộc default `X`; sáu metadata fields vẫn được giữ riêng cho grouping/Trace Engine.
- Cấu hình 49 features có thêm hai port chỉ là experiment tương lai; PR migration không triển khai
  hoặc tuyên bố kết quả so sánh này.
- Chính sách missing/positive-infinity phải được chọn và fit chỉ trên train. Report hiện ghi
  `SOURCE_INTEGRITY: PASS`, `RAW_QUALITY: FINDINGS_RECORDED`, `ML_READY: BLOCKED`; chưa có
  split/model thật được chấp nhận.

## Định nghĩa metric

- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2 * Precision * Recall / (Precision + Recall)
- Macro-F1 = trung bình điểm F1 theo từng lớp
- Confusion matrix: hàng/cột phải ghi rõ nhãn (bình thường / bất thường)
- FPR = FP / (FP + TN) — chỉ báo cáo khi có ý nghĩa cho trường hợp sử dụng

C4 còn yêu cầu Autoencoder reconstruction-error và unknown-attack holdout; threshold của
cả hai chỉ được chọn trên validation, không dùng test/holdout để tối ưu.

Cập nhật: 2026-10-22 (migration NF-UNSW-NB15-v3 + EDA Issue #6).
