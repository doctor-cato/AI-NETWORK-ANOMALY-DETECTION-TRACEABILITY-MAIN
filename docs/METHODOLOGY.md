# Phương pháp Mô hình — NetFlow Sentinel v2

## 1. Luồng tổng thể (`canonical-flow-v2-18`)

1. **Acquisition & Provenance:** Xác minh HTTPS + SHA-256 cho **AIT NetFlow Data Set v2 (`AIT-NDS-v2`)**, **AIT Log Data Set v2.1 (`AIT-LDS-v2.1`)**, **AIT Alert Data Set (`AIT-ADS`)**, và **CTU-SME-11** (`scripts/fetch_multi_source_dataset.py`). Nguồn `UGR'16` giữ trạng thái `BLOCKED` do cổng chính thức trả HTTP 403.
2. **Streaming Profiling & Quality Gate:** Kiểm tra schema, giá trị missing/non-finite, nhãn unmapped/background, duplicate và temporal consistency (`scripts/profile_multi_source.py`).
3. **Chuẩn hóa & Scenario-Disjoint Split (`v2-scenario-group-purged-v1`):** Ánh xạ về đúng 18 đặc trưng (`canonical-flow-v2-18`) + `taxonomy-v2` (tuyệt đối không gán `background`/`unknown` thành `Benign`; loại `unmapped` khỏi supervised metrics). Chia Train (`fox, harrison, santos, wardbeck, wilson`), Validation (`russellmitchell`) và Held-out Test (`shaw, wheeler`) với kiểm toán 0 overlap scenario và `(scenario, 5-tuple, ts_bucket)`.
4. **Tiền xử lý Train-only (`asinh_robust`):** `TrainOnlyPreprocessor` chỉ fit trên `1,930,219` dòng Train: biến đổi `arcsinh` + `RobustScaler` cho 17 biến định lượng, giữ nguyên `protocol_num` dạng mã số nguyên, điền missing bằng Train median/mode, giữ dòng `duration_ms == 0.0`.
5. **Huấn luyện 4 Mô hình v2:** Random Forest & XGBoost (supervised), Isolation Forest & Autoencoder (benign-only unsupervised + validation threshold calibration).
6. **Đánh giá In-domain, Rare-Class, Unknown-Holdout & Cross-Source Real Capture:** Đánh giá trên `AIT-Test`, `CTU-Echo` và `CTU-Windows7AD` cùng phân tích feature-shift và giới hạn khoa học.

---

## 2. Giao thức từng Mô hình

### Random Forest (Supervised Baseline)
- **Huấn luyện:** `Train` (`1,930,219` dòng), hợp đồng `rf-v2-baseline-canonical-v1`, `n_estimators=200`, `max_depth=16`, `random_state=42`.
- **Audit chống rò rỉ:** Kiểm tra shortcut single-feature & loại bỏ hoàn toàn 5 trace metadata + 4 target columns khỏi `X`.

### XGBoost (Supervised)
- **Huấn luyện:** `Train` (`1,930,219` dòng), dùng `eval_metric`, early stopping trên Validation, ghi nhận `scale_pos_weight` (`6.1115` giữa Benign/Attack trên Train) và feature importance.

### Isolation Forest (Unsupervised Benign-Only)
- **Fit population:** Chỉ fit trên `1,658,795` dòng Benign (`label_binary == 0`) của `ait_train`; nhãn chỉ dùng để lọc quần thể benign trước khi fit, không truyền vào model.
- **Threshold calibration:** Chọn ngưỡng `0.002736309694079453` từ phân vị Validation benign với `target_fpr = 0.05` (`empirical_val_fpr = 0.049986 <= 0.05` theo strict `>`), sau đó đóng băng trước khi chạm `ait_test` hay `CTU-SME-11`.

### Autoencoder (`MLPRegressor` 18 → 16 → 8 → 16 → 18)
- **Fit population:** Chỉ fit trên `1,658,795` dòng Benign thuộc `ait_train` sau chuẩn hóa `asinh_robust` (khắc phục nhược điểm không scale khiến MSE bị chi phối bởi byte count).
- **Anomaly score:** Sai số tái tạo MSE `>= threshold` (`0.0002279976895622908`, hiệu chuẩn trên Validation benign `target_fpr = 0.05`, `empirical_val_fpr = 0.049996 <= 0.05`).

---

## 3. Bảo vệ Rò rỉ & Kiểm toán Cross-Source

- Không chia ngẫu nhiên theo dòng (random row split) vì làm lọt cùng kịch bản/phiên giữa Train và Test.
- Không fit preprocessor, calibration threshold hay early stopping trên Test hoặc trên `CTU-SME-11`.
- Mọi kết quả holdout/unknown-attack trên `AIT-NDS-v2` được tách biệt hoàn toàn khỏi đánh giá domain-shift thực tế trên `CTU-SME-11`.
