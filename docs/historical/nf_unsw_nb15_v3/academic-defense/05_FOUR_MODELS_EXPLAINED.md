# 05 — Giải thích Chi tiết Bốn Mô hình AI (`FOUR_MODELS_EXPLAINED.md`)

> **Nguyên tắc:** Mô tả đúng 100% những gì mã nguồn và artifact manifest thực sự triển khai. Không gán cho mô hình các kỹ thuật chưa có trong code (ví dụ: Autoencoder trong repo dùng `sklearn.neural_network.MLPRegressor`, **không** dùng PyTorch/LSTM/Attention).

---

## 1. Bảng tổng hợp 4 mô hình từ mã nguồn & manifest

| Tiêu chí | 1. Random Forest | 2. XGBoost | 3. Isolation Forest | 4. Autoencoder |
|---|---|---|---|---|
| **Loại học** | Supervised (Binary `Label`) | Supervised (Binary `Label`) | Unsupervised (Benign-only) | Unsupervised (Benign-only) |
| **Nhãn quản trị Desktop** | **`MODEL_VALIDATED`** | **`RESEARCH_ONLY`** *(xem §6)* | **`RESEARCH_ONLY`** | **`RESEARCH_ONLY`** |
| **Thuật toán / Class** | `sklearn.ensemble.RandomForestClassifier` | `xgboost.XGBClassifier` | `sklearn.ensemble.IsolationForest` | `sklearn.neural_network.MLPRegressor` |
| **Training Data** | `1.655.797` dòng Train (Benign + Attack) | `1.655.797` dòng Train (Benign + Attack) | `1.590.608` dòng Train (**Benign-only**, loại `65.189` Attack) | `1.590.608` dòng Train (**Benign-only**) |
| **Input Shape** | `(N, 47)` `float64` | `(N, 47)` `float64` | `(N, 47)` `float64` | `(N, 47)` `float64` |
| **Preprocessing** | `TrainOnlyPreprocessor` (`scaler=none`) | `TrainOnlyPreprocessor` (`scaler=none`) | `TrainOnlyPreprocessor` (`scaler=none`) | `TrainOnlyPreprocessor` (`scaler=none`) |
| **Hyperparameters khóa** | `n_estimators=200`, `max_depth=16`, `criterion="gini"`, `max_features="sqrt"`, `min_samples_split=2`, `min_samples_leaf=1`, `bootstrap=True`, `random_state=42` | `n_estimators=200`, `max_depth=6`, `learning_rate=0.1`, `subsample=0.8`, `colsample_bytree=0.8`, `objective="binary:logistic"`, `eval_metric="logloss"`, `tree_method="hist"`, `random_state=42` | `n_estimators=100`, `max_samples="auto"`, `contamination=0.1`, `max_features=1.0`, `bootstrap=False`, `random_state=42` | `hidden_layer_sizes=(32, 16, 32)`, `activation="relu"`, `solver="adam"`, `alpha=0.0001`, `batch_size=256`, `learning_rate_init=0.001`, `max_iter=50`, `random_state=42` |
| **Output thô của model** | `predict_proba(X)[:, 1]` $\in [0, 1]$ | `predict_proba(X)[:, 1]` $\in [0, 1]$ | `raw_anomaly_score = -decision_function(X)` (càng cao = càng bất thường) | `MSE(X, X_hat)` (càng cao = càng bất thường) |
| **Threshold** | `0.5` (mặc định nhị phân) | `0.5` (mặc định nhị phân) | `-0.033526858092757406` (`max-F1-on-known-attacks` trên Validation) | `17234985.792475585` (`fpr_constrained` `Val FPR <= 0.05`) |
| **Artifact & SHA-256** | `random_forest_baseline.joblib` (`801afcbb...`, 917 KB) | `xgboost_baseline.joblib` (`3098b75a...`, 73 KB) | `isolation_forest.joblib` (`15a69cc4...`, 269 KB) | `autoencoder_model.joblib` (`df24752b...`) + `model_config.json` + `threshold.json` |
| **Evaluation Evidence** | Val + Held-out Test (`rf-heldout-ea330b9`) `EXPERIMENTALLY VALIDATED` | Val + Held-out Test (`xgb-baseline-1794755807`) `EXPERIMENTALLY VALIDATED` | Val + Held-out Test (`if-c4-20261115T055359Z`) `EXPERIMENTALLY VALIDATED & REPRODUCED` | Val + Held-out Test (`ae_fpr_constrained_20261115T163000Z`) `EXPERIMENTALLY VALIDATED` |

---

## 2. Random Forest (`src/network_anomaly/models/random_forest.py`)

- **Cơ chế hoạt động:** Là mô hình ensemble gồm **200 cây quyết định** (`n_estimators=200`, độ sâu tối đa `max_depth=16`), mỗi cây huấn luyện trên một mẫu bootstrap của tập Train (`1.655.797` dòng) và chọn đặc trưng chia nhánh tốt nhất (theo Gini impurity) từ tập con $\sqrt{47} \approx 6$ đặc trưng ngẫu nhiên tại mỗi nút. Dự đoán cuối cùng lấy trung bình xác suất lá của 200 cây (`predict_proba`) rồi so với ngưỡng `0.5`.
- **Vai trò:** Baseline supervised chính thức (`MODEL_VALIDATED`), cho phép cả Security Dry-Run (#27) đề xuất `ISOLATE_RECOMMENDED` khi xác minh trên server.
- **Giới hạn:** Nhạy cảm với shortcut testbed (`MIN_TTL` + `MAX_TTL` chiếm tỷ trọng cao; sụp đổ hoàn toàn `Recall = 0.0` khi đổi sang dataset `NF-CSE-CIC-IDS2018-v3`); không phát hiện được tấn công hoàn toàn khác phân phối nếu nằm ngoài không gian học của Train.

---

## 3. XGBoost (`src/network_anomaly/models/xgboost_model.py`)

- **Cơ chế hoạt động:** Gradient Boosted Decision Trees (`XGBClassifier`, `tree_method="hist"`): thay vì xây 200 cây độc lập như Random Forest, XGBoost xây **200 cây tuần tự** (`max_depth=6`, `learning_rate=0.1`, `subsample=0.8`, `colsample_bytree=0.8`), mỗi cây mới học phần dư (gradient của hàm mất mát `binary:logistic` / log-loss) để sửa lỗi của các cây trước đó.
- **Khác biệt chính với Random Forest:** Bagging (giảm phương sai, cây sâu `16`, song song) so với Boosting (giảm sai số tuần tự, cây nông `6`, regularize bằng `learning_rate=0.1` và subsampling `0.8`). Kích thước tệp artifact XGBoost rất gọn (`73.287` bytes so với `917.227` bytes của RF).
- **Vì sao thuộc `RESEARCH_ONLY` trên Desktop UI dù Held-out Test đạt `F1=0,999984`?**
  1. Trong `src/network_anomaly/ingestion/compatibility.py` (`DEFAULT_BENCHMARK_REGISTRY`), chỉ có `RandomForest` (`rf-baseline-1794068628`) được cấp quyền `MODEL_VALIDATED` cho phép các hành động leo thang trên UI (`ISOLATE_RECOMMENDED` trong `#27`).
  2. Run `xgb-baseline-1794755807` (`3098b75a...`) được huấn luyện tại commit `7f51390` với `git_dirty=True` trước commit phát hành và chưa gắn vào `DEFAULT_BENCHMARK_REGISTRY` làm `MODEL_VALIDATED`, nên `_evaluate_gate()` tại `desktop_csv.py:994-1003` và `OnboardingGuidePanel.svelte:117` xếp XGBoost vào nhóm **`RESEARCH_ONLY`** để đối chiếu khoa học.

---

## 4. Isolation Forest (`src/network_anomaly/models/isolation_forest.py`)

- **Cơ chế hoạt động:** Là mô hình **unsupervised anomaly detection**. Xây `100` cây phân tách ngẫu nhiên (`iTree`) bằng cách chọn ngẫu nhiên một đặc trưng và một điểm cắt ngẫu nhiên giữa min–max. Nguyên lý: các điểm dị biệt (nằm thưa thớt, khác biệt) bị cô lập ở độ sâu nông (đường đi từ gốc tới lá ngắn) hơn các điểm bình thường nằm cụm dày đặc.
- **Có cần nhãn Attack khi train (`fit`) không?** **Không.** Hàm `fit_model(model, X_train_benign)` chỉ truyền ma trận `X` của **`1.590.608` dòng Benign (`Label == 0`)** trong Train (loại bỏ `65.189` dòng Attack). Nhãn chỉ dùng *bên ngoài* để lọc quần thể benign-only trước khi fit, tuyệt đối không truyền `y` vào `IsolationForest.fit()`.
- **Chiều điểm và ngưỡng:**
  - `sklearn.IsolationForest.decision_function(X)` trả giá trị âm cho điểm bất thường, nên code đảo dấu: `raw_anomaly_score = -decision_function(X)` (`higher_is_more_anomalous`).
  - Tham số `contamination=0.1` là cấu hình khởi tạo của sklearn, nhưng quyết định phân loại thực tế của dự án **không dùng `predict()` mặc định của sklearn**, mà dùng ngưỡng đóng băng hiệu chuẩn trên **Validation** (chỉ trên `Benign + 7 known attacks`, loại trừ `{Backdoor, Worms}`): chọn ngưỡng `-0.033526858092757406` theo chính sách `max-F1-on-known-attacks` (quét `74.421` ngưỡng ứng viên).
  - Luật quyết định: `Attack (1)` nếu `raw_anomaly_score >= -0.033526858092757406`. API còn tính `normalized_anomaly_score ∈ [0, 1]` bằng nội suy phân vị trên tập Validation (`score_normalization` trong manifest) và giữ **`attack_probability = null`**.

---

## 5. Autoencoder (`src/network_anomaly/models/autoencoder.py`)

- **Cơ chế hoạt động:** Dùng mạng nơ-ron đa tầng đối xứng **`MLPRegressor(hidden_layer_sizes=(32, 16, 32), activation="relu", solver="adam")`** huấn luyện theo mục tiêu **tự tái tạo đầu vào** (`model.fit(X_arr, X_arr)` tại `autoencoder.py:313`):
  - Input `47` → Encoder `32` (ReLU) → Bottleneck/Latent `16` (ReLU) → Decoder `32` (ReLU) → Output `47` (Linear/Identity).
  - Vì mạng chỉ học tái tạo `1.590.608` dòng **Benign** trong Train (`alpha=0.0001`, `batch_size=256`, `learning_rate_init=0.001`, `max_iter=50`, `random_state=42`), về nguyên lý các flow khác biệt sẽ có sai số tái tạo MSE $\frac{1}{47}\sum_{j=1}^{47}(x_j - \hat{x}_j)^2$ lớn hơn.
- **Ngưỡng và lý do ngưỡng lên tới `17.234.985,79`:**
  - Vì `TrainOnlyPreprocessor` dùng `scaler_type = "none"`, các cột như `SRC_TO_DST_AVG_THROUGHPUT` có giá trị lên tới hàng chục triệu bps. Khi bình phương sai số $(x_j - \hat{x}_j)^2$ trên các cột chưa scale này, giá trị MSE tự nhiên ở thang $10^7$!
  - Ngưỡng đóng băng được hiệu chuẩn trên Validation bằng phương pháp `fpr_constrained` với ràng buộc `target_fpr <= 0.05` (loại `{Backdoor, Worms}`), cho ngưỡng **`17.234.985,792475585`** (`empirical_val_fpr = 0.049998253 <= 0.05`). (Run trước đó `ae_benign_quantile_20261115T151859Z` có `Val FPR = 0.050001429 > 0.05` đã được lưu tách biệt tại `reports/evaluation/autoencoder/runs/`).
- **Vì sao Reconstruction Error KHÔNG phải Attack Probability?**
  - MSE là khoảng cách tái tạo không bị chặn trên $[0, +\infty)$, **không** tuân theo tiên đề xác suất có điều kiện $P(Y=1|X) \in [0, 1]$ và không được hiệu chuẩn trên nhãn tấn công. Một flow Benign lạ (lưu lượng tải file lớn hoặc outlier vô hại) vẫn có thể cho MSE rất cao. Do đó API trả `attack_probability = null`, trả `raw_anomaly_score = MSE` và `normalized_anomaly_score` nội suy phân vị Validation, không bao giờ ép MSE qua hàm sigmoid để gọi là xác suất tấn công.
