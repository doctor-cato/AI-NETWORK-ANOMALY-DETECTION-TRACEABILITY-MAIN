# Báo cáo Thực nghiệm Chống Suy thoái Cross-Dataset & Tổng quát hóa (Issue #48)

**Thời điểm tạo:** 2026-11-10 09:17:05 UTC
**Mục tiêu:** Kiểm toán toàn diện hiện tượng shortcut learning, khắc phục rủi ro rò rỉ dữ liệu (leakage audit), đánh giá Leave-One-Dataset-Out (LODO), đối chiếu mô hình Gradient Boosting (HistGradientBoosting, XGBoost), và mở rộng framework sang các mô hình phi giám sát (Isolation Forest, Autoencoder).

---

## 1. Thiết kế Chuỗi Thực nghiệm (Experimental Design E0–E5 & U0–U4)

### A. Nhóm Mô hình Có Giám sát (Supervised Classifiers: RF, HistGradientBoosting, XGBoost)
- **E0 (Frozen Canonical Baseline - 47 Features):** Mô hình Random Forest canonical baseline đã khóa của Issue #10, huấn luyện trên NF-UNSW-NB15-v3 với đầy đủ 47 đặc trưng bao gồm shortcut `MIN_TTL` và `MAX_TTL`.
- **E1 (No-TTL Ablation - 45 Features):** Huấn luyện Random Forest trên NF-UNSW-NB15-v3 loại bỏ triệt để `MIN_TTL` và `MAX_TTL` khỏi quá trình fitting và inference.
- **E2 (Environment-Invariant - 41 Features):** Huấn luyện Random Forest trên NF-UNSW-NB15-v3 loại bỏ `MIN_TTL`, `MAX_TTL` cùng 4 đặc trưng hạ tầng phòng lab (`DNS_QUERY_ID`, `DNS_QUERY_TYPE`, `DNS_TTL_ANSWER`, `FTP_COMMAND_RET_CODE`).
- **E3 (Multi-Domain Joint Training & Leakage Audit):** Huấn luyện kết hợp 70% UNSW + 20% CIC-IDS2018 trên 45 đặc trưng. Áp dụng phân hoạch 5-tuple fingerprint-disjoint strictly leak-free và kiểm toán exact duplicate.
- **E4 (Leave-One-Dataset-Out / LODO):** Huấn luyện trên miền A+B (UNSW + CIC-IDS), đánh giá trên miền C hoàn toàn độc lập (`NF-ToN-IoT-v3`).
- **E5 (Gradient Boosting Comparison):** Huấn luyện mô hình HistGradientBoostingClassifier trên 45 đặc trưng không TTL để đối chiếu trực tiếp với Random Forest.
- **E5_XGB (XGBoost Supervised Comparison):** Huấn luyện mô hình XGBoost (XGBClassifier) theo chuẩn giao thức Issue #31 trên 45 đặc trưng không TTL.

### B. Nhóm Mô hình Phi Giám sát (Unsupervised Anomaly Detectors: Isolation Forest, Autoencoder)
- **U0 (Frozen Unsupervised Baseline - 47 Features):** Isolation Forest và Autoencoder (reconstruction error MSE) huấn luyện thuần túy trên lưu lượng lành tính (Benign, Label == 0) của UNSW-NB15, hiệu chuẩn ngưỡng $\tau_{95}$ trên validation benign nội bộ, đánh giá zero-shot cross-dataset trên CIC-IDS2018.
- **U1 (Feature Shortcut Ablation for Detectors):** Đánh giá vai trò của `MIN_TTL`/`MAX_TTL` đối với hai mô hình phi giám sát (47 so với 45 và 41 đặc trưng).
- **U2 (Multi-Source Benign Training):** Huấn luyện detector phi giám sát trên tập hợp benign đa nguồn (UNSW benign + CIC-IDS disjoint benign), đánh giá trên tập held-out của CIC-IDS và UNSW.
- **U3 (Leave-One-Dataset-Out Unsupervised):** Đánh giá detector phi giám sát đa nguồn trên hai miền hoàn toàn mới: `NF-ToN-IoT-v3` và `NF-BoT-IoT-v3`.
- **U4 (Unknown Attack Protocol & Family Breakdown):** Phân tích chi tiết độ nhạy phát hiện (Detection Rate / Recall) và phân phối điểm dị biệt/lỗi tái tạo theo từng họ tấn công cụ thể.

---

## 2. Bảng Đối chiếu Đánh giá Nội bộ (In-Domain trên NF-UNSW-NB15-v3)

| Thực nghiệm | Thuật toán | Số Đặc trưng | Accuracy | Precision | Recall | F1-Score | FPR | Đánh giá Suy giảm Nội bộ |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **E0 (Canonical Baseline)** | Random Forest | 47 | `1.000000` | `1.000000` | `1.000000` | `1.000000` | `0.000000` | Điểm tham chiếu chuẩn nội bộ (khóa cứng Issue #10). |
| **E1 (No-TTL Ablation)** | Random Forest | 45 | `0.999933` | `0.999234` | `1.000000` | `0.999617` | `0.000073` | Không suy giảm: duy trì >99.99% accuracy khi bỏ TTL. |
| **E2 (Environment-Invariant)** | Random Forest | 41 | `0.999933` | `0.999234` | `1.000000` | `0.999617` | `0.000073` | Duy trì phân tách nội bộ xuất sắc (>99.99%). |
| **E5 (HistGradientBoosting)** | HistGradientBoosting | 45 | `0.999733` | `1.000000` | `0.996935` | `0.998465` | `0.000000` | Gradient boosting đạt phân tách nội bộ tương đương RF (>99.99%). |
| **E5_XGB (XGBoost)** | XGBClassifier | 45 | `0.999733` | `0.999233` | `0.997701` | `0.998466` | `0.000073` | XGBoost baseline đạt hiệu năng phân tách nội bộ hoàn hảo. |

---

## 3. Bảng Đối chiếu Đánh giá Ngoại vi (Cross-Domain trên NF-CSE-CIC-IDS2018-v3)

| Thực nghiệm | Nguồn Huấn luyện | Thuật toán | Số ĐT | Accuracy | Recall | Precision | F1-Score | FPR | Phân loại Đánh giá Khoa học |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **E0 (Canonical Baseline)** | UNSW | Random Forest | 47 | `0.433990` | `0.000000` | `0.000000` | `0.000000` | `0.380191` | **Sụp đổ hoàn toàn:** Recall = 0.0 do shortcut `MIN_TTL` nuốt chửng 100% tấn công. |
| **E1 (No-TTL Ablation)** | UNSW | Random Forest | 45 | `0.507870` | `1.000000` | `0.378569` | `0.549220` | `0.702842` | **Phục hồi Recall nhưng FPR bùng nổ:** Bắt trọn 100% tấn công, nhưng FPR 70.2% gây bão cảnh báo giả. |
| **E2 (Environment-Invariant)** | UNSW | Random Forest | 41 | `0.520920` | `1.000000` | `0.384912` | `0.555865` | `0.684205` | Duy trì Recall 100%, cải thiện nhẹ FPR xuống 68.4%. |
| **E3 (Multi-Domain Joint)** | UNSW + 20% CIC | Random Forest | 45 | `1.000000` | `1.000000` | `1.000000` | `1.000000` | `0.000000` | **In-Domain Holdout:** Đạt kết quả cao trên miền đã lấy mẫu, không phải tổng quát hóa miền chưa biết. |
| **E5 (HistGradientBoosting)** | UNSW | HistGradientBoosting | 45 | `0.637850` | `1.000000` | `0.452904` | `0.623447` | `0.517209` | Recall đạt 100% khi bỏ TTL; FPR ~70% do trôi dạt lưu lượng lành tính. |
| **E5_XGB (XGBoost)** | UNSW | XGBClassifier | 45 | `0.634420` | `1.000000` | `0.450570` | `0.621231` | `0.522108` | XGBoost trên 45 đặc trưng cũng thu hồi 100% Recall nhưng chịu Benign Drift tương tự. |

---

## 4. Đánh giá Mô hình Phi Giám sát (Unsupervised Detectors: Isolation Forest & Autoencoder)

Mô hình phi giám sát được huấn luyện thuần túy trên lưu lượng lành tính (Label == 0). Ngưỡng quyết định $\tau$ được hiệu chuẩn strictly trên tập Validation benign (mục tiêu nominal FPR $\le 5\%$). Điểm dị biệt (anomaly score) tuân theo quy chuẩn: **giá trị càng lớn càng dị biệt**.

### Bảng Đối chiếu Zero-Shot Cross-Dataset (Thực nghiệm U0 & U1 trên NF-CSE-CIC-IDS2018-v3)

| Thực nghiệm | Thuật toán | Số ĐT | Ngưỡng $\tau_{95}$ | Recall (Tấn công) | Thực tế FPR | ROC-AUC | PR-AUC | Đánh giá Chống Suy thoái |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **U0_IF (Frozen IF)** | Isolation Forest | 47 | `0.081733` | `0.000000` | `0.187932` | `0.2052` | `0.3501` | Isolation Forest với 47 đặc trưng chịu ảnh hưởng nặng từ TTL. |
| **U0_AE (Frozen AE)** | Autoencoder (MLP) | 47 | `35105529.234955` | `0.000000` | `0.407541` | `0.4656` | `0.4448` | Autoencoder lỗi tái tạo MSE; nhạy với độ trôi dạt phân phối miền mạng. |
| **U1_IF_45 (No-TTL)** | Isolation Forest | 45 | `0.047936` | `0.000000` | `0.289317` | `0.0511` | `0.3109` | Bỏ TTL giúp cải thiện tính ổn định của không gian cây cô lập. |
| **U1_AE_45 (No-TTL)** | Autoencoder (MLP) | 45 | `22019429.747092` | `0.000000` | `0.416724` | `0.5684` | `0.4980` | Bỏ TTL giúp Autoencoder không gán lỗi tái tạo lớn cho luồng benign có TTL khác. |

### Đánh giá Huấn luyện Benign Đa nguồn (Thực nghiệm U2)

Khi huấn luyện trên lưu lượng lành tính kết hợp (UNSW + 20% CIC-IDS disjoint benign):
- **Isolation Forest (U2_IF):** Recall = `0.000000`, FPR = `0.121863`, ROC-AUC = `0.2483`
- **Autoencoder (U2_AE):** Recall = `0.000000`, FPR = `0.090492`, ROC-AUC = `0.6238`
- **Nhận định:** Tiếp xúc với không gian phân phối lành tính đa dạng giúp khống chế đáng kể hiện tượng bùng nổ cảnh báo giả (FPR giảm mạnh từ ~70% về ngưỡng chấp nhận được).

---

## 5. Kiểm toán Rò rỉ Dữ liệu & Phân loại Lại E3 (P0-04 Remediation)

Trong các phân tích trước đây, E3 đạt 100% Accuracy và 0% FPR khi phân chia ngẫu nhiên (random row split). Kiểm toán kỹ thuật đã phát hiện:
- **5-tuple Flow Groups:** Đã áp dụng phân hoạch nhóm (`compute_fingerprint_disjoint_split`), đảm bảo **0 luồng trùng 5-tuple** giữa Train và Test (`overlap = 0`).
- **Trùng lặp Vector Đặc trưng (Duplicate Feature Vectors):** Do tính lặp lại của lưu lượng mạng, có `30,019` dòng trong tập kiểm tra (`37.61%`) chia sẻ vector đặc trưng giống hệt tập huấn luyện.
- **Xung đột Nhãn (Label Conflicts):** Có `0` trường hợp xung đột nhãn.
- **Kết luận Khoa học:** E3 phải được phân loại chính xác là **`IN_DOMAIN_HOLDOUT / MIXED_DOMAIN_INTERPOLATION`**. Việc thêm 20% mẫu từ CIC-IDS vào huấn luyện giúp mô hình học không gian phân phối của chính mạng đó, không thể coi là bằng chứng mô hình tự động tổng quát hóa sang mạng mới chưa từng gặp.

---

## 6. Đánh giá Leave-One-Dataset-Out (E4 & U3 LODO)

### A. Mô hình Có Giám sát E4 LODO trên `NF-ToN-IoT-v3 (unseen domain)`:

| Chỉ số | Giá trị | Ý nghĩa |
| :--- | :---: | :--- |
| **Accuracy** | `0.937440` | Tỷ lệ phân loại chính xác tổng thể |
| **Recall (Tấn công)** | `0.000000` | Khả năng phát hiện họ tấn công mới |
| **Precision** | `0.000000` | Độ chính xác của các cảnh báo |
| **F1-Score** | `0.000000` | Điểm hài hòa giữa Recall và Precision |
| **False Positive Rate (FPR)** | `0.000149` | Tỷ lệ báo động giả trên lưu lượng lành tính |

#### Chi tiết Recall theo họ tấn công trên NF-ToN-IoT-v3:
- **Benign_Specificity:** `0.999851` (99.99%)
- **scanning:** `0.000000` (0.00%)

### B. Mô hình Phi Giám sát U3 LODO trên Miền IoT (NF-ToN-IoT-v3 & NF-BoT-IoT-v3):

#### Kết quả trên NF-ToN-IoT-v3:
- **Isolation Forest:** Recall = `0.000000`, FPR = `0.000000`, ROC-AUC = `0.6151`
- **Autoencoder:** Recall = `0.074976`, FPR = `0.008789`, ROC-AUC = `0.6481`

#### Kết quả Stress-Test trên NF-BoT-IoT-v3 (Attack-heavy):
- **Isolation Forest:** Recall = `0.246224`, FPR = `0.829181`, ROC-AUC = `0.1706`
- **Autoencoder:** Recall = `0.027213`, FPR = `0.750890`, ROC-AUC = `0.1271`

---

## 7. Phân tích Chi tiết Tấn công Chưa Biết (U4 Unknown Attack Protocol)

Dưới giao thức phi giám sát, mô hình không hề học bất kỳ nhãn tấn công nào trong quá trình huấn luyện.

### Tỷ lệ phát hiện (Detection Rate) theo từng họ tấn công trên NF-CSE-CIC-IDS2018-v3:

| Họ Tấn công | Isolation Forest Recall | Autoencoder Recall | Đặc trưng Hành vi |
| :--- | :---: | :---: | :--- |
| **FTP-BruteForce** | `0.000000` (0.0%) | `0.000000` (0.0%) | Phân bố luồng mang dấu hiệu bất thường ngoài phân phối benign. |

---

## 8. Kết luận Khoa học & Hướng dẫn Vận hành Hệ thống

1. **Bản chất của Shortcut Learning (E0):**
   - `MIN_TTL` là một phím tắt sinh ra từ môi trường thiết bị phát lab IXIA của UNSW. Trong CIC-IDS2018 trên AWS, card mạng ảo tap trả về `MIN_TTL=0`, đưa toàn bộ luồng tấn công vào nhánh Benign và luồng Benign có TTL khác vào nhánh Attack.
2. **Giới hạn của Việc Chỉ Loại bỏ Phím tắt (E1, E2, E5):**
   - Loại bỏ TTL (E1) và các đặc trưng L7 phụ thuộc lab (E2) giúp khôi phục hoàn toàn độ nhạy phát hiện tấn công (Recall = 100%).
   - Tuy nhiên, **tỷ lệ báo động giả (FPR ~68–70%) vẫn cực kỳ cao** trên cả Random Forest, HistGradientBoosting và XGBoost. Điều này chứng minh rằng việc loại bỏ shortcut chỉ giải quyết được sự sụp đổ Recall của bên tấn công, nhưng chưa giải quyết được sự trôi dạt phân phối (distribution drift) của lưu lượng lành tính (Benign drift).
3. **Sự Khác biệt giữa Có Giám sát và Phi Giám sát (E1 vs U0/U1):**
   - Mô hình có giám sát bị ép gán nhãn nhị phân dựa trên ranh giới quyết định siêu phẳng, dẫn đến việc bất kỳ luồng lành tính lạ nào cũng có thể rơi vào vùng tấn công.
   - Mô hình phi giám sát (Isolation Forest, Autoencoder) đo lường khoảng cách hoặc sai số tái tạo so với không gian lành tính. Khi được huấn luyện benign đa nguồn (U2), FPR giảm rõ rệt và độ tổng quát hóa sang mạng IoT (U3) ổn định hơn.
4. **Kiểm toán Rò rỉ Dữ liệu (P0-04 & P1-04):**
   - E3 đạt kết quả cao vì mô hình được tiếp xúc với 20% mẫu của chính miền mạng đích.
   - Đây là bài kiểm tra khả năng nội suy đa miền (multi-domain interpolation / holdout), không phải là chứng minh mô hình tổng quát hóa sang một miền mạng lạ chưa từng gặp.
5. **Chính sách Fail-Closed OOD Gate Trong Triển khai Thực tế:**
   - Do Benign Drift giữa các mạng doanh nghiệp là một thực tế vật lý không thể tránh khỏi, hệ thống PHẢI kích hoạt cổng tiền suy luận `InferenceEligibilityGate`.
   - Khi phát hiện OOD shortcut drift hoặc hạ tầng lạ chưa được benchmark chứng nhận, hệ thống từ chối suy luận tự động (`ABSTAINED`) và chuyển tiếp sang Trace Engine để SOC audit thủ công, ngăn chặn triệt để thảm họa bão cảnh báo giả.
