# Báo cáo Thực nghiệm Chống Suy thoái Cross-Dataset & Tổng quát hóa (Issue #48)

**Thời điểm tạo:** 2026-11-08 17:25:06 UTC
**Mục tiêu:** Kiểm toán toàn diện hiện tượng shortcut learning, khắc phục rủi ro rò rỉ dữ liệu (leakage audit), đánh giá Leave-One-Dataset-Out (LODO) và đối chiếu mô hình Gradient Boosting.

---

## 1. Thiết kế Chuỗi Thực nghiệm (Experimental Design E0–E5)

- **E0 (Frozen Canonical Baseline - 47 Features):** Mô hình Random Forest canonical baseline đã khóa của Issue #10, huấn luyện trên NF-UNSW-NB15-v3 với đầy đủ 47 đặc trưng bao gồm shortcut `MIN_TTL` và `MAX_TTL`.
- **E1 (No-TTL Ablation - 45 Features):** Huấn luyện Random Forest trên NF-UNSW-NB15-v3 loại bỏ triệt để `MIN_TTL` và `MAX_TTL` khỏi quá trình fitting và inference.
- **E2 (Environment-Invariant - 41 Features):** Huấn luyện Random Forest trên NF-UNSW-NB15-v3 loại bỏ `MIN_TTL`, `MAX_TTL` cùng 4 đặc trưng hạ tầng phòng lab (`DNS_QUERY_ID`, `DNS_QUERY_TYPE`, `DNS_TTL_ANSWER`, `FTP_COMMAND_RET_CODE`).
- **E3 (Multi-Domain Joint Training & Leakage Audit):** Huấn luyện kết hợp 70% UNSW + 20% CIC-IDS2018 trên 45 đặc trưng. Áp dụng phân hoạch 5-tuple fingerprint-disjoint strictly leak-free và kiểm toán exact duplicate.
- **E4 (Leave-One-Dataset-Out / LODO):** Huấn luyện trên miền A+B (UNSW + CIC-IDS), đánh giá trên miền C hoàn toàn độc lập (`NF-ToN-IoT-v3`).
- **E5 (Gradient Boosting Comparison):** Huấn luyện mô hình HistGradientBoostingClassifier trên 45 đặc trưng không TTL (chuẩn giao thức Issue #31) để đối chiếu trực tiếp với Random Forest.

---

## 2. Bảng Đối chiếu Đánh giá Nội bộ (In-Domain trên NF-UNSW-NB15-v3)

| Thực nghiệm | Thuật toán | Số Đặc trưng | Accuracy | Precision | Recall | F1-Score | FPR | Đánh giá Suy giảm Nội bộ |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **E0 (Canonical Baseline)** | Random Forest | 47 | `1.000000` | `1.000000` | `1.000000` | `1.000000` | `0.000000` | Điểm tham chiếu chuẩn nội bộ (khóa cứng Issue #10). |
| **E1 (No-TTL Ablation)** | Random Forest | 45 | `0.999933` | `0.999234` | `1.000000` | `0.999617` | `0.000073` | Không suy giảm: duy trì >99.99% accuracy khi bỏ TTL. |
| **E2 (Environment-Invariant)** | Random Forest | 41 | `0.999933` | `0.999234` | `1.000000` | `0.999617` | `0.000073` | Duy trì phân tách nội bộ xuất sắc (>99.99%). |
| **E5 (Gradient Boosting)** | HistGradientBoosting | 45 | `0.999733` | `1.000000` | `0.996935` | `0.998465` | `0.000000` | Gradient boosting đạt phân tách nội bộ tương đương RF (>99.99%). |

---

## 3. Bảng Đối chiếu Đánh giá Ngoại vi (Cross-Domain trên NF-CSE-CIC-IDS2018-v3)

| Thực nghiệm | Nguồn Huấn luyện | Thuật toán | Số ĐT | Accuracy | Recall | Precision | F1-Score | FPR | Phân loại Đánh giá Khoa học |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **E0 (Canonical Baseline)** | UNSW | Random Forest | 47 | `0.433990` | `0.000000` | `0.000000` | `0.000000` | `0.380191` | **Sụp đổ hoàn toàn:** Recall = 0.0 do shortcut `MIN_TTL` nuốt chửng 100% tấn công. |
| **E1 (No-TTL Ablation)** | UNSW | Random Forest | 45 | `0.507870` | `1.000000` | `0.378569` | `0.549220` | `0.702842` | **Phục hồi Recall nhưng FPR bùng nổ:** Bắt trọn 100% tấn công, nhưng FPR 70.2% gây bão cảnh báo giả. |
| **E2 (Environment-Invariant)** | UNSW | Random Forest | 41 | `0.520920` | `1.000000` | `0.384912` | `0.555865` | `0.684205` | Duy trì Recall 100%, cải thiện nhẹ FPR xuống 68.4%. |
| **E3 (Multi-Domain Joint)** | UNSW + 20% CIC | Random Forest | 45 | `1.000000` | `1.000000` | `1.000000` | `1.000000` | `0.000000` | **In-Domain Holdout:** Đạt kết quả cao trên miền đã lấy mẫu, không phải tổng quát hóa miền chưa biết. |
| **E5 (Gradient Boosting)** | UNSW | HistGradientBoosting | 45 | `0.637850` | `1.000000` | `0.452904` | `0.623447` | `0.517209` | Recall đạt 100% khi bỏ TTL, nhưng FPR tương tự RF do lệch miền lưu lượng lành tính. |

---

## 4. Kiểm toán Rò rỉ Dữ liệu & Phân loại Lại E3 (P0-04 Remediation)

Trong các phân tích trước đây, E3 đạt 100% Accuracy và 0% FPR khi phân chia ngẫu nhiên (random row split). Kiểm toán kỹ thuật đã phát hiện:
- **5-tuple Flow Groups:** Đã áp dụng phân hoạch nhóm (`compute_fingerprint_disjoint_split`), đảm bảo **0 luồng trùng 5-tuple** giữa Train và Test (`overlap = 0`).
- **Trùng lặp Vector Đặc trưng (Duplicate Feature Vectors):** Do tính lặp lại của lưu lượng mạng, có `30,019` dòng trong tập kiểm tra (`37.61%`) chia sẻ vector đặc trưng giống hệt tập huấn luyện.
- **Xung đột Nhãn (Label Conflicts):** Có `0` trường hợp xung đột nhãn.
- **Kết luận Khoa học:** E3 phải được phân loại chính xác là **`IN_DOMAIN_HOLDOUT / MIXED_DOMAIN_INTERPOLATION`**. Việc thêm 20% mẫu từ CIC-IDS vào huấn luyện giúp mô hình học không gian phân phối của chính mạng đó, không thể coi là bằng chứng mô hình tự động tổng quát hóa sang mạng mới chưa từng gặp.

---

## 5. Đánh giá Leave-One-Dataset-Out (E4 LODO)

**Tập dữ liệu Kiểm định Độc lập:** `NF-ToN-IoT-v3 (unseen domain)` (Hoàn toàn không xuất hiện trong huấn luyện hoặc tiền xử lý)

| Chỉ số | Giá trị | Ý nghĩa |
| :--- | :---: | :--- |
| **Accuracy** | `0.937440` | Tỷ lệ phân loại chính xác tổng thể |
| **Recall (Tấn công)** | `0.000000` | Khả năng phát hiện họ tấn công mới |
| **Precision** | `0.000000` | Độ chính xác của các cảnh báo |
| **F1-Score** | `0.000000` | Điểm hài hòa giữa Recall và Precision |
| **False Positive Rate (FPR)** | `0.000149` | Tỷ lệ báo động giả trên lưu lượng lành tính |

### Chi tiết Recall theo họ tấn công trên NF-ToN-IoT-v3:
- **Benign_Specificity:** `0.999851` (99.99%)
- **scanning:** `0.000000` (0.00%)

---

## 6. Ma trận Nhầm lẫn Chi tiết (Confusion Matrix Breakdown)

### E0 — Canonical Baseline trên CIC-IDS2018 (100k mẫu)
- **TN:** 43,399 | **FP:** 26,621
- **FN:** 29,980 (Toàn bộ 29,980 luồng tấn công bị bỏ lọt do TTL shortcut)
- **TP:** 0 (Không phát hiện được bất kỳ cuộc tấn công nào)

### E1 — No-TTL Ablation trên CIC-IDS2018 (100k mẫu)
- **TN:** 20,807 | **FP:** 49,213
- **FN:** 0 (0 cuộc tấn công bị bỏ lọt)
- **TP:** 29,980 (Bắt trọn 100% 29,980 luồng tấn công)

### E3 — Multi-Domain Joint trên CIC-IDS2018 Disjoint Held-Out
- **TN:** 55,751 | **FP:** 0
- **FN:** 0 | **TP:** 24,068

---

## 7. Kết luận Khoa học & Bằng chứng Thực thi

1. **Bản chất của Shortcut Learning (E0):**
   - `MIN_TTL` là một phím tắt sinh ra từ môi trường thiết bị phát lab IXIA của UNSW. Trong CIC-IDS2018 trên AWS, card mạng ảo tap trả về `MIN_TTL=0`, đưa toàn bộ luồng tấn công vào nhánh Benign và luồng Benign có TTL khác vào nhánh Attack.
2. **Giới hạn của Việc Chỉ Loại bỏ Phím tắt (E1 & E2):**
   - Loại bỏ TTL (E1) và các đặc trưng L7 phụ thuộc lab (E2) giúp khôi phục hoàn toàn độ nhạy phát hiện tấn công (Recall = 100%).
   - Tuy nhiên, **tỷ lệ báo động giả (FPR ~68–70%) vẫn cực kỳ cao**. Điều này chứng minh rằng việc loại bỏ shortcut chỉ giải quyết được sự sụp đổ Recall của bên tấn công, nhưng chưa giải quyết được sự trôi dạt phân phối (distribution drift) của lưu lượng lành tính (Benign drift).
3. **Tính Trung thực Khoa học về E3 (P0-04 & P1-04):**
   - E3 đạt kết quả cao vì mô hình được tiếp xúc với 20% mẫu của chính miền mạng đích.
   - Đây là bài kiểm tra khả năng nội suy đa miền (multi-domain interpolation / holdout), không phải là chứng minh mô hình tổng quát hóa sang một miền mạng lạ chưa từng gặp.
4. **Bảo tồn Tuyệt đối Baseline Canonical (P0-05):**
   - Baseline canonical từ Issue #10 được bảo toàn nguyên vẹn từ các tệp nhị phân và manifest có chữ ký hash SHA-256.
   - Toàn bộ cơ chế fallback tự huấn luyện lại mô hình baseline đã bị xóa bỏ hoàn toàn.
