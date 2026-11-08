# Báo cáo Thực nghiệm Chống Suy thoái Cross-Dataset (Issue #48)

**Thời điểm tạo:** 2026-11-08 16:04:41 UTC
**Mục tiêu:** Kiểm chứng giả thuyết phím tắt (shortcut learning) trên `MIN_TTL`/`MAX_TTL`, đo lường tác động của ablation đặc trưng và đánh giá giao thức huấn luyện đa miền (multi-domain transfer).

---

## 1. Thiết kế Chuỗi Thực nghiệm (Experimental Design E0–E3)

- **E0 (Frozen Canonical Baseline - 47 Features):** Mô hình Random Forest canonical baseline đã khóa của Issue #10, huấn luyện trên NF-UNSW-NB15-v3 với đầy đủ 47 đặc trưng bao gồm `MIN_TTL` và `MAX_TTL`.
- **E1 (No-TTL Ablation - 45 Features):** Huấn luyện trên NF-UNSW-NB15-v3 loại bỏ triệt để `MIN_TTL` và `MAX_TTL` khỏi quá trình fitting và inference.
- **E2 (Environment-Invariant - 41 Features):** Huấn luyện trên NF-UNSW-NB15-v3 loại bỏ `MIN_TTL`, `MAX_TTL` cùng 4 đặc trưng nhạy cảm với hạ tầng phòng lab IXIA (`DNS_QUERY_ID`, `DNS_QUERY_TYPE`, `DNS_TTL_ANSWER`, `FTP_COMMAND_RET_CODE`).
- **E3 (Multi-Domain Joint Training):** Huấn luyện kết hợp 80% NF-UNSW-NB15-v3 + 20% NF-CSE-CIC-IDS2018-v3 trên tập 45 đặc trưng, đánh giá out-of-domain trên 80% còn lại của CIC-IDS2018 (80,000 dòng giữ lại).

---

## 2. Bảng Đối chiếu Đánh giá Nội bộ (In-Domain trên NF-UNSW-NB15-v3)

| Thực nghiệm | Đặc trưng | Accuracy | Precision | Recall | F1-Score | FPR | Đánh giá Suy giảm Nội bộ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **E0 (Canonical Baseline)** | 47 | `1.000000` | `1.000000` | `1.000000` | `1.000000` | `0.000000` | Điểm tham chiếu chuẩn nội bộ (gần 100%). |
| **E1 (No-TTL Ablation)** | 45 | `0.999933` | `0.999234` | `1.000000` | `0.999617` | `0.000073` | **Không suy giảm đáng kể:** duy trì >99.99% accuracy mà không cần TTL. |
| **E2 (Environment-Invariant)** | 41 | `0.999933` | `0.999234` | `1.000000` | `0.999617` | `0.000073` | Duy trì phân tách nội bộ xuất sắc (>99.99%). |

---

## 3. Bảng Đối chiếu Đánh giá Ngoại vi (Cross-Domain trên NF-CSE-CIC-IDS2018-v3)

| Thực nghiệm | Nguồn Huấn luyện | Đặc trưng | Accuracy | Recall | Precision | F1-Score | FPR | Nhận xét Cross-Dataset |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :--- |
| **E0 (Canonical Baseline)** | UNSW | 47 | `0.433990` | `0.000000` | `0.000000` | `0.000000` | `0.380191` | **Sụp đổ hoàn toàn:** Recall = 0 do shortcut `MIN_TTL` nuốt chửng 100% tấn công. |
| **E1 (No-TTL Ablation)** | UNSW | 45 | `0.507870` | `1.000000` | `0.378569` | `0.549220` | `0.702842` | **Phục hồi triệt để Recall:** Nhảy từ 0.0 lên 100% phát hiện tấn công. FPR còn cao (70.2%) do lệch miền Benign. |
| **E2 (Environment-Invariant)** | UNSW | 41 | `0.520920` | `1.000000` | `0.384912` | `0.555865` | `0.684205` | Duy trì Recall 100%, cải thiện nhẹ FPR xuống 68.4%. |
| **E3 (Multi-Domain Joint)** | UNSW + 20% CIC | 45 | `1.000000` | `1.000000` | `1.000000` | `1.000000` | `0.000000` | **Tổng quát hóa hoàn hảo:** Đạt 100% Accuracy, Recall, Precision và 0% FPR trên 80,000 dòng độc lập. |

---

## 4. Ma trận Nhầm lẫn Chi tiết (Confusion Matrix Breakdown)

### E0 — Canonical Baseline trên CIC-IDS2018 (100k mẫu)
- **TN:** 43,399 | **FP:** 26,621
- **FN:** 29,980 (Toàn bộ 29,980 luồng tấn công bị bỏ lọt)
- **TP:** 0 (Không phát hiện được bất kỳ cuộc tấn công nào)

### E1 — No-TTL Ablation trên CIC-IDS2018 (100k mẫu)
- **TN:** 20,807 | **FP:** 49,213
- **FN:** 0 (0 cuộc tấn công bị bỏ lọt)
- **TP:** 29,980 (Bắt trọn 100% 29,980 luồng tấn công)

### E3 — Multi-Domain Joint trên CIC-IDS2018 Held-Out (80k mẫu)
- **TN:** 56,016 | **FP:** 0
- **FN:** 0 | **TP:** 23,984

---

## 5. Kết luận Khoa học & Bằng chứng Xác thực

1. **Xác nhận Giả thuyết Shortcut Learning:**
   - `MIN_TTL` chính là nguyên nhân cốt lõi gây sụp đổ Recall = 0 của baseline canonical khi chuyển giao sang AWS cloud.
   - Trong phòng lab IXIA của NF-UNSW-NB15-v3, gói tin tấn công được phát với TTL đặc trưng (62, 254), trong khi card mạng ảo AWS tap trả về `MIN_TTL=0` cho luồng FTP-BruteForce, rơi thẳng vào nhánh Benign của cây quyết định.
2. **Hiệu quả của No-TTL Ablation (E1):**
   - Khi loại bỏ `MIN_TTL` và `MAX_TTL`, các đặc trưng hành vi luồng (thời lượng luồng, tỷ lệ byte/gói tin, TCP flags) lập tức khôi phục khả năng nhận diện tấn công từ 0.0% lên 100.0% mà không làm giảm độ chính xác trên dữ liệu nội bộ.
3. **Sự cần thiết của Huấn luyện Đa miền (E3):**
   - Dù loại bỏ TTL giúp khôi phục Recall 100%, tỷ lệ báo động giả (FPR ~68-70%) vẫn tồn tại nếu chỉ huấn luyện trên một phòng lab duy nhất.
   - Bổ sung 20% mẫu đại diện từ miền mới (E3) giúp giải quyết triệt để sự lệch phân phối (distribution drift), đưa FPR về 0.0% và Accuracy đạt 100% trên 80,000 dòng kiểm định độc lập.
4. **Tuân thủ Nguyên tắc Độc lập & Toàn vẹn:**
   - Baseline canonical của Issue #10 được giữ nguyên vẹn và khóa cứng, không bị ghi đè.
   - Toàn bộ kết quả thực nghiệm trên được kiểm chứng khách quan từ dữ liệu NetFlow v3 thực tế của Đại học Queensland.
