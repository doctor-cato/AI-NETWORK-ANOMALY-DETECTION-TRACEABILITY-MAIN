# Báo cáo Thực nghiệm RQ4: Đánh Giá Phát Hiện Tấn Công Mới Chưa Từng Thấy (Unknown Attack Holdout)

**Mã tài liệu:** `EXP-RQ4-UNKNOWN-001`  
**Milestone:** `M6.3 (AI Research)`  
**Issue:** `#98`  
**Trạng thái:** `HYPOTHESIS CONFIRMED`  

---

## 1. Giả thuyết Khoa học (Hypothesis H4)

Các hệ thống phòng thủ truyền thống dựa trên phân loại có giám sát (Supervised Learning) thường gặp hiện tượng "điểm mù thế giới đóng" (closed-world assumption): khi gặp một họ tấn công mới (Zero-Day hoặc Novel Variant), mô hình có xu hướng gán nhãn luồng tấn công đó thành Bình thường (Benign).

**Giả thuyết H4:**  
> Các mô hình phát hiện bất thường không giám sát (Autoencoder Reconstruction Error và Isolation Forest) duy trì tỷ lệ phát hiện cao (Recall $\ge 0.75$) trên các họ tấn công hoàn toàn chưa từng quan sát trong tập huấn luyện, trong khi các mô hình có giám sát (Random Forest, XGBoost) bị suy giảm độ nhạy nghiêm trọng (Recall $< 0.40$).

---

## 2. Giao thức Thực nghiệm Holdout (Strict Protocol)

- **Họ tấn công bị giữ lại (Holdout Family):** `Backdoors & Exfiltration` bị loại bỏ 100% khỏi tập Huấn luyện (Train) và tập Thẩm định (Validation).
- **Tập Train/Validation:** Chỉ chứa lưu lượng Benign và các họ tấn công đã biết (DoS, Reconnaissance, Exploits, Fuzzers).
- **Tập Test:** Đánh giá trên các mẫu `Backdoors & Exfiltration` chưa từng thấy cùng lưu lượng Benign kiểm thử.
- **Cam kết không rò rỉ:** 0 mẫu của họ Backdoors xuất hiện trong quá trình huấn luyện hoặc hiệu chuẩn ngưỡng.

---

## 3. Bảng So sánh Hiệu năng Phát hiện Tấn công Mới

| Mô hình | Trường phái (Paradigm) | Recall Tấn công đã biết | Recall Tấn công mới (Holdout) | Mức độ suy giảm ($\Delta$ Recall) | F1 Tấn công mới |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Random Forest** | Có giám sát (Tree Ensemble) | 97.4% | **34.2%** | **-64.89%** | 48.1% |
| **XGBoost** | Có giám sát (Gradient Boosting) | 97.8% | **36.8%** | **-62.37%** | 50.9% |
| **Isolation Forest** | Không giám sát (Anomaly Isolation) | 85.2% | **78.4%** | **-7.98%** | 73.7% |
| **Autoencoder** | Không giám sát (Reconstruction Loss) | 86.5% | **83.6%** | **-3.35%** | **78.6%** |
| **Sentinel v2 Ensemble** | **Tập hợp đa mô hình thích ứng** | **96.8%** | **84.5%** | **-12.70%** | **80.0%** |

---

## 4. Kết luận Khoa học & Cơ sở Thiết kế Kiến trúc

1. **Khẳng định Giả thuyết H4:**  
   - Mô hình có giám sát bị bỏ sót hơn 63-65% các cuộc tấn công mới do ranh giới quyết định bị bó hẹp trong các mẫu đã thấy.
   - Autoencoder duy trì Recall **83.6%** (chỉ suy giảm 3.35%) nhờ cơ chế đo lường độ lệch khỏi phân bố bình thường (normal manifold).
2. **Minh chứng cho Kiến trúc Tập hợp Đa Mô hình (Multi-Model Aggregator #109):**  
   Kết quả này chứng minh rằng việc kết hợp Supervised (độ chính xác cao trên tấn công phổ biến) với Anomaly Detection (cảnh báo sớm tấn công lạ) là kiến trúc tối ưu cho NetFlow Sentinel v2.0.
3. **Giới hạn thực nghiệm:**  
   Holdout trong benchmark mô phỏng sự vắng mặt của chữ ký tấn công nhưng chưa bao quát toàn bộ các kỹ thuật che giấu payload (polymorphism / adversarial evasion) của tấn công APT trong thực tế.
