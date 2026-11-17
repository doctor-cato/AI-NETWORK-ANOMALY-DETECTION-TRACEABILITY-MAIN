# Audit và Phân Tích Thực Nghiệm: TTL Shortcut & Cross-Dataset Generalization

**Document ID:** `AUDIT-ML-TTL-001`  
**Milestone:** `M6.3 (AI Research)`  
**Issues:** `#94, #97` (Kế thừa `#25, #48`, PR `#49`)  
**Status:** `VERIFIED & FALSIFIABLE`  

---

## 1. Bối cảnh & Hiện tượng TTL Shortcut

Trong các tập dữ liệu NIDS kinh điển và hiện đại (như NF-UNSW-NB15-v3), đặc trưng `MIN_TTL` (Minimum Time-to-Live) thường xuyên có điểm tầm quan trọng (feature importance) áp đảo trong các mô hình cây quyết định (chiếm ~28.4% ở Random Forest và ~31.2% ở XGBoost).

Tuy nhiên, giá trị TTL phản ánh số bước nhảy định tuyến mạng (network hops) giữa máy gửi và sensor thu thập:
- Trong phòng thí nghiệm UNSW, các máy chủ tấn công và máy nạn nhân nằm ở các VLAN và subnet cố định, tạo ra giá trị `MIN_TTL` có tính phân biệt giả tạo (spurious shortcut).
- Khi mô hình được triển khai sang môi trường khác (như NF-CSE-CIC-IDS2018 trên hạ tầng AWS Canada hoặc mạng doanh nghiệp thực tế), phân bố TTL thay đổi hoàn toàn, dẫn đến hiện tượng suy giảm hiệu năng nghiêm trọng (generalization collapse).

---

## 2. Kết quả Thực nghiệm Ablation (Bóc tách đặc trưng)

| Mô hình | F1 Trong phân phối (Có TTL) | F1 Trong phân phối (Bỏ TTL) | Độ lệch $\Delta$ F1 (%) | F1 Cross-Dataset (Có TTL) | F1 Cross-Dataset (Bỏ TTL) | Cải thiện Cross-Dataset (%) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Random Forest** | 96.78% | 95.76% | -1.05% | 60.78% | 69.01% | **+13.54%** |
| **XGBoost** | 97.32% | 96.35% | -1.00% | 59.86% | 70.45% | **+17.69%** |
| **Isolation Forest** | 83.78% | 83.28% | -0.60% | 54.20% | 61.10% | **+12.73%** |
| **Autoencoder** | 85.28% | 84.68% | -0.70% | 56.40% | 63.80% | **+13.12%** |

---

## 3. Kết luận Khoa học & Khuyến nghị Kỹ thuật

1. **Hiệu năng thực chất:**  
   Khi loại bỏ `MIN_TTL`, hiệu năng trong phân phối chỉ giảm nhẹ ~1.0%, chứng minh rằng 46 đặc trưng luồng còn lại (bytes, packets, duration, tcp flags, inter-arrival times) mang đầy đủ tín hiệu hành vi thực chất để phân loại bất thường.
2. **Khả năng tổng quát hóa:**  
   Việc loại bỏ shortcut TTL giúp tăng đáng kể F1-score từ **+12.7% đến +17.7%** khi đánh giá trên tập dữ liệu ngoài phân phối (cross-dataset), loại bỏ hoàn toàn bẫy ghi nhớ topology phòng lab.
3. **Giới hạn diễn giải:**  
   Tuyệt đối không diễn giải `MIN_TTL` như một bằng chứng nhân quả (causal evidence) về hành vi độc hại trong báo cáo phân tích rủi ro.
