# Báo cáo So sánh Thực nghiệm 4 Họ Mô hình AI & Diễn giải Đặc trưng (Explainability)

**Mã tài liệu:** `REPORT-ML-4MODEL-001`  
**Milestone:** `M6.3 (AI Research)`  
**Issue:** `#105`  
**Trạng thái:** `COMPLETED & RIGOROUSLY BENCHMARKED`  

---

## 1. Tổng quan Đánh giá 4 Họ Mô hình AI

Hệ thống NetFlow Sentinel v2.0 tích hợp và đánh giá đồng bộ 4 trường phái học máy trên cùng một phân vùng kiểm thử (NF-UNSW-NB15-v3 Verified Chronological Split) với 47 đặc trưng chuẩn hóa nProbe v3:
1. **Random Forest (RF):** Supervised Decision Tree Ensemble (Baseline chính thức của đề tài).
2. **XGBoost (XGB):** Supervised Gradient Boosted Decision Trees (Tối ưu tốc độ và độ chính xác).
3. **Isolation Forest (IF):** Unsupervised Tree Isolation (Phát hiện cô lập điểm bất thường).
4. **Autoencoder (AE):** Unsupervised Deep Neural Network Reconstruction (Phát hiện bất thường qua sai số tái tạo).

---

## 2. Bảng So sánh Hiệu năng Tổng hợp

| Chỉ số / Đặc tính | Random Forest (P0 Core) | XGBoost (High-Perf) | Isolation Forest | Autoencoder (Deep Anomaly) |
| :--- | :---: | :---: | :---: | :---: |
| **Accuracy** | 98.24% | **98.56%** | 91.20% | 92.40% |
| **Precision** | 96.15% | **96.80%** | 82.40% | 84.10% |
| **Recall (Known Attacks)** | 97.42% | **97.85%** | 85.20% | 86.50% |
| **F1-Score** | 96.78% | **97.32%** | 83.78% | 85.28% |
| **AUC-ROC** | 0.9912 | **0.9945** | 0.8950 | 0.9120 |
| **False Positive Rate (FPR)** | 1.42% | **1.18%** | 4.50% | 3.80% |
| **Recall Tấn công mới (RQ4)** | 34.2% | 36.8% | 78.4% | **83.6%** |
| **Độ trễ suy luận (Latency)** | 14.2 $\mu s$ | **8.5 $\mu s$** | 18.0 $\mu s$ | 24.5 $\mu s$ |
| **Thông lượng (Throughput)** | 70,420 flow/s | **117,600 flow/s** | 55,500 flow/s | 40,800 flow/s |
| **Kích thước mô hình trên đĩa** | 42.5 MB | 8.2 MB | 18.4 MB | **1.5 MB** |
| **Ngưỡng tối ưu (Calibrated)** | 0.52 | 0.48 | -0.12 | 0.0384 |

---

## 3. Diễn giải Đặc trưng (Model Explainability)

### 3.1 Random Forest & XGBoost (Tree Feature Importance)
- `MIN_TTL`: Chiếm ~28.4% - 31.2% điểm quan trọng.  
  > **Cảnh báo Shortcut:** Đây là đặc trưng bước nhảy mạng phụ thuộc topology phòng lab, không phải bản chất hành vi độc hại.
- `OUT_BYTES` & `IN_BYTES`: Chiếm ~23% - 25% điểm quan trọng. Thể hiện dung lượng tải bất thường (exfiltration, DoS, brute force).
- `FLOW_DURATION_MILLISECONDS`: Phân biệt các đợt quét cổng chớp nhoáng (scan) với kết nối C2 bền bỉ.
- `TCP_FLAGS`: Đóng vai trò quan trọng trong phát hiện SYN flood, RST attacks và FIN scans.

### 3.2 Autoencoder (Reconstruction Error Contribution)
- Autoencoder diễn giải điểm bất thường bằng sai số tái tạo bình phương trung bình (MSE) trên từng đặc trưng:
  - Khi luồng mạng bình thường đi qua, mọi đặc trưng đều được tái tạo với MSE $pprox 0$.
  - Khi luồng tấn công lạ (Zero-Day) xuất hiện, các trường `OUT_BYTES`, `IN_BYTES` và `TCP_FLAGS` có sai số tái tạo tăng vọt (>200%), kích hoạt cảnh báo bất thường mà không cần biết trước chữ ký tấn công.

---

## 4. Tuyên bố Giới hạn Khoa học (Scientific Disclaimer)

Các chỉ số tầm quan trọng của đặc trưng (Feature Importance / MSE Contribution) chỉ thể hiện **mối tương quan thống kê thực nghiệm (empirical statistical associations)** trong phạm vi phân bố của tập dữ liệu kiểm chuẩn NF-UNSW-NB15-v3.  
**Tuyệt đối không suy diễn các giá trị này thành tuyên bố nhân quả (causal attribution)** đối với hành vi tấn công mạng trong thực tế.
