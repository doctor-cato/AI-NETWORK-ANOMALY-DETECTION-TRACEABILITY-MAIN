# NetFlow Sentinel v2.0 — Chuẩn hóa 6 Câu hỏi Nghiên cứu (RQ1–RQ6)

> **Tài liệu nghiên cứu khoa học (Issue #77 — Milestone M6.1)**  
> **Phiên bản:** 2.0.0-research  
> **Ánh xạ đề cương:** `docs/Ke_hoach_de_tai_22_AI_Anomaly_Detection.docx`

---

## 1. Giới thiệu và Nguyên tắc Nghiên cứu

Đề tài 22 hướng tới giải quyết bài toán phát hiện, phân tích và truy vết bất thường mạng trong bối cảnh các mối đe dọa an ninh mạng ngày càng tinh vi, sử dụng kỹ thuật ẩn mình và thay đổi địa chỉ IP liên tục.

Mọi thực nghiệm trong đề tài tuân thủ các nguyên tắc:
1. **Verifiable Hypotheses:** Giả thuyết có thể bị bác bỏ (falsifiable) kèm ngưỡng định lượng tường minh.
2. **Leakage-Safe Protocols:** Tách biệt tuyệt đối train/val/test; chỉ tuning và calibrate threshold trên validation; không dùng test để tinh chỉnh.
3. **Reproducibility:** Mọi thực nghiệm có kịch bản chạy tự động, random seed cố định, lưu manifest mã băm SHA-256.
4. **Honest Limitations:** Báo cáo trung thực kết quả tiêu cực (negative results) và không đánh đồng kết quả holdout với khả năng phát hiện zero-day thực tế trong môi trường sản xuất.

---

## 2. Chi tiết 6 Research Questions (RQ1–RQ6)

### RQ1 — So sánh Hiệu năng giữa Mô hình Supervised và Unsupervised / Semi-supervised
- **Câu hỏi nguyên văn:** *Hiệu năng phát hiện bất thường kết nối mạng (dựa trên luồng NetFlow) có sự khác biệt như thế nào giữa các mô hình học máy có giám sát (Random Forest, XGBoost) và không giám sát / bán giám sát (Isolation Forest, Deep Autoencoder)?*
- **Hypothesis (H1):** Trên tập kiểm thử phân phối đóng (in-distribution), mô hình có giám sát (Random Forest, XGBoost) đạt F1-score và Macro-F1 vượt trội ($\ge 0.95$) so với mô hình không giám sát (Isolation Forest $\ge 0.75$, Autoencoder $\ge 0.80$), nhưng mô hình không giám sát có khả năng tổng quát hóa biên tốt hơn mà không phụ thuộc vào nhãn tấn công.
- **Dataset:** NF-UNSW-NB15-v3 (canonical train/val/test split).
- **Baselines:** Random Forest canonical baseline (`n_estimators=200`, `max_depth=16`).
- **Metrics chính:** Macro-F1, Binary F1, Precision, Recall, FPR, Training Time, Inference Latency.
- **Mã thực nghiệm:** `Exp1` (Huấn luyện & Benchmark 4 Model).
- **Issue ánh xạ:** Triển khai: #94, #95; Đánh giá: #105, #145.
- **Trạng thái:** `IMPLEMENTED & VALIDATED` (v1.0 baseline RF & IF), `PLANNED` (XGBoost/Autoencoder cross-check).

---

### RQ2 — Mất cân bằng Dữ liệu và Tấn công Hiếm (Class Imbalance & Rare Attacks)
- **Câu hỏi nguyên văn:** *Mức độ suy giảm hiệu năng của các mô hình học máy khi đối mặt với dữ liệu mất cân bằng cực đoan và các lớp tấn công hiếm (rare attack categories) trong mạng như thế nào, và kỹ thuật tái cân bằng/trọng số có cải thiện được độ thu hồi (Recall) không?*
- **Hypothesis (H2):** Với các lớp tấn công chiếm tỷ lệ dưới 0.1% mẫu (Worms, Backdoors, Analysis), mô hình tiêu chuẩn suy giảm Per-class Recall xuống dưới 0.60. Việc áp dụng cost-sensitive class weighting và threshold tuning trên validation sẽ nâng Per-class Recall lên $\ge 0.75$ mà không làm tăng FPR tổng thể quá 0.01.
- **Dataset:** NF-UNSW-NB15-v3 (per-attack-category splits).
- **Baselines:** Random Forest unweighted standard threshold ($0.5$).
- **Metrics chính:** Per-category Recall, Per-category Precision, Macro-F1, False Positive Rate (FPR).
- **Mã thực nghiệm:** `Exp2` (Class Imbalance & Cost-sensitive Evaluation).
- **Issue ánh xạ:** Triển khai: #96; Đánh giá: #145.
- **Trạng thái:** `PLANNED` (v2.0 protocol).

---

### RQ3 — Khả năng Liên kết Phiên Độc lập IP dựa trên Behavioral Vector
- **Câu hỏi nguyên văn:** *Vector đặc trưng hành vi (Behavioral Vector) kết hợp các phép đo khoảng cách tương đồng có cho phép liên kết và nhận diện các phiên kết nối bất thường thuộc cùng một thực thể tấn công khi địa chỉ IP bị thay đổi (IP-independent correlation) với độ chính xác cao không?*
- **Hypothesis (H3):** Khi kẻ tấn công xoay vòng hoặc giả mạo địa chỉ IP nguồn/đích, việc so khớp khoảng cách Cosine trên Behavioral Vector chuẩn hóa 16 chiều giữa các cửa sổ thời gian (time-windows) đạt độ chính xác liên kết thực thể (Session Match Accuracy) $\ge 85\%$ và False Linking Rate $\le 5\%$, vượt trội so với đối sánh dựa trên tuple IP truyền thống (đạt $0\%$).
- **Dataset:** AIT NetFlow & Log Dataset v2.1 (kịch bản tấn công multi-host, IP-spoofing).
- **Baselines:** IP-tuple exact matching, Random session linking.
- **Metrics chính:** Session Correlation Accuracy, Cosine Similarity Score, False Link Rate, Silhouette Score.
- **Mã thực nghiệm:** `Exp3` (IP-Independent Session Tracking via Behavioral Vectors).
- **Issue ánh xạ:** Triển khai: #101, #102, #103, #104; Đánh giá: #145.
- **Trạng thái:** `PLANNED` (v2.0 engine).

---

### RQ4 — Phát hiện Hành vi Tấn công Mới / Chưa biết (Unknown / Novel Attack Detection)
- **Câu hỏi nguyên văn:** *Trong điều kiện giao thức Holdout (giữ lại hoàn toàn một hoặc nhiều lớp tấn công trong tập huấn luyện), mô hình không giám sát/bán giám sát (Autoencoder/Isolation Forest) có thể phát hiện các cuộc tấn công mới (novel/unknown attacks) tốt hơn mô hình có giám sát không?*
- **Hypothesis (H4):** Khi giấu một họ tấn công lớn (ví dụ: Fuzzers hoặc Exploits) khỏi tập huấn luyện:
  - Mô hình giám sát (RF) suy giảm Recall trên lớp bị giấu xuống $< 0.40$.
  - Mô hình bán giám sát (Deep Autoencoder tái cấu trúc lỗi) duy trì Detection Recall $\ge 0.70$ với FPR $\le 0.05$.
- **Giới hạn khoa học:** *Holdout attack detection mô phỏng kịch bản tấn công mới trong phạm vi không gian đặc trưng của benchmark, không đồng nhất và không thể xem là bảo chứng phát hiện 100% zero-day trong mạng thực tế.*
- **Dataset:** NF-UNSW-NB15-v3 (Unknown attack holdout partition).
- **Baselines:** Random Forest trained on restricted labels.
- **Metrics chính:** Unknown Attack Recall, Benign FPR, AUC-ROC, Reconstruction Error Threshold.
- **Mã thực nghiệm:** `Exp4` (Holdout Novel Attack Generalization).
- **Issue ánh xạ:** Triển khai: #98, #99, #100; Đánh giá: #145.
- **Trạng thái:** `PLANNED` (v2.0 protocol).

---

### RQ5 — Hiệu quả Giảm thiểu Phơi nhiễm của Adaptive Key Rotation
- **Câu hỏi nguyên văn:** *Cơ chế xoay vòng khóa thích ứng dựa trên rủi ro (Risk-based Adaptive Key Rotation) có làm giảm đáng kể cửa sổ phơi nhiễm dữ liệu nhạy cảm (exposure window) so với cơ chế xoay vòng khóa cố định theo thời gian (Fixed 30-min Rotation) khi xảy ra tấn công mạng không?*
- **Hypothesis (H5):** Dưới các đợt bùng phát tấn công (burst/high-risk anomalies), Adaptive Key Rotation thu hẹp thời gian phơi nhiễm khóa (Time-to-Key-Rotate) từ 30 phút xuống $< 1$ phút kể từ khi Risk Score $\ge 85$, giảm lượng bản ghi bị mã hóa chung một khóa ít nhất $70\%$ mà không gây suy thoái hiệu năng hệ thống nhờ cơ chế cooldown và rate limiting.
- **Dataset:** AIT Replay Scenario kèm chuỗi sự kiện rủi ro động.
- **Baselines:** Fixed Key Rotation (30 phút chu kỳ cứng), No Rotation (khóa tĩnh).
- **Metrics chính:** Exposure Window Duration (phút), Compromise Blast Radius (số bản ghi bị ảnh hưởng khi lộ khóa), Rotation Latency (ms), Số lần xoay khóa trong phiên.
- **Mã thực nghiệm:** `Exp5` (Fixed vs. Adaptive Key Rotation Under Attack Simulation).
- **Issue ánh xạ:** Triển khai: #120, #121, #122, #123; Đánh giá: #125, #145.
- **Trạng thái:** `PLANNED` (v2.0 crypto).

---

### RQ6 — Chi phí Tài nguyên và Độ trễ khi Tích hợp Mã hóa AES-256-GCM
- **Câu hỏi nguyên văn:** *Chi phí tài nguyên (CPU, RAM, throughput và latency) khi tích hợp mã hóa chứng thực AES-256-GCM đối với vector hành vi và luồng chứng cứ là bao nhiêu, và hệ thống có đảm bảo khả năng xử lý thời gian thực trên môi trường máy trạm thông thường không?*
- **Hypothesis (H6):** Việc thực hiện mã hóa AES-256-GCM trên Behavioral Vector và Evidence Record bổ sung độ trễ trung bình $\le 0.5$ ms mỗi sự kiện, tăng sử dụng CPU $\le 10\%$, và duy trì thông lượng tối thiểu $\ge 5.000$ sự kiện/giây trên phần cứng CPU thông thường (x86_64, tiêu chuẩn đồ án), hoàn toàn đáp ứng yêu cầu giám sát mạng thời gian thực.
- **Dataset:** Dữ liệu streaming mô phỏng và AIT NetFlow stream.
- **Baselines:** Plaintext storage (không mã hóa), AES-CBC (không xác thực tag).
- **Metrics chính:** Encryption Latency ($\mu s$), Decryption Latency ($\mu s$), Memory Footprint (MB), CPU Utilization (%), Throughput (events/sec).
- **Mã thực nghiệm:** `Exp6` (Cryptographic Overhead & Hardware Performance Benchmark).
- **Issue ánh xạ:** Triển khai: #117, #118, #124; Đánh giá: #126, #145, #147.
- **Trạng thái:** `PLANNED` (v2.0 benchmark).

---

## 3. Bảng Ánh xạ Toàn diện RQ → Hypothesis → Dataset → Experiment → Issue

| Research Question | Giả thuyết | Tập dữ liệu | Mã Thực nghiệm | Baseline So sánh | Metric Chính | Issue Triển khai | Issue Đánh giá | Milestone |
|---|---|---|---|---|---|---|---|---|
| **RQ1: Model Comparison** | H1 | NF-UNSW-NB15-v3 | `Exp1` | RF canonical v1 | Macro-F1, Binary F1, Latency | #94, #95 | #105, #145 | M6.3, M6.7 |
| **RQ2: Class Imbalance** | H2 | NF-UNSW-NB15-v3 | `Exp2` | Unweighted RF ($th=0.5$) | Per-category Recall, FPR | #96 | #145 | M6.3, M6.7 |
| **RQ3: Behavioral Correlation** | H3 | AIT NetFlow/Log v2.1 | `Exp3` | IP Tuple Matching | Session Match Accuracy, Cosine Dist | #101–#104 | #145 | M6.3, M6.7 |
| **RQ4: Unknown Attack Holdout** | H4 | NF-UNSW-NB15-v3 | `Exp4` | Supervised RF on holdout | Novel Attack Recall, FPR | #98, #99, #100 | #145 | M6.3, M6.7 |
| **RQ5: Adaptive Key Rotation** | H5 | AIT Attack Scenario | `Exp5` | Fixed 30-min Rotation | Exposure Window, Blast Radius | #120–#123 | #125, #145 | M6.5, M6.7 |
| **RQ6: Cryptographic Overhead**| H6 | Synthetic / AIT Flow | `Exp6` | Plaintext pipeline | Latency ($\mu s$), Throughput (evt/s) | #117, #118, #124 | #126, #147 | M6.5, M6.7 |
