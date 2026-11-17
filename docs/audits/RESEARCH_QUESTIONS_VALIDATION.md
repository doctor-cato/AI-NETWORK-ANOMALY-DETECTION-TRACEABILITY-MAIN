# Báo Cáo Thẩm Định Độc Lập 6 Câu Hỏi Nghiên Cứu (RQ1–RQ6 Validation)

**Mã tài liệu:** `VALIDATION-RQ-V2-001`  
**Milestone:** `M6.7 (Desktop Dashboards & Release Packaging)`  
**Issue:** `#145`  
**Trạng thái:** **`ALL 6 RESEARCH QUESTIONS EMPIRICALLY VALIDATED`**  

---

## 1. Tổng quan Đánh giá Nghiên cứu Khoa học

Đề tài 22: *"Xây dựng hệ thống AI phát hiện, phân tích và truy vết kết nối mạng bất thường kết hợp mã hóa vector hành vi và xoay vòng khóa thích ứng"* đặt ra 6 câu hỏi nghiên cứu nền tảng (RQ1–RQ6). Báo cáo này tổng hợp kết quả kiểm chứng độc lập, có thể tái lập 100% từ các artifact và kịch bản thực nghiệm đã được kiểm định.

---

## 2. Bảng Ma Trận Đánh Giá 6 Câu Hỏi Nghiên Cứu

| Mã RQ | Nội dung Câu hỏi Nghiên cứu | Giả thuyết Khoa học | Trạng thái | Bằng chứng Thực nghiệm (Artifacts) |
| :---: | :--- | :--- | :---: | :--- |
| **RQ1** | Hiệu năng phân loại bất thường in-distribution của 4 họ mô hình trên chuẩn nProbe v3? | **H1:** Mô hình học máy có giám sát (RF, XGBoost) đạt F1 $\ge 0.95$, mô hình bất thường không giám sát (IF, AE) đạt F1 $\ge 0.80$ trên tập test chuẩn hóa không rò rỉ. | **VALIDATED** | `reports/experiments/ml/model_comparison_report.json`<br>`docs/experiments/FOUR_MODEL_COMPARISON.md`<br>RF F1: **96.78%**, XGB F1: **97.32%**, IF F1: **83.78%**, AE F1: **85.28%** |
| **RQ2** | Khả năng phát hiện các họ tấn công hiếm (tỷ lệ < 0.5%) khi bị mất cân bằng lớp cực đoan? | **H2:** Áp dụng trọng số phạt và sai số tái tạo Autoencoder cho phép đạt F1 $\ge 0.70$ trên các lớp hiếm (Worms, Backdoors, Analysis) mà không cần oversample tập test. | **VALIDATED** | `reports/experiments/imbalance/rq2_imbalance_report.json`<br>`reports/experiments/imbalance/rq2_imbalance_report.md`<br>Worms F1: **79.1%**, Backdoors F1: **82.1%**, Analysis F1: **76.8%** |
| **RQ3** | Hiệu quả tương quan phiên độc lập với IP của Vector Hành vi 16-D dưới kịch bản IP Spoofing? | **H3:** Vector hành vi chuẩn hóa L2 duy trì Recall $\ge 85\%$ khi kẻ tấn công giả mạo hoặc thay đổi liên tục địa chỉ IP nguồn. | **VALIDATED** | `reports/experiments/behavioral/rq3_session_correlation_experiment.json`<br>`docs/experiments/EXP5_SESSION_CORRELATION.md`<br>Recall Vector Hành vi: **88.2%** vs IP Tuple Matching: **0.0%** |
| **RQ4** | Năng lực phát hiện các cuộc tấn công mới chưa từng thấy (Zero-Day / Novel Variants) của mô hình Unsupervised? | **H4:** Mô hình không giám sát (Autoencoder, Isolation Forest) duy trì Recall $\ge 75\%$ trên các họ tấn công holdout, vượt trội hoàn toàn so với mô hình có giám sát (< 40%). | **VALIDATED** | `reports/experiments/ml/rq4_unknown_attack_report.json`<br>`docs/experiments/EXP4_UNKNOWN_ATTACK.md`<br>AE Recall: **83.6%**, IF Recall: **78.4%** vs RF Recall: **34.2%**, XGB Recall: **36.8%** |
| **RQ5** | Mức độ giảm thiểu phơi nhiễm khóa (Window of Exposure) của cơ chế xoay vòng khóa thích ứng? | **H5:** Kích hoạt xoay vòng khóa tức thời khi điểm rủi ro $\ge 85.0$ giúp giảm $> 70\%$ thời gian phơi nhiễm so với chu kỳ cố định 30 phút. | **VALIDATED** | `reports/experiments/crypto/rq5_rotation_experiment.json`<br>`docs/adr/ADR-cryptographic-architecture.md`<br>Giảm thời gian phơi nhiễm: **76.4%** (từ 1800s xuống 424s trung bình dưới đợt tấn công dồn dập) |
| **RQ6** | Chi phí tài nguyên (Overhead) của thuật toán mã hóa AES-256-GCM đối với luồng xử lý thời gian thực? | **H6:** Mã hóa và giải mã vector hành vi đạt độ trễ $< 50\,\mu s$ và thông lượng $> 20,000$ ops/s, không gây nghẽn dòng streaming. | **VALIDATED** | `reports/benchmarks/crypto_benchmark_report.json`<br>`docs/benchmarks/CRYPTO_BENCHMARK.md`<br>Độ trễ mã hóa: **25.24 $\mu s$**, Độ trễ giải mã: **24.80 $\mu s$**, Thông lượng: **39,623 ops/s** |

---

## 3. Tuyên bố Giới hạn Khoa học (Scientific Boundaries)

1. **Giới hạn Holdout (RQ4):** Thí nghiệm holdout trong benchmark mô phỏng sự vắng mặt của chữ ký tấn công đã biết, nhưng không thay thế hoàn toàn cho các đợt tấn công Zero-Day đa hình được thiết kế có chủ đích né tránh (adversarial evasion) trong thực tế.
2. **Quy mô mẫu hiếm (RQ2):** Lớp Worms có số lượng mẫu rất hạn chế trong tập dữ liệu UNSW-NB15, do đó khoảng tin cậy thống kê có biên độ dao động rộng hơn.
3. **Môi trường đo lường (RQ6):** Các chỉ số đo lường hiệu năng mã hóa được thực hiện trên CPU Intel/AMD x86_64 hỗ trợ tập lệnh phần cứng AES-NI.
