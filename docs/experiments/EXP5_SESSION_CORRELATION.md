# Experiment 5 (RQ3): IP-Independent Session Correlation Benchmark

> **Experiment ID:** EXP-RQ3-CORRELATION-01  
> **Evaluation Date:** 2026-11-17T07:47:30.157985+00:00  
> **Status:** EXPERIMENTALLY VALIDATED (Hypothesis Confirmed: True)

## 1. Executive Summary
- **Hypothesis (H3):** H3: Behavioral Vector achieves >= 85% session correlation accuracy independent of IP
- **Outcome:** **CONFIRMED**. Chiến lược so khớp vector hành vi đạt độ thu hồi **100.0%**, trong khi phương pháp IP truyền thống sụp đổ về **0.0%** khi kẻ tấn công thay đổi IP.

## 2. Kết quả Đối sánh Thực nghiệm

| Chiến lược Liên kết Phiên | Cặp Liên kết Đúng | Độ thu hồi (Recall) | Đánh giá Khả năng Kháng IP Spoofing |
|---|:---:|:---:|:---:|
| **Strategy A: IP Tuple Exact Matching** | 0 / 30 | **0.0%** | **Thất bại hoàn toàn khi đổi IP** |
| **Strategy B: Behavioral Vector Cosine ($\ge 0.85$)** | 30 / 30 | **100.0%** | **Thành công (Đạt giả thuyết $\ge 85\%$)** |

## 3. Kết luận
Under IP rotation / spoofing, Strategy A (IP-matching) collapsed to 0.0% recall. In contrast, Strategy B (Behavioral Vector Cosine similarity) maintained 100.0% correlation recall, empirically validating Hypothesis H3.
