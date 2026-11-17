# Cryptographic Performance & Resource Overhead Benchmark (RQ6)

> **Benchmark ID:** BM-CRYPTO-OVERHEAD-RQ6  
> **Iterations:** 10,000 operations  
> **Status:** EXPERIMENTALLY VALIDATED (Hypothesis Confirmed: True)

## 1. Executive Summary
- **Hypothesis (H6):** H6: AES-256-GCM adds <= 500 us latency per event, throughput >= 5,000 events/sec
- **Outcome:** **CONFIRMED**. Độ trễ mã hóa trung bình chỉ **25.24 $\mu s$** (thấp hơn ngưỡng cho phép 500 $\mu s$ gấp 10+ lần), thông lượng đạt **39,623 sự kiện/giây** (vượt xa yêu cầu 5.000 events/sec).
- **Bộ nhớ (Memory Footprint):** Mức chiếm dụng bộ nhớ đỉnh (Peak RAM) chỉ **6.15 MB**.

## 2. Bảng Kết quả Đo lường Chi tiết

| Chỉ số Đo lường | Giá trị Thực nghiệm | Ngưỡng Yêu cầu Đề tài (RQ6) | Đánh giá |
|---|:---:|:---:|:---:|
| **Độ trễ Mã hóa (Encryption Latency)** | **25.24 $\mu s$** (0.025 ms) | $\le 500\ \mu s$ (0.5 ms) | **ĐẠT (VƯỢT TRỘI)** |
| **Độ trễ Giải mã (Decryption Latency)** | **4.66 $\mu s$** (0.04 ms) | $\le 500\ \mu s$ (0.5 ms) | **ĐẠT (VƯỢT TRỘI)** |
| **Thông lượng Mã hóa (Throughput)** | **39,623 events/s** | $\ge 5.000\ events/s$ | **ĐẠT (GẤP ~10 LẦN)** |
| **Thông lượng Giải mã (Throughput)** | **214,527 events/s** | $\ge 5.000\ events/s$ | **ĐẠT** |
| **Bộ nhớ Đỉnh (Peak RAM)** | **6.15 MB** | $\le 100\ MB$ | **ĐẠT** |

## 3. Kết luận
AES-256-GCM demonstrated an average encryption latency of 25.2 us and a sustained throughput of 39,623 events/second, fully meeting the real-time requirements of RQ6 (Latency <= 500 us, Throughput >= 5,000 evt/s).
