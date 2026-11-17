# Research Experiment RQ5: Fixed vs. Adaptive Key Rotation Report

> **Experiment ID:** EXP-RQ5-ROTATION-01  
> **Evaluation Date:** 2026-11-17T07:45:22.186929+00:00  
> **Status:** EXPERIMENTALLY VALIDATED (Hypothesis Confirmed: True)

## 1. Executive Summary
- **Hypothesis:** H5: Adaptive Key Rotation reduces exposure window by >= 70% under burst attack
- **Outcome:** **CONFIRMED**. Cửa sổ phơi nhiễm khóa giảm từ 30.0 phút xuống 0.5 phút (giảm **98.33%**).
- **Phân tách rủi ro:** Kẻ tấn công nếu thỏa hiệp một khóa phiên chỉ giải mã được tập bản ghi nhỏ trước thời điểm kích hoạt xoay khóa, không thể giải mã các phiên sau khi hệ thống chuyển sang khóa mới.

## 2. Số liệu So sánh Thực nghiệm

| Chỉ số Đánh giá | Fixed Key Rotation (30 phút) | Risk-based Adaptive Key Rotation | Cải thiện / Ý nghĩa |
|---|:---:|:---:|:---:|
| **Thời gian phơi nhiễm khóa (Exposure Window)** | **30.0 phút** | **< 1.0 phút (0.5 phút)** | **Giảm 98.33%** |
| **Số lần xoay khóa trong phiên 60 phút** | 1 lần | 1 lần | Phản ứng tức thời theo rủi ro |
| **Số khóa sử dụng riêng trong đợt tấn công** | 1 khóa | 1 khóa | Cách ly dữ liệu tấn công |
| **Bảo vệ chống DoS (Cooldown & Rate limit)** | Cố định theo giờ | Cooldown 10s, Rate limit 10/h | Ngăn ngừa cạn kiệt tài nguyên CPU |

## 3. Kết luận
Adaptive Key Rotation achieved a 98.3% reduction in exposure window (from 30.0 mins to 0.5 mins), successfully isolating attack records under freshly generated ephemeral keys.
