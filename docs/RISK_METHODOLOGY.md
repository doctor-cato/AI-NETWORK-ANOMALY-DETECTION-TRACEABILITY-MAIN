# NetFlow Sentinel v2.0 — Risk Assessment & Decision Aggregation Methodology

> **Tài liệu phương pháp luận chấm điểm rủi ro (Issues #108, #109 — Milestone M6.4)**  
> **Phiên bản:** 2.0.0-risk  
> **Module thực thi:** `src/network_anomaly/risk/`

---

## 1. Mục tiêu và Nguyên tắc Thiết kế
Risk Engine hợp nhất các tín hiệu từ nhiều mô hình AI độc lập, độ lệch vector hành vi, thông tin cổng/giao thức nhạy cảm và các sự kiện bảo mật (như authentication failures) thành một thang điểm rủi ro tổng hợp chuẩn hóa từ **0.0 đến 100.0**.

### Nguyên tắc Bất biến:
1. **Deterministic Scoring:** Cùng một vector đặc trưng và trạng thái luôn cho ra chính xác một điểm rủi ro duy nhất.
2. **Fail-Closed Adaptive Trigger:** Khi điểm rủi ro chạm ngưỡng $\ge 85.0$, hệ thống tự động kích hoạt xoay vòng khóa thích ứng (Adaptive Key Rotation) để bảo vệ dữ liệu.
3. **OOD Safety Guard:** Các mẫu ngoài phân phối (Out-of-Distribution - OOD) được đánh dấu cờ cảnh báo riêng và bị chặn trần ở mức điểm $\le 65.0$, ngăn chặn hiện tượng xoay khóa giả do dữ liệu nhiễu lạ.

---

## 2. Công thức Tính Điểm Rủi ro Chuẩn tắc

Điểm rủi ro tổng hợp $R \in [0.0, 100.0]$ được xác định theo mô hình cộng dồn trọng số:

$$R = \min\left(100.0, C_{\text{AI}} + C_{\text{Beh}} + C_{\text{Port}} + C_{\text{Auth}}\right)$$

Trong đó:
1. **$C_{\text{AI}}$ — Đóng góp từ AI Consensus (Tối đa 50 điểm):**
   $$C_{\text{AI}} = P_{\text{ensemble}} \times 50.0$$
   Với $P_{\text{ensemble}}$ là xác suất bất thường tổng hợp từ 4 mô hình.
2. **$C_{\text{Beh}}$ — Đóng góp từ Độ lệch Vector Hành vi (Tối đa 25 điểm):**
   $$C_{\text{Beh}} = S_{\text{anomaly}} \times 25.0$$
   Với $S_{\text{anomaly}} = 1.0 - S_{\text{cos}}(\text{vector}, \text{baseline\_profile})$.
3. **$C_{\text{Port}}$ — Đóng góp từ Mức độ Nhạy cảm của Dịch vụ / Cổng (Tối đa 15 điểm):**
   - $C_{\text{Port}} = 15.0$ nếu đích là các cổng dịch vụ quản trị nhạy cảm: `22 (SSH)`, `23 (Telnet)`, `88 (Kerberos)`, `389 (LDAP)`, `445 (SMB)`, `1433 (MSSQL)`, `3389 (RDP)`, `5985/5986 (WinRM)`.
   - $C_{\text{Port}} = 6.0$ cho các cổng đặc quyền khác ($< 1024$).
   - $C_{\text{Port}} = 0.0$ cho cổng thông thường.
4. **$C_{\text{Auth}}$ — Đóng góp từ Tần suất Thất bại Xác thực (Tối đa 10 điểm):**
   $$C_{\text{Auth}} = \min(10.0, N_{\text{auth\_failures}} \times 2.5)$$

---

## 3. Phân cấp Mức độ Nghiêm trọng (Severity Calibration)

| Khoảng Điểm Rủi ro | Cấp độ Nghiêm trọng | Ý nghĩa Hoạt động | Hành động Tự động của Hệ thống |
|:---:|:---:|---|---|
| **$0.0 \le R < 30.0$** | **`LOW`** | Lưu lượng bình thường hoặc biến thiên nhỏ. | Ghi log nền, duy trì chu kỳ xoay khóa 30 phút cố định. |
| **$30.0 \le R < 70.0$** | **`MEDIUM`** | Bất thường mức độ thấp hoặc mẫu OOD chưa xác nhận. | Ghi nhận sự kiện, tăng cường giám sát phiên. |
| **$70.0 \le R < 85.0$** | **`HIGH`** | Khả năng cao là hành vi tấn công (Exploit/Scan). | Tạo Incident cảnh báo, đưa vào Attack Timeline. |
| **$85.0 \le R \le 100.0$** | **`CRITICAL`** | Tấn công nguy hiểm, nguy cơ xâm nhập hệ thống. | **Kích hoạt tức thời Adaptive Key Rotation**, cách ly luồng dữ liệu. |

---

## 4. Các Chính sách Tổng hợp Quyết định Đa Mô hình (Issue #109)

Hệ thống hỗ trợ 4 chính sách tổng hợp quyết định từ 4 mô hình:
1. **`WEIGHTED_ENSEMBLE` (Mặc định):** Tổ hợp tuyến tính có trọng số chuẩn hóa trên tập validation:
   $$P_{\text{ensemble}} = 0.40 \cdot P_{\text{RF}} + 0.30 \cdot P_{\text{XGB}} + 0.15 \cdot P_{\text{IF}} + 0.15 \cdot P_{\text{AE}}$$
2. **`RANDOM_FOREST_PRIMARY`:** Lấy quyết định của Random Forest làm chủ đạo, IF và AE làm kiểm chứng chéo.
3. **`STRICT_CONSENSUS`:** Chỉ kết luận bất thường khi cả 4 mô hình đồng thuận $P \ge 0.50$ (giảm tối đa False Positive).
4. **`MAX_SEVERITY`:** Lấy xác suất cao nhất giữa các mô hình (chiến lược fail-safe bảo vệ tối đa, chấp nhận FPR cao hơn).
