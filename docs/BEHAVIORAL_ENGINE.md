# NetFlow Sentinel v2.0 — Behavioral Vector Engine Specification

> **Tài liệu kỹ thuật Behavioral Intelligence (Issues #101, #102, #103 — Milestone M6.3)**  
> **Phiên bản:** 2.0.0-behavioral  
> **Module thực thi:** `src/network_anomaly/behavioral/`

---

## 1. Giới thiệu và Nguyên tắc Thiết kế
Behavioral Vector Engine là một trong ba trụ cột khoa học cốt lõi của Đề tài 22. Trong khi mô hình AI phát hiện bất thường trên từng luồng mạng riêng lẻ, Behavioral Vector Engine phân tích và liên kết chuỗi hành vi của các thực thể mạng theo cửa sổ thời gian (time-window sessionization).

### Các nguyên tắc:
1. **IP-Independence:** Không ràng buộc định danh đối tượng vào địa chỉ IP nguồn/đích; hỗ trợ liên kết các phiên kết nối khi kẻ tấn công giả mạo hoặc thay đổi IP liên tục.
2. **Deterministic Vector Construction:** Thuật toán chuẩn hóa 16 chiều xác định (deterministic scaling), đảm bảo tính lại trên cùng tập dữ liệu luôn cho ra cùng mã băm SHA-256.
3. **Strict Mathematical Bounds:** Mọi đặc trưng được chuẩn hóa về phạm vi toán học ổn định, kiểm tra triệt để `NaN`/`Inf` và chiếu lên hypersphere đơn vị qua L2-normalization.

---

## 2. Lược đồ 16 Đặc trưng Hành vi Chuẩn tắc (16-D Feature Space)

| Chỉ số | Tên Đặc trưng | Công thức / Ý nghĩa | Miền giá trị |
|---|---|---|:---:|
| `1` | `log_duration` | $\ln(\text{duration\_seconds} + 1)$ | $[0, \infty)$ |
| `2` | `log_bytes_in` | $\ln(\text{bytes\_in} + 1)$ | $[0, \infty)$ |
| `3` | `log_bytes_out` | $\ln(\text{bytes\_out} + 1)$ | $[0, \infty)$ |
| `4` | `bytes_ratio_clipped` | $\min(\text{bytes\_in} / \text{bytes\_out}, 10.0)$ | $[0, 10]$ |
| `5` | `log_pkts_in` | $\ln(\text{pkts\_in} + 1)$ | $[0, \infty)$ |
| `6` | `log_pkts_out` | $\ln(\text{pkts\_out} + 1)$ | $[0, \infty)$ |
| `7` | `pkts_ratio_clipped` | $\min(\text{pkts\_in} / \text{pkts\_out}, 10.0)$ | $[0, 10]$ |
| `8` | `unique_ports_norm` | $\min(\text{unique\_ports} / 100.0, 1.0)$ | $[0, 1]$ |
| `9` | `unique_protocols_norm` | $\min(\text{unique\_protocols} / 10.0, 1.0)$ | $[0, 1]$ |
| `10` | `syn_flag_ratio` | $\text{syn\_count} / \text{event\_count}$ | $[0, 1]$ |
| `11` | `rst_flag_ratio` | $\text{rst\_count} / \text{event\_count}$ | $[0, 1]$ |
| `12` | `dns_intensity` | $\min(\text{dns\_count} / \text{duration}, 50.0)$ | $[0, 50]$ |
| `13` | `http_intensity` | $\min(\text{http\_count} / \text{duration}, 50.0)$ | $[0, 50]$ |
| `14` | `auth_failure_ratio` | $\text{auth\_failure\_count} / \text{event\_count}$ | $[0, 1]$ |
| `15` | `log_mean_iat` | $\ln(\text{mean\_iat\_ms} + 1)$ | $[0, \infty)$ |
| `16` | `log_std_iat` | $\ln(\text{std\_iat\_ms} + 1)$ | $[0, \infty)$ |

Sau khi tính 16 đặc trưng thô, vector được chuẩn hóa L2:
$$v_{norm} = \frac{v}{\|v\|_2}$$

---

## 3. Các Phép đo Khoảng cách Tương đồng (Similarity Metrics)
Hệ thống cung cấp 3 phép đo khoảng cách:
1. **Cosine Similarity (Chuẩn tắc):**
   $$S_{cos}(u, v) = \frac{u \cdot v}{\|u\|_2 \|v\|_2}$$
   Ngưỡng xác định cùng chiến dịch tấn công: $S_{cos} \ge 0.85$.
2. **Normalized Euclidean Similarity:**
   $$S_{euc}(u, v) = \frac{1}{1 + \|u - v\|_2}$$
3. **Manhattan Similarity:**
   $$S_{man}(u, v) = \frac{1}{1 + \|u - v\|_1}$$

---

## 4. Tích hợp Mật mã At-rest
Mỗi `BehavioralVector` khi lưu vào cơ sở dữ liệu được mã hóa bằng AES-256-GCM qua `EncryptedStorageVault`:
- `vector_json` trên đĩa là `NULL`.
- Dữ liệu vector được lưu dưới dạng `ciphertext`, `nonce`, `tag` kèm khóa `key_id`.
- Khi cần so sánh tương đồng (similarity matching), vector được giải mã trong RAM an toàn và thực hiện phép nhân vô hướng.
