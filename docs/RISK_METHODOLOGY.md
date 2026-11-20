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

Hệ thống hỗ trợ 5 chính sách tổng hợp quyết định từ 4 mô hình:
1. **`WEIGHTED_ENSEMBLE` (Mặc định):** Tổ hợp tuyến tính có trọng số chuẩn hóa trên tập validation:
   $$P_{\text{ensemble}} = 0.40 \cdot P_{\text{RF}} + 0.30 \cdot P_{\text{XGB}} + 0.15 \cdot P_{\text{IF}} + 0.15 \cdot P_{\text{AE}}$$
2. **`OOD_AWARE_ENSEMBLE`:** Giữ trọng số mặc định khi $S_{\text{OOD}} < 0.35$ (hoặc không có `ood_score`), và tự động chuyển trọng số sang `0.15 RF + 0.40 XGB + 0.35 IF + 0.10 AE` khi $S_{\text{OOD}} \ge 0.35$ để giảm phụ thuộc vào Random Forest khi gặp dịch chuyển miền.
3. **`RANDOM_FOREST_PRIMARY`:** Lấy quyết định của Random Forest làm chủ đạo, IF và AE làm kiểm chứng chéo.
4. **`STRICT_CONSENSUS`:** Chỉ kết luận bất thường khi cả 4 mô hình đồng thuận $P \ge 0.50$ (giảm tối đa False Positive).
5. **`MAX_SEVERITY`:** Lấy xác suất cao nhất giữa các mô hình (chiến lược fail-safe bảo vệ tối đa, chấp nhận FPR cao hơn).

---

## 5. So sánh Thực nghiệm 5 Chính sách & Calibration Độ nhạy Rủi ro (`#108 AC2`, `#109 AC1/AC2`)

Kết quả chạy chỉ-đọc trên toàn bộ các partition canonical (`ait_val`: `377,704` flows; `ait_test`: `988,805` flows; `ctu_echo`: `76,073` flows; `ctu_windows7ad`: `175,146` flows) với 4 mô hình `E0` đóng băng (`scripts/evaluate_behavioral_and_risk_policies.py`, báo cáo tại [behavioral_risk_aggregation_eval.json](../reports/experiments/risk/behavioral_risk_aggregation_eval.json)):

| Partition | Policy | Accuracy | Precision | Recall | F1 | FPR | ROC-AUC | Mean Risk (Benign / Attack) |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `ait_test` | `WEIGHTED_ENSEMBLE` | `0.9671` | `0.9985` | `0.8160` | `0.8981` | `0.0003` | `0.9991` | `14.15` / `46.32` |
| `ait_test` | `OOD_AWARE_ENSEMBLE` | `0.9671` | `0.9984` | `0.8160` | `0.8980` | `0.0003` | `0.9989` | `14.16` / `46.32` |
| `ait_test` | `RANDOM_FOREST_PRIMARY` | `0.9982` | `0.9989` | `0.9911` | `0.9950` | `0.0002` | `0.9994` | `7.23` / `50.04` |
| `ait_test` | `STRICT_CONSENSUS` | `0.9184` | `0.9984` | `0.5419` | `0.7025` | `0.0002` | `0.9709` | `18.93` / `43.83` |
| `ait_test` | `MAX_SEVERITY` | `0.4319` | `0.2383` | `0.9996` | `0.3849` | `0.6908` | `0.8999` | `38.14` / `51.68` |
| `ctu_echo` | `WEIGHTED_ENSEMBLE` | `0.4522` | `0.2739` | `0.0843` | `0.1290` | `0.2071` | `0.7276` | `24.14` / `21.55` |
| `ctu_echo` | `OOD_AWARE_ENSEMBLE` | `0.4522` | `0.2738` | `0.0843` | `0.1290` | `0.2071` | `0.7272` | `24.15` / `21.55` |
| `ctu_echo` | `RANDOM_FOREST_PRIMARY` | `0.4898` | `0.2318` | `0.0264` | `0.0474` | `0.0811` | `0.6137` | `12.98` / `8.60` |
| `ctu_echo` | `STRICT_CONSENSUS` | `0.4974` | `0.2672` | `0.0260` | `0.0473` | `0.0660` | `0.7589` | `31.36` / `30.10` |
| `ctu_echo` | `MAX_SEVERITY` | `0.4808` | `0.4808` | `1.0000` | `0.6494` | `1.0000` | `0.7964` | `53.54` / `52.63` |
| `ctu_windows7ad` | `WEIGHTED_ENSEMBLE` | `0.8336` | `0.0391` | `0.5643` | `0.0731` | `0.1633` | `0.8562` | `23.98` / `40.37` |
| `ctu_windows7ad` | `OOD_AWARE_ENSEMBLE` | `0.8335` | `0.0391` | `0.5643` | `0.0731` | `0.1633` | `0.8561` | `23.99` / `40.37` |
| `ctu_windows7ad` | `RANDOM_FOREST_PRIMARY` | `0.8358` | `0.0381` | `0.5412` | `0.0712` | `0.1608` | `0.8392` | `11.71` / `34.55` |
| `ctu_windows7ad` | `STRICT_CONSENSUS` | `0.8375` | `0.0384` | `0.5397` | `0.0717` | `0.1590` | `0.8653` | `30.36` / `43.93` |
| `ctu_windows7ad` | `MAX_SEVERITY` | `0.0119` | `0.0116` | `1.0000` | `0.0230` | `0.9997` | `0.7367` | `52.97` / `55.42` |

### 5.1 Phân phối Điểm Rủi ro Đa Tín hiệu (`RiskScorer`: AI + `EntityBaselineProfiler` + Port)
Kết hợp `WEIGHTED_ENSEMBLE` AI confidence, độ lệch hành vi từ `EntityBaselineProfiler` (warmed trên `ait_val` benign) và độ nhạy cổng đích trên các phiên (`20,000` flow subset/partition):

| Partition | Group | Sessions | Mean | P10 | P50 | P90 | P95 | Max | Overlap Rate | Critical Trigger Rate |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `ait_test` | Benign | `3,721` | `19.84` | `12.19` | `18.24` | `46.76` | `50.19` | `50.19` | `0.1116` | `0.0000` |
| `ait_test` | Attack | `6` | `45.86` | `36.97` | `46.34` | `54.27` | `56.32` | `58.36` | `0.1116` | `0.0000` |
| `ctu_echo` | Benign | `539` | `17.15` | `16.73` | `16.73` | `16.73` | `21.39` | `24.77` | `0.9441` | `0.0000` |
| `ctu_echo` | Attack | `51` | `26.90` | `17.30` | `32.30` | `36.95` | `36.95` | `36.95` | `0.9441` | `0.0000` |
| `ctu_windows7ad` | Benign | `827` | `42.40` | `20.97` | `35.47` | `69.93` | `69.93` | `69.93` | `0.0445` | `0.0000` |
| `ctu_windows7ad` | Attack | `4` | `50.89` | `50.89` | `50.89` | `50.89` | `50.89` | `50.89` | `0.0445` | `0.0000` |

### 5.2 Phân tích Độ nhạy Trọng số (`Weight Sensitivity Ablation`)
So sánh 3 cấu hình trọng số `(W_AI, W_Beh, W_Port, W_Auth)` trên cùng tập phiên đa tín hiệu:

| Partition | Config (`AI/Beh/Port/Auth`) | Benign Mean | Benign P95 | Attack Mean | Attack P95 | Mean Separation | Overlap Rate |
|---|---|---:|---:|---:|---:|---:|---:|
| `ait_test` | `default_50_25_15_10` | `19.84` | `50.19` | `45.86` | `56.32` | `+26.02` | `0.1116` |
| `ait_test` | `ai_heavy_70_15_10_5` | `23.67` | `59.26` | `56.51` | `68.00` | `+32.84` | `0.1113` |
| `ait_test` | `behavioral_heavy_35_40_15_10` | `15.60` | `39.63` | `35.25` | `43.92` | `+19.65` | `0.1116` |
| `ctu_echo` | `default_50_25_15_10` | `17.15` | `21.39` | `26.90` | `36.95` | `+9.75` | `0.9441` |
| `ctu_echo` | `ai_heavy_70_15_10_5` | `23.64` | `25.55` | `31.01` | `40.73` | `+7.37` | `0.9441` |
| `ctu_echo` | `behavioral_heavy_35_40_15_10` | `12.15` | `16.77` | `21.55` | `30.37` | `+9.40` | `0.9441` |
| `ctu_windows7ad` | `default_50_25_15_10` | `42.40` | `69.93` | `50.89` | `50.89` | `+8.49` | `0.0445` |
| `ctu_windows7ad` | `ai_heavy_70_15_10_5` | `50.05` | `76.86` | `60.24` | `60.24` | `+10.19` | `0.0445` |
| `ctu_windows7ad` | `behavioral_heavy_35_40_15_10` | `37.44` | `69.48` | `40.12` | `40.12` | `+2.68` | `0.0445` |

### Kết luận Calibration & Adaptive Key Rotation (`#108 AC2`)
1. **Bảo vệ chống xoay khóa giả trên flow đơn lẻ (`critical_rotation_trigger_rate = 0.0`):** Khi chỉ có NetFlow (`behavioral_deviation = 0.0`, `auth_failures = 0`), trần điểm lý thuyết của `RiskScorer` là $50.0 + 15.0 = 65.0 < 85.0$, nên cả 4 chính sách đều cho **0% false-positive adaptive key rotation trên lưu lượng Benign**.
2. **Điều kiện kích hoạt `CRITICAL (>= 85.0)`:** Xoay khóa thích ứng chỉ kích hoạt khi có xác nhận đa tín hiệu (AI consensus $\ge 0.90$ cho $\ge 45$ điểm + dịch vụ nhạy cảm $15$ điểm + độ lệch hành vi $\ge 0.60$ cho $\ge 15$ điểm + chuỗi auth failures cho $\ge 10$ điểm).
3. **Chọn chính sách vận hành:** Khuyến nghị giữ `WEIGHTED_ENSEMBLE` (mặc định cân bằng cross-source) hoặc `RANDOM_FOREST_PRIMARY` (đạt in-domain `F1 = 0.9950`, `FPR = 0.0002`); tránh dùng `MAX_SEVERITY` trong vận hành mặc định vì `FPR = 0.6908–1.0000` do percentile score của mô hình unsupervised thường vượt `0.50` khi dịch miền.
