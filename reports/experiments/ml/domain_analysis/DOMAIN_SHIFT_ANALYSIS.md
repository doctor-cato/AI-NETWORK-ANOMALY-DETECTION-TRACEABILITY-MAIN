# Phân tích Domain Shift & Khả năng Tương thích Feature (AIT-NDS-v2 vs CTU-SME-11)

**Contract kiểm định:** `canonical-flow-v2-18` (6 base observed features + 12 deterministic derived features)  
**Nguồn số liệu thực nghiệm:**  
- Thống kê định lượng đầy đủ: [`ait_vs_ctu_statistics.json`](ait_vs_ctu_statistics.json) (`schema_version: v2-domain-analysis-v1`, 302,164 bytes, LF)  
- Kiểm định tương thích ngữ nghĩa & đơn vị: [`feature_compatibility_analysis.json`](feature_compatibility_analysis.json) (59,013 bytes, LF)  
- Dữ liệu đã xử lý kiểm tra: `data/processed/v2/{ait_train,ait_val,ait_test,ctu_echo,ctu_windows7ad}.csv.gz` cùng 3 tệp `*_unmapped*.csv.gz`

---

## 1. Tổng quan Phân bố Nguồn, Mất cân bằng Lớp & Kiểm tra Toàn vẹn Ma trận

Tất cả 5 tập dữ liệu đã xử lý đều không có giá trị thiếu (`missing/blank = 0`), `NaN = 0`, `+Inf/-Inf = 0`, giá trị âm ở các feature không âm (`negative_count = 0`), và sai số công thức 12 derived features bằng `0.0` (`derived_formula_max_abs_diff = 0.0`). Tuy nhiên, cấu trúc mất cân bằng lớp và thành phần giao thức chênh lệch rất mạnh giữa các nguồn:

| Tập dữ liệu | Số dòng hợp lệ | Unmapped bị loại | Benign | Attack (%) | Tỉ lệ mất cân bằng (`Benign:Attack`) | Phân bố giao thức (`TCP` / `UDP` / `ICMP`) |
|---|---:|---:|---:|---:|---:|---|
| **`ait_train`** (`fox, harrison, santos, wardbeck, wilson`) | 1,930,219 | — | 1,658,795 | 271,424 (14.06%) | `6.1115 : 1` | TCP `1,221,149` (63.26%) / UDP `709,070` (36.74%) / ICMP `0` |
| **`ait_val`** (`russellmitchell`) | 377,704 | — | 206,676 | 171,028 (45.28%) | `1.2084 : 1` | TCP `278,209` (73.66%) / UDP `99,495` (26.34%) / ICMP `0` |
| **`ait_test`** (`shaw, wheeler`) | 923,292 | 942 (`shaw` SMTP `:25` rỗng) | 747,610 | 175,682 (19.03%) | `4.2555 : 1` | TCP `581,974` (63.03%) / UDP `341,318` (36.97%) / ICMP `0` |
| **`ctu_echo`** (`Echo1stGen-1`) | 76,073 | 0 | 39,497 | 36,576 (48.08%) | `1.0799 : 1` | TCP `49,892` (65.58%) / UDP `19,810` (26.04%) / **ICMP `6,371` (8.37%)** |
| **`ctu_windows7ad`** (`Windows7AD-1`) | 175,146 | 9,394 (`Unknown\|(empty)`) | 173,108 | 2,038 (1.16%) | `84.9401 : 1` | TCP `12,359` (7.06%) / UDP `158,089` (90.26%) / **ICMP `4,698` (2.68%)** |

Phân bố Attack Categories (`taxonomy-v2`):
- **AIT-NDS-v2 (Train / Val / Test):** Chủ yếu là `Reconnaissance` (`181,843` / `155,181` / `95,487`) và `Data_Exfiltration` (`87,268` / `15,778` / `80,075`), cùng nhóm thiểu số rất nhỏ `Credential_Attack` (`2,104` / `11` / `78`), `Post_Exploitation_Discovery` (`180` / `56` / `37`), `Exploitation_And_C2` (`29` / `2` / `5`).
- **`ctu_echo`:** 100% Attack thuộc `Reconnaissance` (`36,576` flows từ `Malicious|From_malicious-To_benign-Discovery`).
- **`ctu_windows7ad`:** Gần như hoàn toàn là `Exploitation_And_C2` (`2,036` flows: `1,815` `Human_attacks` + `221` `Trickbot`) và `2` flows `Malware_And_DoS` (`Lockbit_2.0-SMB2`), hoàn toàn không có `Reconnaissance` hay `Data_Exfiltration`.

---

## 2. Phân tích Domain Shift Định lượng (KS Statistic & Wasserstein-1)

Phép đo Kolmogorov–Smirnov (`KS`) và Wasserstein-1 (`W1`) được tính trên không gian gốc (`raw_space`), không gian tiền xử lý đã fit trên Train (`asinh_robust_space`), và phân tầng theo từng lớp (`benign_only_raw_space`, `attack_only_raw_space`).

### 2.1. Tổng hợp Feature Shift: Intra-AIT vs Cross-Source (`ait_train` làm tham chiếu)

| Feature | `train` vs `val` KS (`W1_scaled`) | `train` vs `test` KS (`W1_scaled`) | `train` vs `ctu_echo` KS (`W1_scaled`) | `train` vs `ctu_echo` Att-KS | `train` vs `ctu_win7ad` KS (`W1_scaled`) | `train` vs `ctu_win7ad` Att-KS |
|---|---:|---:|---:|---:|---:|---:|
| `duration_ms` | 0.2253 (0.1969) | 0.0627 (0.0400) | **0.4642** (0.2862) | 0.1688 | 0.3812 (0.2430) | **0.8143** |
| `bytes_in` | 0.3280 (0.6761) | 0.0905 (0.0562) | 0.3619 (0.3712) | **0.5702** | 0.3783 (0.3730) | **0.5702** |
| `bytes_out` | 0.3116 (0.6884) | 0.0936 (0.0508) | **0.4227** (0.9556) | 0.4124 | **0.4786** (0.9365) | **0.5701** |
| `pkts_in` | 0.2348 (0.2615) | 0.0495 (0.0318) | **0.4117** (0.3066) | **0.8866** | **0.4435** (0.3535) | 0.4078 |
| `pkts_out` | 0.2707 (0.3584) | 0.0420 (0.0374) | **0.4444** (0.4593) | **0.4746** | **0.4951** (0.5968) | **0.4362** |
| `protocol_num` | 0.1039 (1.1432) | 0.0023 (0.0256) | 0.1069 (1.5951) | 0.2259 | **0.5353 (6.0220)** | 0.3215 |
| `total_bytes` | 0.3279 (0.7674) | 0.0937 (0.0578) | **0.4040** (0.4699) | **0.5697** | **0.4293** (0.4934) | **0.5699** |
| `total_pkts` | 0.2734 (0.3256) | 0.0412 (0.0352) | 0.3113 (0.2577) | 0.4337 | **0.4560** (0.3910) | 0.4361 |
| `bytes_in_ratio` | 0.3279 (0.4244) | 0.0632 (0.0219) | **0.5583 (1.2942)** | **0.9905** | **0.4284 (1.0468)** | **0.9862** |
| `pkts_in_ratio` | 0.2708 (**2.4241**) | 0.0365 (0.1189) | **0.4495 (4.0480)** | **0.4791** | 0.3766 (**3.2556**) | 0.4362 |
| `bytes_per_pkt_in` | 0.3279 (1.2081) | 0.0624 (0.0878) | **0.4058** (0.5710) | **0.5718** | 0.3069 (0.5311) | **0.5722** |
| `bytes_per_pkt_out` | 0.3116 (1.2935) | 0.0726 (0.0727) | **0.4856 (1.9135)** | 0.4271 | **0.5008 (1.5790)** | **0.5703** |
| `bytes_per_sec_in` | 0.3299 (0.3625) | 0.0517 (0.0326) | **0.4573** (0.5043) | **0.5700** | 0.3307 (0.3706) | **0.5709** |
| `bytes_per_sec_out` | 0.3167 (0.3647) | 0.0510 (0.0337) | **0.4227** (0.3521) | 0.4095 | 0.3312 (0.2689) | **0.5696** |
| `pkts_per_sec` | 0.2186 (0.1663) | 0.0565 (0.0428) | 0.3755 (0.3199) | **0.4731** | 0.2380 (0.1838) | 0.3336 |
| `has_response` | 0.2707 (0.2386) | 0.0098 (0.0086) | **0.4444** (0.3917) | **0.4746** | 0.3529 (0.3110) | **0.4362** |
| `is_tcp` | 0.1039 (0.1039) | 0.0023 (0.0023) | 0.0232 (0.0232) | 0.2185 | **0.5621** (0.5621) | 0.3215 |
| `is_udp` | 0.1039 (0.1039) | 0.0023 (0.0023) | 0.1069 (0.1069) | 0.2259 | **0.5353** (0.5353) | 0.3215 |

*(Ghi chú: Giữa `ctu_echo` và `ctu_windows7ad`, chuyển dịch giao thức cũng rất lớn: `protocol_num` KS = `0.6422`, `is_udp` KS = `0.6422`, `is_tcp` KS = `0.5853`, `bytes_per_pkt_in` KS = `0.4195`, và trên tập Attack thì 8/18 feature có KS >= `0.9108` do `ctu_echo` là scan đơn hướng `has_response=0` chiếm 91.08% còn `ctu_windows7ad` 100% Attack đều có phản hồi `has_response=1`.)*

### 2.2. Các Phát hiện Chính từ Phân tích Dịch chuyển Phân phối

1. **Intra-AIT Test (`ait_train` vs `ait_test`) rất đồng nhất về marginal, nhưng `ait_val` lệch vì tỉ trọng `tcp_nocomplete`:**
   - `ait_train` vs `ait_test` có `KS <= 0.0937` trên toàn bộ 18 feature (và `protocol_num` KS chỉ `0.0023`), giải thích vì sao mô hình supervised học từ AIT-Train đạt `ROC-AUC = 0.9996` trên `ait_test` (`random_forest`).
   - Ngược lại, `ait_val` (`russellmitchell`) có 41.00% dòng là `tstat:tcp_nocomplete` (so với 8.13% ở Train) và tỉ lệ Attack tới `45.28%`, làm KS lên `0.3299` (`bytes_per_sec_in`) nhưng chủ yếu ở phân tầng `attack_only` (`KS = 0.3374`).

2. **Đảo chiều cực đoan trên lớp Attack giữa AIT và CTU (`bytes_in_ratio` Att-KS = `0.9905` & `0.9862`):**
   - Trong AIT (`Tstat`), các luồng scan/SYN không payload có `bytes_in = 0.0` (tỉ lệ `bytes_in == 0` ở Attack: `56.95%` tại `ait_train`, `90.49%` tại `ait_val`, `46.75%` tại `ait_test`) -> **`bytes_in_ratio` median = `0.0`** (`p95 = 0.4836`, mean `0.1902` ở Train Attack; thậm chí Attack Exfiltration/HTTP có `bytes_out` lớn nên `bytes_in_ratio < 0.5`).
   - Trong CTU (`Zeek orig_ip_bytes`/`resp_ip_bytes` tính cả IP+TCP/UDP header), **0.0%** luồng Attack có `bytes_in == 0`! Scan `S0` không payload của `ctu_echo` lại mang `bytes_in = 80/88`, `bytes_out = 0` -> **`bytes_in_ratio` median = `1.0`** (`mean = 0.9573`, `p05 = 0.5238`). Tại `ctu_windows7ad`, Attack (`REJ`/`RSTR`/`RSTO`) cũng có **`bytes_in_ratio` median = `0.5574`** (`p05 = 0.5238`, `mean = 0.6771`) — **nằm gần như tách rời hoàn toàn bên phải phân phối Attack của AIT** (chỉ 1% trên ngưỡng `p99 = 0.4838` của AIT Train Attack!).
   - Hệ quả trực tiếp: Single-feature class AUC của `bytes_in_ratio` trong `ait_train` mang chiều âm (`AUC = 0.2800`, thấp = Attack; `ait_val` `AUC = 0.0658`), nhưng trong `ctu_echo` lại **đảo dấu hoàn toàn thành chiều dương (`AUC = 0.8737`, cao = Attack)**! Điều này giải thích hiện tượng **XGBoost có `ROC-AUC = 0.0373` trên `ctu_echo` và `0.1599` trên `ctu_windows7ad`**: cây quyết định học ngưỡng ngược chiều vật lý so với chuẩn byte IP-layer của Zeek.

3. **Khuếch đại sai lệch do `asinh_robust` trên `pkts_in_ratio` (`W1_scaled = 4.0480`):**
   - Trên `ait_train`, `pkts_in_ratio` có `p25 = 0.5`, `p50 = 0.5`, `p75 = 0.55` -> `IQR = 0.05` trên thang gốc và chỉ **`0.044269`** trên thang `arcsinh` (`artifacts/preprocessing/v2_flow_preprocessor.joblib`).
   - Khi gặp `ctu_echo` với median `pkts_in_ratio = 1.0`, giá trị sau biến đổi tăng vọt từ `0.0` (Train median) lên **`+9.0394`** (`median_b` trong `asinh_robust_space`), kéo `scaled_wasserstein_1 = 4.0480` (`3.2556` với `ctu_windows7ad`) — lớn hơn gấp nhiều lần mọi feature số lượng khác, đồng thời khuếch đại nhạy cảm của Autoencoder và Isolation Forest (Autoencoder FPR lên `65.20%` trên `ctu_echo` và `85.45%` trên `ctu_windows7ad`).

4. **Khác biệt `domain_auc` cho thấy mô hình phân biệt nguồn gần như tầm thường:**
   - Cặp `ait_train` vs `ctu_echo`: `bytes_in_ratio` có `abs_auc = 0.8407`, `bytes_per_pkt_out` `0.7859`, `bytes_per_sec_in` `0.7521`, `bytes_out` `0.7344`.
   - Cặp `ait_train` vs `ctu_windows7ad`: `is_tcp` `0.7810`, `bytes_per_pkt_out` `0.7735`, `is_udp` `0.7676`, `bytes_in_ratio` `0.7671`, `bytes_out` `0.7638`, `protocol_num` `0.7591`.
   - Cặp `ait_train` vs `ait_test`: `max abs_auc` chỉ **`0.5277`** (`bytes_in`), chứng tỏ không có dấu vết testbed rõ rệt giữa AIT-Train và AIT-Test nhưng hố ngăn miền rất sâu giữa AIT và CTU.

---

## 3. Hiện tượng Bão hòa Tốc độ từ Bug Đơn vị UDP & Clamping `1 ms`

Trong toàn bộ AIT-NDS-v2, Tstat ghi `udp_complete.csv` bằng **giây (`c_durat:4`, `s_durat:13`)**, trong khi `tcp_*.csv` `durat:31` ghi bằng **mili-giây**. Vì `v2_schema.py:281` và `build_v2_dataset_and_split.py:205-208` bỏ quên `* 1000.0`, đồng thời `compute_flow_features_from_base:148` ép mẫu số `safe_dur_ms = max(duration_ms, 1.0)`:

- Tỉ lệ flow UDP có `duration_ms < 1.0`:
  - `ait_train`: **`94.9953%`** (`673,583 / 709,070`, trong đó `22,795` flow `0 < duration_ms < 1.0`)
  - `ait_val`: **`93.7153%`** (`93,242 / 99,495`, gồm `1,909` flow `0 < duration_ms < 1.0`)
  - `ait_test`: **`97.5182%`** (`332,847 / 341,318`, gồm `7,812` flow `0 < duration_ms < 1.0`)
- Hệ quả: Toàn bộ luồng UDP thật dài từ `1 ms` đến `999 ms` bị ép xuống `< 1.0` rồi kẹp vào mẫu số `1.0 ms`, tạo giá trị `bytes_per_sec_*` và `pkts_per_sec` **bằng bội số nguyên của 1,000** (`p75/p95` `pkts_per_sec` của Benign AIT Train chạm đúng `2000.0`, max `bytes_per_sec_in = 53,828,790,000 B/s` và max `pkts_per_sec = 197,381,000 pkt/s` tại `ait_val`, trong khi tại CTU thực tế chỉ tối đa `3,539,000–4,059,000 B/s` và `16,000–33,000 pkt/s`).

---

## 4. Dấu vết Công cụ/Testbed & Trùng lặp Xung đột Nhãn

### 4.1. Dấu vết Probe & Số lượng Gói tin (`packet_signature_audit`)
- **AIT (`Tstat`):** Do hành vi công cụ phát hiện/scan trong testbed (vd: 1 gói SYN đơn lẻ, không retransmit), **`pkts_in == 1`** chiếm **`88.91%`** Attack ở `ait_train`, **`99.63%`** ở `ait_val`, và **`92.24%`** ở `ait_test` (`pkts_in == 2` chỉ `0.0236%` / `0.0041%` / `0.0216%`).
- **`ctu_echo` (`Zeek`):** Trong môi trường thật, scanner gửi 2 SYN retry trước timeout (`('tcp','S0','2','0',...)`): **`pkts_in == 2`** chiếm tới **`91.83%`** Attack (`attack_pkts_in_eq_2_rate = 0.918334`), còn `pkts_in == 1` chỉ **`0.2515%`**.
- **Luồng cắt ngang giữa phiên (`pkts_in == 0`):** Hoàn toàn vắng mặt trong AIT (`0` dòng), nhưng tồn tại hợp lệ trong Zeek (`32` dòng Benign tại `ctu_echo`, `1,793` dòng Benign tại `ctu_windows7ad`, đa số UDP DNS/5353/5060).
- **Lớp ICMP (`protocol_num == 1`):** Vắng mặt tuyệt đối trong AIT (`0` dòng), nhưng có `6,371` dòng tại `ctu_echo` (gồm `237` Attack) và `4,698` dòng tại `ctu_windows7ad`. Trên `ctu_windows7ad`, `is_tcp` đơn lẻ đạt `abs_auc = 0.9702` vì 100% Attack đều là TCP nhưng >92% Benign là UDP/ICMP.

### 4.2. Trùng lặp 18-Feature Vector & Xung đột Nhãn (`Benign` vs `Attack`)

Không gian 18 feature lượng hóa thô dẫn tới tỷ lệ trùng lặp vector rất cao, bao gồm cả **xung đột nhãn trực tiếp trên cùng một vector 18-chiều chính xác**:

| Tập dữ liệu | Vector 18-feat duy nhất | Dòng trùng lặp 18-feat (%) | Trùng lặp gần (`10ms` / `asinh r2`) | Số vector xung đột nhãn | Tổng dòng xung đột (`Attack` / `Benign`) |
|---|---:|---:|---:|---:|---:|
| **`ait_train`** | 1,102,694 | 827,525 (**42.87%**) | 65.13% / 67.75% | **48** | **126,166** (`125,954` Att / `212` Ben) |
| **`ait_val`** | 135,723 | 241,981 (**64.07%**) | 80.50% / 81.71% | **4** | **131,881** (`131,860` Att / `21` Ben) |
| **`ait_test`** | 492,614 | 430,678 (**46.65%**) | 68.37% / 70.78% | **9** | **69,992** (`69,874` Att / `118` Ben) |
| **`ctu_echo`** | 36,200 | 39,873 (**52.41%**) | 89.76% / 80.95% | **75** | **13,862** (`12,244` Att / `1,618` Ben) |
| **`ctu_windows7ad`** | 118,481 | 56,665 (**32.35%**) | 80.24% / 58.77% | **0** | 0 |

- Trong AIT, xung đột nhãn rơi chủ yếu vào vector `(dur=0.0, b_in=0, b_out=0, p_in=1, p_out=0, proto=6)` (probe TCP không phản hồi vừa là `host_discover_local`/`service_scan`, vừa là `broken flow - benign`) và `(dur=0.5xx, b_in=0, b_out=0, p_in=1, p_out=1, proto=6)`.
- Trong `ctu_echo`, vector `(dur=0.0, b_in=80, b_out=0, p_in=2, p_out=0, proto=6)` xuất hiện `10,570` lần (`10,566` Attack vs `4` Benign), và `(dur=0.0, b_in=120, b_out=0, p_in=2, p_out=0, proto=6)` xuất hiện `1,510` lần (`802` Attack vs `708` Benign) — bất kỳ bộ phân loại flow đơn lẻ thuần 18-feature nào đều chạm giới hạn Bayes error trên các vector này nếu thiếu ngữ cảnh cổng dịch vụ hoặc chuỗi thời gian / cửa sổ host.

### 4.3. Đa cộng tuyến Nghiêm trọng (`|r| >= 0.85`)
Trên toàn bộ 5 tập dữ liệu đều có từ `11` đến `16` cặp feature có `|Pearson r| >= 0.85`, điển hình:
- Trong AIT: `protocol_num` ↔ `is_tcp` (`r = -1.0`), `protocol_num` ↔ `is_udp` (`r = +1.0`), `is_tcp` ↔ `is_udp` (`r = -1.0`), `pkts_out` ↔ `total_pkts` (`0.9868–0.9900`), `bytes_out` ↔ `total_bytes` (`0.9784–0.9875`), `pkts_in_ratio` ↔ `has_response` (`-0.9395` đến `-0.9859`).
- Trong CTU (`ctu_echo` / `ctu_windows7ad`): `bytes_out` ↔ `total_bytes` (`0.9996–0.9998`), `pkts_in_ratio` ↔ `has_response` (`-0.9934` / `-0.9691`), `bytes_in_ratio` ↔ `pkts_in_ratio` (`0.9622–0.9653`), `protocol_num` ↔ `is_udp` (`0.9658–0.9824`).

---

## 5. Kết luận Tương thích Cross-Source

Từ các bằng chứng trên, `canonical-flow-v2-18` hiện tại **KHÔNG đạt tương thích ngữ nghĩa (semantically incompatible)** giữa Tstat (AIT) và Zeek (CTU) ở 3 điểm nghẽn gốc:
1. Lệch đơn vị 1,000x của `udp_complete` trong AIT (`seconds` vs `milliseconds`).
2. Lệch định nghĩa byte (`Tstat` payload bytes vs `Zeek` IP+L4-header bytes), đảo dấu hoàn toàn phân phối Attack trên `bytes_in`, `bytes_in_ratio`, `bytes_per_pkt_in` (`Att-KS = 0.9905`).
3. Thiếu hụt không gian giao thức (`ICMP = 0` trong AIT) và phân mảnh hình thái thăm dò (`pkts_in == 1` vs `== 2`, `pkts_in == 0` chỉ có ở Zeek), cộng với sai lệch `asinh_robust` trên `pkts_in_ratio` và lỗi cắt mất `233,185` dòng `tcp_complete.csv` ở builder.

---

## 6. Trạng thái Sau Khắc phục Phase 2 (`v2-domain-analysis-v2-post-remediation`)

Sau khi áp dụng các sửa lỗi `DATA-A01`, `DATA-A02`, `DATA-A03`, `DATA-A04`, `DATA-A08` vào `v2_schema.py`, `build_v2_dataset_and_split.py` và `pipeline.py`:

1. **Khôi phục đầy đủ `3,464,400` dòng AIT hợp lệ (`+233,185` dòng):**
   - `ait_train`: **`2,097,891`** dòng (`1,825,866` Benign / `272,025` Attack; `wilson`: `629,553` đủ 100%).
   - `ait_val`: **`377,704`** dòng (`206,676` Benign / `171,028` Attack).
   - `ait_test`: **`988,805`** dòng (`812,980` Benign / `175,825` Attack; `shaw`: `452,599` + `942` unmapped, `wheeler`: `536,206`).
2. **Giảm mạnh đảo chiều ngữ nghĩa trên `bytes_in_ratio` (`DATA-A03`):**
   - `ctu_echo` `Attack bytes_in == 0`: tăng từ `0.0%` lên **`92.49%`**, đồng nhất với `ait_train` (`56.83%`), `ait_val` (`90.49%`) và `ait_test` (`46.72%`).
   - `ait_train` vs `ctu_echo` `bytes_in_ratio` `Attack KS`: giảm từ `0.9905` xuống **`0.3540`**; `ctu_windows7ad` `Attack KS`: giảm từ `0.9862` xuống **`0.4862`**.
   - Single-feature `ROC-AUC` của `bytes_in_ratio` trên `ctu_echo` chuyển từ `0.8737` (ngược dấu) về **`0.1120`** (cùng chiều với AIT).
3. **Ổn định `pkts_in_ratio` (`DATA-A04` `MIN_BOUNDED_SCALE_FLOOR = 0.25`):**
   - `ait_train` vs `ctu_echo` `pkts_in_ratio`: `scaled_W1` giảm từ `4.0480` xuống **`0.7272`**; `scaled_median` giảm từ `+9.0394` xuống **`+1.6006`**.
4. **Hạn chế còn tồn tại:** Khác biệt vật lý giữa mạng giả lập AIT (chỉ TCP/UDP, không có ICMP, nhiều TCP scan 1-pkt `0B`) và thiết bị lab thật CTU (`Echo` IoT 2-pkt scan, `Windows7AD` + `ICMP`) vẫn tạo ra domain shift thực chất (`ctu_echo` `pkts_per_sec` `Att-KS = 0.4760`; `ait_train` vs `ctu_windows7ad` `protocol_num` `KS = 0.5642`), đòi hỏi đánh giá tách biệt in-domain (`AIT`) và cross-source (`CTU`).
