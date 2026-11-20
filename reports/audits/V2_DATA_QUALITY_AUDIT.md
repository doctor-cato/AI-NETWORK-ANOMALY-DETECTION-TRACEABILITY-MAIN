# Báo cáo Kiểm toán Chất lượng Dữ liệu & Hợp đồng Feature v2 (Phase 0 Audit)

**Phạm vi kiểm toán:** Toàn bộ manifest, dữ liệu raw (`AIT-NDS-v2`, `AIT-LDS-v2.1`, `AIT-ADS`, `CTU-SME-11`, trạng thái `UGR'16`), dữ liệu đã chuẩn hóa (`data/processed/v2/*.csv.gz`), schema `canonical-flow-v2-18`, adapter/builder/preprocessor và bằng chứng đánh giá chéo nguồn hiện tại.  
**Chế độ thực hiện:** Chỉ đọc và phân tích kiểm chứng (không sửa đổi mã nguồn, manifest hoặc dữ liệu).  
**Tài liệu phân tích bổ trợ:**  
- [`../experiments/ml/domain_analysis/DOMAIN_SHIFT_ANALYSIS.md`](../experiments/ml/domain_analysis/DOMAIN_SHIFT_ANALYSIS.md)  
- [`../experiments/ml/domain_analysis/ait_vs_ctu_statistics.json`](../experiments/ml/domain_analysis/ait_vs_ctu_statistics.json)  
- [`../experiments/ml/domain_analysis/feature_compatibility_analysis.json`](../experiments/ml/domain_analysis/feature_compatibility_analysis.json)

---

## 1. Tóm tắt Điều hành & Bảng Phát hiện Nghiêm trọng

Mặc dù toàn bộ 18 tệp raw hiện diện khớp 100% SHA-256/MD5/byte size với manifest và các tệp `*.csv.gz` đã sinh không chứa `NaN`/`Inf`/ô trống, cuộc kiểm toán Phase 0 phát hiện **3 lỗi hợp đồng/dữ liệu mức `CRITICAL`**, **3 vấn đề kiến trúc/build mức `HIGH`** và **4 sai lệch hồ sơ/leakage phụ mức `MEDIUM`**, giải thích trực tiếp nguyên nhân các mô hình supervised (`random_forest`, `xgboost`) sụp đổ khi suy luận zero-shot sang `CTU-SME-11`:

| ID | Mức độ | Vị trí (`file:dòng`) | Tóm tắt phát hiện | Tác động định lượng thực tế |
|---|---|---|---|---|
| **A01** | `CRITICAL` | `scripts/build_v2_dataset_and_split.py:141-145,192,215,237-247` | **Mất index khi đọc theo chunk làm rơi 233,185 dòng AIT:** `_classify_series()` trả về `pd.Series` index `0..n-1`, trong khi `chunk` thứ 2+ của `pd.read_csv(..., chunksize=250_000)` có `RangeIndex(250000, ...)`. Gán `feat_df["label_status"] = lst` alignment sai tạo toàn `<NA>`, khiến cả `unm_mask.any()` và `(~unm_mask).any()` thành `False`. | Cắt cụt toàn bộ `tcp_complete.csv` vượt quá `250,000` dòng: `wilson` mất `167,672`, `shaw` mất `31,478`, `wheeler` mất `34,035` (`6.73%` của `3,465,342` raw); mất **`334` dòng `Credential_Attack` (`13.22%`)** và **`7` dòng `Exploitation_And_C2` (`16.28%`)**. |
| **A02** | `CRITICAL` | `src/network_anomaly/data/v2_schema.py:281`; `scripts/build_v2_dataset_and_split.py:205-208` | **Sai đơn vị thời lượng AIT UDP (`seconds` vs `milliseconds`):** Raw Tstat `udp_complete.csv` ghi `c_durat:4`/`s_durat:13` theo **giây** (khác `durat:31` mili-giây ở TCP và Zeek `duration * 1000`), nhưng parser và builder đọc trực tiếp không nhân `1000.0`. | **`94.9953%`** UDP ở `ait_train`, **`93.7153%`** ở `ait_val`, **`97.5182%`** ở `ait_test` bị tụt xuống `< 1.0 ms` rồi bị `safe_dur = max(duration_ms, 1.0)` kẹp về `1.0 ms`, thổi phồng `bytes_per_sec_in` tới `53,828,790,000 B/s` và `pkts_per_sec` tới `197,381,000 pkt/s`. |
| **A03** | `CRITICAL` | `src/network_anomaly/data/v2_schema.py:282-283,295-296,350-351`; `scripts/build_v2_dataset_and_split.py:209-210,222-223,287-288`; `src/network_anomaly/ingestion/adapters/zeek.py:73-84` | **Bất tương thích ngữ nghĩa byte (`Tstat payload` vs `Zeek IP+header`):** AIT `c_bytes_all`/`s_bytes_all` chỉ đếm L4 payload (`0 B` với SYN/probe rỗng), còn CTU `orig_ip_bytes`/`resp_ip_bytes` đếm cả IP+L4 header (`>= 40 B` với SYN, `96 B` so với `68 B` payload ở NTP). `ZeekConnAdapter` lại dùng `orig_bytes` (`-` -> `0`, `ml_features=None`). | Tỉ lệ Attack có `bytes_in == 0` rơi từ `56.95%` (Train) / `90.49%` (Val) / `46.75%` (Test) xuống **`0.0%`** ở cả 2 tập CTU. Attack `bytes_in_ratio` đạt `KS = 0.9905` (Echo) / `0.9862` (Win7AD), đảo chiều AUC; zero-shot **RF recall = `0.0%`**, **XGBoost recall = `0.0%` (Echo, `ROC-AUC = 0.0373`) / `0.0491%` (Win7AD)**. |
| **A04** | `HIGH` | `src/network_anomaly/preprocessing/pipeline.py:300-326,354-370` | **Khác biệt không gian giao thức (`ICMP`) & nhạy cảm `asinh_robust`:** AIT không có `ICMP` (`0` dòng), CTU có `8.37%` (Echo) & `2.68%` (Win7AD). `protocol_num` chỉ có vocab `[6, 17]` và `passthrough` nguyên số `1` chưa scale; `pkts_in_ratio` có `IQR_arcsinh = 0.044269` rất nhỏ. | `ctu_echo` median `pkts_in_ratio = 1.0` biến đổi thành **`+9.0394`** (`scaled_W1 = 4.0480`); kết hợp giao thức lạ `1` khiến zero-shot Autoencoder đạt `FPR = 65.20%` (Echo) và `85.45%` (Win7AD), Isolation Forest `FPR = 20.86%` và `43.34%`. |
| **A05** | `HIGH` | `src/network_anomaly/ingestion/adapters/v2_adapter.py:74-80`; `src/network_anomaly/ingestion/adapters/canonical_v2.py:47-60`; `src/network_anomaly/data/v2_schema.py:274-301,347-348` | **Dấu vết probe/hướng luồng/missing & xung đột nhãn:** AIT attack `pkts_in == 1` (`88.91%–99.63%`) đối lập `ctu_echo` `pkts_in == 2` (`91.83%`); Zeek có luồng mid-stream `pkts_in == 0` (`32` Echo, `1,793` Win7AD) còn AIT là `0`; Zeek `duration == "-"` bị ép thành `0.0 ms`. | Trên cùng một vector 18-feature chính xác tồn tại **`126,166` dòng xung đột nhãn** ở `ait_train` (`48` vectors), `131,881` ở `ait_val`, `69,992` ở `ait_test`, `13,862` ở `ctu_echo` (`75` vectors). Cả `UnifiedNetFlowAdapter` lẫn `CanonicalFlowV2Adapter` đều kế thừa bug A02/A03 qua `parse_ait_nds_tstat_row`/`parse_ctu_zeek_conn_row`. |
| **A06** | `HIGH` | `scripts/build_v2_dataset_and_split.py:385-401,485-486`; `pipeline.py:468,673-675`; `.gitattributes` | **Rủi ro SHA-256 theo CRLF vs LF trên JSON manifests & `*.csv.gz`:** `Path.write_text()` trên Windows tạo **CRLF** cho `V2_SPLIT_MANIFEST.json`, `v2_split_manifest.json`, `v2_flow_preprocessing_manifest.json`, `v2_multi_source_profile.json` và 4 model manifests (`i/lf w/crlf`), xung đột `.gitattributes` (`eol=lf`). | `split_manifest_sha256` lưu trong preprocessing manifest (`1b7fa7ae...`, 4,851 B CRLF) khác với SHA-256 Git index LF (`7840d5cd...`, 4,716 B). Khi checkout LF trên Linux CI (`ubuntu-latest`), kiểm tra byte SHA-256 ở `pipeline.py:673-675` không khớp nếu manifest không đồng bộ LF. Tương tự `df.to_csv()` ghi `\r\n` bên trong các tệp `.csv.gz`. |
| **A07** | `MEDIUM` | `docs/DATASET.md:10` | **Sai lệch tài liệu license `AIT-LDS-v2.1`:** Ghi `VERIFIED (CC BY 4.0)` thay vì `CC BY-NC-SA 4.0`. | Mâu thuẫn trực tiếp với `AIT_DATASETS_MANIFEST.json:15`, `EXTERNAL_DATASETS_PROVENANCE.json:14`, `NOTICE:39`, `THIRD_PARTY_NOTICES.md:13` và `DISTRIBUTION_AUTHORIZATION.json:57`. |
| **A08** | `MEDIUM` | `scripts/build_v2_dataset_and_split.py:15,518` | **Sai lệch docstring về phương pháp scaling:** Ghi `scaler_type="robust"` / `RobustScaler` trong khi dòng `495` chạy thực tế là `scaler_type="asinh_robust"`. | Gây hiểu nhầm khi kiểm toán tham số tiền xử lý giữa mã nguồn và tài liệu `docs/dataset/V2_LEAKAGE_AUDIT.md`. |
| **A09** | `MEDIUM` | `data/processed/v2/ctu_{echo,windows7ad}.csv.gz`; `ait_{train,val}.csv.gz` | **Overlap 5-tuple & nhãn đối nghịch giữa 2 thiết bị CTU cùng capture:** `ctu_echo` và `ctu_windows7ad` chia sẻ `42` cặp `(5-tuple, timestamp_ms)` chính xác (`45` nhóm `canonical_flow_group` theo bucket 300s, `47` dòng giao tiếp `192.168.1.50 <-> 192.168.1.108`), trong đó một luồng bị gán `Malicious` ở Echo nhưng `Benign` ở Win7AD. AIT Train vs Val cũng có `11` nhóm broadcast DHCP `0.0.0.0:68 <-> 255.255.255.255:67` (`90` dòng Benign) và giao nhau thời gian đồng hồ (`wardbeck` vs `russellmitchell`). | Phải giữ nghiêm tách biệt scenario/device khi đánh giá; không được trộn chéo `ctu_echo` và `ctu_windows7ad` vào cùng split train/test không phân nhóm 5-tuple+time. |
| **A10** | `MEDIUM` | `reports/datasets/v2_multi_source_profile.json`; `data/EXTERNAL_DATASETS_PROVENANCE.json:8,32-39` | **`UGR'16` bị `BLOCKED` & liên kết `AIT-NDS-v2 <-> AIT-LDS-v2.1` không join trực tiếp:** `UGR'16` HTTP `403`; `AIT-NDS-v2` xuất phát từ `AIT-LDS-v2.0` nên `direct_uid_join_possible = false` và lệch cửa sổ thời gian `dnsteal` ở `fox`. | Giữ nguyên trạng thái `BLOCKED` cho `UGR'16` (không thay dữ liệu giả) và chỉ correlate `AIT-ADS`/`AIT-LDS-v2.1` theo cửa sổ thời gian + IP thực thể. |

---

## 2. Dataset Evidence Ledger (Raw, Processed, Manifests, Line Endings & Licenses)

### 2.1. Kiểm tra Manifest & Trạng thái CRLF/LF (Git Index vs Working Tree)

Kiểm tra trực tiếp bằng `git ls-files --eol` (với `.gitattributes` quy định `* text=auto eol=lf`) và đọc byte trực tiếp:

| Tệp Manifest / Profile | Kích thước Working Tree | Line Endings (`crlf` / `lf_only`) | Git Index EOL | Working Tree SHA-256 | Git Index (LF) SHA-256 |
|---|---:|---|---|---|---|
| `data/AIT_DATASETS_MANIFEST.json` | 8,023 B | `0` CRLF / `207` LF | `i/lf w/lf` | `c80f6add65a9e864626e769f2b03b11839234f568acff08bdd3b6c56ce3c329f` | Giống Working Tree |
| `data/CTU_SME_11_MANIFEST.json` | 2,053 B | `0` CRLF / `48` LF | `i/lf w/lf` | `174e057851bf056a91e459a0192628bfc3cfde546b8c9d7594ae1b5be38c4dce` | Giống Working Tree |
| `data/EXTERNAL_DATASETS_PROVENANCE.json` | 1,593 B | `0` CRLF / `41` LF | `i/lf w/lf` | `d549ae714f1857cc8b9add7a2ddd4384306ef8b82163df04f0499f0114ddd084` | Giống Working Tree |
| `data/V2_SPLIT_MANIFEST.json` *(giống hệt `reports/splits/v2_split_manifest.json`)* | 4,851 B | **`135` CRLF** / `0` LF | **`i/lf w/crlf`** | `1b7fa7aebaf3560f27b3d23ec05919a83aacd1ed6ea5448f96a6a42c7a264e0a` | `7840d5cdd18acb29ad222ec7d29e26e645fabb76646b62081e1d7368488eefe8` (4,716 B) |
| `reports/preprocessing/v2_flow_preprocessing_manifest.json` | 2,769 B | **`101` CRLF** / `0` LF | **`i/lf w/crlf`** | `473b564655726e72cf9d42afa414c43791a6945d18c512cc8520c7edefd6d825` | `eff0c30ce6256e7047702fd2421afab55d9c9c4b51fc670da5d162f4b476e44a` (2,668 B) |
| `reports/datasets/v2_multi_source_profile.json` | 19,154 B | **`610` CRLF** / `0` LF | **`i/lf w/crlf`** | `dda1a1f98ac4809739144c4a74a094ca5a3c5fb523362fbaeb569c6a50bcb512` | — |
| `reports/models/{random_forest,xgboost,isolation_forest,autoencoder}_manifest.json` | — | CRLF trên đĩa | **`i/lf w/crlf`** | Khớp `split_manifest_sha256 = 1b7fa7ae...` | — |

> **Phát hiện tính nhất quán hash:** `split_manifest_sha256` ghi trong `v2_flow_preprocessing_manifest.json` (`1b7fa7aebaf3560f27b3d23ec05919a83aacd1ed6ea5448f96a6a42c7a264e0a`) và `dataset_sha256` (`cc7553ad813ac0ee696f826a877af7afe9c7e07d3443beb34d8c9c21fbe81acf`), cũng như `artifact_sha256` của `artifacts/preprocessing/v2_flow_preprocessor.joblib` (`d33dfe09630687f825d7e4cfa604001c3e091560538059da2eb397b49f44bc32`) đều khớp trên working tree Windows hiện tại, nhưng **sẽ lệch hash SHA-256 trên máy Linux (`ubuntu-latest` CI)** nếu kiểm tra `verify_preprocessing_artifact` đọc bản LF đã checkout từ Git (`7840d5cd...`).

### 2.2. Kiểm kê Dữ liệu Raw, Khả năng Parse & Giấy phép (18/18 tệp `VERIFIED`)

Tất cả 18 tệp raw đều khớp 100% `size_bytes`, `md5` và `sha256` với `AIT_DATASETS_MANIFEST.json` và `CTU_SME_11_MANIFEST.json`:

| Tập dữ liệu & License | DOI / Nguồn & Trạng thái | Tệp thực tế trên đĩa | Kích thước (bytes) | SHA-256 (khớp Manifest) | Kết quả parse & kiểm định nội dung |
|---|---|---|---:|---|---|
| **AIT-NDS-v2** (`CC BY 4.0`; từ `AIT-LDS-v2.0`) | `10.5281/zenodo.13168643` (`VERIFIED_LOCAL`, 8/8 scenarios) | `data/raw/ait_nds_v2/fox_netflows.zip` | 25,870,023 | `e2bfacdfe9822109c807300f941d0a0c9fa1b370bcf2822fd12f27ed23928381` | Zip hợp lệ; 351,908 flows (184,521 / 48,296 / 119,091); parse 138/52/28 cột OK |
| **AIT-NDS-v2** | nt | `data/raw/ait_nds_v2/harrison_netflows.zip` | 31,245,912 | `3b4a0cbe9355b65890a8364a6309c5ac9da50b88095dee9d608dd91c13398834` | Zip hợp lệ; 437,659 flows (204,134 / 67,462 / 166,063); parse OK |
| **AIT-NDS-v2** | nt | `data/raw/ait_nds_v2/russellmitchell_netflows.zip` | 20,849,591 | `760e37d2c862c72604920cc1334768d8e582056b6979a3b160923b73525b0186` | Zip hợp lệ; 377,704 flows (123,332 / 154,877 / 99,495); parse OK |
| **AIT-NDS-v2** | nt | `data/raw/ait_nds_v2/santos_netflows.zip` | 25,726,503 | `72a37bb3e69a4e17103bacdd75d50817427bdfb6deaf06430ba3b942d462e328` | Zip hợp lệ; 288,547 flows (178,744 / 5,778 / 104,025); parse OK |
| **AIT-NDS-v2** | nt | `data/raw/ait_nds_v2/shaw_netflows.zip` | 37,791,047 | `c9c432b6eb64b89ba6c941dcd2cd3b13a7d57236fd92cc9c5c1d1bbab5cdeacb` | Zip hợp lệ; 453,541 flows (281,478 / 2,530 / 169,533); có 942 nhãn rỗng SMTP `:25` |
| **AIT-NDS-v2** | nt | `data/raw/ait_nds_v2/wardbeck_netflows.zip` | 34,616,579 | `9269999153f6a08522045d3f9102e6005ce719e7b1cd51ff4034455930d19a52` | Zip hợp lệ; 390,224 flows (246,907 / 4,438 / 138,879); parse OK |
| **AIT-NDS-v2** | nt | `data/raw/ait_nds_v2/wheeler_netflows.zip` | 41,199,118 | `d328705dbd6df28e225274624b830e6be2589a2339929daaa0f7154ba33859c8` | Zip hợp lệ; 536,206 flows (284,035 / 80,386 / 171,785); parse OK |
| **AIT-NDS-v2** | nt | `data/raw/ait_nds_v2/wilson_netflows.zip` | 56,386,626 | `130d9c0cdafc5a958db38ce05ebf8965618e5936c0a604af71dfa32639812749` | Zip hợp lệ; 629,553 flows (417,672 / 30,869 / 181,012); parse OK |
| **AIT-NDS-v2** | nt | `data/raw/ait_nds_v2/label_info.txt`, `README.md` | 986 / 2,104 | `87f1d8775150cbfe214937110d2851eb2e37b0f3db79018b597edf787362248f` / `b66b99710695e907ebb74032bbff1a469d5ee845cf581ed1206cf1fd9012e55e` | Văn bản UTF-8 hợp lệ |
| **AIT-LDS-v2.1** (**`CC BY-NC-SA 4.0`**) | `10.5281/zenodo.19483937` (`VERIFIED_SUBSET_LOCAL`) | `data/raw/ait_lds_v2_1/fox_no-pcaps.zip` | 688,586,900 | `8d71d31a31df469d836c80bdbfdc35da566e90322cf9ae490233e176a0c88d49` | Zip hợp lệ (16,094 entries); chỉ dùng audit/trace, không nạp vào weight/demo (`CC BY-NC-SA 4.0`) |
| **AIT-LDS-v2.1** (**`CC BY-NC-SA 4.0`**) | nt | `data/raw/ait_lds_v2_1/russellmitchell_no-pcaps.zip` | 522,084,364 | `51a03f51daea0fbbdcfe9b8abe0dbbe10633716f4f98074f861204a162ee1978` | Zip hợp lệ (14,898 entries); tách version v2.1 vs v2.0 của NDS (`direct_uid_join_possible = false`) |
| **AIT-ADS** (`CC BY 4.0`; từ `AIT-LDS-v2.0`) | `10.5281/zenodo.8263181` (`VERIFIED_LOCAL`) | `data/raw/ait_ads/ait_ads.zip` | 96,202,946 | `9f0595c4ebe56ac9223763881f55369dd4f249a8108064e4ae108eb3309aeeb9` | 16 JSONL files (`*_aminer.json`, `*_wazuh.json`), JSONL parse OK |
| **AIT-ADS** | nt | `data/raw/ait_ads/labels.csv` | 3,703 | `633e09b42772eabbbe5b48598220860eead60b7352efb01973fc45a5034290c0` | 79 dòng cửa sổ nhãn tấn công trên 8 scenarios |
| **CTU-SME-11** (`CC BY 4.0`) | `10.5281/zenodo.7958258` / v `7958259` (`VERIFIED_SUBSET_LOCAL`, 2/11 thiết bị) | `data/raw/ctu_sme_11/CTU-SME-11_Experiment-VM-Microsoft-Windows7AD-1_v1.0.0.tar.bz2` | 1,581,328,775 | `1654712980ae8cb27e4417359ffe1483156c582d674d2dcf031112b141652a63` | Tar.bz2 hợp lệ; 7 `conn.log.labeled` ở `ctu_sme_11_extracted/` (184,540 dòng: 173,108 Benign, 2,038 Attack, 9,394 `Unknown`) |
| **CTU-SME-11** | nt | `data/raw/ctu_sme_11/CTU-SME-11_Honeypot-Assistant-Amazon-Echo1stGen-1_v1.0.0.tar.bz2` | 742,890,363 | `eb0ac427cab9a346cd2aa446c59290f50b43d162f5ba4da02a8a12a0211dbb84` | Tar.bz2 hợp lệ; 7 `conn.log.labeled` ở `ctu_sme_11_extracted/` (76,073 dòng: 39,497 Benign, 36,576 `Malicious`, 0 `Unknown`) |
| **CTU-SME-11** | nt | `CTU-SME-11_summary_table.csv`, `README.md` | 1,953 / 2,566 | `c052dbe5795cecfd3be96e125fbcf1ad5f77c1f7da32959a73a6acd829181432` / `4bde3c65f31836881f518fa5f648d56e67f625c8a494ad07ca68e970912c1059` | Hợp lệ; lưu ý lab 7 ngày không phải production enterprise |
| **UGR'16** | `https://nesg.ugr.es/nesg-ugr16/` | *(Không có tệp local)* | 0 | — | **`BLOCKED`:** Portal trả `HTTP 403` / `Portal en Mantenimiento`. Không chấp nhận license hay tải được; tuyệt đối không tạo dữ liệu thay thế. |

### 2.3. Kiểm toán Đối soát Raw vs Processed AIT (`233,185` Dòng Bị Cắt Cụt)

Tất cả 8 tệp `data/processed/v2/*.csv.gz` và 3 tệp `splits/*_indices.csv.gz` khớp SHA-256 với `V2_SPLIT_MANIFEST.json`, nhưng **không khớp tổng số dòng của dữ liệu raw AIT-NDS-v2**:

- **Raw AIT-NDS-v2 (`v2_multi_source_profile.json`):** **`3,465,342`** dòng (`3,464,400` dòng có nhãn hợp lệ + `942` dòng unmapped).
- **Processed AIT (`V2_SPLIT_MANIFEST.json`):** `1,930,219` (Train) + `377,704` (Val) + `923,292` (Test) + `942` (Unmapped) = **`3,232,157`** dòng.
- **Chênh lệch mất mát:** **`233,185` dòng (`6.73%`) bị rơi âm thầm** hoàn toàn từ chunk thứ 2 của `tcp_complete.csv` ở 3 scenario vượt quá `chunksize=250_000`:

| Scenario / Nhóm nhãn | Raw (`profile.json`) | Processed (`.csv.gz`) | Số dòng mất | Tỉ lệ mất |
|---|---:|---:|---:|---:|
| **`wilson`** (Train) | 629,553 (`tcp_complete`: 417,672) | 461,881 (`tcp_complete`: **250,000**) | **-167,672** | -26.63% |
| **`shaw`** (Test) | 453,541 (`tcp_complete`: 281,478) | 421,121 + 942 unm (`tcp_complete`: **250,000**) | **-31,478** | -6.94% |
| **`wheeler`** (Test) | 536,206 (`tcp_complete`: 284,035) | 502,171 (`tcp_complete`: **250,000**) | **-34,035** | -6.35% |
| *5 scenarios còn lại* (`fox, harrison, russellmitchell, santos, wardbeck`) | 1,846,042 | 1,846,042 | 0 | 0.00% |
| **Theo lớp: `Benign`** | 2,845,522 | 2,613,081 | **-232,441** | -8.17% |
| **Theo lớp: `Reconnaissance`** | 432,912 | 432,511 | **-401** | -0.09% |
| **Theo lớp: `Credential_Attack`** | 2,527 | 2,193 | **-334** | **-13.22%** |
| **Theo lớp: `Exploitation_And_C2`** | 43 | 36 | **-7** | **-16.28%** |
| **Theo lớp: `Post_Exploitation_Discovery`** | 275 | 273 | **-2** | -0.73% |
| **Theo lớp: `Data_Exfiltration` & `Unmapped`** | 183,121 / 942 | 183,121 / 942 | 0 / 0 | 0.00% |

**Xác minh tái lập gốc:** Chạy `_canonicalize_ait_scenario(Path("data/raw/ait_nds_v2/wilson_netflows.zip"))` trực tiếp trong bộ nhớ tái lập chính xác `labeled = 461,881`, `tstat:tcp_complete = 250,000` (trong khi `tstat:tcp_nocomplete` vẫn có `flow_id` bắt đầu từ `417672`).

---

## 3. Kiểm định Hợp đồng 18 Features `canonical-flow-v2-18` (AIT Tstat vs CTU Zeek)

Các định nghĩa được đối chiếu từ `src/network_anomaly/data/v2_schema.py`, `scripts/build_v2_dataset_and_split.py`, `src/network_anomaly/ingestion/adapters/v2_adapter.py`, `canonical_v2.py` và `zeek.py`.

### 3.1. Bảng Đối chiếu 18 ML Features (`canonical-flow-v2-18`)

| # | Feature | AIT source (`Tstat` 138/52/28 cột) | CTU source (`Zeek conn.log.labeled` 23 cột) | Unit | Semantics | Compatibility |
|---:|---|---|---|---|---|---|
| 1 | `duration_ms` | TCP: `durat:31` (`tcp_complete` / `tcp_nocomplete`); UDP: `max(c_durat:4, s_durat:13)` (`udp_complete`) | `duration` (chỉ định `-`/`""`/`(empty)` -> `0.0`), nhân `1000.0` | **AIT TCP & CTU: `ms`**; **AIT UDP: `seconds` (SAI 1000x)** | AIT UDP thiếu `* 1000.0`; Zeek `-` (1-pkt/no-interval, `22,505` Echo / `37,331` Win7AD raw) bị gộp vào `0.0 ms` giống TCP multi-pkt `<1us`. | **`INCOMPATIBLE` (Bug A02)** |
| 2 | `bytes_in` | TCP: `c_bytes_all:9`; UDP: `c_bytes_all:5` | `orig_ip_bytes` *(chú ý `zeek.py` dùng `orig_bytes`)* | Bytes | **AIT = L4 transport payload bytes** (SYN/probe rỗng = `0`); **CTU = IP+L4 headers+payload** (mọi packet >= `20–40 B`, NTP `96 B` vs `68 B` payload). | **`INCOMPATIBLE` (Bug A03)** |
| 3 | `bytes_out` | TCP: `s_bytes_all:23`; UDP: `s_bytes_all:14` | `resp_ip_bytes` *(chú ý `zeek.py` dùng `resp_bytes`)* | Bytes | Như trên: phản hồi TCP ACK/RST rỗng trong AIT bằng `0 B`, trong CTU bằng `40–52+ B`. | **`INCOMPATIBLE` (Bug A03)** |
| 4 | `pkts_in` | TCP: `c_pkts_all:3`; UDP: `c_pkts_all:6` | `orig_pkts` | Packets | AIT luôn >= `1` (client-initiated `pkts_in == 0` là `0`); CTU có mid-stream `pkts_in == 0` (`32` Echo, `1,793` Win7AD). Ngoài ra scan AIT `pkts_in=1` (`88.9–99.6%`) vs CTU-Echo `pkts_in=2` (`91.83%`). | **`PARTIAL` (Hướng/Probe bias)** |
| 5 | `pkts_out` | TCP: `s_pkts_all:17`; UDP: `s_pkts_all:15` | `resp_pkts` | Packets | Số gói chiều server -> client. Đồng nhất đơn vị gói nhưng phụ thuộc trạng thái firewall/chính sách retry của từng testbed. | **`COMPATIBLE` (nhạy testbed)** |
| 6 | `protocol_num` | Gán cứng từ tên tệp: TCP=`6`, UDP=`17` | `proto` qua `PROTOCOL_NAME_TO_NUMBER` (`ICMP=1`, `TCP=6`, `UDP=17`, ...) | IANA int code (8-bit) | AIT thiếu hoàn toàn `ICMP=1` (`0` dòng); CTU có `ICMP=1` (`8.37%` Echo, `2.68%` Win7AD) bị `passthrough` chưa scale cùng cột `asinh_robust`. | **`PARTIAL` (OOD ICMP + Passthrough)** |
| 7 | `total_bytes` | Derived: `bytes_in + bytes_out` | Derived: `bytes_in + bytes_out` | Bytes | Cộng gộp độ lệch IP-header giữa AIT (payload) và CTU (IP bytes); zero-rate AIT Train `8.41%` / Val `41.19%` vs CTU **`0.0%`**. | **`INCOMPATIBLE` (kế thừa A03)** |
| 8 | `total_pkts` | Derived: `pkts_in + pkts_out` | Derived: `pkts_in + pkts_out` | Packets | Tổng gói 2 chiều (>= 1 trên toàn bộ cả 5 tập). | **`COMPATIBLE`** |
| 9 | `bytes_in_ratio` | Derived: `bytes_in / max(total_bytes, 1.0)` | Derived: `bytes_in / max(total_bytes, 1.0)` | Ratio `[0, 1]` | **Đảo chiều mạnh nhất:** AIT Attack `bytes_in=0` -> ratio `0.0`; CTU-Echo `S0` `bytes_in=80..88, bytes_out=0` -> ratio **`1.0`** (`Att-KS = 0.9905`, single AUC đảo `0.2800 -> 0.8737`). | **`INCOMPATIBLE` (Đảo dấu phân phối)** |
| 10 | `pkts_in_ratio` | Derived: `pkts_in / max(total_pkts, 1.0)` | Derived: `pkts_in / max(total_pkts, 1.0)` | Ratio `[0, 1]` | Độc lập byte, nhưng AIT `IQR_arcsinh = 0.044269` biến đổi CTU-Echo median `1.0` lên `+9.0394` (`W1_scaled = 4.0480`); CTU mid-stream có giá trị `0.0` (AIT min `0.0345–0.0495`). | **`PARTIAL` (Scaler & Mid-stream)** |
| 11 | `bytes_per_pkt_in` | Derived: `bytes_in / max(pkts_in, 1.0)` | Derived: `bytes_in / max(pkts_in, 1.0)` | Bytes/pkt | Trong CTU bị chặn dưới bởi IP/TCP header (`min = 28 B` trên Attack Echo, `42 B` Win7AD); trong AIT bằng `0.0` cho mọi SYN/ACK-only. | **`INCOMPATIBLE` (kế thừa A03)** |
| 12 | `bytes_per_pkt_out` | Derived: `bytes_out / max(pkts_out, 1.0)` | Derived: `bytes_out / max(pkts_out, 1.0)` | Bytes/pkt | Phản ánh payload-per-pkt (AIT) vs IP-bytes-per-pkt (CTU), cộng shift HTTP/DNS lớn ở AIT vs IoT ở Echo (`KS = 0.4856–0.5008`). | **`INCOMPATIBLE` (kế thừa A03)** |
| 13 | `bytes_per_sec_in` | Derived: `(bytes_in * 1000.0) / max(duration_ms, 1.0)` | Derived: `(bytes_in * 1000.0) / max(duration_ms, 1.0)` | Bytes/sec | Thừa hưởng cả **A02** (UDP `<1s` bị kẹp `1 ms`, thổi phồng tới `53.8B B/s` ở AIT) lẫn **A03** (IP vs payload) lẫn clamp `0.0 ms -> 1 ms`. | **`INCOMPATIBLE` (A02 + A03)** |
| 14 | `bytes_per_sec_out` | Derived: `(bytes_out * 1000.0) / max(duration_ms, 1.0)` | Derived: `(bytes_out * 1000.0) / max(duration_ms, 1.0)` | Bytes/sec | Nt (`ait_val` max `44,794,346,000 B/s` vs CTU max `10,704,588 B/s`). | **`INCOMPATIBLE` (A02 + A03)** |
| 15 | `pkts_per_sec` | Derived: `(total_pkts * 1000.0) / max(duration_ms, 1.0)` | Derived: `(total_pkts * 1000.0) / max(duration_ms, 1.0)` | Pkts/sec | Bị sai lệch do **A02** trên toàn bộ UDP AIT (`95–97.5%` bị ép vào bội số `1,000 pkt/s`, `ait_val` max `197,381,000 pkt/s`), dù bản thân tử số không phụ thuộc byte. | **`INCOMPATIBLE` (kế thừa A02)** |
| 16 | `has_response` | Derived: `1.0 if pkts_out > 0.0 else 0.0` | Derived: `1.0 if pkts_out > 0.0 else 0.0` | Binary `{0, 1}` | Nhất quán công thức nhưng phân phối lệch nặng theo tỷ lệ `S0` (`ctu_echo` `has_response=0` chiếm `54.17%` tổng / `91.08%` Attack vs AIT Train `9.73%` / `43.62%`). | **`COMPATIBLE` (Domain shift)** |
| 17 | `is_tcp` | Derived: `1.0 if protocol_num == 6 else 0.0` | Derived: `1.0 if protocol_num == 6 else 0.0` | Binary `{0, 1}` | Với AIT, `is_tcp = 1 - is_udp` (`r = -1.0`); với CTU còn trường hợp `is_tcp = 0, is_udp = 0` (ICMP). | **`COMPATIBLE` (Đa cộng tuyến ở AIT)** |
| 18 | `is_udp` | Derived: `1.0 if protocol_num == 17 else 0.0` | Derived: `1.0 if protocol_num == 17 else 0.0` | Binary `{0, 1}` | Như trên (`ctu_windows7ad` 90.26% UDP Benign nhưng 100% Attack TCP -> `is_tcp` single AUC = `0.9702`). | **`COMPATIBLE` (Domain shift)** |

*(Metadata & Trace: `timestamp_ms` từ `first:29` [ms] / `c_first_abs:3` [ms] / Zeek `ts * 1000.0` [ms] nhất quán; nhưng `flow_id` AIT gán tuần tự giả lập `{scenario}:{fname}:{row_seq}` còn CTU lấy `uid` Zeek; `canonical_flow_group` chuẩn hóa 5-tuple bất biến hướng + bucket 300s.)*

### 3.2. Bằng chứng Raw cho Hai Lỗi Gốc A02 & A03

1. **Chứng minh AIT `udp_complete` lưu giây vs TCP `ms` (`fox_netflows.zip`, `wilson_netflows.zip`):**
   - Trong `fox/tcp_complete.csv`: `last:30 - first:29 == durat:31` chính xác tới mili-giây (`2188.354 ms`, `2194.525 ms`, `21675.281 ms`), `min_nz = 0.2710–0.5290 ms`.
   - Trong `fox/udp_complete.csv`:
     - Flow `bootp` 10 gói: `c_durat:4 = 60.424808` (tức **60.4 giây**, khớp khoảng lặp BOOTP ~6s/gói).
     - Flow `benign DNS` 2+2 gói (`1642209153924.525 -> 1642209153932.39`): `c_durat:4 = 0.008058` (**8.058 ms** biểu diễn bằng giây), `systemd-resolver` = `0.000022` (**22 us** biểu diễn bằng giây).
     - Max `c/s_durat` ở `wilson` là `474,174.637599` (giây = ~5.49 ngày trong capture ~6 ngày), trong khi `tcp_complete` max `durat:31` là `433,583,263.502 ms` (~5.02 ngày). Tổng số flow UDP raw có giá trị `> 600` (tức >10 phút tính theo giây) trên 8 scenarios là **`23,304` flows**.
2. **Chứng minh AIT `Tstat` payload bytes vs CTU `Zeek` IP-layer bytes:**
   - Trong AIT `fox`: UDP `NTP` 1 gói (`c_pkts_all:6 = 1`) có `c_bytes_all:5 = 48`, `s_bytes_all:14 = 48` (chính xác 48 byte NTP payload, không cộng 28 byte IPv4+UDP header); TCP `tcp_nocomplete` scan `host_discover_local`/`service_scan` (`33,078` dòng `p_in=1,p_out=0` và `14,582` dòng `p_in=1,p_out=1`) có **`c_bytes_all:9 = 0, s_bytes_all:23 = 0`**.
   - Trong CTU `ctu_echo`: Zeek NTP 1 gói có `orig_bytes = 68` (payload NTP) nhưng **`orig_ip_bytes = 96`** (`+28 B` IPv4+UDP header); ICMP echo không payload có `orig_bytes = '-'`, **`orig_ip_bytes = 212`**; TCP `S0` scan 2 gói (`orig_pkts=2, resp_pkts=0`) có `orig_bytes = '0'` hoặc `'-'` nhưng **`orig_ip_bytes = 80` hoặc `88`** (40/44 B IP+TCP SYN header x 2 gói).
   - Vì `v2_schema.py:350-351` và `build_v2_dataset_and_split.py:287-288` chọn `orig_ip_bytes`/`resp_ip_bytes` để tránh `'-'` (xuất hiện ở `22,505` dòng `29.58%` của Echo và `37,331` dòng `20.23%` raw của Win7AD trên `duration`, `orig_bytes`, `resp_bytes`), toàn bộ bảng dữ liệu CTU mang **IP-layer bytes** còn AIT mang **transport payload bytes** — gây ra xung đột ngữ nghĩa không thể điều hòa chỉ bằng scaler.

---

## 4. Kết quả Kiểm toán Chất lượng Dữ liệu, Leakage & Impact Mô hình

### 4.1. Thống kê Đầy đủ `data/processed/v2/*.csv.gz`

Các bảng chi tiết `mean, std, p05, p25, p50, p75, p95, p99, max, zero_rate` cho toàn bộ 18 features ở trạng thái overall, benign-only và attack-only được lưu đầy đủ trong [`ait_vs_ctu_statistics.json`](../experiments/ml/domain_analysis/ait_vs_ctu_statistics.json). Tóm tắt 6 đại lượng đặc trưng chính (overall median `[p25, p75]`, zero rate):

| Tập dữ liệu | `duration_ms` med `[p25, p75]` (`zero%`) | `bytes_in` med `[p25, p75]` (`zero%`) | `bytes_out` med `[p25, p75]` (`zero%`) | `pkts_in` med `[p25, p75]` | `bytes_in_ratio` med (`zero%`) | `pkts_per_sec` med `[p25, p75]` (`max`) |
|---|---|---|---|---|---|---|
| **`ait_train`** | `260.1` `[0.0, 31478.8]` (`39.86%`) | `841` `[49, 1697]` (`8.41%`) | `1,199` `[113, 4886]` (`11.89%`) | `10` `[1, 13]` | `0.3217` (`8.41%`) | `195.2` `[0.80, 2000.0]` (`49,287,000`) |
| **`ait_val`** | `0.0` `[0.0, 6024.6]` (`59.09%`) | `52` `[0, 1403]` (`41.20%`) | `116` `[0, 2504]` (`43.05%`) | `1` `[1, 11]` | `0.2020` (`41.20%`) | `1000.0` `[3.92, 2000.0]` (`197,381,000`) |
| **`ait_test`** | `24.9` `[0.0, 29118.1]` (`42.65%`) | `250` `[48, 1606]` (`9.35%`) | `265` `[105, 4784]` (`12.54%`) | `6` `[1, 12]` | `0.3217` (`9.35%`) | `549.3` `[1.11, 2000.0]` (`3,464,262`) |
| **`ctu_echo`** | `1.72` `[0.0, 188.6]` (`29.58%`) | `136` `[88, 840]` (`0.04%`) | `0` `[0, 396]` (`54.17%`) | `2` `[2, 10]` | `1.0000` (`0.04%`) | `2000.0` `[139.2, 2000.0]` (`33,000`) |
| **`ctu_windows7ad`** | `2.42` `[0.22, 421.4]` (`20.60%`) | `164` `[130, 384]` (`1.02%`) | `93` `[0, 254]` (`45.02%`) | `2` `[1, 4]` | `0.5214` (`1.02%`) | `1000.0` `[19.06, 2000.0]` (`16,000`) |

### 4.2. Kiểm toán Leakage 5-Tuple & Cross-Partition

1. **Trong AIT-NDS-v2 (`ait_train`, `ait_val`, `ait_test`):**
   - Overlap scenario = `0`, overlap `(scenario, 5-tuple, timestamp_ms)` = `0`, overlap `canonical_flow_group` có kèm scenario = `0` (`PASS` theo `v2_split_manifest.json`).
   - Khi bỏ `scenario_or_device`: `ait_train` vs `ait_val` chia sẻ `11` nhóm `canonical_flow_group` (`90` dòng toàn bộ là `bootp` Benign từ `0.0.0.0:68 -> 255.255.255.255:67` ở `wardbeck` & `russellmitchell` trùng thời điểm đồng hồ UTC `2022-01-21..23`); `timeless_5tuple_overlap` ở mức vài chục cặp địa chỉ tĩnh (`17` Train-Val, `43` Train-Test, `15` Val-Test) cùng `1,508–4,458` IP trùng (chủ yếu CDN/DNS công cộng và giải IP ảo `10.*/192.168.*` tái dùng giữa các kịch bản).
   - Trùng lặp vector ML 18-chiều xuyên phân hoạch rất cao do các flow rỗng/DNS ngắn lặp lại giống hệt nhau: `10,048` vector chung Train–Val (`27.47%` dòng Train, `59.80%` dòng Val) và `21,560` vector chung Train–Test (`32.91%` dòng Train, `41.62%` dòng Test).
2. **Trong CTU-SME-11 (`ctu_echo` vs `ctu_windows7ad`):**
   - Cả hai thiết bị được capture đồng thời trong cùng tuần `2023-02-20 .. 2023-02-27` trên cùng mạng LAN (`192.168.1.50` = Amazon Echo, `192.168.1.108` = Windows7AD).
   - Có **`42` giao tiếp trùng khớp chính xác `(5-tuple, timestamp_ms)`**, **`45` nhóm `canonical_flow_group`** (`47` dòng) giữa `ctu_echo` và `ctu_windows7ad`, với **nhãn mâu thuẫn góc nhìn quan sát**: ví dụ UDP `192.168.1.108:56700 -> 192.168.1.50:50025` mang nhãn `Malicious|From_malicious-To_benign-Discovery` trong `ctu_echo` nhưng lại mang nhãn `Benign|From_benign-To_benign` trong `ctu_windows7ad` (còn 3 nhóm bổ sung rơi vào cùng bucket 300s).

### 4.3. Hệ quả Thực nghiệm lên Mô hình (`reports/experiments/ml/ctu_cross_source_eval.json`)

Những bất tương thích trên giải thích chính xác kết quả đánh giá zero-shot và device-disjoint hiện tại:

| Mô hình (Train chỉ trên AIT) | `ait_test` Recall / F1 / ROC-AUC | `ctu_echo` Recall / F1 / FPR / ROC-AUC | `ctu_windows7ad` Recall / F1 / FPR / ROC-AUC |
|---|---|---|---|
| **Random Forest** | `0.8185` / `0.8997` / `0.9996` (`FPR 0.02%`) | **`0.0000` (`0/36,576`)** / `0.0000` / `0.08%` / `0.7996` | **`0.0000` (`0/2,038`)** / `0.0000` / `1.31%` / `0.6888` |
| **XGBoost** | `0.8042` / `0.8910` / `0.9786` (`FPR 0.02%`) | **`0.0000` (`0/36,576`)** / `0.0000` / `4.68%` / **`0.0373`** | **`0.0005` (`1/2,038`)** / `0.0007` / `0.39%` / **`0.1599`** |
| **Isolation Forest** | `0.4698` / `0.5766` / `0.7753` (`FPR 3.76%`) | `0.9108` / `0.8527` / **`20.86%`** / `0.7845` | `0.0034` / `0.0002` / **`43.34%`** / `0.3067` |
| **Autoencoder** | `0.4681` / `0.5788` / `0.7886` (`FPR 3.51%`) | `0.9176` / `0.7000` / **`65.20%`** / `0.7588` | `0.9146` / `0.0246` / **`85.45%`** / `0.7813` |

*(Ghi chú: Khi ghép thêm `ctu_echo` vào tập huấn luyện theo cấu hình `device_disjoint_ait_plus_echo_to_unseen_win7ad`, Recall trên `ctu_windows7ad` tăng từ `0.00%` lên `50.74%` ở RF và `50.39%` ở XGBoost nhưng FPR tăng lên `17.00%` và `19.38%`, khẳng định lỗi hợp đồng AIT-vs-Zeek là nút thắt cản trở tổng quát hóa đa nguồn.)*

---

## 5. Đề xuất Sửa đổi Adapter, Builder, Preprocessor & Governance cho Phase 2

*(Các đề xuất dưới đây dùng cho Phase 2 sau khi phê duyệt; Phase 0 chưa sửa mã nguồn, manifest hay dataset.)*

### 5.1. Nhóm `P0` — Sửa Lỗi Hợp đồng Dữ liệu & Mất Dữ liệu (Bắt buộc trước mọi lần retrain v2.1)
1. **Sửa lỗi rơi chunk ở `scripts/build_v2_dataset_and_split.py`:**
   - Reset index cho mỗi chunk (`chunk = chunk.reset_index(drop=True)` sau dòng 193) hoặc gán `bins, cats, stats` trực tiếp bằng mảng NumPy / `pd.Series(..., index=feat_df.index)` trong `_classify_series()`.
   - Thêm assertion bắt buộc tại bước `[1/5]` đối chiếu tổng số dòng `len(df_labeled) + len(df_unmapped)` của mỗi scenario khớp 100% với tổng dòng raw (`3,465,342` dòng tổng cộng).
2. **Sửa đơn vị `udp_complete` trong `v2_schema.py:281` và `build_v2_dataset_and_split.py:205-208`:**
   - Nhân hệ số `* 1000.0` cho `max(float(raw["c_durat:4"]), float(raw["s_durat:13"]))` khi `flow_kind == "udp_complete"` để quy chuẩn đồng nhất về **milliseconds** giống `durat:31` (TCP) và Zeek `duration * 1000.0`.
3. **Chuẩn hóa ngữ nghĩa Byte L4 Payload vs IP-Layer (`v2_schema.py`, `build_v2_dataset_and_split.py`, `v2_adapter.py`, `zeek.py`):**
   - Chọn **một** định nghĩa thống nhất trong toàn bộ pipeline (khuyến nghị **L4/transport payload bytes** nếu coi Zeek `orig_bytes == '-'`/`0` là `0`, **hoặc** bổ sung/ước lượng IP+L4 header bytes nhất quán cho AIT ở chế độ `bytes_semantics = "ip_layer"` bằng `c_bytes_all + c_pkts_all * header_est` hoặc đánh dấu tường minh hai contract tách biệt thay vì trộn lẫn ngầm):
     - Cụ thể: trong Zeek `conn.log.labeled`, `orig_bytes`/`resp_bytes` chính là L4 payload tương đương Tstat `c_bytes_all`/`s_bytes_all` (`ctu_echo` NTP `68 B` vs AIT `48 B`, `S0` scan `0 B` khớp `tcp_nocomplete` `0 B`), chỉ bị `'-'` khi Zeek không ghi nhận payload (`duration == '-'` hoặc `0` byte). Nếu quy ước `orig_bytes == '-' -> 0` (hoặc giữ song song cột payload + header/packet-size features không bị lệch layer), `bytes_in_ratio` và `bytes_per_pkt_in` sẽ không bị đảo chiều 180 độ khi scan.
     - Hợp nhất `zeek.py` (`ZeekConnAdapter`), `canonical_v2.py` và `v2_adapter.py` dùng chung một hàm chuẩn hóa byte/duration đã sửa, tránh 2 adapter Zeek xử lý trái ngược nhau (`orig_bytes` vs `orig_ip_bytes`).

### 5.2. Nhóm `P1` — Preprocessor, Chuẩn hóa Feature Chống Domain Shift & Line-Ending Determinism
4. **Cải thiện `TrainOnlyPreprocessor` (`src/network_anomaly/preprocessing/pipeline.py`):**
   - Cho phép truyền `floor_scale` tối thiểu (vd `max(iqr, 0.25)`) cho `asinh_robust` hoặc không dùng `asinh_robust` cho các feature bounded trong `[0, 1]` như `bytes_in_ratio`, `pkts_in_ratio`, `has_response`, `is_tcp`, `is_udp` (giữ nguyên `[0, 1]` tránh bùng nổ `IQR = 0.044269` -> `+9.04`).
   - Mã hóa an toàn `protocol_num` (vd nhóm `protocol_bucket` `TCP=6 / UDP=17 / ICMP=1 / OTHER` bằng one-hot/ordinal ổn định thay vì để `1` passthrough không scale bên cạnh các cột chuẩn hóa).
   - Bổ sung indicator/cờ phân biệt `is_zero_duration_or_unmeasured` và giữ lại phân biệt ngưỡng cho tỷ lệ tốc độ (`bytes_per_sec_*`, `pkts_per_sec`) sau khi sửa UDP ms.
5. **Đảm bảo tính xác định byte LF đa nền tảng (Windows vs Linux CI):**
   - Sửa `build_v2_dataset_and_split.py:485-486` và `pipeline.py:468` dùng `.open("w", encoding="utf-8", newline="\n")` khi ghi tất cả tệp JSON/Markdown, và truyền `lineterminator="\n"` vào `df.to_csv()` ở dòng 385-401.
   - Khi tái tạo artifact ở Phase 2, kiểm tra `verify_preprocessing_artifact` chạy `PASS` với đúng bản LF khớp Git index (`i/lf w/lf`).

### 5.3. Nhóm `P2` — Cân chỉnh Tài liệu, Deduplication Guard & Governance
6. **Sửa sai lệch tài liệu & docstring:**
   - Cập nhật `docs/DATASET.md:10` sửa license của `ait_lds_v2_1` từ `CC BY 4.0` thành **`CC BY-NC-SA 4.0`**.
   - Cập nhật docstring `scripts/build_v2_dataset_and_split.py:15,521` từ `"robust"`/`RobustScaler` sang `"asinh_robust"` (hoặc cấu hình mới sau Phase 2).
7. **Ngăn rò rỉ CTU khi đánh giá & kiểm tra trọng số/mất cân bằng:**
   - Nếu có thử nghiệm cross-source hoặc fine-tune trên một phần CTU ở Phase 2, bắt buộc dedup/group theo `(5-tuple, time_bucket)` giữa `ctu_echo` và `ctu_windows7ad` để loại trừ `42–47` luồng LAN chung có nhãn đối nghịch.
   - Khai báo rõ giới hạn không gian feature (48 vector AIT-Train & 75 vector Echo xung đột nhãn trực tiếp) và không suy diễn độ tổng quát ngoài miền khi thiếu ISP traffic (`UGR'16` vẫn `BLOCKED`).

---

## 6. Kiểm chứng Sau Khắc phục Phase 2 (`FIXED_AND_VERIFIED`)

Toàn bộ các sửa lỗi dữ liệu Phase 2 đã được triển khai và xác minh trực tiếp trên bộ dữ liệu chuẩn hóa mới:

| Finding | Trạng thái | Bằng chứng thay đổi & kiểm chứng |
|---|---|---|
| **`DATA-A01`** | **`FIXED_AND_VERIFIED`** | Sửa `chunk.reset_index(drop=True)` + `.to_numpy()` + kiểm tra khớp tổng số dòng raw trong `scripts/build_v2_dataset_and_split.py`. Khôi phục đủ `233,185` dòng (`wilson=629,553`, `shaw=452,599 + 942 unm`, `wheeler=536,206`), tổng hợp lệ AIT = **`3,464,400`** (`ait_train=2,097,891`, `ait_val=377,704`, `ait_test=988,805`). |
| **`DATA-A02`** | **`FIXED_AND_VERIFIED`** | Nhân `* 1000.0` cho `c_durat:4`/`s_durat:13` khi `udp_complete` trong `src/network_anomaly/data/v2_schema.py` và `scripts/build_v2_dataset_and_split.py`; `ait_test` max `bytes_per_sec_in` giảm về `2,772,677.01 B/s` (`pkts_per_sec` max `8,642.84`). |
| **`DATA-A03`** | **`FIXED_AND_VERIFIED`** | Đồng bộ hóa CTU Zeek sang L4 payload `orig_bytes`/`resp_bytes` (`-`/`(empty)` -> `0.0`) tại `v2_schema.py` và `build_v2_dataset_and_split.py`. `ctu_echo` `Attack KS` của `bytes_in_ratio` giảm từ `0.9905` xuống `0.3540`, cùng chiều AUC (`0.1120` vs `0.2800` của AIT). |
| **`DATA-A04`** | **`FIXED_AND_VERIFIED`** | Áp dụng `MIN_BOUNDED_SCALE_FLOOR = 0.25` cho `BOUNDED_UNIT_COLUMNS` (`bytes_in_ratio`, `pkts_in_ratio`, `has_response`, `is_tcp`, `is_udp`) trong `src/network_anomaly/preprocessing/pipeline.py` (`test_preprocessing_pipeline.py`: `23 passed`). `pkts_in_ratio` `scaled_W1` giảm từ `4.0480` xuống `0.7272`. |
| **`DATA-A08` & LF** | **`FIXED_AND_VERIFIED`** | Sửa docstring/báo cáo sang `asinh_robust`; ghi toàn bộ `.csv.gz`, JSON, MD theo LF (`\n`); `verify_preprocessing_artifact` trả **`PASS`**. |
| **`DATA-A06` / `A07`** | `MITIGATED` / `BLOCKED` | Tách biệt `ctu_echo` ↔ `ctu_windows7ad` và khử trùng lặp `(5-tuple, time_bucket)` trong đánh giá cross-source Phase 6 (`DATA-A06`); `UGR'16` HTTP `403` và `AIT-NDS-v2 ↔ AIT-LDS-v2.1` `direct_uid_join_possible=false` giữ nguyên trạng thái `BLOCKED` / `NOT VERIFIED`. |
