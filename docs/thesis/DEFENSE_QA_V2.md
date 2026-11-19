# Bộ 25 Câu hỏi & Trả lời Phản biện Hội đồng Bảo vệ Đồ án — NetFlow Sentinel v2.0

> **Phạm vi:** 25 câu hỏi chuyên sâu theo 6 nhóm chủ đề phục vụ phiên Hỏi đáp (10 phút) bảo vệ Đề tài 22 (Issue `#153`). Mọi câu trả lời đều viện dẫn trực tiếp tệp mã nguồn, báo cáo thực nghiệm và số liệu đã kiểm chứng trong repository.

---

## Nhóm I — Dữ liệu, Chống Rò rỉ (Leakage) & Bản quyền (`Q1–Q5`)

### Q1. Tại sao nhóm bỏ `UNSW-NB15` (`NF-UNSW-NB15-v3`) trong đề cương để chuyển sang `AIT-NDS-v2`? Làm thế nào chứng minh không mất tính kế thừa?
- **Trả lời:** Qua kiểm toán tại [`docs/historical/nf_unsw_nb15_v3/MODEL_AUDIT_TTL_ABLATION.md`](../historical/nf_unsw_nb15_v3/MODEL_AUDIT_TTL_ABLATION.md), `NF-UNSW-NB15-v3` mắc 3 khuyết tật không thể khắc phục bằng tinh chỉnh siêu tham số:
  1. **Shortcut Learning:** `Random Forest` đạt `F1 = 0.999886` (`MIN_TTL importance = 0.240573`) và `XGBoost` đạt `F1 = 0.999984` (`MIN_TTL importance = 0.829272`) nhờ đặc trưng `TTL` giả lập của máy phát IXIA; bỏ `MIN_TTL` còn 46 cột vẫn giữ `0.999804 / 0.999984` do `MAX_TTL` rò rỉ.
  2. **Sụp đổ OOD:** Đánh giá `RF` v1 *zero-shot* trên `NF-CSE-CIC-IDS2018-v3` (`100,000` mẫu) rơi xuống `Recall = 0.0`, `F1 = 0.0`, `FPR = 0.3802`.
  3. **Bản quyền & Schema:** Vướng **UQ License ID `454104`** (cấm thương mại, hạn chế tái phân phối) và 47 trường `nProbe v3` không tương thích `Tstat`/`Zeek`.
- **Quyết định:** Theo [`docs/adr/ADR-dataset-hard-cutover-v2.md`](../adr/ADR-dataset-hard-cutover-v2.md), nhóm thực hiện *hard cutover* sang `AIT-NDS-v2` (`CC BY 4.0`) dưới hợp đồng `canonical-flow-v2-18`, lưu trữ toàn bộ 160 tệp v1 chỉ đọc trong `*/historical/nf_unsw_nb15_v3/` và bảo toàn toàn bộ lõi sản phẩm (Tauri 2, FastAPI, Behavioral, Crypto, Trace, Risk).

### Q2. Làm thế nào đảm bảo 100% không có Data Leakage giữa Train, Validation và Test trên `AIT-NDS-v2`?
- **Trả lời:** Thay vì chia ngẫu nhiên theo dòng (dễ làm cùng một phiên tấn công xuất hiện ở cả Train và Test), nhóm áp dụng chiến lược **`v2-scenario-group-purged-v1`** tại [`data/V2_SPLIT_MANIFEST.json`](../../data/V2_SPLIT_MANIFEST.json) (SHA-256 `ed542ee8...`):
  - `ait_train`: `2,097,891` flows (`fox, harrison, santos, wardbeck, wilson`).
  - `ait_val`: `377,704` flows (`russellmitchell`) — dùng duy nhất để hiệu chuẩn ngưỡng (`threshold_provenance.test_touched = false`).
  - `ait_test`: `988,805` flows (`shaw, wheeler`).
- Kiểm toán tại [`docs/dataset/V2_LEAKAGE_AUDIT.md`](../dataset/V2_LEAKAGE_AUDIT.md) xác nhận **0** giao thoa kịch bản và **0** giao thoa bộ `(scenario, 5-tuple, timestamp)`. Ngoài ra, `TrainOnlyPreprocessor` (`0866dec7...`) chỉ được `fit()` trên `ait_train`.

### Q3. Nhóm đã phát hiện và xử lý những lỗi dữ liệu gốc nào trước khi huấn luyện mô hình?
- **Trả lời:** Ở Phase 0, nhóm phát hiện và sửa 3 lỗi nghiêm trọng:
  1. **`DATA-A01`:** Khôi phục `233,185` dòng bị rơi âm thầm khi đọc theo *chunk* từ CSV `AIT-NDS-v2`, bảo toàn đủ `3,464,400` flows có nhãn + `942` dòng `Unmapped`.
  2. **`DATA-A02`:** Bảng `udp_complete` của Tstat lưu `duration` theo đơn vị giây, khác với mili-giây của `tcp_complete` → nhân `1000.0` để đồng nhất đơn vị `duration_ms`.
  3. **`DATA-A03`:** Căn chỉnh L4 payload `orig_bytes`/`resp_bytes` của Zeek (`CTU-SME-11`) tương ứng `c_bytes_all`/`s_bytes_all` của Tstat, tránh lệch kích thước header L3.

### Q4. Tại sao `UGR'16` bị `BLOCKED` và nhóm xử lý thế nào? Các tập thay thế có dùng được ngay không?
- **Trả lời:** Cổng phân phối chính thức `https://nesg.ugr.es/nesg-ugr16/` trả lỗi `HTTP 403` (*Portal en Mantenimiento*). Nhóm tuyệt đối không tự sinh dữ liệu giả lập để thay thế cho lưu lượng ISP thật.
- Tại [`reports/audits/V2_UGR16_ALTERNATIVES_REVIEW.md`](../../reports/audits/V2_UGR16_ALTERNATIVES_REVIEW.md), nhóm đã đánh giá 9 ứng viên theo 12 tiêu chí và kết luận không có tập nào thay thế trực tiếp (*drop-in*) cho `UGR'16`. Ba ứng viên khả dĩ cho giai đoạn tiếp theo là **`LITNET-2020`** (`ISP_COMPARABLE`, cần kiểm định ghép 2 chiều vì `opkt=0/obyt=0`), **`LUFlow`** và **`CTU-13`** (bắt buộc tái parse `*.truncated.pcap.bz2`, cấm `.binetflow` vì thiếu `pkts_in/out`). Hiện tại, `UWF-ZeekData24` (`95,871` flows, `evaluation_only = true`) chỉ đóng vai trò kiểm định bổ sung *cross-source*, không thay thế `UGR'16`.

### Q5. Dữ liệu `AIT-LDS-v2.1` mang giấy phép `CC BY-NC-SA 4.0` có làm lây nhiễm ShareAlike sang mô hình và mã nguồn Apache-2.0 không? Và vì sao Issue `#85` vẫn `BLOCKED`?
- **Trả lời:** **Không lây nhiễm.** Toàn bộ 4 mô hình `E0` `.joblib`, `v2_flow_preprocessor.joblib` và `data/demo/demo_*.csv` được huấn luyện/trích xuất **100% từ `AIT-NDS-v2` (`CC BY 4.0`)**. Dữ liệu `AIT-LDS-v2.1` (`CC BY-NC-SA 4.0`) chỉ được lưu cục bộ trong thư mục `.gitignored` (`data/raw/ait_lds_v2_1/`) để kiểm toán liên kết log (`0%` trong trọng số và demo CSV), được xác nhận trong [`reports/governance/DISTRIBUTION_AUTHORIZATION.json`](../../reports/governance/DISTRIBUTION_AUTHORIZATION.json).
- Issue `#85` giữ **`BLOCKED`** vì kiểm toán tại [`docs/dataset/AIT_LINKAGE_FEASIBILITY.md`](../dataset/AIT_LINKAGE_FEASIBILITY.md) xác nhận `DIRECT_UID_LINK = False`: Tstat CSV (`AIT-NDS-v2`) và log Suricata/host (`AIT-LDS-v2.1`) không có khóa ngoại chung (`uid`/`flow_id`/`community_id`), chỉ có thể tương quan heuristic theo thực thể và cửa sổ thời gian.

---

## Nhóm II — Mô hình AI, `E0` vs `E1`, Autoencoder & `Credential_Attack` (`Q6–Q11`)

### Q6. Tại sao `Random Forest` đạt `F1 = 0.9950` trên `AIT-Test` nhưng cả 4 mô hình `E0` đều bị gán `RESEARCH_ONLY`?
- **Trả lời:** Vì `ModelRegistry` (`src/network_anomaly/models/registry.py`) áp dụng cơ chế **4 cổng độc lập**: `artifact_verified` (`4/4 True`), `in_domain_evaluated` (`4/4 True`), **`cross_source_validated`** (`0/4 False`) và `deployment_tier`.
- Cổng `cross_source_validated` yêu cầu mô hình đạt đồng thời `Recall >= 0.70` và `FPR <= 0.10` trên **cả** `CTU-Echo` (`N=76,073`) và `CTU-Win7AD` (`N=175,146`). Khi chạy *zero-shot* từ `AIT-Train`, `RF` tụt xuống `F1 = 0.0474` trên `CTU-Echo` và `F1 = 0.0712` (`FPR = 0.1608`) trên `CTU-Win7AD` do lệch phân phối thời lượng giữa Tstat (`5.1s` Benign) và Zeek (`2.4ms` DNS). Do đó, hệ thống tự động khóa **`4/4 RESEARCH_ONLY`** và `production_ready = False`, không cho phép tự động cô lập ngoài dry-run.

### Q7. Cơ chế `OODRejectionGate` và `MIN_BOUNDED_SCALE_FLOOR = 0.25` hoạt động như thế nào để bảo vệ suy luận?
- **Trả lời:** Hệ thống có 2 lớp bảo vệ trong [`src/network_anomaly/ingestion/ood.py`](../../src/network_anomaly/ingestion/ood.py) và [`src/network_anomaly/ml/ood_gate.py`](../../src/network_anomaly/ml/ood_gate.py):
  1. `OODValidator`: Kiểm tra các bất biến vật lý tuyệt đối (`duration_ms >= 0`, counters `>= 0`, ports `[0, 65535]`, `protocol_num [0, 255]`, ratios `[0, 1]`, giá trị hữu hạn).
  2. `OODRejectionGate` (`artifacts/ml/ood_reference_gate.json`, `SHA-256: 8a52bfe5...`, `std_margin = 4.0`, `statistical_threshold = 5.0`): Phát hiện `MISSING_MANDATORY_FEATURES`, `FEATURE_BOUNDS_EXTREME_BREACH` và `STATISTICAL_OUTLIER_DISTANCE` → trả về `ABSTAINED_OOD` (`predicted_label = None`, `risk_score = None`).
- Hằng số `MIN_BOUNDED_SCALE_FLOOR = 0.25` trong `TrainOnlyPreprocessor` ngăn IQR của biến tỷ lệ như `pkts_in_ratio` (`0.044269`) bị co quá nhỏ dẫn tới phóng đại sai lệch luồng một chiều trên CTU lên `+9.04 sigma` (kéo `scaled_W1` xuống `0.7272`).

### Q8. Tại sao trong `RQ2`, cả Cost-Sensitive và Train-Only Oversampling (`Exp 3`) chỉ phát hiện được `14.10%` (`11/78`) `Credential_Attack`?
- **Trả lời:** Theo [`reports/experiments/imbalance/rq2_imbalance_report.md`](../../reports/experiments/imbalance/rq2_imbalance_report.md), trong không gian đặc trưng đơn-flow 18-D (`canonical-flow-v2-18`), `67/78` luồng tấn công dò mật khẩu (`online_cracking` trên HTTP/SSH) có thời lượng, số gói và số byte L4 trùng lắp hoàn toàn với các phiên HTTP/SSH hợp lệ (`Bayes error` giao thoa). Vì vậy, dù tăng trọng số lớp (`RF_CostSensitive`) hay sinh thêm mẫu trên tập Train (`target = 15,000`, `0.015*std` Gaussian jitter chỉ trên `ait_train`), mô hình đơn-flow vẫn dừng ở `11/78` (`0.1410`), dẫn tới phán quyết trung thực **`h2_full_confirmed = false`**. Đây là lý do trực tiếp chứng minh sự cần thiết của tầng `BehavioralVector` (thống kê tần suất/thất bại xác thực theo cửa sổ phiên).

### Q9. Kết quả `RQ4` (`44` mẫu holdout) có chứng minh được khả năng phát hiện tấn công *zero-day* thực tế không?
- **Trả lời:** **Không.** Nhóm công bố rõ trong [`docs/experiments/EXP4_UNKNOWN_ATTACK.md`](../experiments/EXP4_UNKNOWN_ATTACK.md) và [`docs/RESEARCH_QUESTIONS.md`](../RESEARCH_QUESTIONS.md) rằng `RQ4` loại bỏ hoàn toàn `Exploitation_And_C2` và `Post_Exploitation_Discovery` khỏi Train (`216` dòng) và Val (`58` dòng, `zero_leakage_verified = true`), nhưng tập Test holdout chỉ có `44` flows trong cùng *testbed* AIT. Kết quả: `Isolation Forest = 0.9091` (`40/44`), `Random Forest = 0.9091`, `XGBoost = 0.7500`, còn **`Autoencoder = 0.2045` (`9/44`)**, nên giả thuyết `H4` (`unsupervised_ge_0_75_both`) là **`False`**. Thí nghiệm này chỉ đánh giá khả năng tổng quát hóa nội bộ *testbed* ở quy mô mẫu nhỏ, không tuyên bố phát hiện *zero-day* ngoài thực tế.

### Q10. Nhóm đã làm gì để khắc phục sự sụp đổ *cross-source* của `E0` mà không vi phạm quy tắc đóng băng `E0`?
- **Trả lời:** Nhóm thực hiện 3 hướng tối ưu hóa tách biệt hoàn toàn khỏi 4 artifact `E0` (`e0_artifacts_untouched = true`):
  1. **Thực nghiệm Đa miền `E1` ([`docs/experiments/E1_MULTIDOMAIN_EXPERIMENT.md`](../experiments/E1_MULTIDOMAIN_EXPERIMENT.md)):** Huấn luyện trên `442,961` dòng kết hợp (`AIT=200,001 + CTU=175,853 + UWF=67,107`). `E1_RandomForest_Binary` nâng `CTU_Test F1` từ `0.0501` lên **`0.9703`** (`FPR = 0.004650`), `UWF_Test F1` lên **`0.9992`** (`ROC-AUC = 1.0000`), và giảm `CTU_Win7AD FPR` xuống `0.472%`.
  2. **`Autoencoder_E3b_VarianceNormalized`:** Chuẩn hóa phương sai trên không gian đặc trưng giúp giảm `CTU-Win7AD FPR` từ **`72.09%`** (`0.720930`) xuống **`4.42%`** (`0.044190`) và nâng `CTU_Test ROC-AUC` từ `0.6302` lên `0.8156`.
  3. **`LocalBenignCalibrator` & `OOD_AWARE_ENSEMBLE`:** Cho phép hiệu chuẩn ngưỡng trên phân vị dữ liệu sạch của mạng đích (`src/network_anomaly/ml/local_calibration.py`) và chuyển dịch trọng số ensemble sang `XGB + IF` khi có dịch chuyển OOD vừa phải (`src/network_anomaly/models/aggregation.py`).

### Q11. Vì sao `Stage2MulticlassClassifier` chạy tách riêng, và vì sao dùng `sklearn MLPRegressor` thay cho PyTorch, dùng Feature/Permutation Importance thay cho SHAP?
- **Trả lời:**
  - `Stage2MulticlassClassifier` (`src/network_anomaly/models/stage2_multiclass.py`, `Test Macro-F1 = 0.7347` với `RF_multiclass`, `0.6378` với `XGB_multiclass`) được tách riêng vì dữ liệu đơn-flow 18-D có độ phân tách thấp ở lớp hiếm (`Credential_Attack F1 = 0.0455`), nên giữ ensemble binary `E0` cho đường chạy chính để tránh nhiễu phân loại lớp.
  - Dùng `sklearn.neural_network.MLPRegressor` `(16, 8, 16)` thay cho PyTorch để giữ gói phụ thuộc thuần `scikit-learn`/`joblib`, giúp đóng gói PyInstaller sidecar gọn nhẹ trên Windows không cần runtime PyTorch/CUDA và tái lập tất định.
  - Dùng `tree_feature_importances` (RF/XGB) và `validation_permutation_importance` (IF/AE) để xuất giải thích tất định không phụ thuộc `shap`, và hiển thị đúng tên phương pháp trên `ModelComparisonPanel.svelte`.

---

## Nhóm III — Động cơ Hành vi, Đánh giá Rủi ro & Truy vết (`Q12–Q15`)

### Q12. Nếu hệ thống chỉ nhận dữ liệu NetFlow/IPFIX (không có log DNS/HTTP/Auth), 3 chiều ứng dụng trong `BehavioralVector` 16-D có bị suy diễn giá trị giả không?
- **Trả lời:** **Không suy diễn âm thầm.** Theo [`docs/architecture/BEHAVIORAL_ENGINE.md`](../architecture/BEHAVIORAL_ENGINE.md) và [`src/network_anomaly/behavioral/vector.py`](../../src/network_anomaly/behavioral/vector.py), khi thiếu sự kiện DNS/HTTP/Auth, 3 chiều `dns_intensity`, `http_intensity`, `auth_failure_ratio` mang giá trị `0.0`, đồng thời `BehavioralVector` ghi tường minh danh sách `missing_feature_names` và gắn cờ **`completeness_status = "partial_flow_only"`** thay vì `"complete"`.

### Q13. Tại sao thực nghiệm `RQ3` ban đầu thất bại (`F1 = 0.5556 < 0.85`), và bản nâng cấp đã cải thiện gì?
- **Trả lời:** Trong [`docs/experiments/EXP5_SESSION_CORRELATION.md`](../experiments/EXP5_SESSION_CORRELATION.md), `BehavioralVector` ban đầu dùng chuẩn hóa L2 toàn vector, làm triệt tiêu thông tin quy mô tuyệt đối nên các chiến dịch khác nhau nhưng có tỷ lệ phân bố giống nhau bị va chạm cosine (`FalseLink = 0.80` ở `cos >= 0.85`, `0.30` ở `cos >= 0.95`, `F1 = 0.5556 < 0.85`). Khi nâng cấp `IPSpoofingSessionCorrelator` sang **Feature-Standardized 16-D Cosine**, mô phỏng đạt `F1 = 1.0000` và kiểm chứng trên `56` phiên / `8` tactic của `UWF-ZeekData24` đạt **`F1 = 0.7192`** (`Precision = 0.8022`, `FalseLink = 0.0449`), vượt mốc khớp IP truyền thống (`F1 = 0.6919`, `FalseLink = 0.1653`).

### Q14. Làm thế nào `RiskScorer` ngăn chặn một mẫu OOD kích hoạt cảnh báo giả mức `CRITICAL` và xoay khóa khẩn cấp?
- **Trả lời:** Trong [`src/network_anomaly/risk/scoring.py`](../../src/network_anomaly/risk/scoring.py), `RiskScorer` tổng hợp 4 thành phần `[0..100]` (`AI 0–50`, `Behavioral 0–25`, `Sensitive Port 0–15`, `Auth 0–10`). Tuy nhiên, nếu `is_ood = True` hoặc đầu vào chứa `NaN`/`Inf`, hệ thống kích hoạt **OOD Guard**: ép điểm rủi ro tối đa **`<= 65.0`** (dưới ngưỡng `HIGH >= 70.0` và `CRITICAL >= 85.0`) và khóa cứng **`trigger_adaptive_rotation = False`**.

### Q15. Độ chính xác `1.0 / 1.0` của Trace Engine được đo trong điều kiện nào?
- **Trả lời:** Con số `Precision = 1.0 / Recall = 1.0` (so với `0.375 / 0.50` của phương pháp tìm kiếm log động) được đo tại [`reports/experiments/trace/traceability_evaluation.json`](../../reports/experiments/trace/traceability_evaluation.json) trên **kịch bản tổng hợp (`SYNTHETIC`) gồm `8` sự kiện**. Vì liên kết đa nguồn thực nghiệm trên AIT (`#85`) đang `BLOCKED`, đây chưa phải là đánh giá trên chiến dịch tấn công thực tế quy mô lớn.

---

## Nhóm IV — Mật mã At-Rest, DPAPI & Xoay khóa Thích ứng (`Q16–Q19`)

### Q16. Dữ liệu hành vi trong SQLite được bảo vệ như thế nào? Có nguy cơ lộ plaintext hoặc tái sử dụng nonce không?
- **Trả lời:** Trong [`src/network_anomaly/crypto/encrypted_storage.py`](../../src/network_anomaly/crypto/encrypted_storage.py) và `aead.py`, cột `vector_json` trong SQLite luôn lưu **`NULL`**; chỉ ciphertext `AES-256-GCM` kèm tag xác thực `128-bit` được ghi xuống đĩa. Mỗi phép mã hóa dùng nonce `96-bit` (`12 bytes`) cấp phát qua `NonceRegistry` chống trùng lặp và gắn *Additional Authenticated Data* (AAD) theo ngữ cảnh (`domain:behavioral|entity:<id>|win:<ts>`) để chống tráo đổi bản ghi giữa các thực thể/cửa sổ thời gian.

### Q17. Cơ chế bảo vệ khóa gốc `master.key` và DEK hoạt động ra sao trên Windows và Linux?
- **Trả lời:** Trên Windows, `KeyManager` (`src/network_anomaly/crypto/key_manager.py`) bắt buộc bảo vệ `master.key` thông qua **Windows DPAPI** (`CryptProtectData` / `CryptUnprotectData`) theo chế độ **fail-closed** (tuyệt đối không fallback lưu plaintext nếu DPAPI lỗi). DEK được bọc bằng `NETFLOW_WRAPPED_DEK_V2` (`AAD = key_id|domain|version`), kiểm tra `_validate_safe_identifier()` chống *path traversal* và ghi tệp nguyên tử qua `os.replace`. Giới hạn trung thực: trên POSIX/Linux (không có DPAPI), khóa dựa vào quyền tệp `0600` của hệ điều hành, và hệ thống không chống lại kẻ tấn công đã chiếm quyền Administrator/Kernel đọc trực tiếp RAM tiến trình.

### Q18. Cơ chế xoay khóa thích ứng (`RQ5`) có thể bị lợi dụng để tấn công từ chối dịch vụ (Rotation DoS) không?
- **Trả lời:** Không, nhờ `KeyRotationPolicy` (`src/network_anomaly/crypto/rotation.py`) áp dụng đồng thời hai lớp chống DoS: `cooldown >= 60s` giữa hai lần xoay khẩn cấp (`risk_score >= 85.0`) và `rate_limit <= 10 rotations/hour`, trạng thái bộ đếm được lưu bền vững qua khởi động lại trong bảng SQLite `rotation_audit`. Trong mô phỏng 60 phút (`RQ5`), cơ chế này giảm **`87.5%`** thời gian phơi nhiễm (`1,200.0s -> 150.01s`) và **`85.0%`** *blast radius* (`40 -> 6` bản ghi tấn công/khóa).

### Q19. Tại sao `RQ6` microbenchmark ghi nhận `13.3 us` P95 cho `AES-256-GCM`, nhưng thực nghiệm A/B `Exp 7` lại giảm `32.85%` thông lượng?
- **Trả lời:** Microbenchmark `RQ6` (`reports/benchmarks/crypto_benchmark_report.json`) đo thuần túy hàm mã hóa `AES-256-GCM` trên bộ nhớ (`256 B`: P95 `13.3 us`, `75,851.2 ops/s`). Trong khi đó, thực nghiệm A/B `Exp 7` (`N=500 × 3`) đo toàn bộ chu trình ghi/đọc SQLite vault và quản lý khóa đi kèm (`Encryption OFF: 181.2 flow/s` → `Encryption ON: 121.7 flow/s`, CPU `+53.56%`). Cả hai con số đều nhất quán và bổ trợ cho nhau ở hai cấp độ đo khác nhau.

---

## Nhóm V — Kiến trúc Desktop, Hiệu năng & Bảo mật Giao tiếp (`Q20–Q22`)

### Q20. Vì sao chọn `Tauri 2 + Svelte 5 + SQLite` thay vì `Web (React/Streamlit) + PostgreSQL + Docker` như đề cương?
- **Trả lời:** Để đáp ứng bài toán ứng dụng phân tích an ninh mạng chạy cục bộ (*offline-first*) trên máy trạm Windows của chuyên viên điều tra mà không bắt người dùng cuối cài đặt Docker hay quản trị PostgreSQL server. Tauri 2 tạo vỏ ứng dụng nhẹ, khóa CSP chặt, còn SQLite *single-writer* đủ đáp ứng lưu trữ cục bộ theo phiên. Nhóm ghi nhận trung thực giới hạn: kiến trúc này không dùng cho triển khai *multi-tenant server* phân tán.

### Q21. Tại sao thông lượng Single-Event E2E chỉ đạt `16.75 flow/s`, và làm thế nào đạt `386.37 flow/s`? Tại sao chưa dùng Rust Collector (`#128`)?
- **Trả lời:** Theo [`docs/benchmarks/SYSTEM_PERFORMANCE.md`](../benchmarks/SYSTEM_PERFORMANCE.md), ở chế độ *single-event*, mỗi sự kiện phải trả chi phí gọi tuần tự qua 4 mô hình AI Python (`multi_model_ai_inference` median `62.23 ms`), nên thông lượng dừng ở `16.75 ± 0.11 flow/s`. Khi gom nhóm qua **`process_batch(batch_size=32)`** (vector hóa suy luận `numpy`/`scikit-learn` và giảm chi phí điều phối), thông lượng tăng **`>23x`** lên **`386.37 ± 12.88 flow/s`** (`Replay`: `399.44 ± 15.47 flow/s`, `dropped = 0`).
- Rust Collector (`#128`) chủ động hoãn (`DEFERRED`) ra ngoài phạm vi `v2.0.0` vì `Python UDPFlowCollector` + `StreamingEventPipeline` (`capacity = 10,000`) đã đáp ứng đầy đủ giải mã NetFlow v9/IPFIX trong phòng lab.

### Q22. Nếu một tiến trình độc hại trên cùng máy trạm gửi request vào FastAPI sidecar thì sao?
- **Trả lời:** Sidecar chỉ lắng nghe trên loopback `127.0.0.1` và mọi endpoint nghiệp vụ (ngoại trừ `/health` và `OPTIONS`) đều kiểm tra header **`X-Sentinel-Session-Token`** bằng hàm so sánh hằng thời gian `hmac.compare_digest` (`src/network_anomaly/api/main.py`), trả HTTP `401` nếu thiếu hoặc sai token ngẫu nhiên theo phiên do Tauri cấp phát. Ngoài ra, ở chế độ mặc định `"deployment"`, nếu thiếu neo tin cậy `NETFLOW_OOD_GATE_SHA256`, suy luận AI tự khóa ở trạng thái `UNAVAILABLE`.

---

## Nhóm VI — Quản trị Phát hành & Giới hạn Còn mở (`Q23–Q25`)

### Q23. Vì sao Response Engine vẫn khóa Dry-Run (`executed = false`) dù đề cương có đề cập rate-limit / isolate?
- **Trả lời:** Vì 3 lý do an toàn bắt buộc: (1) Toàn bộ 4 mô hình `E0` đang ở cấp `RESEARCH_ONLY` (`cross_source_validated = false`); (2) Chưa có kiểm định trên thiết bị mạng vật lý (`#137`); (3) Chống nguy cơ *self-DoS* nếu mô hình nhận nhầm lưu lượng quản trị là tấn công. Do đó `src/network_anomaly/api/response_policy.py` áp dụng cổng kép fail-closed (`ABSTAINED_OOD` và `HOLD_RESEARCH_ONLY_MODEL`), chỉ ghi nhận khuyến nghị mô phỏng (`executed = false`).

### Q24. Nghiệm thu Live UDP (`#137`) đã chứng minh được gì và còn thiếu gì?
- **Trả lời:** Kịch bản `scripts/run_live_lab_acceptance.py` đã chứng minh toàn bộ đường ống Live UDP (`127.0.0.1:51817`) chạy thông suốt `13/13` bước: giải mã NetFlow v9/IPFIX, từ chối gói lỗi (`malformed_packet_count = 1`), suy luận `4/4 REAL_MODELS`, mã hóa `AES-256-GCM`, dựng `trace_graph` (`8` nodes / `6` cạnh) và hiển thị cảnh báo `HIGH (84.035)` trên GUI Svelte (`live_gui_alert_synthetic_loopback.png`), cũng như phát lại `65/65` flows `ait_test.csv.gz` ở chế độ `"deployment"`. Tuy nhiên, phần thu thập dùng *synthetic loopback* với quy ước lab `PEN 50000`, `real_device_tested = false` — nghiệm thu với switch/router vật lý (AC #4–#5 của `#137`) vẫn đang `BLOCKED`.

### Q25. Hệ thống hiện tại đã sẵn sàng phát hành công khai (`#154`) chưa? Nếu chưa thì thiếu những điều kiện nào?
- **Trả lời:** **Chưa.** Theo [`docs/audits/V2_RELEASE_READINESS.md`](../audits/V2_RELEASE_READINESS.md), hệ thống đạt **`READY`** cho **Bảo vệ Đồ án & Nghiên cứu Học thuật**, đạt **`READY_WITH_LIMITS`** cho **Thử nghiệm Lab / Offline Cục bộ** (`local_offline APPROVED`), nhưng **`BLOCKED`** cho **Phát hành Công khai (`#154`)** vì 5 rào cản bắt buộc:
  1. `DISTRIBUTION_AUTHORIZATION.json` giữ `approved = false` (`HOLD_FOR_MAINTAINER_SIGNOFF`).
  2. `4/4` mô hình `E0` giữ `deployment_tier = RESEARCH_ONLY` (`cross_source_validated = false`) và `git_dirty = true` tại commit huấn luyện `79ebb678`.
  3. Chưa build và kiểm định bộ cài NSIS trên Clean Windows 10/11 VM (`#148` / `#73`, `0/4 AC`).
  4. Chưa thay thế placeholder ở `LICENSE:1` và `pyproject.toml:12-13`, chưa cấp `NETFLOW_OOD_GATE_SHA256` độc lập cho bản đóng gói.
  5. PR `#156` cần commit sạch đợt remediation cục bộ, chạy CI xanh mới và được reviewer gỡ trạng thái `CHANGES_REQUESTED`.
