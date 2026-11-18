---
name: network-intrusion-detection
description: "Phân tích hoặc triển khai logic phát hiện xâm nhập trên network flow (canonical-flow-v2-18), diễn giải feature L4, nhãn, FP/FN, OOD gate và giới hạn domain shift. Dùng khi task liên quan semantics NIDS, error analysis hoặc security claim; không dùng cho thay đổi repository thuần túy."
---

# Network Intrusion Detection (v2.0)

Áp dụng kiến thức NIDS vào code, test, đánh giá và báo cáo trong phạm vi NetFlow Sentinel v2.0. Đọc [phạm vi dự án](../../rules/project-scope.md) trước khi đề xuất hành vi mới; không tuyên bố hệ thống đạt ngưỡng `production-ready`.

## Xác định bài toán trước khi hành động

- **Binary supervised classification (`Random Forest`, `XGBoost`):** dự đoán `Benign`/`Attack` trên 18 đặc trưng `canonical-flow-v2-18`.
- **Multiclass supervised classification:** dự đoán `Benign` và 5 nhóm `attack_category` (`Reconnaissance`, `Data_Exfiltration`, `Credential_Attack`, `Post_Exploitation_Discovery`, `Exploitation_And_C2`); kiểm tra support lớp hiếm (`N=5` ở `Exploitation_And_C2` không đủ lực thống kê).
- **Unsupervised anomaly detection (`Isolation Forest`, `Autoencoder`):** học trên normal/training population không dùng nhãn; raw anomaly score được map qua empirical percentile (`score_normalization.json`) và threshold chọn thuần trên `ait_val`.

Không gọi supervised classification hay holdout 44 flow (`RQ4`) là bằng chứng phát hiện zero-day tổng quát ngoài thực tế.

## Lập luận trên network flow (`canonical-flow-v2-18`)

Một hàng flow tóm tắt phiên L3/L4, **không** mang payload L7 HTTP/Auth log:

- 6 trường cơ sở: `duration_ms`, `bytes_in`, `bytes_out`, `pkts_in`, `pkts_out`, `protocol_num` (L4 TCP/UDP payload bytes, thống nhất giữa AIT Tstat & Zeek conn.log);
- 12 trường động học dẫn xuất xác định (`total_bytes`, `total_pkts`, `bytes_in_ratio`, `pkts_in_ratio`, `bytes_per_pkt_in/out`, `bytes_per_sec_in/out`, `pkts_per_sec`, `has_response`, `is_tcp`, `is_udp`);
- Cột trace/định danh (`timestamp_ms`, `source_ip`, `dest_ip`, `source_port`, `dest_port`) và TTL shortcuts bị loại nghiêm ngặt khỏi 18 ML features, chỉ dùng cho `BehavioralVector` / `Trace Engine`.

Lưu ý vật lý khi phân tích lỗi:
- Thiếu L7 payload khiến tấn công kiểu credential stuffing hoặc slow DNS tunneling ở mức flow rất dễ lẫn với traffic thường (`Credential_Attack` recall thấp).
- Tách bạch L4 payload bytes vs L3 IP packet length (kiểm tra SYN-only unanswered probes `median(bytes_in) = 0.0`).
- **OOD abstention (`OODValidator` / `OODRejectionGate`):** từ chối/chặn ngưỡng rủi ro với flow vi phạm physical invariant hoặc ngoài phân phối train, không ép dự đoán sai.

## Áp dụng vào thay đổi

- **Code:** giữ đúng thứ tự cột `ML_FEATURE_COLUMNS` và `feature_contract_version == "canonical-flow-v2-18"`; không sửa heuristic im lặng khi thiếu cột.
- **Test:** kiểm tra cả `Benign` và `Attack`, thứ tự nhãn, đường lỗi schema/OOD abstention và `fail-closed` trong `"deployment"`.
- **Evaluation:** báo rõ precision/recall/F1/FPR/ROC-AUC, per-class breakdown và tách rõ **in-domain (`AIT-Test`)** với **zero-shot cross-source (`CTU-SME-11`, `UWF-ZeekData24`)**.
- **Report:** nêu rõ domain shift (`CTU` vs `AIT` vs `UWF`), non-attribution (không quy kết attacker thật từ IP/vector) và `executed=false` containment.

## Điều kiện kết luận

Chỉ gọi kết quả là `EXPERIMENTALLY VALIDATED` khi đã chạy trên dữ liệu benchmark v2 thật (`AIT-NDS-v2`, `CTU-SME-11`, `UWF-ZeekData24`) có provenance và split hợp lệ. Synthetic fixture hay localhost UDP replay tối đa chứng minh `TESTED`. Phối hợp [unsw-nb15-protocol](../unsw-nb15-protocol/SKILL.md) cho protocol dữ liệu và [ml-experiment-audit](../ml-experiment-audit/SKILL.md) cho audit leakage/evaluation.
