# Multi-Source Ingestion Pipeline & Event Alignment Specification (v2)

**Document ID:** `SPEC-PIPELINE-MULTI-001`
**Milestone:** `M6.2 (Multi-source Data Engineering)`
**Issue:** `#93`
**Status:** `VERIFIED & OPERATIONAL (canonical-flow-v2-18)`

---

## 1. Tổng quan Kiến trúc Pipeline Đa nguồn v2

Kiến trúc pipeline đa nguồn của NetFlow Sentinel v2.0 thực hiện chuyển đổi, thẩm định chất lượng và liên kết các luồng dữ liệu phân tán theo hợp đồng `canonical-flow-v2-18`:
1. **Network Flow:** `AIT-NDS-v2` (Tstat), `CTU-SME-11` (Zeek `conn.log.labeled`), NetFlow v9/IPFIX (`18 canonical ML features`).
2. **DNS Logs:** Bản ghi truy vấn tên miền (Zeek DNS / Bind9 / `AIT-LDS-v2.1`).
3. **Web Server Logs:** Nhật ký truy cập HTTP / API (Apache / Nginx).
4. **Authentication & Identity Logs:** Nhật ký đăng nhập SSH, PAM, VPN.
5. **System, Audit & Alert Logs:** Linux auditd / Windows Sysmon / `AIT-ADS`.

*(Nguồn `NF-UNSW-NB15-v3` và hợp đồng 47 đặc trưng cũ đã được chuyển sang lưu trữ lịch sử và không còn chạy qua pipeline hiện hành.)*

---

## 2. Quy trình Xử lý (Pipeline Stages)

```
[Flow Logs]   --> [CanonicalV2FlowAdapter]   --\
[DNS Logs]    --> [ApplicationDNSAdapter]    ---\
[Web Logs]    --> [ApplicationWebAdapter]    ----> [MultiSourceQualityGate] (Fail-Closed)
[Auth Logs]   --> [IdentityAuthAdapter]      ---/          |
[Sys Logs]    --> [SystemAuditAdapter]      --/            v
                                                  [CrossSourceAligner]
                                                  (Sliding Window Δt <= 3s)
                                                           |
                          +--------------------------------+-------------------------------+
                          |                                                                |
                          v                                                                v
                 [ML Feature Pipeline]                                        [Behavioral & Trace Pipeline]
                 - Đủ 18 đặc trưng canonical-flow-v2-18                       - Non-flow logs (DNS, Web, Auth, System)
                 - is_ml_complete = True                                      - Flow thiếu base metrics
                 - Ready for 4 v2 AI Models                                   - KHÔNG TỰ Ý IMPUTE SỐ 0/MEDIAN
                                                                              - Chuyển sang Behavioral / Risk / Trace
```

---

## 3. Chính sách Phân luồng Zero Imputation (Strict Routing)

- Các sự kiện tầng ứng dụng và hệ thống (`DNS`, `Web`, `Auth`, `Audit`) không phải là network flow và không chứa 18 đặc trưng `canonical-flow-v2-18`.
- **Quy tắc tuyệt đối:** Không được phép tự động gán giá trị `0` hoặc `median` vào các đặc trưng thiếu để cố ép 4 mô hình AI flow chạy dự đoán.
- Mọi sự kiện `is_ml_complete=False` được gắn `route_only=True` và chuyển nguyên vẹn sang:
  - **Behavioral Sessionizer (`src/network_anomaly/behavioral/`):** Xây dựng vector hành vi 16-D.
  - **Multi-criteria Risk Engine (`src/network_anomaly/risk/`):** Đánh giá rủi ro đa tiêu chí `[0..100]`.
  - **Entity Graph & Attack Timeline Reconstructor (`src/network_anomaly/trace/`):** Tái dựng chuỗi sự kiện và đồ thị liên kết khi có đủ khóa đồng bộ hợp lệ.
