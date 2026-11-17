# Multi-Source Ingestion Pipeline & Event Alignment Specification

**Document ID:** `SPEC-PIPELINE-MULTI-001`  
**Milestone:** `M6.2 (Multi-source Data Engineering)`  
**Issue:** `#93`  
**Status:** `VERIFIED & OPERATIONAL`  

---

## 1. Tổng quan kiến trúc Pipeline đa nguồn

Kiến trúc pipeline đa nguồn của NetFlow Sentinel v2.0 thực hiện chuyển đổi, thẩm định chất lượng và liên kết các luồng dữ liệu phân tán:
1. **Network Flow:** Lưu lượng NetFlow v9 / IPFIX / nProbe (47 baseline ML features).
2. **DNS Logs:** Bản ghi truy vấn tên miền (Zeek DNS / Bind9).
3. **Web Server Logs:** Nhật ký truy cập HTTP / API (Apache / Nginx).
4. **Authentication & Identity Logs:** Nhật ký đăng nhập SSH, PAM, VPN.
5. **System & Audit Logs:** Linux auditd / Windows Sysmon process events.

---

## 2. Quy trình xử lý (Pipeline Stages)

```
[Flow Logs]   --> [UnifiedNetFlowAdapter]   --\
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
                 - Flow có 47 đặc trưng                                       - Non-flow logs (DNS, Web, Auth)
                 - is_ml_complete = True                                      - Flow thiếu đặc trưng
                 - Ready for AI Models (M6.3)                                 - KHÔNG TỰ Ý IMPUTE SỐ 0/MEDIAN
                                                                              - Chuyển sang Risk/Trace (M6.4)
```

---

## 3. Chính sách phân luồng Zero Imputation (Strict Routing)

- Đối với các sự kiện tầng ứng dụng và hệ thống (DNS, Web, Auth, Audit): Chúng không phải là network flow và không chứa 47 đặc trưng nProbe.
- **Quy tắc tuyệt đối:** Không được phép tự động gán giá trị 0 hoặc median vào các đặc trưng thiếu để cố ép mô hình ML chạy dự đoán.
- Tất cả các sự kiện này được gắn nhãn `route_only=True` (`is_ml_complete=False`) và được chuyển nguyên vẹn sang:
  - **Behavioral Sessionizer (#101):** Để xây dựng 16-D Behavioral Vector.
  - **Risk Scoring (#108):** Đánh giá rủi ro đa tiêu chí.
  - **Entity Graph & Attack Timeline Reconstructor (#110, #112):** Tái dựng chuỗi tấn công hoàn chỉnh.
