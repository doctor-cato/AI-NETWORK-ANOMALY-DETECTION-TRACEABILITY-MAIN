# NetFlow Sentinel v2.0 — Multi-Source Dataset Audit & Provenance

**Document ID:** `AUDIT-DATA-V2-001`  
**Milestone:** `M6.2 (Multi-source Data Engineering)`  
**Issue:** `#82`  
**Status:** `APPROVED & COMPLETED`  
**License Compliance:** Apache-2.0, UQ License ID 454104, CC BY-SA 4.0  

---

## 1. Executive Summary

Để hiện thực hóa đề tài 22 về **"Hệ thống AI phát hiện, phân tích và truy vết kết nối mạng bất thường kết hợp mã hóa vector hành vi và xoay vòng khóa thích ứng"**, hệ thống yêu cầu dữ liệu đa nguồn gồm:
1. **Network Flow:** NetFlow v9 / IPFIX / nProbe với đầy đủ 47 ML features chuẩn hóa.
2. **Application Log:** DNS queries, Web/HTTP requests, API access logs.
3. **Identity & System Log:** Authentication (SSH, VPN, PAM), host audit logs, OS events.

Báo cáo này tiến hành audit nguồn dữ liệu cho Milestone M6.2, đánh giá tính khả thi, giấy phép bản quyền (license), tính độc lập, khả năng tái lập và ranh giới an toàn.

---

## 2. Evaluation Criteria & Taxonomy Matrix

Các nguồn dữ liệu được đánh giá dựa trên 8 tiêu chí chuẩn:
- **C1: License & Redistribution:** Giấy phép cho phép nghiên cứu học thuật/thương mại, không vi phạm NDA/chính sách bảo mật.
- **C2: Provenance & Ground Truth:** Nhãn tấn công rõ ràng, tài liệu hóa kịch bản tấn công (attack scenario documentation).
- **C3: Multi-Source Synchronization:** Có dữ liệu flow đồng bộ với host/application log theo mốc thời gian thực tế.
- **C4: Schema Compatibility:** Tương thích với Canonical Security Event Contract v2.0 (không đòi hỏi impute ngầm).
- **C5: Availability & Stability:** Hosting ổn định (Zenodo, IEEE Dataport, University Repositories), có DOI/checksum cố định.
- **C6: Entity Identifiers:** Cung cấp địa chỉ IP, port, host id, user identity để phục vụ Entity Graph & Behavioral Vector.
- **C7: Temporal Consistency:** Timestamp độ phân giải cao (millisecond/second epoch UTC) hỗ trợ sessionization.
- **C8: Volume & Feasibility:** Dung lượng phù hợp cho CI/CD và lab testbed, không làm quá tải tài nguyên máy chủ.

---

## 3. Dataset Audit & Decision Matrix

| Dataset | Priority | Decision | License / Terms | Modalities | Role in NetFlow Sentinel v2.0 | Justification |
| :--- | :---: | :---: | :--- | :--- | :--- | :--- |
| **NF-UNSW-NB15-v3** | P0 | **ACCEPTED** | UQ Permitted Re-Use (ID 454104) / CC BY-NC-ND | NetFlow (nProbe v3, 47 features) | Baseline NIDS Training, Verification, Benchmark | Nguồn dữ liệu cốt lõi của v1.0.0, 100% tương thích 47 feature contract, đã được audit chống rò rỉ. |
| **AIT NetFlow Dataset v2.1** | P0 | **ACCEPTED** | Creative Commons Attribution-ShareAlike 4.0 (CC BY-SA 4.0) | NetFlow v9 / IPFIX | Flow Ingestion for Multi-Source Pipeline & Evaluation | Cung cấp kịch bản mạng thực tế từ Austrian Institute of Technology, có ground truth rõ ràng. |
| **AIT Log Dataset v2.1** | P0 | **ACCEPTED** | Creative Commons Attribution-ShareAlike 4.0 (CC BY-SA 4.0) | Syslog, Apache Access, Bind9 DNS, Auditd, Suricata | Application & System Log Adapters, Attack Traceability | Đồng bộ thời gian hoàn hảo với AIT NetFlow, cho phép liên kết flow ↔ log để tái dựng Attack Timeline. |
| **NF-CSE-CIC-IDS2018-v3** | P1 | **ACCEPTED (DEFERRED)** | UQ Permitted Re-Use (ID 454104) | NetFlow (nProbe v3) | Cross-Dataset Robustness (#48) | Dung lượng lớn (~20M flows), dùng riêng cho kiểm thử tổng quát hóa mô hình ngoài phân phối (OOD). |
| **NF-ToN-IoT-v3** | P1 | **ACCEPTED (DEFERRED)** | UQ Permitted Re-Use (ID 454104) | NetFlow (IoT / IIoT) | IoT Cross-Domain Robustness | Xem xét mở rộng cho môi trường IoT/Scada trong tương lai; không bắt buộc cho release v2.0 core. |
| **NF-BoT-IoT-v3** | P2 | **DEFERRED** | UQ Permitted Re-Use (ID 454104) | NetFlow | Stress Test | Tỷ lệ tấn công cực đoan (99.69% attack), không phản ánh môi trường mạng thực tế của doanh nghiệp. |
| **LANL Cyber Security Dataset** | P2 | **REJECTED** | CC0 1.0 Universal | Host Events, Authentication | N/A | Dữ liệu bị ẩn danh hóa toàn bộ (anonymized IP/User), không có network flow thực để đối chiếu. |
| **DARPA / KDD99** | P2 | **REJECTED** | Public Domain | Network Connections | N/A | Lỗi thời (>25 năm), nhiều đặc trưng giả lập (synthetic artifacts), đã bị cộng đồng an ninh mạng loại bỏ. |

---

## 4. Deep Dive: AIT Dataset Suite v2.1 (P0 Accepted)

### 4.1 Provenance & Publisher
- **Tổ chức phát hành:** Austrian Institute of Technology (AIT) Data Science & Digital Safety and Security.
- **DOI / Lưu trữ:** Zenodo Open Access repository.
- **Giấy phép:** `CC BY-SA 4.0` (Được phép sử dụng, chuyển thể cho nghiên cứu và hệ thống với ghi nhận nguồn).
- **Kịch bản tấn công:**
  - Kịch bản gồm máy tính người dùng nội bộ, máy chủ DNS (Bind9), máy chủ Web (Apache), Mail server, Firewall và Attacker box.
  - Các giai đoạn tấn công: Nmap Port Scanning, Directory Bruteforce (Gobuster), Apache Struts2 RCE, Sudo privilege escalation, Data exfiltration qua DNS tunneling / SCP.

### 4.2 Cấu trúc dữ liệu và đồng bộ
- **NetFlow:** Định dạng CSV / nfdump chứa Flow Start, Duration, Src/Dst IP, Src/Dst Port, Protocol, Bytes, Packets, TCP Flags.
- **Application Logs:**
  - `access.log` (Apache HTTP Server): Timestamp UTC, Client IP, Method, URI, HTTP Status, User-Agent.
  - `named.log` / `queries.log` (Bind9 DNS): Timestamp UTC, Client IP, Query FQDN, Query Type, Return Code.
  - `auth.log` (PAM / OpenSSH): Timestamp, Hostname, Event Type (sshd accept/failed, sudo executed), Username.
  - `audit.log` (Linux Auditd): Syscall logging, execve arguments, process lineage.

---

## 5. Risk Assessment & Safe Handling Rules

1. **Không commit dữ liệu thô vào Git:**
   - Mọi tệp dữ liệu thô (`.csv`, `.pcap`, `.log`, `.gz`, `.parquet`) bắt buộc được đặt trong `data/` và nằm trong `.gitignore`.
   - Chỉ lưu trữ các tệp manifest (`AIT_DATASETS_MANIFEST.json`) kèm mã băm SHA-256 để đảm bảo tính toàn vẹn (cryptographic integrity).
2. **Không lưu trữ bí mật / Tokens:**
   - Script tải tự động không nhúng API key, token truy cập hoặc mật khẩu. Mọi nguồn tải đều sử dụng giao thức HTTPS mở công khai từ Zenodo.
3. **Fail-Closed Verification:**
   - Quá trình nạp dữ liệu luôn kiểm tra checksum SHA-256. Nếu checksum không khớp, pipeline lập tức hủy tiến trình với exit code khác 0.
