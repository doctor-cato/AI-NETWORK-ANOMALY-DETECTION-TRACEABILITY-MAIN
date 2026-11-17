# AIT Multi-Source Dataset Profiling Report

**Milestone:** `M6.2 (Multi-source Data Engineering)`  
**Issue:** `#84`  
**Status:** `VERIFIED & DETERMINISTIC`  

## 1. Overview
Hệ thống NetFlow Sentinel v2.0 hỗ trợ giám sát đa nguồn kết hợp Network Flow và Application/Host Logs. Dữ liệu mẫu chuẩn hóa từ AIT Dataset Suite v2.1 được dùng để đánh giá tính chất thống kê.

## 2. Statistical Profiles by Source

### 2.1 NetFlow (AIT NetFlow v2.1)
- **Tệp nguồn:** `ait_netflow_v2.1_sample.csv`
- **Số bản ghi:** `5`
- **Trường thời gian:** `FLOW_START_MILLISECONDS`
- **Khoảng thời gian:** `2020-11-05T08:00:00+00:00` đến `2020-11-05T08:00:20+00:00`
- **Thực thể nhận diện:** `IPV4_SRC_ADDR, IPV4_DST_ADDR, L4_SRC_PORT, L4_DST_PORT`
- **Phân bố nhãn:**
```json
{
  "Benign": 1,
  "Reconnaissance": 1,
  "Exploits": 1,
  "Backdoors": 1,
  "Exfiltration": 1
}
```

### 2.2 DNS Logs (Bind9 / Zeek)
- **Tệp nguồn:** `ait_dns_v2.1_sample.log`
- **Số bản ghi:** `3`
- **Trường thời gian:** `ts`
- **Khoảng thời gian:** `2020-11-05T08:00:00.100000+00:00` đến `2020-11-05T08:00:20.150000+00:00`
- **Loại truy vấn:** `{"A": 2, "TXT": 1}`

### 2.3 Web Logs (Apache Access Log)
- **Tệp nguồn:** `ait_web_v2.1_sample.log`
- **Số bản ghi:** `3`
- **Mã phản hồi HTTP:** `{"200": 2, "404": 1}`

### 2.4 Auth & Audit Logs (OpenSSH / PAM / Sudo)
- **Tệp nguồn:** `ait_auth_v2.1_sample.log`
- **Số bản ghi:** `3`
- **Kết quả xác thực:** `{"SUCCESS": 1, "FAILURE": 2}`
