# NetFlow Sentinel v2.0 — Incident Investigation Report Specification

> **Tài liệu đặc tả báo cáo điều tra số hóa (Issue #113 — Milestone M6.4)**  
> **Phiên bản:** 2.0.0-investigation  
> **Module thực thi:** `src/network_anomaly/trace/investigation.py`

---

## 1. Giới thiệu
Investigation Report Generator tự động tổng hợp toàn bộ ngữ cảnh sự cố từ Unified Security Events, Attack Timeline, Entity Graph và Evidence Records thành báo cáo điều tra có chữ ký kiểm toán SHA-256 xác định (deterministic artifact hash).

### Cấu trúc Báo cáo:
1. **Header & Metadata:**
   - `report_id`, `incident_id`, `generated_at_utc`, `severity`.
   - `artifact_hash`: Mã băm SHA-256 cố định tính toán trên nội dung sự cố, timeline và evidence provenance.
2. **Root Cause Summary:**
   - Tóm tắt nguyên nhân gốc rễ và cơ chế xâm nhập ban đầu.
3. **Attack Timeline Table:**
   - Bảng phân giai đoạn các sự kiện theo chuẩn Cyber Kill Chain / MITRE ATT&CK.
4. **Evidence Provenance Ledger:**
   - Danh sách nguồn gốc bằng chứng số: tên tệp gốc, số dòng hoặc byte offset, và mã băm SHA-256 của tệp bằng chứng.
5. **Recommended Actions:**
   - Danh sách hành động khuyến nghị tự động (kích hoạt xoay khóa khẩn cấp, cô lập giao diện mạng, rà soát vector hành vi).

---

## 2. API Xuất Báo cáo
Chuyên viên phân tích hoặc giao diện Desktop có thể tạo báo cáo thông qua endpoint REST:
```http
POST /api/v1/trace/investigation/generate
Content-Type: application/json
X-Sentinel-Session-Token: <token>

{
  "incident_id": "INC-2026-001",
  "title": "Web Server Exploit Incident",
  "severity": "CRITICAL",
  "root_cause_summary": "Unauthenticated RCE vulnerability exploited on port 80.",
  "events": [...],
  "evidence_records": [...]
}
```
Phản hồi trả về cả định dạng đối tượng có cấu trúc (JSON) và văn bản trình bày hoàn chỉnh dạng Markdown (`markdown_content`).
