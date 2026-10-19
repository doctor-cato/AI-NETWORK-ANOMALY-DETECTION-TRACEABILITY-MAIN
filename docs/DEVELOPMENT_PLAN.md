# Kế hoạch triển khai C0–C11

| Thứ tự | Checkpoint | Milestone | Dependency cứng |
|---|---|---|---|
| 1 | C0 Governance & documentation | M7 | không phụ thuộc PR #22 |
| 2 | C1 Data quality & EDA | M1 | C0; #4/#5 workstream riêng |
| 3 | C2 Preprocessing | M2 | C1 leakage/split decision |
| 4 | C3 Supervised ML | M2–M3 | C2 |
| 5 | C4 Unsupervised & unknown | M3 | C2; protocol C3 để so sánh |
| 6 | C5 Behavioral Vector | M6 | C2 và lab schema |
| 7 | C6 Risk & Trace | M6 | C3–C5 |
| 8 | C7 Encryption & key lifecycle | M6 | C5 storage contract |
| 9 | C8 Adaptive response | M6 | C6–C7 |
| 10 | C9 Backend & dashboard | M6 | C3–C8 |
| 11 | C10 Seven experiments | M7 | checkpoint liên quan đã TESTED |
| 12 | C11 Delivery | M7 | C0–C10, regression/security audit |

M0–M5 và bằng chứng lịch sử được giữ nguyên trên GitHub. M6 chứa C5–C9 integration;
M7 chứa C0, C10–C11. Mỗi checkpoint có branch/commit/PR riêng và không tự merge.

Cập nhật: 2026-10-19 (C0)
