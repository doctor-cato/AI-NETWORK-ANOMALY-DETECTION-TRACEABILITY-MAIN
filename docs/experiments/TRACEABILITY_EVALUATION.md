# Traceability & Event Correlation Evaluation Report (Issue #114)

> **Evaluation ID:** EVAL-TRACEABILITY-M64
> **Evaluation Date:** 2026-11-19T14:16:39.140407+00:00
> **Status:** TESTED (Synthetic 10-Event 4-Phase Scenario)

## 1. Executive Summary
- **Stage Attribution Accuracy:** **90.0%** (Đạt phân loại chính xác các giai đoạn Reconnaissance, Initial Access, Lateral Movement, Exfiltration).
- **Trace Path Completeness:** **100.0%** (Duyệt đầy đủ các bước trong chuỗi tấn công không bị đứt đoạn).

## 2. Bảng Đối sánh với Baseline Không Cấu trúc

| Chỉ số Đo lường | Baseline Log Grep Truyền thống | Trace Engine v2 (Entity Graph + Timeline) | Mức độ Cải thiện |
|---|:---:|:---:|:---:|
| **Độ chính xác Gán giai đoạn (Stage Attribution)** | 30.0% | **90.0%** | **+60.0%** |
| **Độ hoàn chỉnh Chuỗi vết (Path Completeness)** | 40.0% | **100.0%** | **+60.0%** |

## 3. Qualitative Error Analysis & Sample-Size Caveats

- **1/10 (`10%`) Stage Misclassification (`ev-7`):** Event `ev-7` (`type="winrm"`, `dest_port=5985`, `10.0.0.2 -> 10.0.0.4`) was misattributed to `INITIAL_ACCESS` instead of `LATERAL_MOVEMENT`. In `src/network_anomaly/trace/timeline.py:121-123`, `AttackTimelineReconstructor` checks keywords `["lateral", "internal", "worm", "smb"]` and internal ports `(445, 139, 3389, 22)`, missing WinRM ports `5985/5986` and falling through to the default `INITIAL_ACCESS` branch (`timeline.py:135`).
- **Missed-Link Example:** Without explicit `EntityRelationshipGraph` `CONNECTS_TO` edges, source-IP-only correlation stops at the initial perimeter target (`198.51.100.1 -> 10.0.0.1`) and misses downstream internal lateral hops (`10.0.0.2 -> 10.0.0.4`).
- **False-Link Example:** On shared admin bastions or NAT gateways (e.g., `10.0.0.2`), purely IP-based `CONNECTS_TO` edges can falsely link benign administrative WinRM/RDP flows into an attack campaign when temporal/behavioral constraints are absent.
- **Sample-Size Caveat:** This evaluation uses `N=10` synthetic events (`1` event = `10.0%` accuracy step); it validates deterministic graph traversal and timeline attribution logic, not production telemetry distribution.

## 4. Kết luận
Trace Engine v2 achieved 90.0% stage attribution accuracy and 100.0% path completeness across the 10-event 4-phase synthetic attack progression (TESTED on synthetic scenario, not production telemetry).
