# NetFlow Sentinel v2 — Data Quality Gates Report

**Contract:** `canonical-flow-v2-18` (18 features)

| Check | AIT-NDS-v2 | CTU-SME-11 Subset | Status |
|---|---:|---:|---|
| Schema Header Consistency | 3 exact Tstat schemas (`tcp_complete`, `tcp_nocomplete`, `udp_complete`) | Exact Zeek `conn.log.labeled` across 14 files | `PASS` |
| Unparseable / Invalid Numeric Cells | 0 | 0 | `PASS` |
| Negative Duration / Byte / Packet Counters | 0 | 0 | `PASS` |
| Unmapped Labels Audited (Never Coerced to Benign) | 942 | 9,394 | `PASS` |
| Same-Scenario Exact (5-tuple + Timestamp) Duplicates | 413 | Audited in split | `RECORDED` |
