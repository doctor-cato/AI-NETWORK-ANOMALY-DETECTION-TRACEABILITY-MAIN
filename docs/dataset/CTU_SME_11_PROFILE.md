# CTU-SME-11 — Empirical Profile (Acquired Subset)

**Source:** DOI `10.5281/zenodo.7958258` (version record `7958259`), License `CC BY 4.0`
**Note:** Controlled SME lab environment on real devices/VMs across 7 days; NOT live production enterprise traffic.
**Total rows profiled:** 260,613 across 14 Zeek `conn.log.labeled` files
**Zeek `duration == '-'` rows:** 59,836 (explicitly mapped to `0.0` ms for unanswered/single-packet probes)
**Zeek `orig_ip_bytes == '-'` rows:** 0 (100% populated, avoiding `-` payload missingness in `orig_bytes`)

## Device Breakdown
| Device | Total Flows | Capture Span | Category Counts (`taxonomy-v2`) |
|---|---:|---:|---|
| `Experiment-VM-Microsoft-Windows7AD-1` | 184,540 | 7 days | Benign=173,108, Exploitation_And_C2=2,036, Malware_And_DoS=2, Unmapped=9,394 |
| `Honeypot-Assistant-Amazon-Echo1stGen-1` | 76,073 | 7 days | Benign=39,497, Reconnaissance=36,576 |

## Observed Probe Domain Shift vs. AIT-NDS-v2
- **Byte Accounting:** AIT-NDS-v2 Tstat reports TCP payload bytes (`c_bytes_all`), whereas CTU-SME-11 Zeek reports IP packet bytes (`orig_ip_bytes` / `resp_ip_bytes`, IP+TCP/UDP header overhead included).
- **Unknown Labels:** `Experiment-VM-Microsoft-Windows7AD-1` contains 9,394 `Unknown` (`(empty)`) rows; preserved as `UNMAPPED` and excluded from labeled ML evaluation metrics.
