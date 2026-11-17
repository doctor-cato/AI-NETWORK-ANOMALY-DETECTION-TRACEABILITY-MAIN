# NetFlow Sentinel v2 — Multi-Source Dataset Audit

**Generated (UTC):** 2026-11-17T18:05:59.242597+00:00
**Feature Contract:** `canonical-flow-v2-18` (18 features)

| Dataset | Identifier / Source | License | Role in v2 | Verification Status |
|---|---|---|---|---|
| **AIT NetFlow Data Set v2** | `10.5281/zenodo.13168643` | CC BY 4.0 | Primary synthetic NetFlow ML benchmark (8 scenarios, Tstat CSVs derived from AIT-LDS-v2.0 PCAPs) | `PRESENT` (3,465,342 rows) |
| **AIT Log Data Set v2.1** | `10.5281/zenodo.19483937` | CC BY-NC-SA 4.0 | Host/DNS/Auth/Web logs (`fox`, `russellmitchell` acquired for Trace/Behavioral correlation audit) | `PRESENT` |
| **AIT Alert Data Set** | `10.5281/zenodo.8263181` | CC BY 4.0 | Wazuh/AMiner alert correlation & ground-truth attack windows (derived from AIT-LDS-v2.0, not standalone ML benchmark) | `PRESENT` |
| **CTU-SME-11** | `10.5281/zenodo.7958258` (`7958259`) | CC BY 4.0 | Real captured SME lab traffic (`Echo` IoT + `Windows7AD` Windows VM, 7 days Zeek `conn.log.labeled`) | `PRESENT` (260,613 rows) |
| **UGR'16** | `https://nesg.ugr.es/nesg-ugr16/` | Unreachable | ISP real-traffic validation | `BLOCKED` (HTTP 403 / Portal en Mantenimiento) |

## Explicit Migration Rules Enforced
1. `AIT NetFlow Data Set v2` is strictly named `v2` (NOT `v2.1`) and traced to `AIT-LDS-v2.0` PCAPs.
2. `NF-UNSW-NB15-v3`, its 47-feature nProbe contract, TTL shortcuts (`MIN_TTL`/`MAX_TTL`), and v1 weights are retired to `*/historical/nf_unsw_nb15_v3/`.
3. `UGR'16` failed HTTP access check (`403 Forbidden`) and remains `BLOCKED` with zero synthetic replacement.
