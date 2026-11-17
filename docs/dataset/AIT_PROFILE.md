# AIT NetFlow Data Set v2 — Empirical Profile

**Total rows profiled:** 3,465,342 across 8 scenarios
**Invalid numeric cells:** 0 | **Negative flow counters:** 0
**Unmapped empty labels (`""`):** 942 (all in `shaw/tcp_complete.csv`; excluded from binary splits, never coerced to Benign)

## Scenario Breakdown
| Scenario | Total Flows | Unmapped | UTC Window | Category Counts (`taxonomy-v2`) |
|---|---:|---:|---|---|
| `fox` | 351,908 | 0 | 2022-01-15T00:00:00.869370+00:00 .. 2022-01-19T23:59:59.055075+00:00 | Benign=280,735, Credential_Attack=61, Data_Exfiltration=14,668, Exploitation_And_C2=2, Post_Exploitation_Discovery=26, Reconnaissance=56,416 |
| `harrison` | 437,659 | 0 | 2022-02-04T00:00:03.030726+00:00 .. 2022-02-08T23:58:23.407420+00:00 | Benign=337,307, Credential_Attack=738, Data_Exfiltration=23,457, Exploitation_And_C2=12, Post_Exploitation_Discovery=20, Reconnaissance=76,125 |
| `russellmitchell` | 377,704 | 0 | 2022-01-21T00:00:02.274306+00:00 .. 2022-01-24T23:59:57.389599+00:00 | Benign=206,676, Credential_Attack=11, Data_Exfiltration=15,778, Exploitation_And_C2=2, Post_Exploitation_Discovery=56, Reconnaissance=155,181 |
| `santos` | 288,547 | 0 | 2022-01-14T00:00:02.425734+00:00 .. 2022-01-17T23:59:53.819441+00:00 | Benign=269,762, Credential_Attack=228, Data_Exfiltration=12,848, Exploitation_And_C2=2, Post_Exploitation_Discovery=56, Reconnaissance=5,651 |
| `shaw` | 453,541 | 942 | 2022-01-25T00:00:02.508266+00:00 .. 2022-01-30T23:58:30.842123+00:00 | Benign=389,344, Credential_Attack=78, Data_Exfiltration=60,898, Exploitation_And_C2=2, Post_Exploitation_Discovery=14, Reconnaissance=2,263, Unmapped=942 |
| `wardbeck` | 390,224 | 0 | 2022-01-19T00:00:01.756110+00:00 .. 2022-01-23T23:59:14.968378+00:00 | Benign=370,049, Credential_Attack=676, Data_Exfiltration=15,076, Exploitation_And_C2=4, Post_Exploitation_Discovery=70, Reconnaissance=4,349 |
| `wheeler` | 536,206 | 0 | 2022-01-26T00:00:02.659843+00:00 .. 2022-01-30T23:55:30.582722+00:00 | Benign=423,636, Data_Exfiltration=19,177, Exploitation_And_C2=3, Post_Exploitation_Discovery=25, Reconnaissance=93,365 |
| `wilson` | 629,553 | 0 | 2022-02-03T00:00:02.696198+00:00 .. 2022-02-08T23:59:52.400297+00:00 | Benign=568,013, Credential_Attack=735, Data_Exfiltration=21,219, Exploitation_And_C2=16, Post_Exploitation_Discovery=8, Reconnaissance=39,562 |

## Leakage-Risk Audit in Raw AIT-NDS-v2 Columns
- `role_cli` / `role_serv` explicitly encode scenario actor roles such as `attacker_0`, `internal_server`, `monitoring`. **Strict rule:** excluded from `ML_FEATURE_COLUMNS` via `v2_schema.validate_feature_selection`.
- `c_ttl_min:50` / `s_ttl_min:61` are absent from `udp_complete.csv` and `tcp_nocomplete.csv` and act as topology shortcuts -> excluded from `canonical-flow-v2-18`.
