# AIT Cross-Source Linkage Feasibility Report

- **Issue:** `#85` — **`3/3 AC VERIFIED LOCALLY (Tier-2 Empirical Alignment Executed; Tier-1 Direct UID = FALSE)`** *(provenance, schema/UID audit, RQ3 honest boundary, and empirical `(ip, ±3s)` timestamp/timezone alignment on verified UTC-synchronized scenarios `fox` & `russellmitchell` completed; row-level 1-to-1 UID linkage remains impossible without direct flow identifiers and full `AIT-LDS-v2.0` PCAPs)*
- **Datasets Audited:** `AIT-NDS-v2` (`10.5281/zenodo.13168643`), `AIT-LDS-v2.0` (`10.5281/zenodo.5789064`), `AIT-LDS-v2.1` (`10.5281/zenodo.19483937`), and `AIT-ADS` (`10.5281/zenodo.8263181`)
- **Primary Evidence Sources:** `data/AIT_DATASETS_MANIFEST.json`, `data/EXTERNAL_DATASETS_PROVENANCE.json`, `reports/datasets/v2_multi_source_profile.json`, `reports/datasets/ait_timestamp_alignment_report.json` (`scripts/verify_ait_timestamp_alignment.py`), Zenodo REST API records (`13168643`, `5789064`, `19483937`, `8263181`), and local raw archive inspection (`fox`, `russellmitchell`, `shaw`, and all 8 `*_netflows.zip` scenarios)

---

## 1. 3-Tier Linkage Policy Verdict

| Tier | Policy Classification | Status | Empirical Basis |
|---|---|---|---|
| **Tier 1** | `DIRECT_UID_LINK` | **`NO — FALSE`** (`direct_uid_join_possible: false`) | Zero shared `uid`, `flow_id`, `conn_id`, `packet_id`, or `community_id` across `AIT-NDS-v2` Tstat CSVs, `AIT-LDS-v2.1` logs/`labels/`, and `AIT-ADS` alerts. |
| **Tier 2** | `ENTITY_TIME_CORRELATION` | **`HEURISTIC ONLY`** (`(scenario, normalized_ip_entity, utc_epoch_window)`) | Coarse co-occurrence supported for Trace/Behavioral heuristics (`11/11` `fox` Wazuh agent IPs and `32/32` `servers.yaml` IPv4s appear in `fox_netflows.zip`), **subject to strict caveat**: IP overlap $\neq$ same flow record and temporal proximity $\neq$ UID. |
| **Tier 3** | `UNVERIFIED` | **`CROSS-VERSION / FULL PACKET ALIGNMENT UNVERIFIED`** | Local workspace holds only `AIT-LDS-v2.1` `*_no-pcaps.zip` (`fox`, `russellmitchell`, 0 PCAPs); full `AIT-LDS-v2.0` PCAP archives were **not** downloaded or locally checksum-verified. |

---

## 2. Zenodo Provenance, Licensing & Archive Comparison (`v2.0` vs `v2.1`)

### 2.1 Official Record & License Matrix

| Dataset | Zenodo Record / DOI | Concept DOI | Version / Pub Date | License | Source Relationship | Local Workspace Status |
|---|---|---|---|---|---|---|
| **AIT Netflow Data Set (`AIT-NDS-v2`)** | [`10.5281/zenodo.13168643`](https://zenodo.org/records/13168643) | `10.5281/zenodo.6610488` | `2024-08-02` | `CC BY 4.0` | Tstat CSVs generated from `AIT-LDS-v2.0` PCAPs (`5789064`) | **All 12 files present & MD5-verified** (`data/raw/ait_nds_v2/`) |
| **AIT Log Data Set V2.0 (`AIT-LDS-v2.0`)** | [`10.5281/zenodo.5789064`](https://zenodo.org/records/5789064) | `10.5281/zenodo.5789063` | `v2_0` (`2022-02-24`) | `CC BY-NC-SA 4.0` | Original 8 full testbed archives (host logs + PCAPs, ~7.1–26.5 GB/zip) | **NOT downloaded locally** (Zenodo metadata verified via API) |
| **AIT Log Data Set V2.1 (`AIT-LDS-v2.1`)** | [`10.5281/zenodo.19483937`](https://zenodo.org/records/19483937) | `10.5281/zenodo.5789063` | `v2_1` (`2026-04-09`) | `CC BY-NC-SA 4.0` | Adds 8 `*_no-pcaps.zip` archives alongside the 8 full `<scenario>.zip` archives | **Subset present & MD5/SHA-256 verified:** `fox_no-pcaps.zip` & `russellmitchell_no-pcaps.zip` only (`data/raw/ait_lds_v2_1/`) |
| **AIT Alert Data Set (`AIT-ADS`)** | [`10.5281/zenodo.8263181`](https://zenodo.org/records/8263181) | `10.5281/zenodo.8263180` | `1` (`2023-08-18`) | `CC BY 4.0` | Wazuh + AMiner alerts & attack interval CSV derived from `AIT-LDS-v2.0` | **All 2 files present & MD5/SHA-256 verified** (`data/raw/ait_ads/`) |

> **License Governance Caveat:** `AIT-NDS-v2` and `AIT-ADS` are licensed under **`CC BY 4.0`**, whereas `AIT-LDS-v2.0` and `AIT-LDS-v2.1` are licensed under **`CC BY-NC-SA 4.0`** (NonCommercial-ShareAlike). Raw `AIT-LDS-v2.1` logs are restricted to research/non-commercial audit and excluded from Git tracking.

### 2.2 `AIT-LDS-v2.0` vs `AIT-LDS-v2.1` File Inventory & Local Scope

- **Zenodo API comparison (`5789064` vs `19483937`):** All 8 full `<scenario>.zip` archives in `AIT-LDS-v2.1` (`fox.zip` `15,837,626,707` B `md5:b6cd133398fbed6f3e7434dafbc45756`, `harrison.zip` `16,773,705,987` B `md5:4fbe3dd17a194776b2851116f8b51380`, `russellmitchell.zip` `7,132,670,599` B `md5:78e9b7d169b438f03816019b52ab3ff7`, `santos.zip`, `shaw.zip`, `wardbeck.zip`, `wheeler.zip`, `wilson.zip`) match `AIT-LDS-v2.0` identically by byte size and MD5 checksum. `AIT-LDS-v2.1` adds 8 stripped `*_no-pcaps.zip` archives (omitting `.pcap` captures to reduce download footprint).
- **Local `data/raw/ait_nds_v2/` inventory (12/12 Zenodo `13168643` files verified):** All 8 `*_netflows.zip` archives (`fox_netflows.zip` `25,870,023` B `md5:d3024ef6033fbd45982464f6b6f50984`, `sha256:e2bfacdfe9822109c807300f941d0a0c9fa1b370bcf2822fd12f27ed23928381`, etc.), `README.md` (`2,104` B `md5:4143e85bea156333b463ebd5548fa443`), `label_info.txt` (`986` B `md5:e32c0e08d15725999df0c6a0c02aff47`), `1_format_dataset_info.ipynb` (`10,448` B `md5:ebcd97a6049926090238e88520089798`), and `2_label_logs.ipynb` (`31,496` B `md5:52eedcedbdc4391c575dd2606bc893cc`). *(Note: `data/AIT_DATASETS_MANIFEST.json` catalogs the 8 scenario zips plus `README.md` and `label_info.txt`; the two notebooks are present in `data/raw/ait_nds_v2/` and match Zenodo `13168643` MD5s.)*
- **Local `data/raw/ait_lds_v2_1/` inventory (2/16 Zenodo `19483937` files):** Only `fox_no-pcaps.zip` (`688,586,900` B, `md5:27b09dd2876ec08ee99a9b53e8718c92`, `sha256:8d71d31a31df469d836c80bdbfdc35da566e90322cf9ae490233e176a0c88d49`, `16,094` entries, `0` `.pcap` files) and `russellmitchell_no-pcaps.zip` (`522,084,364` B, `md5:abb43a46c70939ad9f98669e3510d2b7`, `sha256:51a03f51daea0fbbdcfe9b8abe0dbbe10633716f4f98074f861204a162ee1978`, `14,898` entries, `0` `.pcap` files) were downloaded.
- **Local `data/raw/ait_ads/` inventory (2/2 Zenodo `8263181` files):** `ait_ads.zip` (`96,202,946` B, `md5:43db6b1f0996e0024befd617706c50e9`, `sha256:9f0595c4ebe56ac9223763881f55369dd4f249a8108064e4ae108eb3309aeeb9`) and `labels.csv` (`3,703` B, `md5:60ff33796c77fd2136c4d1a4bc841bd9`, `sha256:633e09b42772eabbbe5b48598220860eead60b7352efb01973fc45a5034290c0`).
- **Verification Limit:** Because full `AIT-LDS-v2.0` PCAP zips (`fox.zip`, etc.) were **not** downloaded locally, Tstat flow regeneration from raw PCAPs and byte-level `v2.0` local checksum verification remain **unverified** (`Tier 3: UNVERIFIED`).

---

## 3. Schema & UID Audit (`DIRECT_UID_LINK: False`)

| Source | Artifact / Schema Observed | Join / Identifier Fields Present | `uid` / `flow_id` / `conn_id` / `packet_id` Compatibility |
|---|---|---|---|
| **`AIT-NDS-v2`** (`*_netflows.zip`) | 3 uniform Tstat CSV schemas per scenario (`README.md`: `mergecap` + `tstat <filename>`):<br>- `tcp_complete.csv` (`138` cols)<br>- `tcp_nocomplete.csv` (`52` cols)<br>- `udp_complete.csv` (`28` cols) | 5-tuple (`#15#c_ip:1`/`#c_ip:1`, `c_port:2`, `s_ip:15`/`s_ip:10`, `s_port:16`/`s_port:11`, file-type TCP/UDP), Tstat timestamps, and `2_label_logs.ipynb` role enrichments (`role_cli`, `role_serv`, `network_*`, `label`). | **NONE.** Zero `uid`, `flow_id`, `conn_id`, `packet_id`, or `community_id` columns. *(`c_tls_sesid:120` in `tcp_complete.csv` is Tstat's TLS session-resumption indicator/ID, not a cross-log join key.)* |
| **`AIT-LDS-v2.1`** (`*_no-pcaps.zip`) | **0 Zeek logs (`zeek=[]`).** Network probe logs are **Suricata** (`gather/*/logs/suricata/eve.json`, `fast.log`, `stats.log`). Host/app logs: `dnsmasq.log`, `apache2`, `audit.log`, `auth.log`, `openvpn.log`, `dnsteal.log`, `attacks.log`, `sm.log`, `logstash`. | Suricata `eve.json` has `flow_id` (64-bit internal Suricata hash, e.g., `161110071116466`), 5-tuple, and **no `community_id`**. Ground-truth `labels/` (`8` files in `fox`, `8` in `russellmitchell`) use **1-based file line offsets** (`{"line": N, "labels": [...], "rules": {...}}`). | **INCOMPATIBLE.** `AIT-NDS-v2` was produced by `tstat` (not Suricata), so Suricata `flow_id` does not exist in `AIT-NDS-v2`. Moreover, `suricata/eve.json` has **no** ground-truth file in `labels/`, and `labels/` line numbers (`{"line": N}`) carry zero flow/packet IDs. |
| **`AIT-ADS`** (`ait_ads.zip`, `labels.csv`) | `*_wazuh.json` (`fox_wazuh.json`: `462,523` lines), `*_aminer.json` (`fox_aminer.json`: `10,581` lines), `labels.csv` (`79` scenario attack rows). | Wazuh: internal alert `id`, `agent.ip`, `@timestamp`, `location`, `rule`, `full_log`; `11,084` `suricata/eve.json` records carry `data.flow_id`. AMiner: `LogData` (`RawLogData`, `Timestamps`, `DetectionTimestamp`). `labels.csv`: `(scenario, attack, start, end)`. | **INCOMPATIBLE.** `data.flow_id` on the `11,084` Suricata/Wazuh subset has no counterpart in `AIT-NDS-v2` Tstat CSVs; `fox_wazuh.json` has `0` `dnsmasq.log` alerts and only `24` SELinux/AppArmor `audit.log` alerts. `labels.csv` contains interval bounds only. |

**Conclusion:** `DIRECT_UID_LINK` is **`NO — FALSE`**. No deterministic foreign key links a Tstat NetFlow row in `AIT-NDS-v2` to a specific Suricata event, host log line in `AIT-LDS-v2.1`, or Wazuh/AMiner alert in `AIT-ADS`.

---

## 4. Timestamp Semantics, Clock Basis & Host Entity Audit

### 4.1 Timezone, Precision & Clock Basis Across Sources

- **Common Clock Basis:** `processing/config/servers.yaml` explicitly declares `timezone: UTC` across all configured hosts (`30/30` host entries in `fox`, `22/22` in `russellmitchell`), and `processing/config/attacker.yaml` declares `timezone: "UTC"`. `dataset.yaml` specifies UTC simulation windows (`fox`: `2022-01-15T00:00:00` .. `2022-01-20T00:00:00`; `russellmitchell`: `2022-01-21T00:00:00` .. `2022-01-25T00:00:00`).
- **Format & Precision Heterogeneity:**
  - `AIT-NDS-v2` Tstat: float Unix epoch **milliseconds** (`first:29`, `last:30` for TCP; `c_first_abs:3`, `s_first_abs:12` for UDP), plus `2_label_logs.ipynb` derived `timestamp` and 1-second `rounded_timestamp` (`udp_complete.csv`). *Schema caveat:* TCP `durat:31` is recorded in **ms**, whereas UDP `c_durat:4`/`s_durat:13` are recorded in **seconds** (normalized in `src/network_anomaly/data/v2_schema.py`).
  - `AIT-LDS-v2.1` configs (`attacker.yaml`, `foothold.yaml`, `escalate.yaml`): ISO-8601 UTC millisecond strings (`...Z`).
  - `AIT-LDS-v2.1` raw logs: `suricata/eve.json` (`YYYY-MM-DDTHH:MM:SS.ffffff+0000`), `apache2` (`[18/Jan/2022:08:02:04 +0000]`), `audit.log` (`audit(epoch_sec.ms:seq)`), `dnsteal.log` (float Unix epoch seconds), `attacks.log` (`YYYY-MM-DD HH:MM:SS.ffffff+00:00`), `openvpn.log` (naive `YYYY-MM-DD HH:MM:SS` in UTC), and `dnsmasq.log` / `auth.log` (RFC 3164 `Jan 15 00:00:03` — **yearless and timezone-offsetless**, requiring `dataset.yaml` + `servers.yaml` UTC context).
  - `AIT-ADS`: `labels.csv` uses float Unix epoch **seconds** (`1642410288.0`); `fox_wazuh.json` uses ISO-8601 `@timestamp` (`...Z`, second-truncated on syslog/apache, microsecond on Suricata); `fox_aminer.json` uses float Unix epoch seconds (`DetectionTimestamp`, `Timestamps`).

### 4.2 Scenario & Host Entity Identification (`fox` & Multi-Probe Caveats)

- **IP Entity Overlap (`fox`):** `11/11` Wazuh `agent.ip` addresses in `fox_wazuh.json` (`10.35.32.1`, `10.35.33.111`, `10.35.35.206`, `172.17.129.140`, `172.17.130.196`, `172.17.130.37`, `172.17.131.81`, `192.168.128.170`, `192.168.128.195`, `192.168.129.212`, `192.168.131.228`) and `32/32` IPv4 addresses in `processing/config/servers.yaml` appear verbatim in `fox_netflows.zip`.
- **Why IP Overlap $\neq$ Same Flow Record:**
  1. **Multi-homing, VPN aliasing, and IPv6-mapped syntax:** In `fox`, `attacker_0` operates as `192.168.130.77` on the external network and `172.17.130.196` over OpenVPN (`attacker/attacker.yaml`), while `escalate.yaml` records IPv6-mapped IPv4 strings (`::ffff:192.168.130.77`, `::ffff:192.168.128.4`).
  2. **Multi-probe capture duplication across NAT:** `README.md` and `2_label_logs.ipynb` merge Tstat outputs across all host probes (`glob("./*_logs/log*/*.out/...")`). Consequently, the same connection appears twice with NAT-translated source IPs — e.g., `fox` `reverse_shell` (`2022-01-18T13:13:52.825Z..833Z`, `51612 -> 51898`) appears in `fox/tcp_complete.csv` both as `10.35.35.206 (intranet_server) -> 192.168.130.77 (attacker_0)` and `192.168.128.4 (inet-firewall) -> 192.168.130.77 (attacker_0)`.
  3. **Filtered management subnet:** `10.9.0.x` management traffic (e.g., `10.9.0.18` in `fox`) was dropped during `2_label_logs.ipynb` preprocessing.

### 4.3 Quantitative Timestamp, Timezone & `(ip, ±3s)` Alignment Trial (`reports/datasets/ait_timestamp_alignment_report.json`)

Executed via `.venv\Scripts\python.exe scripts/verify_ait_timestamp_alignment.py`, comparing raw `AIT-NDS-v2` Tstat CSVs (`data/raw/ait_nds_v2/{fox,russellmitchell}_netflows.zip`, verified `100%` row-count and timestamp-bound parity against `data/processed/v2/ait_train.csv.gz` and `data/processed/v2/ait_val.csv.gz`) against `AIT-LDS-v2.1` (`data/raw/ait_lds_v2_1/{fox,russellmitchell}_no-pcaps.zip` across 9 log streams: `auth`, `dns`, `http_access`, `audit`, `suricata_fast`, `suricata_eve_sample`, `openvpn`, `dnsteal`, `attacks`):

| Metric / Dimension | `fox` Scenario | `russellmitchell` Scenario | Cross-Scenario / Verdict |
|---|---|---|---|
| **`AIT-NDS-v2` Total Flows & Parity** | `351,908` flows (`tcp_complete`: `184,521`; `tcp_nocomplete`: `48,296`; `udp_complete`: `119,091`; matches `ait_train.csv.gz`) | `377,704` flows (`tcp_complete`: `123,332`; `tcp_nocomplete`: `154,877`; `udp_complete`: `99,495`; matches `ait_val.csv.gz`) | `100%` raw-to-processed v2 parity (`VERIFIED`) |
| **`AIT-NDS-v2` UTC Window & Duration** | `2022-01-15T00:00:00.869370+00:00` .. `2022-01-19T23:59:59.055075+00:00` (`431,998.185704` s / `4.999979` days) | `2022-01-21T00:00:02.274306+00:00` .. `2022-01-24T23:59:57.389599+00:00` (`345,595.115293` s / `3.999943` days) | Inter-scenario gap: `86,403.219231` s (`1.000037` days, `scenarios_temporally_disjoint: true`) |
| **`AIT-LDS-v2.1` Parsed Log Events** | `1,188,593` events (`1,103,196` in NetFlow window; `85,397` in pre/post simulation tails) | `694,380` events (`637,875` in NetFlow window; `56,505` in pre/post simulation tails) | `1,882,973` total parsed log events audited |
| **`AIT-LDS-v2.1` UTC Window & Duration** | `2022-01-14T07:54:46+00:00` .. `2022-01-20T07:15:10+00:00` (`516,024.0` s / `5.972500` days; lead `57,914.87` s, tail `26,110.94` s) | `2022-01-20T11:12:22+00:00` .. `2022-01-25T07:02:47+00:00` (`417,025.0` s / `4.826678` days; lead `46,060.27` s, tail `25,369.61` s) | Same 2022 testbed run (`v2.0` = `v2.1` capture epoch; `date_gap_seconds: 0.0`) |
| **Clock & Timezone Offset** | `UTC (+00:00)` (`30/30` hosts in `servers.yaml` + `attacker.yaml`) | `UTC (+00:00)` (`22/22` hosts in `servers.yaml` + `attacker.yaml`) | Uniform `UTC (+00:00)` across both sources |
| **`time_window_overlap_seconds`** | **`431,998.185705` s** (`4.999979` days, `100.0%` of `AIT-NDS-v2` window) | **`345,595.115293` s** (`3.999943` days, `100.0%` of `AIT-NDS-v2` window) | `windows_overlap: true` (`nds_window_coverage_ratio: 1.0`) |
| **Configured Host IP Intersection** | **`32 / 32` (`100.0%`)** configured host/attacker IPv4s appear in `AIT-NDS-v2` | **`24 / 24` (`100.0%`)** configured host/attacker IPv4s appear in `AIT-NDS-v2` | `100.0%` testbed host IPv4 coverage |
| **Observed Event IPv4 Intersection** | **`3,162 / 6,707` (`47.14%`)** observed log IPv4s intersect `11,370` `AIT-NDS-v2` IPv4s | **`2,108 / 4,940` (`42.67%`)** observed log IPv4s intersect `34,882` `AIT-NDS-v2` IPv4s | Non-intersecting log IPs are uncontacted DNS A-record replies, pre-window provisioning, or filtered `10.9.0.x` management IPs |
| **`(ip, ±3s)` Matched Events ($\ge 1$ Flow)** | **`798,475 / 1,188,593` (`67.18%` all; `72.38%` in-window)** | **`354,011 / 694,380` (`50.98%` all; `55.50%` in-window)** | High coarse temporal+IP co-occurrence (`tier2_heuristic_ip_pm3s_feasible: true`) |
| **`(ip, ±3s)` Unique `1-to-1` vs Ambiguous (`>1` Flow)** | `96,514` unique `1-to-1` (`12.09%`) vs **`701,961` ambiguous (`87.91%` ambiguity rate; mean `29.09` candidate flows/event, max `5,004`)** | `96,054` unique `1-to-1` (`27.13%`) vs **`257,957` ambiguous (`72.87%` ambiguity rate; mean `16.52` candidate flows/event, max `10,528`)** | **`tier2_row_level_disambiguation_possible: false`** (bursty HTTP/DNS/scan traffic + multi-probe NAT duplication yield 73–88% multi-flow ambiguity) |

**Per-Log-Family `(ip, ±3s)` Alignment Breakdown:**

| Log Family | `fox` Parsed Events | `fox` Matched ($\ge 1$ Flow) | `fox` Ambiguity (`>1` Flow) | `fox` Mean Candidates | `russellmitchell` Parsed Events | `russellmitchell` Matched ($\ge 1$ Flow) | `russellmitchell` Ambiguity (`>1` Flow) | `russellmitchell` Mean Candidates |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `http_access` (`apache2`) | `522,221` | `515,311` (`98.68%`) | `503,930` (`97.79%`) | `36.09` | `75,837` | `71,042` (`93.68%`) | `63,146` (`88.89%`) | `11.32` |
| `suricata_fast` (`fast.log`) | `13,510` | `11,071` (`81.95%`, `99.88%` in-win) | `9,831` (`88.80%`) | `35.30` | `10,457` | `9,167` (`87.66%`, `99.79%` in-win) | `8,103` (`88.39%`) | `41.66` |
| `dnsteal` (`dnsteal.log`) | `18,176` | `14,742` (`81.11%`, `99.97%` in-win) | `209` (`1.42%`) | `1.02` | `20,054` | `15,810` (`78.84%`, `89.28%` in-win) | `123` (`0.78%`) | `1.04` |
| `audit` (`audit.log`) | `24,082` | `12,566` (`52.18%`) | `11,875` (`94.50%`) | `11.36` | `18,740` | `9,376` (`50.03%`) | `8,733` (`93.14%`) | `7.30` |
| `dns` (`dnsmasq.log`) | `576,457` | `240,996` (`41.81%`, `46.94%` in-win) | `172,570` (`71.61%`) | `16.66` | `540,882` | `244,460` (`45.20%`, `48.55%` in-win) | `174,009` (`71.18%`) | `18.33` |
| `auth` (`auth.log*`) | `10,808` | `1,781` (`16.48%`, `21.40%` in-win) | `1,606` (`90.17%`) | `29.53` | `6,818` | `1,315` (`19.29%`, `24.69%` in-win) | `1,167` (`88.75%`) | `58.81` |
| `openvpn` (`openvpn.log`) | `7,299` | `1,085` (`14.87%`) | `1,064` (`98.06%`) | `2.01` | `5,537` | `1,841` (`33.25%`) | `1,736` (`94.30%`) | `1.96` |
| `attacks` (`attacks.log`) | `40` | `7` (`17.50%`) | `5` (`71.43%`) | `580.57` | `55` | `25` (`45.45%`) | `6` (`24.00%`) | `284.96` |
| `suricata_eve_sample` (`8 x 2,000`) | `16,000` | `916` (`5.73%`, `45.80%` in-win) | `871` (`95.09%`) | `8.02` | `16,000` | `975` (`6.09%`, `48.75%` in-win) | `934` (`95.79%`) | `8.60` |

---

## 5. Root Cause of `data exfiltration` / `dnsteal` Window Discrepancy vs `foothold` / `wpscan`

### 5.1 Labeling Logic Asymmetry in `data/raw/ait_nds_v2/2_label_logs.ipynb`

1. **`tcp_complete` & `tcp_nocomplete` (Windowed via `foothold.yaml`, but `escalate.yaml` omitted):**
   - `2_label_logs.ipynb` loads `processing/config/attacker/foothold.yaml` and matches exact UTC `[start, stop]` windows for foothold steps (`host_discover_*`, `service_scan`, `wpscan`, `dirb_scan`, `upload_rce_shell`, `host_recon_commands`, `online_cracking`). As a result, `foothold` phases align closely across datasets — e.g., `fox` `wpscan`:
     - `AIT-LDS-v2.1` `foothold.yaml`: `2022-01-18T12:17:47.924Z .. 2022-01-18T12:18:17.975Z`
     - `AIT-NDS-v2` `fox/tcp_complete.csv`: `128` flows, `2022-01-18T12:17:50.429046Z .. 2022-01-18T12:18:13.388249Z`
     - `AIT-ADS` `labels.csv`: `1642508267.0 .. 1642508310.0` (`2022-01-18T12:17:47Z .. 2022-01-18T12:18:30Z`)
   - *Additional omission:* `2_label_logs.ipynb` **never loads `escalate.yaml`**, causing `fox` reverse shell flows (`2022-01-18T13:13:52.825Z..833Z`, port `51898`) to fall into `label_port_based` (`s_port > 1024`) and be mislabeled benign `"update/command on unassigned port"`.
2. **`udp_complete` (No time window — unbounded `else "data exfiltration"` catch-all):**
   - `2_label_logs.ipynb` **never loads `processing/config/attacker.yaml`** (`dnsteal` / `exfiltration_service` timestamps) or any UDP attack window.
   - Cell 485 (`label_udp(x)`) only checks static benign rules (`123`, `67/68`, `1194`, `3478/19302`, `137/138`, `443 & external`, `5353`, `8.8.8.8`, `127.0.0.53`, non-attacker port `53`, and `attacker_0 -> *:53` update queries) and returns `""` for everything else.
   - Cell 498 then applies an unwindowed catch-all across the entire simulation window (`Simulation time`):
     ```python
     udp["label"] = udp["label"].apply(lambda x: x if x != "" else "data exfiltration")
     ```

### 5.2 Empirical Consequences Across `AIT-NDS-v2`, `AIT-LDS-v2.1` & `AIT-ADS`

| Scenario | `AIT-NDS-v2` `data exfiltration` (Flows & UTC Span) | `AIT-LDS-v2.1` Evidence (`*_no-pcaps.zip` / Metadata) | `AIT-ADS` `labels.csv` (`service_stop` & `dnsteal` UTC) | Discrepancy Impact |
|---|---|---|---|---|
| **`fox`** | `14,668` flows (`192.168.255.254 [inet-dns] -> 192.168.130.77 [attacker_0]:53`), `2022-01-15T00:00:03.118Z .. 2022-01-17T09:04:47.679Z` (3 days: `6,167` / `6,150` / `2,351`) | `attacker.yaml`: `dnsteal` `2022-01-14T10:46:03.727Z .. 2022-01-18T11:56:04.763Z`, `exfiltration_service.stop` `2022-01-17T09:04:47.683Z`; `labels/inet-firewall/logs/dnsmasq.log`: `44,016` `dnsteal` lines `Jan 15 00:00:03 .. Jan 17 09:04:47` | `service_stop`: `2022-01-17T09:04:46Z .. 09:04:48Z`; **`dnsteal`: `2022-01-17T09:04:48Z .. 10:00:00Z`** | **Zero temporal overlap** between `AIT-ADS` `dnsteal` and `AIT-NDS-v2`/`AIT-LDS` `dnsteal`. During `09:04:48..10:00:00`, `fox_wazuh.json` logs `381` routine alerts (`336` Dovecot, `17` Suricata/fast.log, `10` ClamAV) and `0` dnsmasq alerts. |
| **`russellmitchell`** | `15,778` flows (`192.168.231.254 [inet-dns] -> 192.168.230.122 [attacker_0]:53`), `2022-01-21T00:00:09.631Z .. 2022-01-24T04:38:08.210Z` (4 days) | `attacker.yaml`: `dnsteal.stop` `2022-01-24T13:50:03.250Z`, `exfiltration_service.stop` `2022-01-24T13:50:39.298Z`; `labels/inet-firewall/logs/dnsmasq.log`: `53,054` `dnsteal` lines up to `Jan 24 13:52:15` | `service_stop`: `2022-01-24T13:50:38Z .. 13:50:40Z`; **`dnsteal`: `2022-01-24T13:50:40Z .. 14:50:40Z`** | `AIT-NDS-v2` `data exfiltration` (and all `attacker_0` UDP) terminates at `04:38:08Z`, **~9h12m before** `exfiltration_service.stop` and `AIT-ADS` `dnsteal`. |
| **`shaw`** | `60,898` flows (`10.70.32.4` [40,599] & `192.168.188.120` [20,299], `role_cli=external` -> `10.70.33.202 [attacker_0]:53`, `fqdn='-'`), `2022-01-25T00:00:09.947Z .. 2022-01-28T21:08:01.487Z` | `1_format_dataset_info.ipynb` & Zenodo `19483937` state: **`Exfiltration visible in DNS logs: No`** | `service_stop`: `2022-01-28T21:08:00Z .. 21:08:02Z`; **`dnsteal`: `2022-01-28T21:08:02Z .. 22:08:02Z`** | Catch-all `else "data exfiltration"` swept `60,898` unmatched `external -> attacker_0:53` UDP flows into `data exfiltration` despite non-DNS-logged exfiltration, and stays disjoint from `AIT-ADS` `dnsteal`. |
| **`harrison`, `santos`, `wardbeck`, `wheeler`, `wilson`** | `23,457` / `12,848` / `15,076` / `19,177` / `21,219` flows (`inet-dns -> attacker_0:53`), each spanning 2–5 days up to/before `service_stop` | Not locally downloaded (`*_no-pcaps.zip` absent) | Each sets `dnsteal` strictly **after** `service_stop.end` (`+1h` or `+2h`) | Consistent structural offset: `AIT-ADS` `labels.csv` timestamps `dnsteal` post-`service_stop`, whereas `AIT-NDS-v2` labels multi-day pre-stop UDP traffic. |

---

## 6. Enforced Engineering & Traceability Rules

1. **No Synthetic Foreign Keys:** Never fabricate a synthetic `flow_id`, `uid`, or `conn_id` to join `AIT-NDS-v2` rows to `AIT-LDS-v2.1` logs or `AIT-ADS` alerts.
2. **Strict Heuristic Framing:** Trace Engine and Behavioral Vector may perform Tier-2 correlation **only** via `(scenario, normalized_ip_entity, utc_epoch_window)` and must explicitly label such correlations as heuristic co-occurrence — **never** as ground-truth flow-to-log identity.
3. **Explicit Caveat Emission:** Any cross-source evaluation using `AIT-NDS-v2` + `AIT-LDS-v2.1` + `AIT-ADS` must surface (a) `AIT-LDS-v2.0` vs `v2.1` `no-pcaps` provenance boundary, (b) `CC BY-NC-SA 4.0` vs `CC BY 4.0` licensing split, (c) multi-probe NAT duplication and VPN IP aliasing, and (d) the `2_label_logs.ipynb` `data exfiltration` catch-all vs `AIT-ADS` post-`service_stop` `dnsteal` window mismatch.
4. **Issue `#85` Gate & Scientific Boundary:** Empirical `(ip, ±3s)` log-to-flow alignment on verified UTC-synchronized scenarios (`fox`, `russellmitchell`) has been executed (`scripts/verify_ait_timestamp_alignment.py` $\to$ `reports/datasets/ait_timestamp_alignment_report.json`), quantitatively proving both coarse temporal/IP overlap (`100%` NetFlow window overlap, `67.18%` / `50.98%` event match rate) and severe multi-flow ambiguity (`87.91%` / `72.87%` matched events map to $>1$ candidate flow). Consequently, **Tier 1 (`DIRECT_UID_LINK`) remains `FALSE`** and **Tier 3 (`AIT-LDS-v2.0` PCAP regeneration) remains `UNVERIFIED`** unless full `AIT-LDS-v2.0` PCAPs or a campaign dataset with native flow/session UIDs is acquired.
