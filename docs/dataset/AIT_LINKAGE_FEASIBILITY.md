# AIT Cross-Source Linkage Feasibility Report

## Scope & Provenance Check
- **Flow source:** `AIT-NDS-v2` (`10.5281/zenodo.13168643`, Tstat output from `AIT-LDS-v2.0` PCAPs)
- **Log source:** `AIT-LDS-v2.1` (`10.5281/zenodo.19483937`, `fox_no-pcaps.zip` [16094 files], `russellmitchell_no-pcaps.zip` [14898 files])
- **Alert source:** `AIT-ADS` (`10.5281/zenodo.8263181`, alerts generated on `AIT-LDS-v2.0`)

## Empirical Findings (`fox` scenario)
- **Direct Flow-UID Join:** `NOT VERIFIED` (`direct_uid_join_possible: False`). Tstat netflow rows have no shared Zeek/Wazuh/host log UID.
- **Host IP Entity Overlap:** `11/11` Wazuh agent IPs appear verbatim in `fox_netflows.zip`.
- **Timestamp & Version Synchronization Caveat:** AIT-NDS-v2 and AIT-ADS derive from AIT-LDS-v2.0, while downloaded log archive is AIT-LDS-v2.1 (10.5281/zenodo.19483937). Observed window discrepancy in fox: AIT-NDS-v2 labels `data exfiltration` across 2022-01-15T00:00:03Z..2022-01-17T09:04:47Z, whereas AIT-ADS labels.csv records `dnsteal` at 2022-01-17T09:04:48..10:00:00 (epoch).
- **Engineering Policy:** Trace Engine and Behavioral Vector correlate flow, log, and alert events ONLY via `(scenario, normalized_ip_entity, utc_epoch_window)` and emit explicit cross-source caveats; never fabricate a synthetic foreign key.
