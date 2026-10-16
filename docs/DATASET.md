# Dataset — UNSW-NB15

## Source

- **Name:** UNSW-NB15 (University of New South Wales — Network Based Data Set 15)
- **Primary sources (planned references; verify at time of download):**
  - UNSW Canberra Cyber Center dataset portal
  - Research paper / documentation from UNSW (recorded in references)
- **Access:** Public for research/academic use; check current license/terms before redistribution.
- **Access date / verification:** Not yet verified at write time (2026-10-16). Plan to confirm before first training run.
- **Checksum / file integrity:** Not yet verified. Plan to record SHA-256 or MD5 after download if available from source.

## Structure (planned; verify after download)

- CSV files (e.g., UNSW-NB15.csv, UNSW-NB15_training_set.csv, UNSW-NB15_testing_set.csv depending on release version).
- Columns include: src_ip, dst_ip, sport, dport, proto, service, duration, state, sbytes, dbytes, sttl, dttl, sloss, dloss, sload, dload, spkts, dpkts, swin, dwin, stcpb, dtcpb, sresb, dresb, stime, atime, ltim, ct_flw_http_mthd, ct_flw_http_done, ct_src_ltm, ct_src_dport_ltm, ct_dst_sm, ct_dst_sport_ltm, ct_dst_ltm, ct_src_dport_ltm, is_ftp_login, ct_ftp_cmd, ct_ftp_subcmd, ct_flw_http_mthd, label (or similar).
- Label values: typically 0 = normal, 1 = anomaly; some versions include attack categories (e.g., Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms).

## Usage license / conditions

- UNSW-NB15 is provided for research/academic purposes. Do not redistribute derived datasets that include the original data without confirming terms.
- This repository does NOT include UNSW-NB15 files because of size (~2.5 GB compressed, larger uncompressed) and licensing conditions.
- Users must download from official source, place files in `data/raw/`, and verify schema before running experiments.

## Download instructions (planned)

1. Visit official UNSW dataset portal (link to be confirmed in `REPRODUCIBILITY.md` after verification).
2. Download dataset package (CSV or CSV + label files).
3. Verify file names and structure against documentation.
4. Place files in `data/raw/`.
5. Run `python scripts/validate_data.py` to check schema and basic statistics.
6. Note version and checksum in `REPRODUCIBILITY.md`.

## Data limitations (must document before training)

- Class imbalance expected (normal >> anomalies in some versions).
- Possible missing values; must check per column.
- Possible duplicate rows; must check and document removal rule.
- Identity columns (source/destination IP, ports, timestamps) can cause leakage if used directly or if split is not by time/session; must audit and document selection/removal.
- Feature encoding needed for categorical variables (protocol, service, state, TCP flags).

## Fixture data for testing

- `tests/` uses synthetic fixtures (`tests/unit/fixture_small.csv`) to verify pipeline components without requiring the full dataset.
- Fixture is clearly marked as synthetic, not UNSW-NB15.

Updated: 2026-10-16 — download instructions and checksum verification planned; not verified yet.
