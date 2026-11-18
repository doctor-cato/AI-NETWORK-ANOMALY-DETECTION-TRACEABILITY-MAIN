# Experiment 5 (RQ3): IP-Independent Session Correlation Benchmark

- **Experiment ID:** `EXP-RQ3-CORRELATION-01`
- **Source Report:** `reports/experiments/behavioral/rq3_session_correlation_experiment.json`
- **Execution Script:** `scripts/run_rq3_session_correlation_experiment.py`
- **Track 1 — Synthetic Behavioral Simulation:** `SIMULATION` (**`simulation_hypothesis_met = false`**)
- **Track 2 — Empirical Cross-Source AIT Validation:** **`BLOCKED`** (`empirical_dataset_status = "BLOCKED"`; Issue `#85` remains **`OPEN (2/3 AC)`** per [`AIT_LINKAGE_FEASIBILITY.md`](../dataset/AIT_LINKAGE_FEASIBILITY.md))
- **Timestamp (UTC):** `2026-11-17T23:04:51.208727+00:00`
- **Hypothesis (H3):** `Behavioral Vector achieves >= 85% session correlation F1/recall independent of IP`

---

## 1. Track 1 — Synthetic IP-Rotation Simulation (`SIMULATION`)

### 1.1 Experimental Configuration
- **Data Source:** `synthetic_ip_rotation_benchmark (synthetic: true)`
- **Scale:** `5` distinct attack campaigns × `4` sessions/campaign = `20` total sessions (`190` unordered session pairs: `30` same-campaign positive pairs, `160` cross-campaign negative pairs)
- **Feature Representation:** `16`-D Behavioral Vector (`cosine_match_threshold = 0.85`; secondary strict ablation at `0.95`), computed strictly without ground-truth labels or IP matching during similarity scoring
- **Seed & Runtime:** `random_seed = 42` (`Windows-11-10.0.26200-SP0`, `Python 3.12.10`, `numpy 2.5.5`, `pandas 3.1.1`, `scikit_learn 1.9.1`, `xgboost 3.4.1`)

### 1.2 Simulation Ablation Results (Exact Counts & Metrics from JSON)

| Strategy | Total Pairs | TP | FP | FN | TN | Pairwise Precision | Pairwise Recall | Pairwise F1 | False Link Rate | Match Accuracy |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **Strategy A:** IP Exact Match | 190 | 0 | 0 | 30 | 160 | 0.0000 | 0.0000 | 0.0000 | 0.0000 | 0.8421 |
| **Strategy B:** 16-D Behavioral Vector (`cos >= 0.85`) | 190 | 30 | 128 | 0 | 32 | 0.1899 | 1.0000 | 0.3191 | 0.8000 | 0.3263 |
| **Strategy B (Strict `cos >= 0.95`)** | 190 | 30 | 48 | 0 | 112 | 0.3846 | 1.0000 | 0.5556 | 0.3000 | 0.7474 |

### 1.3 Simulation Analysis & Hypothesis Verdict (`simulation_hypothesis_met = false`)
- **Where Strategy B outperforms Strategy A:** Under simulated per-session IP rotation (`198.51.<campaign>.<session>`), exact IP matching misses all `30/30` same-campaign pairs (`pairwise_recall = 0.0000`, `pairwise_f1 = 0.0000`), whereas Strategy B recovers `30/30` true pairs (`pairwise_recall = 1.0000`) at both `cos >= 0.85` and `cos >= 0.95`.
- **Why H3 is NOT confirmed even in simulation (`simulation_hypothesis_met: false`):** `H3` requires `pairwise_f1 >= 0.85`. At the default `0.85` cosine threshold, cross-campaign vector collisions produce `128` false-positive links (`false_link_rate = 0.8000`, `pairwise_precision = 0.1899`, `pairwise_f1 = 0.3191`). Raising the threshold to `0.95` cuts false links from `128` to `48` (`false_link_rate = 0.3000`, `pairwise_precision = 0.3846`, `pairwise_f1 = 0.5556`), which improves precision but still falls short of the `>= 0.85` F1 gate.

---

## 2. Track 2 — Empirical Cross-Source AIT Evaluation (`BLOCKED`)

Empirical cross-source validation on the AIT dataset suite is **`BLOCKED`** and strictly separated from the synthetic simulation above:

1. **Automated Experiment Gate (`rq3_session_correlation_experiment.json`):**
   - `official_ait_source_doi`: `10.5281/zenodo.13168643`
   - `empirical_ait_evaluation.status`: **`BLOCKED`** (`files_detected: 0` in `data\raw\ait`)
   - Recorded reason: *"Official AIT campaign-linkage ground truth absent or not verified in `data\raw\ait`; empirical real-dataset validation cannot be claimed from simulation alone."*
2. **Cross-Source Linkage Audit Findings ([`AIT_LINKAGE_FEASIBILITY.md`](../dataset/AIT_LINKAGE_FEASIBILITY.md), Issue `#85` `OPEN (2/3 AC)`):**
   - Even against the verified local archives (`data/raw/ait_nds_v2/`, `data/raw/ait_lds_v2_1/` `*_no-pcaps.zip` subset, and `data/raw/ait_ads/`), empirical pairwise session-correlation scoring remains blocked under the 3-tier linkage policy:
     - **Tier 1 (`DIRECT_UID_LINK: NO — FALSE`):** `AIT-NDS-v2` Tstat NetFlows (`tcp_complete`, `tcp_nocomplete`, `udp_complete`) share **no** `uid`, `flow_id`, `conn_id`, `packet_id`, or `community_id` with `AIT-LDS-v2.1` logs/line-numbered `labels/` or `AIT-ADS` alerts.
     - **Tier 2 (`ENTITY_TIME_CORRELATION: HEURISTIC ONLY`):** Host IP overlap (e.g., `11/11` `fox` Wazuh agent IPs in `fox_netflows.zip`) does not establish row-level flow identity (due to NAT duplication across multi-probe Tstat captures and attacker VPN IP aliasing), and temporal proximity is not a UID (compounded by `2_label_logs.ipynb`'s unwindowed multi-day `data exfiltration` catch-all vs `AIT-ADS` `labels.csv` post-`service_stop` `dnsteal` windows and omitted `escalate.yaml` labels).
     - **Tier 3 (`UNVERIFIED`):** Full `AIT-LDS-v2.0` (`10.5281/zenodo.5789064`) PCAP archives were not downloaded locally (`*_no-pcaps.zip` only for `fox` and `russellmitchell`), leaving cross-version full-packet alignment unverified.

---

## 3. Limitations & Reproducibility

- Synthetic IP-rotation simulation tests algorithmic behavior only (`simulation_hypothesis_met = false`) and **MUST NOT** be treated as empirical validation on real enterprise or multi-source AIT datasets.
- Empirical AIT cross-source session correlation remains **`BLOCKED`**; Issue `#85` stays **`OPEN (2/3 AC)`**.
- **Reproduce simulation JSON:**
  ```powershell
  python scripts/run_rq3_session_correlation_experiment.py
  ```
  *(Note: running `scripts/run_rq3_session_correlation_experiment.py` regenerates both `reports/experiments/behavioral/rq3_session_correlation_experiment.json` and the compact summary template in `docs/experiments/EXP5_SESSION_CORRELATION.md`; preserve this audited Markdown documentation unless deliberately re-running the experiment.)*
