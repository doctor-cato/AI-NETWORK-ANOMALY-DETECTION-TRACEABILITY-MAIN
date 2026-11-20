# ADR: Hard Dataset Cutover from NF-UNSW-NB15-v3 (v1) to AIT + Real Captured Traffic (v2)

> **Architecture Decision Record**
> **Status:** ACCEPTED
> **Date:** 2026-11-18
> **Scope:** Full Dataset Migration — NetFlow Sentinel v2

---

## 1. Context

NetFlow Sentinel v1.0.0 was built on **NF-UNSW-NB15-v3** (University of Queensland nProbe v3 feature export, 55 columns / 47 ML features). Empirical audits (`RQ1`–`RQ4` and `MODEL_AUDIT_TTL_ABLATION`) proved two structural weaknesses:

1. **Testbed Shortcut & Collapse:** Supervised models (Random Forest, XGBoost) achieved near-1.00 F1 on the in-domain UNSW-NB15 test split largely due to testbed artifacts such as `MIN_TTL`/`MAX_TTL`, collapsing to `Recall = 0.0` when evaluated out-of-distribution on `NF-CSE-CIC-IDS2018-v3`.
2. **Schema & Multi-Source Mismatch:** The 47 nProbe v3 columns are not natively available from standard NetFlow v9/IPFIX exporters, Tstat flow probes, Zeek `conn.log`, or enterprise host/application logs, causing `NOT_MODEL_READY` rejection or tempting unsafe zero-imputation.
3. **Licensing Constraints:** NF-UNSW-NB15-v3 is governed by UQ License ID `454104` (*Permitted Re-Use with Commercial Use Restriction*), preventing open redistribution of derived demo assets and standalone installers.

## 2. Decision

Execute a **hard cutover** for NetFlow Sentinel v2 rather than maintaining a dual-pipeline adapter for NF-UNSW-NB15-v3:

1. **Retire NF-UNSW-NB15-v3 to Historical Archive:** Move all v1 manifests, split protocols, preprocessing artifacts, model binaries/manifests, evaluation reports, and dataset scripts into `*/historical/nf_unsw_nb15_v3/`.
2. **Adopt Multi-Source Simulation + Real Captured Traffic:**
   - **AIT NetFlow Data Set v2** (`10.5281/zenodo.13168643`, CC BY 4.0) as the primary synthetic NetFlow ML benchmark (Tstat flows derived from AIT-LDS-v2.0 PCAPs across 8 enterprise testbed scenarios).
   - **AIT Log Data Set v2.1** (`10.5281/zenodo.19483937`, CC BY-NC-SA 4.0) for application/system/DNS/auth logs and behavioral/risk/trace correlation (after verifying version and timestamp alignment with AIT-NDS-v2).
   - **AIT Alert Data Set** (`10.5281/zenodo.8263181`, CC BY 4.0) for alert aggregation, multi-step attack timelines, and correlation evaluation (not as an independent ML flow benchmark).
   - **CTU-SME-11** (`10.5281/zenodo.7958258`, CC BY 4.0) as expert-labeled real captured network traffic from a physical/virtualized SME environment (11 devices, 7 days).
   - **UGR'16** (`https://nesg.ugr.es/nesg-ugr16/`): Evaluated for real ISP traffic external validation; currently marked `BLOCKED` if official portal is in maintenance / HTTP 403 Forbidden.
3. **Build Canonical Flow Feature Contract v2:** Define the ML feature contract strictly from real, semantically equivalent fields shared across the active flow sources (bidirectional bytes, packets, duration, protocol, and derived rates/ratios), with zero fabricated features, zero TTL shortcuts, and zero cross-source silent imputation.
4. **Retrain All 4 Models from Scratch:** Retrain Random Forest, XGBoost, Isolation Forest, and Autoencoder on the v2 split using train-only preprocessing and validation-only threshold calibration, generating fresh manifests, thresholds, and SHA-256 checksums.
5. **No v1 Fallback:** `ModelRegistry`, `InferencePipeline`, FastAPI endpoints, and the Desktop app must reject v1/47-feature artifacts and never fall back to NF-UNSW-NB15-v3.
6. **Preserve Dataset-Independent Product Core:** Keep the Rust/Tauri 2 desktop shell, Svelte 5 UI architecture, FastAPI lifecycle/security, AES-256-GCM DPAPI keystore & adaptive key rotation, Behavioral Vector engine, Risk Engine, Trace Engine, and CI/CD quality gates.

## 3. Consequences

- **Positive:** Eliminates `MIN_TTL` shortcut contamination, aligns ML features with real-world probes (Tstat, Zeek, NetFlow/IPFIX), unblocks open CC-BY-4.0 licensing for flow models/demo data, and enforces honest cross-dataset generalization testing.
- **Negative / Trade-offs:** Historical v1 benchmark numbers are archived and cannot be compared directly as like-for-like metrics; v2 models must earn their metrics transparently on harder, multi-scenario and real-captured traffic.
