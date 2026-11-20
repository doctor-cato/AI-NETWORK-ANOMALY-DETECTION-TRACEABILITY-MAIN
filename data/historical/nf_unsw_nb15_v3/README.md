# Historical Data Archive: NF-UNSW-NB15-v3 (v1)

This directory archives the v1 dataset provenance and split manifests for **NF-UNSW-NB15-v3** (and the deferred v1 external manifest `NF_CSE_CIC_IDS2018_V3_MANIFEST.json`) following the **NetFlow Sentinel v2 Hard Cutover**.

## Status
- **Status:** `HISTORICAL ONLY`
- **Active Pipeline Usage:** **PROHIBITED** — Active v2 code, ingestion, preprocessing, model training, and inference MUST NOT load or fall back to NF-UNSW-NB15-v3 artifacts, splits, or 47-feature contracts.
- **Reason for Cutover:**
  1. NF-UNSW-NB15-v3 contains strong testbed TTL shortcuts (`MIN_TTL`/`MAX_TTL`) and lab-specific nProbe v3 features (`nf-unsw-nb15-v3-baseline-47`) that do not generalize across real-world or non-nProbe flow sources.
  2. UQ License ID `454104` (*Permitted Re-Use with Commercial Use Restriction*) restricted binary distribution and created incompatible dependencies.
  3. NetFlow Sentinel v2 replaces NF-UNSW-NB15-v3 with AIT NetFlow Data Set v2 (`10.5281/zenodo.13168643`), AIT Log Data Set v2.1 (`10.5281/zenodo.19483937`), AIT Alert Data Set (`10.5281/zenodo.8263181`), and real captured network traffic from CTU-SME-11 (`10.5281/zenodo.7958258`).
