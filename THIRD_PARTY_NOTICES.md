# Third-Party Notices & Licensing

## 1. NetFlow Sentinel Source Code

- **License:** [Apache License, Version 2.0](LICENSE)
- **Scope:** Application source code (`src/`, `desktop/`, `scripts/`, `docs/`, `tests/`).

## 2. Dataset & Derived ML Artifacts (Non-Commercial Academic Restriction)

- **Dataset:** `NF-UNSW-NB15-v3`
- **Publisher:** The University of Queensland
- **DOI:** `10.48610/6E0EDA1`
- **UQ RDM UUID:** `abd2f5d8-e268-4ff0-84fb-f2f7b3ca3e8f`
- **Citation:** Majed Luay, Siamak Layeghy, Seyedehfaezeh Hosseininoorbin, Mohanad Sarhan, Nour Moustafa, and Marius Portmann, *"Temporal Analysis of NetFlow Datasets for Network Intrusion Detection Systems"*, `arXiv:2503.04404` (2025).
- **License Terms:** *Permitted Re-Use with Commercial Use Restriction* (UQ License ID `454104`, <https://guides.library.uq.edu.au/research-and-teaching-staff/data-deposit-checklist/license-reuse-noncommercial>).
- **Scope in Standalone Installer:** The embedded Validation demo CSV (`data/demo/demo_flows.csv`, `data/demo/demo_labels.csv`) and the pre-trained preprocessor and 4 ML models (`Random Forest`, `XGBoost`, `Isolation Forest`, `Autoencoder`) are distributed strictly for **academic, educational, and non-commercial research demonstration**. Any commercial use or redistribution requires separate written authorization from The University of Queensland / dataset authors.

## 3. Embedded Runtime & Desktop Software Components

The standalone Windows installer bundles compiled/packaged binaries of open-source libraries, each retaining its original license:

| Component | Purpose | License |
|---|---|---|
| Python Runtime (CPython 3.12+) | Embedded Python interpreter in backend sidecar | PSF License Agreement |
| PyInstaller | Backend executable packaging (bootloader exception applies) | GPL-2.0-or-later with Bootloader Exception |
| FastAPI | Localhost REST API framework (`127.0.0.1`) | MIT |
| Uvicorn | ASGI HTTP server | BSD-3-Clause |
| Pydantic | Schema validation & serialization | MIT |
| NumPy | Numerical array processing | BSD-3-Clause |
| Pandas | Tabular CSV streaming & processing | BSD-3-Clause |
| scikit-learn | Preprocessing, Random Forest, Isolation Forest, Autoencoder (`MLPRegressor`) | BSD-3-Clause |
| XGBoost | Gradient boosted decision tree classifier | Apache-2.0 |
| joblib | Verified artifact serialization/deserialization | BSD-3-Clause |
| httpx | HTTP client for testing & loopback checks | BSD-3-Clause |
| Tauri 2 | Native Windows desktop shell & IPC bridge | Apache-2.0 / MIT |
| Svelte 5 | Desktop frontend UI framework | MIT |
| Microsoft Edge WebView2 Runtime | Windows desktop HTML/JS rendering engine (when bundled/installed) | Microsoft Software License Terms |
