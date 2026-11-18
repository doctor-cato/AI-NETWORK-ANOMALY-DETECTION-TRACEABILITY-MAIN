# Third-Party Notices & Licensing

## 1. NetFlow Sentinel Source Code

- **License:** [Apache License, Version 2.0](LICENSE)
- **Scope:** Application source code (`src/`, `desktop/`, `scripts/`, `docs/`, `tests/`).

## 2. v2 Datasets & Derived ML Artifacts

- **Primary Training & Demo Dataset:** `AIT NetFlow Data Set v2` (`AIT-NDS-v2`, DOI `10.5281/zenodo.13168643`), Publisher: AIT Austrian Institute of Technology GmbH, derived from `AIT-LDS-v2.0` PCAPs. License: **CC BY 4.0** (<https://creativecommons.org/licenses/by/4.0/>).
- **Real Captured External Benchmark:** `CTU-SME-11` (DOI `10.5281/zenodo.7958258`, record `7958259`), Publisher: Stratosphere Laboratory, CTU Prague. License: **CC BY 4.0**.
- **Alert Correlation Dataset:** `AIT Alert Data Set` (`AIT-ADS`, DOI `10.5281/zenodo.8263181`), Publisher: AIT Austrian Institute of Technology GmbH (derived from `AIT-LDS-v2.0`). License: **CC BY 4.0**.
- **Host/System Log Correlation Dataset (research/correlation only, not bundled into ML weights or demo CSV):** `AIT Log Data Set v2.1` (`AIT-LDS-v2.1`, DOI `10.5281/zenodo.19483937`), License: **CC BY-NC-SA 4.0**.
- **Attribution Obligation:** Proper credit to AIT Austrian Institute of Technology and Stratosphere Laboratory (CTU Prague) must be preserved when distributing derived models (`artifacts/models/`, `artifacts/preprocessing/v2_flow_preprocessor.joblib`) and demo subsets (`data/demo/demo_flows.csv`).

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
| cryptography (pyca/cryptography) | AES-256-GCM authenticated encryption & key lifecycle | Apache-2.0 / BSD-3-Clause |
| httpx | HTTP client for testing & loopback checks | BSD-3-Clause |
| Tauri 2 | Native Windows desktop shell & IPC bridge | Apache-2.0 / MIT |
| Svelte 5 | Desktop frontend UI framework | MIT |
| Microsoft Edge WebView2 Runtime | Windows desktop HTML/JS rendering engine (when bundled/installed) | Microsoft Software License Terms |
