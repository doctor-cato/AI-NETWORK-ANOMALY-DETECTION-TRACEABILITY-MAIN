# NetFlow Sentinel M6 (`v0.6.0`) — Desktop Application

Offline-capable Windows x64 desktop application for UNSW-NB15-v3 NetFlow anomaly detection and forensic inspection (requires local Python backend and verified model artifacts).

- **Desktop App Version**: `0.6.0` (synchronized across `Cargo.toml`, `Cargo.lock`, `package.json`, `package-lock.json`, and `tauri.conf.json`; verified by `python scripts/check_desktop_version.py --check`).
- **Python Backend / FastAPI Contract Version**: `0.1.0` (`pyproject.toml`, `src/network_anomaly/__init__.py`, `src/network_anomaly/api/main.py`).

## Architecture

- **Desktop Shell**: Rust + Tauri 2 (`desktop/src-tauri/`)
  - Embeds the compiled Svelte 5 frontend (`desktop/dist/`) via Tauri `custom-protocol` (`http://tauri.localhost/`).
  - Spawns and manages the local Python backend child process (`scripts/run_api.py`) bound strictly to loopback (`127.0.0.1`) on an available port.
  - Resolves the real Python interpreter (`sys.executable` via `resolve_python_candidate`) and terminates the Python process tree on window close or app exit (`taskkill /PID <pid> /T /F` on Windows).
  - Exposes typed Tauri IPC commands (`desktop/src-tauri/src/commands.rs`) for native CSV open/save dialogs and localhost HTTP forwarding (`127.0.0.1` / `localhost` guard enforced).
- **Frontend UI**: Svelte 5 + Vite + TypeScript (`desktop/src/`)
  - 4-model readiness panel (`Random Forest`, `Isolation Forest`, `XGBoost`, `Autoencoder`) with fail-closed SHA-256 verification and score-semantics preservation (`N/A (Unsupervised)` for Isolation Forest, `ABSTAINED (OOD)` for OOD-abstained rows).
  - CSV schema/OOD inspection (`47/47 ML Features`, `MIN_TTL=0` drift check), batch inference table, detached Ground Truth confusion matrix evaluation (excluding `ABSTAINED_OOD` rows and reporting `abstained_rows`), deterministic Evidence Timeline (`#24`), behavioral summary (`#28`), and CSV + `.metadata.json` export.
- **Local Backend**: Python FastAPI + SQLite (`src/network_anomaly/api/`, `scripts/run_api.py`)
  - Runs strictly on `127.0.0.1` (`--host 0.0.0.0` is refused without `--allow-non-local`).
  - Verifies CSV source provenance (`resolve_csv_source_provenance`) before assigning `source:nf-v3-canonical` (`MODEL_VALIDATED`); external/unverified CSVs receive `source:nf-v3-unverified` (`SEMANTICALLY_COMPATIBLE` / `VALIDATION_NOT_VERIFIED`).
  - Abstains from both inference and risk scoring on OOD-flagged rows (`predicted_label = null`, `predicted_class = "ABSTAINED_OOD"`, `risk_level = "ABSTAINED_OOD"`).
  - Persists telemetry/audit state into SQLite (`%LOCALAPPDATA%\NetFlowSentinelM6\network_anomaly.db` by default or `NETWORK_ANOMALY_DB_PATH`).

## Development & Build Commands

Run from the repository root (`AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN`):

1. **Verify desktop version consistency**:
   ```powershell
   python scripts/check_desktop_version.py --check
   ```
2. **Install frontend dependencies & build embedded UI assets (`desktop/dist/`)**:
   ```powershell
   npm --prefix desktop ci
   npm --prefix desktop run check
   npm --prefix desktop test
   npm --prefix desktop run build
   ```
3. **Rust checks & tests** (builds/tests against `desktop/dist/`):
   ```powershell
   cargo fmt --manifest-path desktop/src-tauri/Cargo.toml --check
   cargo clippy --manifest-path desktop/src-tauri/Cargo.toml --all-targets -- -D warnings
   cargo test --manifest-path desktop/src-tauri/Cargo.toml
   ```
4. **Build compiled release executable (`http://tauri.localhost/` embedded frontend, requires external Python backend)**:
   ```powershell
   cargo build --release --manifest-path desktop/src-tauri/Cargo.toml
   ```
   Output: `desktop/src-tauri/target/release/netflow-sentinel-desktop.exe`.
5. **Build Tauri Windows x64 NSIS installer**:
   ```powershell
   npx --prefix desktop tauri build --bundles nsis
   ```
   Output: `desktop/src-tauri/target/release/bundle/nsis/NetFlow Sentinel M6_0.6.0_x64-setup.exe`.
6. **Development mode with hot reload** (`devUrl: http://localhost:1420`):
   ```powershell
   npx --prefix desktop tauri dev
   ```

## Honesty Contract & Packaging Boundary

- `netflow-sentinel-desktop.exe` (and the NSIS installer `NetFlow Sentinel M6_0.6.0_x64-setup.exe`) **embeds the Svelte 5 frontend (`desktop/dist/`)**, so it runs without any external Vite dev server (`localhost:1420` is only used during `tauri dev`).
- **Not a self-contained standalone installer**: M6 `v0.6.0` does **not** bundle an embedded Python interpreter, PyInstaller sidecar, or `.joblib` model artifacts inside the `.exe`. Do not distribute `netflow-sentinel-desktop.exe` as a standalone portable app.
- The target Windows x64 machine requires:
  - **Microsoft Edge WebView2 Runtime**: Pre-installed on Windows 11 and updated Windows 10. Note that Tauri's default NSIS script (`INSTALLWEBVIEW2MODE "downloadBootstrapper"`) downloads `MicrosoftEdgeWebview2Setup.exe` from Microsoft if WebView2 Runtime is missing on the machine; therefore, on an air-gapped machine without WebView2 Runtime, the Microsoft Edge WebView2 Evergreen Standalone Offline Installer must be installed beforehand.
  - **Repository runtime directory layout** (`src/network_anomaly/`, `scripts/run_api.py`, `artifacts/`, `reports/` — resolved via `NETWORK_ANOMALY_REPO_ROOT` or working/executable ancestor search).
  - **Python `>=3.10`** (3.11 / 3.12 recommended) with project dependencies installed (`pip install -e .`), discoverable via `NETWORK_ANOMALY_PYTHON`, `.venv\Scripts\python.exe`, `py -3.14` / `py -3.12` / `py -3`, or `python`.
  - **Verified `.joblib` model & preprocessor artifacts** in `artifacts/` matching manifest SHA-256 digests in `reports/` (missing or mismatched artifacts report `BLOCKED / NOT READY` fail-closed with HTTP `503`).
  - **Demo CSV dataset** (`data/demo/demo_flows.csv`, `data/demo/demo_labels.csv`, `data/demo/demo_manifest.json`) generated via `python scripts/prepare_demo_dataset.py`.

## Documentation References

- Windows Installation & Offline Operation Guide: [`../docs/WINDOWS_INSTALLATION.md`](../docs/WINDOWS_INSTALLATION.md)
- Packaging & Release Engineering Process: [`../docs/RELEASE_PROCESS.md`](../docs/RELEASE_PROCESS.md)
- M6 `v0.6.0` Release Notes: [`../docs/releases/v0.6.0.md`](../docs/releases/v0.6.0.md)
