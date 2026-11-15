# NetFlow Sentinel M6 — Desktop Application

Offline Windows desktop application for UNSW-NB15-v3 NetFlow anomaly detection and forensic inspection.

## Architecture

- **Desktop Shell**: Rust + Tauri 2 (`desktop/src-tauri/`)
  - Embeds the compiled Svelte 5 frontend (`desktop/dist/`) via Tauri `custom-protocol` (`http://tauri.localhost/`).
  - Spawns and manages the local Python backend child process (`scripts/run_api.py`) bound strictly to loopback (`127.0.0.1`) on an available port.
  - Resolves the real Python interpreter (`sys.executable` via `resolve_python_candidate`) and terminates the Python process tree on window close or app exit (`taskkill /PID <pid> /T /F` on Windows).
  - Exposes typed Tauri IPC commands (`desktop/src-tauri/src/commands.rs`) for native CSV open/save dialogs and localhost HTTP forwarding (`127.0.0.1` / `localhost` guard enforced).
- **Frontend UI**: Svelte 5 + Vite + TypeScript (`desktop/src/`)
  - 4-model readiness panel (`Random Forest`, `Isolation Forest`, `XGBoost`, `Autoencoder`) with fail-closed SHA-256 verification and score-semantics preservation (`N/A (Unsupervised)` for Isolation Forest).
  - CSV schema/OOD inspection (`47/47 ML Features`, `MIN_TTL=0` drift check), batch inference table, detached Ground Truth confusion matrix evaluation, deterministic Evidence Timeline (`#24`), behavioral summary (`#28`), and CSV + `.metadata.json` export.
- **Local Backend**: Python FastAPI + SQLite (`src/network_anomaly/api/`, `scripts/run_api.py`)
  - Runs strictly on `127.0.0.1` (`--host 0.0.0.0` is refused without `--allow-non-local`).
  - Persists telemetry/audit state into SQLite (`%LOCALAPPDATA%\NetFlowSentinelM6\network_anomaly.db` by default or `NETWORK_ANOMALY_DB_PATH`).

## Development & Build Commands

Run from the repository root (`AI-NETWORK-ANOMALY-DETECTION-TRACEABILITY-MAIN`):

1. **Install frontend dependencies & build embedded UI assets (`desktop/dist/`)**:
   ```powershell
   npm --prefix desktop ci
   npm --prefix desktop run check
   npm --prefix desktop test
   npm --prefix desktop run build
   ```
2. **Rust checks & tests** (builds/tests against `desktop/dist/`):
   ```powershell
   cargo fmt --manifest-path desktop/src-tauri/Cargo.toml --check
   cargo clippy --manifest-path desktop/src-tauri/Cargo.toml --all-targets -- -D warnings
   cargo test --manifest-path desktop/src-tauri/Cargo.toml
   ```
3. **Build standalone release binary (`http://tauri.localhost/` embedded frontend)**:
   ```powershell
   cargo build --release --manifest-path desktop/src-tauri/Cargo.toml
   ```
   Output: `desktop/src-tauri/target/release/netflow-sentinel-desktop.exe`.
4. **Build Tauri bundle / Windows NSIS installer** (requires NSIS `makensis` or online Tauri NSIS download on first run):
   ```powershell
   npx --prefix desktop tauri build
   ```
5. **Development mode with hot reload** (`devUrl: http://localhost:1420`):
   ```powershell
   npx --prefix desktop tauri dev
   ```

## Honesty Contract & Packaging Boundary

- `netflow-sentinel-desktop.exe` (and the NSIS installer when built) **embeds the Svelte 5 frontend (`desktop/dist/`)**, so it runs without any external Vite dev server (`localhost:1420` is only used during `tauri dev`).
- **Not yet a self-contained single-file Python bundle**: this project does **not** package an embedded Python runtime or PyInstaller executable yet.
- The target machine / execution environment still requires:
  - Repository runtime directory layout (`src/network_anomaly/`, `scripts/run_api.py`, `artifacts/`, `reports/` — resolved via `NETWORK_ANOMALY_REPO_ROOT` or working/executable ancestor search).
  - Python `>=3.11` with project dependencies installed (`pip install -e .`), discoverable via `NETWORK_ANOMALY_PYTHON`, `.venv\Scripts\python.exe`, `py -3.14` / `py -3.12` / `py -3`, or `python`.
  - Model/preprocessor `.joblib` artifacts in `artifacts/` (absent from Git; missing artifacts report `BLOCKED / NOT READY` fail-closed with HTTP `503`).
