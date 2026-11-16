//! Managed localhost FastAPI backend sidecar / child-process lifecycle (#16, #26, #71).
//!
//! Prioritizes the bundled standalone PyInstaller sidecar (`netflow-sentinel-backend.exe`)
//! with embedded ML models/preprocessor/demo data, falling back to local Python +
//! `scripts/run_api.py` in developer/test checkouts. Always binds strictly to `127.0.0.1`
//! with a per-session 256-bit CSPRNG token (`NETWORK_ANOMALY_API_TOKEN`) and terminates
//! the child process tree cleanly on exit.

use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(windows)]
use std::os::windows::process::CommandExt;

#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendStatus {
    pub base_url: String,
    pub port: u16,
    pub running: bool,
    pub managed_child: bool,
    pub pid: Option<u32>,
    pub backend_mode: String,
    pub python_executable: String,
    pub repo_root: String,
    pub runtime_dir: String,
    pub db_path: String,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeDiagnostics {
    pub repo_root: String,
    pub repo_root_valid: bool,
    pub runtime_dir: String,
    pub db_path: String,
    pub backend_mode: String,
    pub sidecar_ready: bool,
    pub sidecar_executable: Option<String>,
    pub python_ready: bool,
    pub python_executable: Option<String>,
    pub python_error: Option<String>,
    pub embedded_status: String,
    pub ready_models: Vec<String>,
    pub demo_flows_exists: bool,
    pub demo_labels_exists: bool,
}

#[derive(Debug)]
struct InnerState {
    port: u16,
    child: Option<Child>,
    managed_child: bool,
    generation: u64,
    backend_mode: String,
    python_executable: String,
    repo_root: PathBuf,
    runtime_dir: PathBuf,
    db_path: PathBuf,
    session_token: String,
    last_error: Option<String>,
}

#[derive(Clone)]
pub struct BackendManager {
    state: Arc<Mutex<InnerState>>,
    pub http: reqwest::Client,
}

impl std::fmt::Debug for BackendManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BackendManager").finish()
    }
}

fn is_valid_standalone_root(path: &Path) -> bool {
    path.join("reports").join("models").is_dir()
        && (path.join("artifacts").is_dir() || path.join("data").is_dir())
}

fn is_valid_dev_repo_root(path: &Path) -> bool {
    path.join("scripts").join("run_api.py").is_file()
        && path.join("src").join("network_anomaly").is_dir()
}

fn is_valid_repo_root(path: &Path) -> bool {
    is_valid_dev_repo_root(path) || is_valid_standalone_root(path)
}

/// Locate the bundled standalone backend sidecar executable adjacent to the desktop binary.
pub fn resolve_sidecar_executable() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("NETWORK_ANOMALY_SIDECAR_EXE") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let candidate = PathBuf::from(trimmed);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            #[cfg(windows)]
            let candidates = [
                dir.join("netflow-sentinel-backend.exe"),
                dir.join("netflow-sentinel-backend-x86_64-pc-windows-msvc.exe"),
            ];
            #[cfg(not(windows))]
            let candidates = [
                dir.join("netflow-sentinel-backend"),
                dir.join("netflow-sentinel-backend-x86_64-unknown-linux-gnu"),
            ];
            for candidate in candidates {
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }
    }
    None
}

/// Locate resource/manifest root containing either standalone `reports/`+`artifacts/` or dev `scripts/run_api.py`.
///
/// Precedence:
/// 1. `NETWORK_ANOMALY_REPO_ROOT` environment variable
/// 2. Tauri bundled `resource_dir` (and `_up_/_up_` fallback if present)
/// 3. Ancestors of `current_exe()` and `current_dir()`
pub fn resolve_repo_root_with_resource_dir(resource_dir: Option<&Path>) -> Result<PathBuf, String> {
    if let Ok(explicit) = std::env::var("NETWORK_ANOMALY_REPO_ROOT") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            let p = PathBuf::from(trimmed);
            if is_valid_repo_root(&p) {
                return Ok(p);
            }
        }
    }

    if let Some(res_dir) = resource_dir {
        if is_valid_repo_root(res_dir) {
            return Ok(res_dir.to_path_buf());
        }
        let up2 = res_dir.join("_up_").join("_up_");
        if is_valid_repo_root(&up2) {
            return Ok(up2);
        }
    }

    let mut search_roots: Vec<PathBuf> = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            search_roots.push(parent.to_path_buf());
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        search_roots.push(cwd);
    }

    for start in search_roots {
        let mut cursor: Option<&Path> = Some(start.as_path());
        for _ in 0..8 {
            if let Some(dir) = cursor {
                if is_valid_repo_root(dir) {
                    return Ok(dir.to_path_buf());
                }
                cursor = dir.parent();
            }
        }
    }

    Err(
        "Không tìm thấy thư mục tài nguyên backend (reports/models + artifacts hoặc scripts/run_api.py)."
            .to_string(),
    )
}

/// Locate the repository root without a Tauri resource directory (dev / tests).
pub fn resolve_repo_root() -> Result<PathBuf, String> {
    resolve_repo_root_with_resource_dir(None)
}

/// Resolve writable per-user runtime directory for SQLite DB, logs, and exports.
pub fn default_runtime_dir(repo_root: &Path) -> PathBuf {
    if let Ok(explicit) = std::env::var("NETWORK_ANOMALY_RUNTIME_DIR") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    // When running from an active git checkout in dev/CI, keep repo_root unless overridden.
    if repo_root.join(".git").exists() {
        return repo_root.to_path_buf();
    }
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let trimmed = local_app_data.trim();
        if !trimmed.is_empty() {
            let dir = PathBuf::from(trimmed).join("NetFlowSentinel");
            if std::fs::create_dir_all(&dir).is_ok() {
                return dir;
            }
        }
    }
    if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        let trimmed = home.trim();
        if !trimmed.is_empty() {
            let dir = PathBuf::from(trimmed).join(".netflow-sentinel");
            if std::fs::create_dir_all(&dir).is_ok() {
                return dir;
            }
        }
    }
    repo_root.to_path_buf()
}

pub fn default_db_path(repo_root: &Path, runtime_dir: &Path) -> PathBuf {
    if let Ok(env_db) = std::env::var("NETWORK_ANOMALY_DB_PATH") {
        let t = env_db.trim();
        if !t.is_empty() {
            return PathBuf::from(t);
        }
    }
    if runtime_dir != repo_root {
        let _ = std::fs::create_dir_all(runtime_dir);
        return runtime_dir.join("network_anomaly.db");
    }
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let dir = PathBuf::from(local_app_data).join("NetFlowSentinel");
        if std::fs::create_dir_all(&dir).is_ok() {
            return dir.join("network_anomaly.db");
        }
    }
    repo_root.join("data").join("network_anomaly.db")
}

fn configure_python_utf8(cmd: &mut Command) {
    cmd.env("PYTHONUTF8", "1");
    cmd.env("PYTHONIOENCODING", "utf-8");
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);
}

fn configure_python_runtime_env(cmd: &mut Command, repo_root: &Path) {
    configure_python_utf8(cmd);
    if !repo_root.join(".git").exists() {
        cmd.env("PYTHONDONTWRITEBYTECODE", "1");
    }
}

fn venv_python_path(base: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        base.join(".venv").join("Scripts").join("python.exe")
    }
    #[cfg(not(windows))]
    {
        base.join(".venv").join("bin").join("python")
    }
}

fn windows_standard_python_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    #[cfg(windows)]
    {
        let versions = ["Python314", "Python313", "Python312", "Python311"];
        if let Ok(local_app) = std::env::var("LOCALAPPDATA") {
            for v in versions {
                out.push(
                    PathBuf::from(&local_app)
                        .join("Programs")
                        .join("Python")
                        .join(v)
                        .join("python.exe"),
                );
            }
        }
        if let Ok(prog_files) = std::env::var("ProgramFiles") {
            for v in versions {
                out.push(PathBuf::from(&prog_files).join(v).join("python.exe"));
            }
        }
    }
    out
}

/// Verify an interpreter candidate can import runtime and 4-model ML dependencies,
/// returning the resolved `sys.executable` path so child PIDs track Python directly.
fn resolve_python_candidate(exe: &str, prefix_args: &[&str], repo_root: &Path) -> Option<String> {
    let mut cmd = Command::new(exe);
    cmd.args(prefix_args);
    cmd.args([
        "-c",
        "import sys, fastapi, uvicorn, httpx, pandas, joblib, sklearn, xgboost, pydantic; print(sys.executable)",
    ]);
    cmd.current_dir(repo_root);
    cmd.env("PYTHONPATH", repo_root.join("src"));
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());
    configure_python_runtime_env(&mut cmd, repo_root);

    let output = cmd.output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let resolved = stdout.lines().last()?.trim();
    if resolved.is_empty() {
        None
    } else {
        Some(resolved.to_string())
    }
}

/// Discover a Python interpreter for dev/test checkouts (when sidecar binary is not bundled).
pub fn discover_python_command_with_runtime(
    repo_root: &Path,
    runtime_dir: &Path,
) -> Result<(String, Vec<String>), String> {
    if let Ok(explicit) = std::env::var("NETWORK_ANOMALY_PYTHON") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            if let Some(resolved) = resolve_python_candidate(trimmed, &[], repo_root) {
                return Ok((resolved, Vec::new()));
            }
        }
    }

    let runtime_venv = venv_python_path(runtime_dir);
    if runtime_venv.is_file() {
        let s = runtime_venv.to_string_lossy().to_string();
        if let Some(resolved) = resolve_python_candidate(&s, &[], repo_root) {
            return Ok((resolved, Vec::new()));
        }
    }

    let local_venv = venv_python_path(repo_root);
    if local_venv.is_file() {
        let s = local_venv.to_string_lossy().to_string();
        if let Some(resolved) = resolve_python_candidate(&s, &[], repo_root) {
            return Ok((resolved, Vec::new()));
        }
    }

    let candidates: &[(&str, &[&str])] = &[
        ("py", &["-3.14"]),
        ("py", &["-3.13"]),
        ("py", &["-3.12"]),
        ("py", &["-3.11"]),
        ("py", &["-3"]),
        ("python", &[]),
    ];

    for (exe, args) in candidates {
        if let Some(resolved) = resolve_python_candidate(exe, args, repo_root) {
            return Ok((resolved, Vec::new()));
        }
    }

    for path in windows_standard_python_paths() {
        if path.is_file() {
            let s = path.to_string_lossy().to_string();
            if let Some(resolved) = resolve_python_candidate(&s, &[], repo_root) {
                return Ok((resolved, Vec::new()));
            }
        }
    }

    Err(
        "Không tìm thấy tiến trình backend nhúng (netflow-sentinel-backend.exe) hoặc môi trường Python phát triển hợp lệ."
            .to_string(),
    )
}

/// Backward-compatible wrapper using `repo_root` as runtime dir.
pub fn discover_python_command(repo_root: &Path) -> Result<(String, Vec<String>), String> {
    discover_python_command_with_runtime(repo_root, repo_root)
}

fn parse_backend_port_str(raw: Option<&str>) -> u16 {
    raw.and_then(|v| v.trim().parse::<u16>().ok())
        .unwrap_or(8000)
}

/// Resolve preferred FastAPI port from `NETWORK_ANOMALY_BACKEND_PORT` (defaults to 8000; 0 picks free port).
pub fn resolve_preferred_backend_port() -> u16 {
    let raw = std::env::var("NETWORK_ANOMALY_BACKEND_PORT").ok();
    parse_backend_port_str(raw.as_deref())
}

/// Bind an unused localhost port on `127.0.0.1`, preferring `preferred` when available.
pub fn pick_available_port(preferred: u16) -> Result<u16, String> {
    if preferred > 0 {
        if let Ok(listener) = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], preferred))) {
            let port = listener
                .local_addr()
                .map_err(|e| format!("Failed reading bound address: {e}"))?
                .port();
            drop(listener);
            return Ok(port);
        }
    }
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .map_err(|e| format!("Failed binding ephemeral loopback port: {e}"))?;
    let port = listener
        .local_addr()
        .map_err(|e| format!("Failed reading ephemeral port: {e}"))?
        .port();
    drop(listener);
    Ok(port)
}

/// Generate a 256-bit (64 lowercase hex) per-session token using the OS CSPRNG.
pub fn generate_session_token() -> Result<String, String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| format!("Failed generating session token: {e}"))?;
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    Ok(out)
}

fn resolve_effective_session_token() -> Result<String, String> {
    if let Ok(raw) = std::env::var("NETWORK_ANOMALY_API_TOKEN") {
        let trimmed = raw.trim();
        if !trimmed.is_empty() {
            return Ok(trimmed.to_string());
        }
    }
    generate_session_token()
}

/// Terminate a child process and its full Windows process tree cleanly.
fn kill_child_process_tree(child: &mut Child) {
    #[cfg(windows)]
    {
        let pid = child.id();
        let mut tk = Command::new("taskkill");
        tk.args(["/PID", &pid.to_string(), "/T", "/F"]);
        tk.stdin(Stdio::null());
        tk.stdout(Stdio::null());
        tk.stderr(Stdio::null());
        tk.creation_flags(CREATE_NO_WINDOW);
        let _ = tk.status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn check_embedded_artifacts_files(base: &Path) -> Vec<String> {
    let prep = base
        .join("artifacts")
        .join("preprocessing")
        .join("nf_unsw_nb15_v3_preprocessor.joblib");
    let prep_manifest = base
        .join("reports")
        .join("preprocessing")
        .join("nf_unsw_nb15_v3_preprocessing_manifest.json");
    if !prep.is_file() || !prep_manifest.is_file() {
        return Vec::new();
    }
    let specs = [
        (
            "random_forest",
            base.join("artifacts")
                .join("models")
                .join("random_forest")
                .join("random_forest_baseline.joblib"),
            base.join("reports")
                .join("models")
                .join("random_forest_manifest.json"),
        ),
        (
            "xgboost",
            base.join("artifacts")
                .join("models")
                .join("xgboost")
                .join("xgboost_baseline.joblib"),
            base.join("reports")
                .join("models")
                .join("xgboost_manifest.json"),
        ),
        (
            "isolation_forest",
            base.join("artifacts")
                .join("models")
                .join("isolation_forest")
                .join("isolation_forest.joblib"),
            base.join("reports")
                .join("models")
                .join("isolation_forest_manifest.json"),
        ),
        (
            "autoencoder",
            base.join("artifacts")
                .join("models")
                .join("autoencoder")
                .join("autoencoder_model.joblib"),
            base.join("reports")
                .join("models")
                .join("autoencoder_manifest.json"),
        ),
    ];
    let mut ready = Vec::new();
    for (key, model_path, manifest_path) in specs {
        if model_path.is_file() && manifest_path.is_file() {
            ready.push(key.to_string());
        }
    }
    ready
}

impl BackendManager {
    pub fn new_with_runtime(
        repo_root: PathBuf,
        runtime_dir: PathBuf,
        db_path: PathBuf,
    ) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(60))
            .no_proxy()
            .build()
            .map_err(|e| format!("Failed building localhost HTTP client: {e}"))?;

        Ok(Self {
            state: Arc::new(Mutex::new(InnerState {
                port: 0,
                child: None,
                managed_child: false,
                generation: 0,
                backend_mode: if resolve_sidecar_executable().is_some() {
                    "embedded_sidecar".to_string()
                } else {
                    "python_script".to_string()
                },
                python_executable: String::new(),
                repo_root,
                runtime_dir,
                db_path,
                session_token: String::new(),
                last_error: None,
            })),
            http,
        })
    }

    pub fn new(repo_root: PathBuf, db_path: PathBuf) -> Result<Self, String> {
        let runtime_dir = default_runtime_dir(&repo_root);
        Self::new_with_runtime(repo_root, runtime_dir, db_path)
    }

    pub fn base_url(&self) -> Result<String, String> {
        let guard = self
            .state
            .lock()
            .map_err(|_| "Backend state lock poisoned".to_string())?;
        if guard.port == 0 {
            return Err("Backend port is not initialized yet.".to_string());
        }
        Ok(format!("http://127.0.0.1:{}", guard.port))
    }

    pub fn session_token(&self) -> Result<String, String> {
        let guard = self
            .state
            .lock()
            .map_err(|_| "Backend state lock poisoned".to_string())?;
        Ok(guard.session_token.clone())
    }

    pub fn repo_root(&self) -> Result<PathBuf, String> {
        let guard = self
            .state
            .lock()
            .map_err(|_| "Backend state lock poisoned".to_string())?;
        Ok(guard.repo_root.clone())
    }

    pub fn runtime_dir(&self) -> Result<PathBuf, String> {
        let guard = self
            .state
            .lock()
            .map_err(|_| "Backend state lock poisoned".to_string())?;
        Ok(guard.runtime_dir.clone())
    }

    pub fn status(&self) -> BackendStatus {
        let mut guard = match self.state.lock() {
            Ok(g) => g,
            Err(_) => {
                return BackendStatus {
                    base_url: String::new(),
                    port: 0,
                    running: false,
                    managed_child: false,
                    pid: None,
                    backend_mode: "unknown".to_string(),
                    python_executable: String::new(),
                    repo_root: String::new(),
                    runtime_dir: String::new(),
                    db_path: String::new(),
                    last_error: Some("Backend state lock poisoned".to_string()),
                };
            }
        };

        let mut running = false;
        let mut pid = None;
        if let Some(child) = guard.child.as_mut() {
            match child.try_wait() {
                Ok(None) => {
                    running = true;
                    pid = Some(child.id());
                }
                Ok(Some(code)) => {
                    guard.last_error =
                        Some(format!("Backend service exited unexpectedly ({code})"));
                    guard.child = None;
                    guard.managed_child = false;
                }
                Err(err) => {
                    guard.last_error = Some(format!("Failed polling child status: {err}"));
                }
            }
        }

        let base_url = if guard.port > 0 {
            format!("http://127.0.0.1:{}", guard.port)
        } else {
            String::new()
        };

        BackendStatus {
            base_url,
            port: guard.port,
            running,
            managed_child: guard.managed_child,
            pid,
            backend_mode: guard.backend_mode.clone(),
            python_executable: guard.python_executable.clone(),
            repo_root: guard.repo_root.to_string_lossy().to_string(),
            runtime_dir: guard.runtime_dir.to_string_lossy().to_string(),
            db_path: guard.db_path.to_string_lossy().to_string(),
            last_error: guard.last_error.clone(),
        }
    }

    /// Inspect bundled sidecar/code root, embedded 4-model artifacts, and demo CSV readiness without requiring Python.
    pub fn diagnostics(&self) -> RuntimeDiagnostics {
        let (repo_root, runtime_dir, db_path, running_exe) = match self.state.lock() {
            Ok(g) => (
                g.repo_root.clone(),
                g.runtime_dir.clone(),
                g.db_path.clone(),
                g.python_executable.clone(),
            ),
            Err(_) => {
                let fallback = PathBuf::from(".");
                (
                    fallback.clone(),
                    fallback.clone(),
                    fallback.join("network_anomaly.db"),
                    String::new(),
                )
            }
        };

        let repo_root_valid = is_valid_repo_root(&repo_root);
        let sidecar = resolve_sidecar_executable();
        let sidecar_ready = sidecar.is_some();
        let sidecar_executable = sidecar.as_ref().map(|p| p.to_string_lossy().to_string());

        let (backend_mode, python_ready, python_executable, python_error) = if let Some(sc) =
            sidecar_executable.clone()
        {
            ("embedded_sidecar".to_string(), true, Some(sc), None)
        } else if !running_exe.is_empty() {
            ("python_script".to_string(), true, Some(running_exe), None)
        } else if repo_root_valid && is_valid_dev_repo_root(&repo_root) {
            match discover_python_command_with_runtime(&repo_root, &runtime_dir) {
                Ok((py, _)) => ("python_script".to_string(), true, Some(py), None),
                Err(err) => ("python_script".to_string(), false, None, Some(err)),
            }
        } else {
            (
                "embedded_sidecar".to_string(),
                false,
                None,
                Some(
                    "Không tìm thấy tệp thực thi backend nhúng (netflow-sentinel-backend.exe) trong thư mục cài đặt."
                        .to_string(),
                ),
            )
        };

        let demo_dir = if repo_root
            .join("data")
            .join("demo")
            .join("demo_flows.csv")
            .is_file()
        {
            repo_root.join("data").join("demo")
        } else {
            runtime_dir.join("data").join("demo")
        };
        let demo_flows_exists = demo_dir.join("demo_flows.csv").is_file();
        let demo_labels_exists = demo_dir.join("demo_labels.csv").is_file();

        let ready_models = check_embedded_artifacts_files(&repo_root);
        let embedded_status = if ready_models.len() == 4 && demo_flows_exists && demo_labels_exists
        {
            "READY".to_string()
        } else {
            "BLOCKED / NOT READY".to_string()
        };

        RuntimeDiagnostics {
            repo_root: repo_root.to_string_lossy().to_string(),
            repo_root_valid,
            runtime_dir: runtime_dir.to_string_lossy().to_string(),
            db_path: db_path.to_string_lossy().to_string(),
            backend_mode,
            sidecar_ready,
            sidecar_executable,
            python_ready,
            python_executable,
            python_error,
            embedded_status,
            ready_models,
            demo_flows_exists,
            demo_labels_exists,
        }
    }

    /// Spawn the FastAPI backend (bundled sidecar preferred, dev Python fallback) on `127.0.0.1`.
    pub fn ensure_started(
        &self,
        preferred_port: u16,
        timeout: Duration,
    ) -> Result<BackendStatus, String> {
        self.shutdown();

        let (repo_root, runtime_dir, db_path, start_gen) = {
            let mut guard = self
                .state
                .lock()
                .map_err(|_| "Backend state lock poisoned".to_string())?;
            guard.generation = guard.generation.wrapping_add(1);
            (
                guard.repo_root.clone(),
                guard.runtime_dir.clone(),
                guard.db_path.clone(),
                guard.generation,
            )
        };

        if !is_valid_repo_root(&repo_root) {
            let err = "Không tìm thấy thư mục tài nguyên mô hình và cấu hình ứng dụng.".to_string();
            if let Ok(mut guard) = self.state.lock() {
                guard.last_error = Some(err.clone());
            }
            return Err(err);
        }

        let explicit_python_override = std::env::var("NETWORK_ANOMALY_PYTHON")
            .ok()
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        let sidecar_opt = if explicit_python_override {
            None
        } else {
            resolve_sidecar_executable()
        };

        let session_token = resolve_effective_session_token()?;
        let port = pick_available_port(preferred_port)?;

        let (mut cmd, display_cmd, effective_mode) = if let Some(sidecar_exe) = sidecar_opt {
            let mut c = Command::new(&sidecar_exe);
            c.args([
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--db-path",
                &db_path.to_string_lossy(),
            ]);
            c.current_dir(&repo_root);
            c.env("NETWORK_ANOMALY_REPO_ROOT", &repo_root);
            c.env("NETWORK_ANOMALY_RESOURCE_DIR", &repo_root);
            c.env("NETWORK_ANOMALY_RUNTIME_DIR", &runtime_dir);
            c.env("NETWORK_ANOMALY_API_TOKEN", &session_token);
            c.stdin(Stdio::null());
            c.stdout(Stdio::null());
            c.stderr(Stdio::null());
            configure_python_utf8(&mut c);
            (
                c,
                sidecar_exe.to_string_lossy().to_string(),
                "embedded_sidecar".to_string(),
            )
        } else {
            if !is_valid_dev_repo_root(&repo_root) {
                let err =
                    "Thiếu tệp thực thi backend nhúng (netflow-sentinel-backend.exe).".to_string();
                if let Ok(mut guard) = self.state.lock() {
                    guard.last_error = Some(err.clone());
                }
                return Err(err);
            }
            let (py_exe, py_prefix) =
                match discover_python_command_with_runtime(&repo_root, &runtime_dir) {
                    Ok(v) => v,
                    Err(err) => {
                        if let Ok(mut guard) = self.state.lock() {
                            guard.last_error = Some(err.clone());
                        }
                        return Err(err);
                    }
                };
            let script_path = repo_root.join("scripts").join("run_api.py");
            let mut c = Command::new(&py_exe);
            c.args(&py_prefix);
            c.arg(&script_path);
            c.args([
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--db-path",
                &db_path.to_string_lossy(),
            ]);
            c.current_dir(&repo_root);
            c.env("PYTHONPATH", repo_root.join("src"));
            c.env("PYTHONUNBUFFERED", "1");
            if !repo_root.join(".git").exists() {
                c.env("PYTHONDONTWRITEBYTECODE", "1");
            }
            c.env("NETWORK_ANOMALY_REPO_ROOT", &repo_root);
            c.env("NETWORK_ANOMALY_RESOURCE_DIR", &repo_root);
            c.env("NETWORK_ANOMALY_RUNTIME_DIR", &runtime_dir);
            c.env("NETWORK_ANOMALY_API_TOKEN", &session_token);
            c.stdin(Stdio::null());
            c.stdout(Stdio::null());
            c.stderr(Stdio::null());
            configure_python_utf8(&mut c);
            let disp = if py_prefix.is_empty() {
                py_exe
            } else {
                format!("{py_exe} {}", py_prefix.join(" "))
            };
            (c, disp, "python_script".to_string())
        };

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed starting backend process '{display_cmd}': {e}"))?;

        let started = Instant::now();
        let health_url = format!("http://127.0.0.1:{port}/health");
        let probe_client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_millis(600))
            .no_proxy()
            .build()
            .map_err(|e| format!("Failed creating health probe client: {e}"))?;

        let mut last_probe_err = String::from("Backend still starting");
        while started.elapsed() < timeout {
            if let Ok(guard) = self.state.lock() {
                if guard.generation != start_gen {
                    drop(guard);
                    kill_child_process_tree(&mut child);
                    return Err("Backend startup canceled due to shutdown.".to_string());
                }
            }

            if let Ok(Some(exit)) = child.try_wait() {
                let err_msg =
                    format!("Backend child process exited early ({exit}) before becoming healthy.");
                if let Ok(mut guard) = self.state.lock() {
                    guard.last_error = Some(err_msg.clone());
                }
                return Err(err_msg);
            }

            match probe_client.get(&health_url).send() {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(mut guard) = self.state.lock() {
                        if guard.generation != start_gen {
                            drop(guard);
                            kill_child_process_tree(&mut child);
                            return Err("Backend startup canceled due to shutdown.".to_string());
                        }
                        guard.port = port;
                        guard.child = Some(child);
                        guard.managed_child = true;
                        guard.backend_mode = effective_mode;
                        guard.python_executable = display_cmd;
                        guard.session_token = session_token;
                        guard.last_error = None;
                    }
                    return Ok(self.status());
                }
                Ok(resp) => {
                    last_probe_err = format!("Health probe HTTP {}", resp.status());
                }
                Err(err) => {
                    last_probe_err = err.to_string();
                }
            }

            std::thread::sleep(Duration::from_millis(200));
        }

        kill_child_process_tree(&mut child);
        let timeout_msg =
            format!("Timed out waiting for FastAPI backend on {health_url} ({last_probe_err}).");
        if let Ok(mut guard) = self.state.lock() {
            guard.last_error = Some(timeout_msg.clone());
        }
        Err(timeout_msg)
    }

    /// Terminate the controlled backend process tree if we spawned it.
    pub fn shutdown(&self) {
        if let Ok(mut guard) = self.state.lock() {
            guard.generation = guard.generation.wrapping_add(1);
            if guard.managed_child {
                if let Some(mut child) = guard.child.take() {
                    kill_child_process_tree(&mut child);
                }
            }
            guard.managed_child = false;
            guard.session_token.clear();
        }
    }
}

impl Drop for BackendManager {
    fn drop(&mut self) {
        if Arc::strong_count(&self.state) == 1 {
            self.shutdown();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_repo_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("desktop")
            .parent()
            .expect("repo")
            .to_path_buf()
    }

    #[test]
    fn test_resolve_repo_root_finds_scripts_and_src() {
        let root = test_repo_root();
        assert!(is_valid_repo_root(&root));
    }

    #[test]
    fn test_resolve_repo_root_uses_resource_dir_fallback() {
        let tmp = std::env::temp_dir().join(format!("nf_res_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("scripts")).unwrap();
        std::fs::create_dir_all(tmp.join("src").join("network_anomaly")).unwrap();
        std::fs::write(tmp.join("scripts").join("run_api.py"), "# test\n").unwrap();

        assert!(is_valid_repo_root(&tmp));
        assert!(resolve_repo_root_with_resource_dir(Some(&tmp)).is_ok());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_resolve_standalone_resource_dir_without_python_sources() {
        let tmp = std::env::temp_dir().join(format!("nf_standalone_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("reports").join("models")).unwrap();
        std::fs::create_dir_all(tmp.join("artifacts").join("models")).unwrap();

        assert!(is_valid_standalone_root(&tmp));
        assert!(is_valid_repo_root(&tmp));
        assert_eq!(
            resolve_repo_root_with_resource_dir(Some(&tmp)).unwrap(),
            tmp
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_generate_session_token_is_64_hex_and_unique() {
        let t1 = generate_session_token().unwrap();
        let t2 = generate_session_token().unwrap();
        assert_eq!(t1.len(), 64);
        assert_eq!(t2.len(), 64);
        assert_ne!(t1, t2);
        assert!(t1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_pick_available_port_handles_busy_port() {
        let occupied = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let busy_port = occupied.local_addr().unwrap().port();
        let chosen = pick_available_port(busy_port).unwrap();
        assert_ne!(chosen, busy_port);
        assert!(chosen > 0);
        drop(occupied);
    }

    #[test]
    fn test_parse_backend_port_str_supports_ephemeral_and_defaults() {
        assert_eq!(parse_backend_port_str(None), 8000);
        assert_eq!(parse_backend_port_str(Some("")), 8000);
        assert_eq!(parse_backend_port_str(Some("invalid")), 8000);
        assert_eq!(parse_backend_port_str(Some(" 0 ")), 0);
        assert_eq!(parse_backend_port_str(Some("9123")), 9123);
    }

    #[test]
    fn test_spawn_and_clean_shutdown_python_backend() {
        let repo_root = test_repo_root();
        let require_python = std::env::var_os("CI").is_some()
            || std::env::var("NETWORK_ANOMALY_REQUIRE_PYTHON_TEST")
                .ok()
                .as_deref()
                == Some("1");
        let (resolved_exe, resolved_args) = match discover_python_command(&repo_root) {
            Ok(found) => found,
            Err(err) => {
                if require_python {
                    panic!(
                        "Python backend interpreter is required when CI or NETWORK_ANOMALY_REQUIRE_PYTHON_TEST=1 is set: {err}"
                    );
                }
                eprintln!(
                    "SKIPPED test_spawn_and_clean_shutdown_python_backend (local Python deps missing): {err}"
                );
                return;
            }
        };
        assert!(resolved_args.is_empty());
        assert!(Path::new(&resolved_exe).is_file());

        let temp_db =
            std::env::temp_dir().join(format!("sentinel_rust_test_{}.db", std::process::id()));
        let mgr = BackendManager::new(repo_root, temp_db.clone()).unwrap();
        let status = mgr.ensure_started(0, Duration::from_secs(20)).unwrap();
        assert!(status.running);
        assert!(status.managed_child);
        assert!(status.pid.is_some());
        assert!(status.base_url.starts_with("http://127.0.0.1:"));
        assert!(Path::new(&status.python_executable).is_file());
        assert!(!mgr.session_token().unwrap().is_empty());

        mgr.shutdown();
        let after = mgr.status();
        assert!(!after.running);
        assert!(!after.managed_child);
        assert!(after.pid.is_none());
        assert!(mgr.session_token().unwrap().is_empty());
        let _ = std::fs::remove_file(temp_db);
    }
}
