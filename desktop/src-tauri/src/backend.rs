//! Managed localhost Python FastAPI child-process lifecycle (#16, #26).
//!
//! Spawns `scripts/run_api.py` strictly on `127.0.0.1` with a per-session CSPRNG
//! token (`NETWORK_ANOMALY_API_TOKEN`), resolves bundled Tauri resources or repo roots,
//! separates read-only code roots from per-user writable runtime directories, and
//! terminates the child process tree cleanly on exit.

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
    pub python_ready: bool,
    pub python_executable: Option<String>,
    pub python_error: Option<String>,
    pub base_python_available: bool,
    pub base_python_executable: Option<String>,
    pub base_python_error: Option<String>,
    pub venv_python_path: String,
    pub venv_exists: bool,
    pub requirements_file_exists: bool,
    pub companion_status: String,
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

fn is_valid_repo_root(path: &Path) -> bool {
    path.join("scripts").join("run_api.py").is_file()
        && path.join("src").join("network_anomaly").is_dir()
}

/// Locate code/manifest root containing `scripts/run_api.py` and `src/network_anomaly`.
///
/// Precedence:
/// 1. `NETWORK_ANOMALY_REPO_ROOT` environment variable
/// 2. Tauri bundled `resource_dir` (and `_up_/_up_` fallback if present)
/// 3. Ancestors of `current_dir()` and `current_exe()`
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
    if let Ok(cwd) = std::env::current_dir() {
        search_roots.push(cwd);
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            search_roots.push(parent.to_path_buf());
        }
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
        "Could not locate backend resources containing scripts/run_api.py and src/network_anomaly."
            .to_string(),
    )
}

/// Locate the repository root without a Tauri resource directory (dev / tests).
pub fn resolve_repo_root() -> Result<PathBuf, String> {
    resolve_repo_root_with_resource_dir(None)
}

/// Resolve writable per-user runtime directory for `.venv`, companion artifacts, demo CSV, and SQLite.
pub fn default_runtime_dir(repo_root: &Path) -> PathBuf {
    if let Ok(explicit) = std::env::var("NETWORK_ANOMALY_RUNTIME_DIR") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    // When running from an active git checkout in dev/CI, keep repo_root unless artifacts are absent.
    if repo_root.join(".git").exists() {
        return repo_root.to_path_buf();
    }
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let trimmed = local_app_data.trim();
        if !trimmed.is_empty() {
            let dir = PathBuf::from(trimmed).join("NetFlowSentinelM6");
            if std::fs::create_dir_all(&dir).is_ok() {
                return dir;
            }
        }
    }
    if let Ok(home) = std::env::var("USERPROFILE").or_else(|_| std::env::var("HOME")) {
        let trimmed = home.trim();
        if !trimmed.is_empty() {
            let dir = PathBuf::from(trimmed).join(".netflow-sentinel-m6");
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
        let dir = PathBuf::from(local_app_data).join("NetFlowSentinelM6");
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

/// Probe a base Python >= 3.12 interpreter (without requiring ML deps yet) for automated `.venv` setup.
fn resolve_base_python_candidate(exe: &str, prefix_args: &[&str]) -> Option<String> {
    let mut cmd = Command::new(exe);
    cmd.args(prefix_args);
    cmd.args([
        "-c",
        "import sys, venv; assert sys.version_info >= (3, 12); print(sys.executable)",
    ]);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());
    configure_python_utf8(&mut cmd);

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

/// Discover a base Python (>= 3.12) capable of creating a virtual environment.
pub fn discover_base_python() -> Result<String, String> {
    if let Ok(explicit) = std::env::var("NETWORK_ANOMALY_PYTHON") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            if let Some(resolved) = resolve_base_python_candidate(trimmed, &[]) {
                return Ok(resolved);
            }
        }
    }

    let candidates: &[(&str, &[&str])] = &[
        ("py", &["-3.12"]),
        ("py", &["-3.13"]),
        ("py", &["-3.14"]),
        ("py", &["-3"]),
        ("python", &[]),
    ];
    for (exe, args) in candidates {
        if let Some(resolved) = resolve_base_python_candidate(exe, args) {
            return Ok(resolved);
        }
    }
    for path in windows_standard_python_paths() {
        if path.is_file() {
            let s = path.to_string_lossy().to_string();
            if let Some(resolved) = resolve_base_python_candidate(&s, &[]) {
                return Ok(resolved);
            }
        }
    }

    Err(
        "Không tìm thấy Python >= 3.12 trên máy. Vui lòng cài Python 3.12 (x64) từ python.org hoặc 'winget install Python.Python.3.12'."
            .to_string(),
    )
}

/// Discover a Python interpreter that can run FastAPI + Uvicorn + all 4-model ML dependencies.
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
        "Không tìm thấy Python có đủ fastapi, uvicorn, pandas, joblib, scikit-learn và xgboost. \
         Hãy bấm 'Thiết lập Python Runtime (.venv)' hoặc đặt NETWORK_ANOMALY_PYTHON."
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
                    guard.last_error = Some(format!("Python backend exited unexpectedly ({code})"));
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
            python_executable: guard.python_executable.clone(),
            repo_root: guard.repo_root.to_string_lossy().to_string(),
            runtime_dir: guard.runtime_dir.to_string_lossy().to_string(),
            db_path: guard.db_path.to_string_lossy().to_string(),
            last_error: guard.last_error.clone(),
        }
    }

    /// Inspect bundled code root, Python runtime, venv, and companion artifact readiness.
    pub fn diagnostics(&self) -> RuntimeDiagnostics {
        let (repo_root, runtime_dir, db_path) = match self.state.lock() {
            Ok(g) => (
                g.repo_root.clone(),
                g.runtime_dir.clone(),
                g.db_path.clone(),
            ),
            Err(_) => {
                let fallback = PathBuf::from(".");
                (
                    fallback.clone(),
                    fallback.clone(),
                    fallback.join("network_anomaly.db"),
                )
            }
        };

        let repo_root_valid = is_valid_repo_root(&repo_root);
        let venv_py = venv_python_path(&runtime_dir);
        let venv_exists = venv_py.is_file();
        let requirements_file_exists = repo_root.join("requirements-runtime.txt").is_file();

        let (python_ready, python_executable, python_error) = if repo_root_valid {
            match discover_python_command_with_runtime(&repo_root, &runtime_dir) {
                Ok((py, _)) => (true, Some(py), None),
                Err(err) => (false, None, Some(err)),
            }
        } else {
            (
                false,
                None,
                Some(
                    "Thiếu thư mục backend scripts/run_api.py và src/network_anomaly.".to_string(),
                ),
            )
        };

        let (base_python_available, base_python_executable, base_python_error) =
            match discover_base_python() {
                Ok(base_py) => (true, Some(base_py), None),
                Err(err) => (false, None, Some(err)),
            };

        let demo_dir = if (runtime_dir.join("data").join("demo").join("demo_flows.csv")).is_file() {
            runtime_dir.join("data").join("demo")
        } else {
            repo_root.join("data").join("demo")
        };
        let demo_flows_exists = demo_dir.join("demo_flows.csv").is_file();
        let demo_labels_exists = demo_dir.join("demo_labels.csv").is_file();

        let mut companion_status = "BLOCKED / NOT READY".to_string();
        let mut ready_models: Vec<String> = Vec::new();
        if repo_root_valid {
            if let Some(py_exe) = python_executable.as_deref() {
                let verify_script = repo_root
                    .join("scripts")
                    .join("verify_companion_artifacts.py");
                if verify_script.is_file() {
                    let mut cmd = Command::new(py_exe);
                    cmd.args([
                        verify_script.to_string_lossy().as_ref(),
                        "--root",
                        repo_root.to_string_lossy().as_ref(),
                        "--runtime-dir",
                        runtime_dir.to_string_lossy().as_ref(),
                    ]);
                    cmd.current_dir(&repo_root);
                    cmd.env("PYTHONPATH", repo_root.join("src"));
                    cmd.stdin(Stdio::null());
                    cmd.stdout(Stdio::piped());
                    cmd.stderr(Stdio::null());
                    configure_python_runtime_env(&mut cmd, &repo_root);
                    if let Ok(out) = cmd.output() {
                        if let Ok(parsed) = serde_json::from_slice::<serde_json::Value>(&out.stdout)
                        {
                            if let Some(st) = parsed.get("overall_status").and_then(|v| v.as_str())
                            {
                                companion_status = st.to_string();
                            }
                            if let Some(arr) = parsed.get("ready_models").and_then(|v| v.as_array())
                            {
                                ready_models = arr
                                    .iter()
                                    .filter_map(|v| v.as_str().map(str::to_string))
                                    .collect();
                            }
                        }
                    }
                }
            }
        }

        RuntimeDiagnostics {
            repo_root: repo_root.to_string_lossy().to_string(),
            repo_root_valid,
            runtime_dir: runtime_dir.to_string_lossy().to_string(),
            db_path: db_path.to_string_lossy().to_string(),
            python_ready,
            python_executable,
            python_error,
            base_python_available,
            base_python_executable,
            base_python_error,
            venv_python_path: venv_py.to_string_lossy().to_string(),
            venv_exists,
            requirements_file_exists,
            companion_status,
            ready_models,
            demo_flows_exists,
            demo_labels_exists,
        }
    }

    /// Create/update `%LOCALAPPDATA%\NetFlowSentinelM6\.venv` with bounded runtime deps, then start backend.
    pub fn setup_python_runtime(
        &self,
        wheelhouse_dir: Option<PathBuf>,
    ) -> Result<BackendStatus, String> {
        let (repo_root, runtime_dir) = {
            let guard = self
                .state
                .lock()
                .map_err(|_| "Backend state lock poisoned".to_string())?;
            (guard.repo_root.clone(), guard.runtime_dir.clone())
        };

        if !is_valid_repo_root(&repo_root) {
            return Err(
                "Backend resources missing scripts/run_api.py and src/network_anomaly.".to_string(),
            );
        }
        let req_path = repo_root.join("requirements-runtime.txt");
        if !req_path.is_file() {
            return Err(format!(
                "Missing runtime dependency specification: {}",
                req_path.display()
            ));
        }

        let base_py = discover_base_python()?;
        std::fs::create_dir_all(&runtime_dir)
            .map_err(|e| format!("Failed creating runtime directory: {e}"))?;

        let venv_dir = runtime_dir.join(".venv");
        let venv_py = venv_python_path(&runtime_dir);
        if !venv_py.is_file() {
            let mut venv_cmd = Command::new(&base_py);
            venv_cmd.args(["-m", "venv", &venv_dir.to_string_lossy()]);
            venv_cmd.stdin(Stdio::null());
            configure_python_utf8(&mut venv_cmd);
            let out = venv_cmd
                .output()
                .map_err(|e| format!("Failed creating virtual environment: {e}"))?;
            if !out.status.success() {
                let err_txt = String::from_utf8_lossy(&out.stderr);
                return Err(format!("Failed creating Python .venv: {}", err_txt.trim()));
            }
        }

        let mut pip_cmd = Command::new(&venv_py);
        pip_cmd.args(["-m", "pip", "install"]);
        if let Some(wh) = wheelhouse_dir {
            pip_cmd.args(["--no-index", "--find-links", wh.to_string_lossy().as_ref()]);
        }
        pip_cmd.args(["-r", req_path.to_string_lossy().as_ref()]);
        pip_cmd.current_dir(&repo_root);
        pip_cmd.stdin(Stdio::null());
        configure_python_utf8(&mut pip_cmd);

        let pip_out = pip_cmd
            .output()
            .map_err(|e| format!("Failed running pip install: {e}"))?;
        if !pip_out.status.success() {
            let err_txt = String::from_utf8_lossy(&pip_out.stderr);
            let out_txt = String::from_utf8_lossy(&pip_out.stdout);
            let detail = if err_txt.trim().is_empty() {
                out_txt.trim()
            } else {
                err_txt.trim()
            };
            return Err(format!("Cài đặt Python dependencies thất bại: {detail}"));
        }

        let preferred_port = resolve_preferred_backend_port();
        self.ensure_started(preferred_port, Duration::from_secs(20))
    }

    /// Install and verify a companion bundle archive (.zip) or directory into `runtime_dir`.
    pub fn install_companion_bundle(
        &self,
        archive_path: Option<PathBuf>,
        bundle_dir: Option<PathBuf>,
        expected_sha256: Option<String>,
    ) -> Result<serde_json::Value, String> {
        let (repo_root, runtime_dir) = {
            let guard = self
                .state
                .lock()
                .map_err(|_| "Backend state lock poisoned".to_string())?;
            (guard.repo_root.clone(), guard.runtime_dir.clone())
        };
        if !is_valid_repo_root(&repo_root) {
            return Err(
                "Backend resources missing scripts/verify_companion_artifacts.py.".to_string(),
            );
        }

        let (py_exe, _) = discover_python_command_with_runtime(&repo_root, &runtime_dir).map_err(
            |_| {
                "Vui lòng hoàn tất Bước 2 (Thiết lập Python Runtime .venv) trước khi nạp Companion Bundle."
                    .to_string()
            },
        )?;
        let verify_script = repo_root
            .join("scripts")
            .join("verify_companion_artifacts.py");

        let mut cmd = Command::new(&py_exe);
        cmd.arg(&verify_script);
        cmd.args([
            "--root",
            repo_root.to_string_lossy().as_ref(),
            "--runtime-dir",
            runtime_dir.to_string_lossy().as_ref(),
        ]);
        match (archive_path, bundle_dir) {
            (Some(zip_path), None) => {
                cmd.args([
                    "--install-bundle-archive",
                    zip_path.to_string_lossy().as_ref(),
                ]);
            }
            (None, Some(dir_path)) => {
                cmd.args(["--install-bundle-dir", dir_path.to_string_lossy().as_ref()]);
            }
            _ => {
                return Err(
                    "Cần chọn đúng một nguồn Companion Bundle (.zip hoặc thư mục).".to_string(),
                );
            }
        }
        if let Some(sha) = expected_sha256 {
            let trimmed = sha.trim();
            if !trimmed.is_empty() {
                cmd.args(["--expect-bundle-sha256", trimmed]);
            }
        }
        cmd.current_dir(&repo_root);
        cmd.env("PYTHONPATH", repo_root.join("src"));
        cmd.stdin(Stdio::null());
        configure_python_runtime_env(&mut cmd, &repo_root);

        let output = cmd
            .output()
            .map_err(|e| format!("Failed executing companion bundle verification: {e}"))?;
        if !output.status.success() {
            let err_txt = String::from_utf8_lossy(&output.stderr);
            let out_txt = String::from_utf8_lossy(&output.stdout);
            let msg = if err_txt.trim().is_empty() {
                out_txt.trim()
            } else {
                err_txt.trim()
            };
            return Err(msg.to_string());
        }

        serde_json::from_slice::<serde_json::Value>(&output.stdout)
            .map_err(|e| format!("Invalid companion installer JSON output: {e}"))
    }

    /// Spawn the FastAPI backend on `127.0.0.1` and wait for `/health` readiness.
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
            let err = "Không tìm thấy thư mục mã nguồn backend (scripts/run_api.py).".to_string();
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

        let session_token = resolve_effective_session_token()?;
        let port = pick_available_port(preferred_port)?;
        let script_path = repo_root.join("scripts").join("run_api.py");

        let mut cmd = Command::new(&py_exe);
        cmd.args(&py_prefix);
        cmd.arg(&script_path);
        cmd.args([
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--db-path",
            &db_path.to_string_lossy(),
        ]);
        cmd.current_dir(&repo_root);
        cmd.env("PYTHONPATH", repo_root.join("src"));
        cmd.env("PYTHONUNBUFFERED", "1");
        if !repo_root.join(".git").exists() {
            cmd.env("PYTHONDONTWRITEBYTECODE", "1");
        }
        cmd.env("NETWORK_ANOMALY_REPO_ROOT", &repo_root);
        cmd.env("NETWORK_ANOMALY_RUNTIME_DIR", &runtime_dir);
        cmd.env("NETWORK_ANOMALY_API_TOKEN", &session_token);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
        configure_python_utf8(&mut cmd);

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed starting FastAPI process with '{py_exe}': {e}"))?;

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
                    format!("FastAPI child process exited early ({exit}) before becoming healthy.");
                if let Ok(mut guard) = self.state.lock() {
                    guard.last_error = Some(err_msg.clone());
                }
                return Err(err_msg);
            }

            match probe_client.get(&health_url).send() {
                Ok(resp) if resp.status().is_success() => {
                    let display_cmd = if py_prefix.is_empty() {
                        py_exe
                    } else {
                        format!("{py_exe} {}", py_prefix.join(" "))
                    };
                    if let Ok(mut guard) = self.state.lock() {
                        if guard.generation != start_gen {
                            drop(guard);
                            kill_child_process_tree(&mut child);
                            return Err("Backend startup canceled due to shutdown.".to_string());
                        }
                        guard.port = port;
                        guard.child = Some(child);
                        guard.managed_child = true;
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

    /// Terminate the controlled Python backend process if we spawned it.
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
        // Shutdown only when the last Arc reference is dropped
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
        // Only assert helper directly without mutating global process env
        assert!(resolve_repo_root_with_resource_dir(Some(&tmp)).is_ok());
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
