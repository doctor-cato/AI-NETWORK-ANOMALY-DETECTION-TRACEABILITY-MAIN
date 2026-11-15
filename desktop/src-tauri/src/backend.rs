//! Managed localhost Python FastAPI child-process lifecycle (#16, #26).
//!
//! Spawns `scripts/run_api.py` strictly on `127.0.0.1`, verifies readiness via
//! `/health`, handles port collisions gracefully, and terminates the child on exit.

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
    pub db_path: String,
    pub last_error: Option<String>,
}

#[derive(Debug)]
struct InnerState {
    port: u16,
    child: Option<Child>,
    managed_child: bool,
    generation: u64,
    python_executable: String,
    repo_root: PathBuf,
    db_path: PathBuf,
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

/// Locate the repository root containing `scripts/run_api.py` and `src/network_anomaly`.
pub fn resolve_repo_root() -> Result<PathBuf, String> {
    if let Ok(explicit) = std::env::var("NETWORK_ANOMALY_REPO_ROOT") {
        let p = PathBuf::from(explicit);
        if is_valid_repo_root(&p) {
            return Ok(p);
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
        "Could not locate repository root containing scripts/run_api.py and src/network_anomaly."
            .to_string(),
    )
}

fn is_valid_repo_root(path: &Path) -> bool {
    path.join("scripts").join("run_api.py").is_file()
        && path.join("src").join("network_anomaly").is_dir()
}

/// Verify an interpreter candidate can import runtime and ML dependencies,
/// returning the resolved `sys.executable` path so child PIDs track Python directly.
fn resolve_python_candidate(exe: &str, prefix_args: &[&str], repo_root: &Path) -> Option<String> {
    let mut cmd = Command::new(exe);
    cmd.args(prefix_args);
    cmd.args([
        "-c",
        "import sys, fastapi, uvicorn, httpx, pandas, joblib, sklearn; print(sys.executable)",
    ]);
    cmd.current_dir(repo_root);
    cmd.env("PYTHONPATH", repo_root.join("src"));
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::null());
    #[cfg(windows)]
    cmd.creation_flags(CREATE_NO_WINDOW);

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

/// Discover a Python interpreter that can run FastAPI + Uvicorn + ML dependencies.
pub fn discover_python_command(repo_root: &Path) -> Result<(String, Vec<String>), String> {
    if let Ok(explicit) = std::env::var("NETWORK_ANOMALY_PYTHON") {
        let trimmed = explicit.trim();
        if !trimmed.is_empty() {
            if let Some(resolved) = resolve_python_candidate(trimmed, &[], repo_root) {
                return Ok((resolved, Vec::new()));
            }
        }
    }

    let local_venv = repo_root.join(".venv").join("Scripts").join("python.exe");
    if local_venv.is_file() {
        let s = local_venv.to_string_lossy().to_string();
        if let Some(resolved) = resolve_python_candidate(&s, &[], repo_root) {
            return Ok((resolved, Vec::new()));
        }
    }

    let candidates: &[(&str, &[&str])] = &[
        ("py", &["-3.14"]),
        ("py", &["-3.12"]),
        ("py", &["-3"]),
        ("python", &[]),
    ];

    for (exe, args) in candidates {
        if let Some(resolved) = resolve_python_candidate(exe, args, repo_root) {
            return Ok((resolved, Vec::new()));
        }
    }

    Err(
        "No Python interpreter with fastapi, uvicorn, pandas, joblib, and scikit-learn was found. \
         Set NETWORK_ANOMALY_PYTHON or install dependencies into Python 3.12/3.14."
            .to_string(),
    )
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

pub fn default_db_path(repo_root: &Path) -> PathBuf {
    if let Ok(env_db) = std::env::var("NETWORK_ANOMALY_DB_PATH") {
        let t = env_db.trim();
        if !t.is_empty() {
            return PathBuf::from(t);
        }
    }
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let dir = PathBuf::from(local_app_data).join("NetFlowSentinelM6");
        if std::fs::create_dir_all(&dir).is_ok() {
            return dir.join("network_anomaly.db");
        }
    }
    repo_root.join("data").join("network_anomaly.db")
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
    pub fn new(repo_root: PathBuf, db_path: PathBuf) -> Result<Self, String> {
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
                db_path,
                last_error: None,
            })),
            http,
        })
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

    pub fn repo_root(&self) -> Result<PathBuf, String> {
        let guard = self
            .state
            .lock()
            .map_err(|_| "Backend state lock poisoned".to_string())?;
        Ok(guard.repo_root.clone())
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
            db_path: guard.db_path.to_string_lossy().to_string(),
            last_error: guard.last_error.clone(),
        }
    }

    /// Spawn the FastAPI backend on `127.0.0.1` and wait for `/health` readiness.
    pub fn ensure_started(
        &self,
        preferred_port: u16,
        timeout: Duration,
    ) -> Result<BackendStatus, String> {
        self.shutdown();

        let (repo_root, db_path, start_gen) = {
            let mut guard = self
                .state
                .lock()
                .map_err(|_| "Backend state lock poisoned".to_string())?;
            guard.generation = guard.generation.wrapping_add(1);
            (
                guard.repo_root.clone(),
                guard.db_path.clone(),
                guard.generation,
            )
        };

        let (py_exe, py_prefix) = match discover_python_command(&repo_root) {
            Ok(v) => v,
            Err(err) => {
                if let Ok(mut guard) = self.state.lock() {
                    guard.last_error = Some(err.clone());
                }
                return Err(err);
            }
        };

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
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());
        #[cfg(windows)]
        cmd.creation_flags(CREATE_NO_WINDOW);

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
    fn test_pick_available_port_handles_busy_port() {
        let occupied = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        let busy_port = occupied.local_addr().unwrap().port();
        let chosen = pick_available_port(busy_port).unwrap();
        assert_ne!(chosen, busy_port);
        assert!(chosen > 0);
        drop(occupied);
    }

    #[test]
    fn test_spawn_and_clean_shutdown_python_backend() {
        let repo_root = test_repo_root();
        let Ok((resolved_exe, resolved_args)) = discover_python_command(&repo_root) else {
            return;
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

        mgr.shutdown();
        let after = mgr.status();
        assert!(!after.running);
        assert!(!after.managed_child);
        assert!(after.pid.is_none());
        let _ = std::fs::remove_file(temp_db);
    }
}
