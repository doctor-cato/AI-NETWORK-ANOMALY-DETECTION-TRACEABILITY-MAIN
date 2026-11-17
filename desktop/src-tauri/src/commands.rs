//! Typed Tauri IPC commands bridging Svelte UI to localhost FastAPI & native file dialogs.

use crate::backend::{
    resolve_preferred_backend_port, strip_windows_verbatim_prefix, BackendLogSnapshot,
    BackendManager, BackendStatus, RuntimeDiagnostics,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tauri::{AppHandle, State};
use tauri_plugin_dialog::DialogExt;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemoPaths {
    pub flows_path: String,
    pub labels_path: String,
    pub flows_exists: bool,
    pub labels_exists: bool,
}

fn verify_loopback_url(url: &str) -> Result<(), String> {
    if url.starts_with("http://127.0.0.1:") || url.starts_with("http://localhost:") {
        Ok(())
    } else {
        Err("Refused non-loopback backend URL (#26 security policy).".to_string())
    }
}

async fn parse_api_response(resp: reqwest::Response) -> Result<Value, String> {
    let status = resp.status();
    let text = resp
        .text()
        .await
        .map_err(|e| format!("Failed reading backend response: {e}"))?;
    let parsed: Value = serde_json::from_str(&text)
        .unwrap_or_else(|_| json!({ "error": "InvalidResponse", "detail": text }));
    if !status.is_success() {
        let detail = parsed
            .get("detail")
            .and_then(|v| v.as_str())
            .unwrap_or("Backend request failed");
        return Err(format!("HTTP {} — {}", status.as_u16(), detail));
    }
    Ok(parsed)
}

async fn get_json(backend: &BackendManager, path: &str) -> Result<Value, String> {
    let base = backend.base_url()?;
    let url = format!("{base}{path}");
    verify_loopback_url(&url)?;
    let mut req = backend.http.get(&url);
    let token = backend.session_token()?;
    if !token.is_empty() {
        req = req.header("X-Sentinel-Session-Token", token);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("Local FastAPI unreachable ({path}): {e}"))?;
    parse_api_response(resp).await
}

async fn post_json(backend: &BackendManager, path: &str, body: Value) -> Result<Value, String> {
    let base = backend.base_url()?;
    let url = format!("{base}{path}");
    verify_loopback_url(&url)?;
    let mut req = backend.http.post(&url).json(&body);
    let token = backend.session_token()?;
    if !token.is_empty() {
        req = req.header("X-Sentinel-Session-Token", token);
    }
    let resp = req
        .send()
        .await
        .map_err(|e| format!("Local FastAPI unreachable ({path}): {e}"))?;
    parse_api_response(resp).await
}

#[tauri::command]
pub fn get_backend_status(backend: State<'_, BackendManager>) -> BackendStatus {
    backend.status()
}

#[tauri::command]
pub fn get_backend_logs(backend: State<'_, BackendManager>) -> BackendLogSnapshot {
    backend.logs_snapshot()
}

#[tauri::command]
pub async fn get_runtime_diagnostics(
    backend: State<'_, BackendManager>,
) -> Result<RuntimeDiagnostics, String> {
    let mgr = backend.inner().clone();
    tauri::async_runtime::spawn_blocking(move || mgr.diagnostics())
        .await
        .map_err(|e| format!("Diagnostics task failed: {e}"))
}

#[tauri::command]
pub fn report_frontend_ready(
    backend: State<'_, BackendManager>,
    summary: Value,
) -> Result<(), String> {
    let Some(target) = std::env::var_os("NETWORK_ANOMALY_DESKTOP_TELEMETRY_FILE") else {
        return Ok(());
    };
    let target_path = PathBuf::from(target);
    if target_path.as_os_str().is_empty() {
        return Ok(());
    }
    if let Some(parent) = target_path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("Failed creating telemetry directory: {e}"))?;
        }
    }
    let backend_status = backend.status();
    let reported_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let frontend_connected = summary
        .get("connected")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
        && backend_status.running;
    let payload = json!({
        "desktop_pid": std::process::id(),
        "frontend_connected": frontend_connected,
        "reported_unix_ms": reported_unix_ms,
        "backend_status": backend_status,
        "summary": summary,
    });
    let serialized = serde_json::to_string_pretty(&payload)
        .map_err(|e| format!("Failed serializing desktop telemetry: {e}"))?;
    let tmp_path = target_path.with_extension("json.tmp");
    std::fs::write(&tmp_path, format!("{serialized}\n"))
        .map_err(|e| format!("Failed writing desktop telemetry temp file: {e}"))?;
    std::fs::rename(&tmp_path, &target_path)
        .map_err(|e| format!("Failed finalizing desktop telemetry file: {e}"))?;
    Ok(())
}

#[tauri::command]
pub async fn restart_backend(backend: State<'_, BackendManager>) -> Result<BackendStatus, String> {
    let mgr = backend.inner().clone();
    let preferred_port = resolve_preferred_backend_port();
    tauri::async_runtime::spawn_blocking(move || {
        mgr.ensure_started(preferred_port, Duration::from_secs(120))
    })
    .await
    .map_err(|e| format!("Restart task panicked: {e}"))?
}

#[tauri::command]
pub fn get_demo_paths(backend: State<'_, BackendManager>) -> Result<DemoPaths, String> {
    let runtime_dir = backend.runtime_dir()?;
    let repo_root = backend.repo_root()?;
    let repo_flows = repo_root.join("data").join("demo").join("demo_flows.csv");
    let repo_labels = repo_root.join("data").join("demo").join("demo_labels.csv");
    let runtime_flows = runtime_dir.join("data").join("demo").join("demo_flows.csv");
    let runtime_labels = runtime_dir
        .join("data")
        .join("demo")
        .join("demo_labels.csv");

    let flows = strip_windows_verbatim_prefix(&if repo_flows.is_file() {
        repo_flows
    } else if runtime_flows.is_file() {
        runtime_flows
    } else {
        repo_flows
    });
    let labels = strip_windows_verbatim_prefix(&if repo_labels.is_file() {
        repo_labels
    } else if runtime_labels.is_file() {
        runtime_labels
    } else {
        repo_labels
    });

    Ok(DemoPaths {
        flows_exists: flows.is_file(),
        labels_exists: labels.is_file(),
        flows_path: flows.to_string_lossy().to_string(),
        labels_path: labels.to_string_lossy().to_string(),
    })
}

#[tauri::command]
pub async fn pick_csv_file(
    app: AppHandle,
    title: Option<String>,
) -> Result<Option<String>, String> {
    let dialog_title = title.unwrap_or_else(|| "Chọn tệp NetFlow CSV".to_string());
    let picked = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_title(&dialog_title)
            .add_filter("NetFlow CSV", &["csv"])
            .blocking_pick_file()
    })
    .await
    .map_err(|e| format!("File dialog task failed: {e}"))?;

    match picked {
        Some(fp) => {
            let path = strip_windows_verbatim_prefix(
                &fp.into_path()
                    .map_err(|e| format!("Invalid local path selected: {e}"))?,
            );
            Ok(Some(path.to_string_lossy().to_string()))
        }
        None => Ok(None),
    }
}

#[tauri::command]
pub async fn pick_save_csv_file(
    app: AppHandle,
    default_name: Option<String>,
) -> Result<Option<String>, String> {
    let fname = default_name.unwrap_or_else(|| "predictions_export.csv".to_string());
    let picked = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_title("Xuất kết quả dự đoán CSV")
            .set_file_name(&fname)
            .add_filter("CSV Files", &["csv"])
            .blocking_save_file()
    })
    .await
    .map_err(|e| format!("Save dialog task failed: {e}"))?;

    match picked {
        Some(fp) => {
            let path = strip_windows_verbatim_prefix(
                &fp.into_path()
                    .map_err(|e| format!("Invalid export path selected: {e}"))?,
            );
            Ok(Some(path.to_string_lossy().to_string()))
        }
        None => Ok(None),
    }
}

#[tauri::command]
pub async fn fetch_health(backend: State<'_, BackendManager>) -> Result<Value, String> {
    get_json(backend.inner(), "/health").await
}

#[tauri::command]
pub async fn fetch_models_status(backend: State<'_, BackendManager>) -> Result<Value, String> {
    get_json(backend.inner(), "/api/v1/models").await
}

#[tauri::command]
pub async fn inspect_csv(
    backend: State<'_, BackendManager>,
    file_path: String,
    preview_limit: Option<u32>,
) -> Result<Value, String> {
    post_json(
        backend.inner(),
        "/api/v1/csv/inspect",
        json!({
            "file_path": file_path,
            "preview_limit": preview_limit.unwrap_or(20),
        }),
    )
    .await
}

#[tauri::command]
pub async fn analyze_csv(
    backend: State<'_, BackendManager>,
    file_path: String,
    model_name: String,
    create_incidents: Option<bool>,
    batch_size: Option<u32>,
) -> Result<Value, String> {
    post_json(
        backend.inner(),
        "/api/v1/csv/analyze",
        json!({
            "file_path": file_path,
            "model_name": model_name,
            "create_incidents": create_incidents.unwrap_or(false),
            "batch_size": batch_size.unwrap_or(500),
            "include_timeline": true,
            "allow_research_only": true,
        }),
    )
    .await
}

#[tauri::command]
pub async fn evaluate_csv(
    backend: State<'_, BackendManager>,
    labels_path: String,
    predictions: Value,
) -> Result<Value, String> {
    post_json(
        backend.inner(),
        "/api/v1/csv/evaluate",
        json!({
            "labels_path": labels_path,
            "predictions": predictions,
        }),
    )
    .await
}

#[tauri::command]
pub async fn export_csv(
    backend: State<'_, BackendManager>,
    payload: Value,
) -> Result<Value, String> {
    post_json(backend.inner(), "/api/v1/csv/export", payload).await
}

#[tauri::command]
pub async fn get_backend_timeline(
    backend: State<'_, BackendManager>,
    limit: Option<u32>,
    offset: Option<u32>,
) -> Result<Value, String> {
    let path = format!(
        "/api/v1/timeline?limit={}&offset={}",
        limit.unwrap_or(50),
        offset.unwrap_or(0)
    );
    get_json(backend.inner(), &path).await
}

#[tauri::command]
pub async fn pick_save_json_file(
    app: AppHandle,
    default_name: Option<String>,
) -> Result<Option<String>, String> {
    let fname = default_name.unwrap_or_else(|| "security_dry_run_evidence.json".to_string());
    let picked = tauri::async_runtime::spawn_blocking(move || {
        app.dialog()
            .file()
            .set_title("Xuất bằng chứng Dry-Run (#27)")
            .set_file_name(&fname)
            .add_filter("JSON Evidence", &["json"])
            .blocking_save_file()
    })
    .await
    .map_err(|e| format!("Save JSON dialog task failed: {e}"))?;

    match picked {
        Some(fp) => {
            let path = strip_windows_verbatim_prefix(
                &fp.into_path()
                    .map_err(|e| format!("Invalid export path selected: {e}"))?,
            );
            Ok(Some(path.to_string_lossy().to_string()))
        }
        None => Ok(None),
    }
}

#[tauri::command]
pub async fn simulate_security_response(
    backend: State<'_, BackendManager>,
    payload: Value,
) -> Result<Value, String> {
    post_json(
        backend.inner(),
        "/api/v1/security/simulate-response",
        payload,
    )
    .await
}

#[tauri::command]
pub async fn list_security_simulations(
    backend: State<'_, BackendManager>,
    limit: Option<u32>,
    offset: Option<u32>,
) -> Result<Value, String> {
    let path = format!(
        "/api/v1/security/simulations?limit={}&offset={}",
        limit.unwrap_or(20),
        offset.unwrap_or(0)
    );
    get_json(backend.inner(), &path).await
}

#[tauri::command]
pub async fn export_security_simulation(
    backend: State<'_, BackendManager>,
    payload: Value,
) -> Result<Value, String> {
    post_json(
        backend.inner(),
        "/api/v1/security/simulations/export",
        payload,
    )
    .await
}

fn encode_query_component(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

#[tauri::command]
pub async fn fetch_crypto_status(
    backend: State<'_, BackendManager>,
    domain: Option<String>,
) -> Result<Value, String> {
    let dom = domain.unwrap_or_else(|| "general".to_string());
    let path = format!(
        "/api/v1/crypto/status?domain={}",
        encode_query_component(&dom)
    );
    get_json(backend.inner(), &path).await
}

#[tauri::command]
pub async fn fetch_trace_timeline(
    backend: State<'_, BackendManager>,
    campaign_name: Option<String>,
) -> Result<Value, String> {
    let camp = campaign_name.unwrap_or_else(|| "APT-Campaign-01".to_string());
    let path = format!(
        "/api/v1/trace/timeline?campaign_name={}",
        encode_query_component(&camp)
    );
    get_json(backend.inner(), &path).await
}

#[tauri::command]
pub async fn fetch_trace_graph(
    backend: State<'_, BackendManager>,
    entity_id: Option<String>,
    depth: Option<u32>,
) -> Result<Value, String> {
    let ent = entity_id.unwrap_or_else(|| "10.0.0.5".to_string());
    let d = depth.unwrap_or(2).clamp(1, 5);
    let path = format!(
        "/api/v1/trace/graph?entity_id={}&depth={d}",
        encode_query_component(&ent)
    );
    get_json(backend.inner(), &path).await
}

#[tauri::command]
pub async fn generate_investigation_report(
    backend: State<'_, BackendManager>,
    payload: Value,
) -> Result<Value, String> {
    post_json(
        backend.inner(),
        "/api/v1/trace/investigation/generate",
        payload,
    )
    .await
}

#[tauri::command]
pub async fn fetch_incidents(
    backend: State<'_, BackendManager>,
    limit: Option<u32>,
    offset: Option<u32>,
    severity: Option<String>,
) -> Result<Value, String> {
    let mut path = format!(
        "/api/v1/incidents?limit={}&offset={}",
        limit.unwrap_or(50),
        offset.unwrap_or(0)
    );
    if let Some(sev) = severity {
        if !sev.is_empty() && sev != "ALL" {
            path.push_str(&format!("&severity={}", encode_query_component(&sev)));
        }
    }
    get_json(backend.inner(), &path).await
}

#[cfg(test)]
mod tests {
    use super::verify_loopback_url;

    #[test]
    fn test_ipc_preserves_prediction_numbers_for_verified_export() {
        let payload = r#"{"results":[{"raw_anomaly_score":51.248178375505404}]}"#;
        let parsed: serde_json::Value = serde_json::from_str(payload).unwrap();
        assert_eq!(serde_json::to_string(&parsed).unwrap(), payload);
    }

    #[test]
    fn test_loopback_guard_accepts_local_only() {
        assert!(verify_loopback_url("http://127.0.0.1:8000/health").is_ok());
        assert!(verify_loopback_url("http://localhost:8000/api/v1/models").is_ok());
        assert!(verify_loopback_url("http://0.0.0.0:8000/health").is_err());
        assert!(verify_loopback_url("https://example.com/api").is_err());
    }
}
