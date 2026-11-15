//! Typed Tauri IPC commands bridging Svelte UI to localhost FastAPI & native file dialogs.

use crate::backend::{BackendManager, BackendStatus};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;
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
    let resp = backend
        .http
        .get(&url)
        .send()
        .await
        .map_err(|e| format!("Local FastAPI unreachable ({path}): {e}"))?;
    parse_api_response(resp).await
}

async fn post_json(backend: &BackendManager, path: &str, body: Value) -> Result<Value, String> {
    let base = backend.base_url()?;
    let url = format!("{base}{path}");
    verify_loopback_url(&url)?;
    let resp = backend
        .http
        .post(&url)
        .json(&body)
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
pub async fn restart_backend(backend: State<'_, BackendManager>) -> Result<BackendStatus, String> {
    let mgr = backend.inner().clone();
    tauri::async_runtime::spawn_blocking(move || mgr.ensure_started(8000, Duration::from_secs(15)))
        .await
        .map_err(|e| format!("Restart task panicked: {e}"))?
}

#[tauri::command]
pub fn get_demo_paths(backend: State<'_, BackendManager>) -> Result<DemoPaths, String> {
    let root = backend.repo_root()?;
    let flows: PathBuf = root.join("data").join("demo").join("demo_flows.csv");
    let labels: PathBuf = root.join("data").join("demo").join("demo_labels.csv");
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
            let path = fp
                .into_path()
                .map_err(|e| format!("Invalid local path selected: {e}"))?;
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
            let path = fp
                .into_path()
                .map_err(|e| format!("Invalid export path selected: {e}"))?;
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
            let path = fp
                .into_path()
                .map_err(|e| format!("Invalid export path selected: {e}"))?;
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

#[cfg(test)]
mod tests {
    use super::verify_loopback_url;

    #[test]
    fn test_loopback_guard_accepts_local_only() {
        assert!(verify_loopback_url("http://127.0.0.1:8000/health").is_ok());
        assert!(verify_loopback_url("http://localhost:8000/api/v1/models").is_ok());
        assert!(verify_loopback_url("http://0.0.0.0:8000/health").is_err());
        assert!(verify_loopback_url("https://example.com/api").is_err());
    }
}
