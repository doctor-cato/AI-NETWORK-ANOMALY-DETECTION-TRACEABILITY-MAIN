pub mod backend;
pub mod commands;

use backend::{
    default_db_path, default_runtime_dir, resolve_preferred_backend_port,
    resolve_repo_root_with_resource_dir, BackendManager,
};
use std::time::Duration;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let resource_dir = app.path().resource_dir().ok();
            let repo_root = resolve_repo_root_with_resource_dir(resource_dir.as_deref())
                .unwrap_or_else(|_| {
                    resource_dir.unwrap_or_else(|| {
                        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
                    })
                });
            let runtime_dir = default_runtime_dir(&repo_root);
            let db_path = default_db_path(&repo_root, &runtime_dir);
            let backend = BackendManager::new_with_runtime(repo_root, runtime_dir, db_path)
                .map_err(std::io::Error::other)?;
            app.manage(backend.clone());

            let preferred_port = resolve_preferred_backend_port();
            std::thread::spawn(move || {
                let _ = backend.ensure_started(preferred_port, Duration::from_secs(120));
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_backend_status,
            commands::get_backend_logs,
            commands::get_runtime_diagnostics,
            commands::report_frontend_ready,
            commands::restart_backend,
            commands::get_demo_paths,
            commands::pick_csv_file,
            commands::pick_save_csv_file,
            commands::fetch_health,
            commands::fetch_models_status,
            commands::inspect_csv,
            commands::analyze_csv,
            commands::evaluate_csv,
            commands::export_csv,
            commands::get_backend_timeline,
            commands::pick_save_json_file,
            commands::simulate_security_response,
            commands::list_security_simulations,
            commands::export_security_simulation,
            commands::fetch_crypto_status,
            commands::fetch_trace_timeline,
            commands::fetch_trace_graph,
            commands::generate_investigation_report,
            commands::fetch_incidents,
        ])
        .build(tauri::generate_context!())
        .expect("Failed to build Tauri desktop application");

    app.run(|app_handle, event| {
        if matches!(
            event,
            tauri::RunEvent::WindowEvent {
                event: tauri::WindowEvent::CloseRequested { .. } | tauri::WindowEvent::Destroyed,
                ..
            } | tauri::RunEvent::ExitRequested { .. }
                | tauri::RunEvent::Exit
        ) {
            if let Some(mgr) = app_handle.try_state::<BackendManager>() {
                mgr.shutdown();
            }
        }
    });
}
