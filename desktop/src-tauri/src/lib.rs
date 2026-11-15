pub mod backend;
pub mod commands;

use backend::{default_db_path, resolve_repo_root, BackendManager};
use std::time::Duration;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let repo_root = resolve_repo_root().unwrap_or_else(|_| {
        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
    });
    let db_path = default_db_path(&repo_root);
    let backend =
        BackendManager::new(repo_root, db_path).expect("Failed initializing BackendManager");

    let app = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(backend)
        .setup(|app| {
            let mgr = app.state::<BackendManager>().inner().clone();
            std::thread::spawn(move || {
                let _ = mgr.ensure_started(8000, Duration::from_secs(20));
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::get_backend_status,
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
