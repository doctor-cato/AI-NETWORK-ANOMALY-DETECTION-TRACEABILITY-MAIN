import { render } from "svelte/server";
import { describe, expect, it } from "vitest";
import RuntimeSetupPanel from "./RuntimeSetupPanel.svelte";
import type { BackendStatus, RuntimeDiagnostics } from "../types";

const baseDiagnostics: RuntimeDiagnostics = {
  repo_root: "C:\\Program Files\\NetFlow",
  repo_root_valid: true,
  runtime_dir: "C:\\Users\\Alice\\AppData\\Local\\NetFlowSentinelM6",
  db_path: "C:\\Users\\Alice\\AppData\\Local\\NetFlowSentinelM6\\network_anomaly.db",
  python_ready: false,
  python_executable: null,
  python_error: "Missing fastapi/sklearn",
  base_python_available: true,
  base_python_executable: "C:\\Python312\\python.exe",
  base_python_error: null,
  venv_python_path: "C:\\Users\\Alice\\AppData\\Local\\NetFlowSentinelM6\\.venv\\Scripts\\python.exe",
  venv_exists: false,
  requirements_file_exists: true,
  companion_status: "BLOCKED / NOT READY",
  ready_models: [],
  demo_flows_exists: false,
  demo_labels_exists: false,
};

const offlineBackend: BackendStatus = {
  base_url: "",
  port: 0,
  running: false,
  managed_child: false,
  pid: null,
  python_executable: "",
  repo_root: "C:\\Program Files\\NetFlow",
  runtime_dir: "C:\\Users\\Alice\\AppData\\Local\\NetFlowSentinelM6",
  db_path: "C:\\Users\\Alice\\AppData\\Local\\NetFlowSentinelM6\\network_anomaly.db",
  last_error: "Missing python",
};

describe("RuntimeSetupPanel cross-machine onboarding UI", () => {
  it("renders Python setup action when base Python is available and runtime is missing", () => {
    const out = render(RuntimeSetupPanel, {
      props: {
        diagnostics: baseDiagnostics,
        backendStatus: offlineBackend,
        preprocessorReady: false,
        readyModelsCount: 0,
        busy: false,
        isTauri: true,
        onSetupPython: () => {},
        onImportZip: () => {},
        onImportFolder: () => {},
        onRefresh: () => {},
      },
    });
    expect(out.body).toContain("Chuẩn bị Môi trường Chạy Cục bộ");
    expect(out.body).toContain("Thiết lập Python Runtime (.venv)");
    expect(out.body).toContain("Nạp Companion Bundle (.zip)");
    expect(out.body).toContain("Hoàn tất <strong>Bước 2 (Python Runtime)</strong> trước khi nạp Companion Bundle");
    expect(out.body).toContain("0/4 READY");
  });

  it("renders winget Python 3.12 installation instructions when no base Python is installed", () => {
    const out = render(RuntimeSetupPanel, {
      props: {
        diagnostics: {
          ...baseDiagnostics,
          base_python_available: false,
          base_python_executable: null,
        },
        backendStatus: offlineBackend,
        preprocessorReady: false,
        readyModelsCount: 0,
        busy: false,
        isTauri: true,
        onSetupPython: () => {},
        onImportZip: () => {},
        onImportFolder: () => {},
        onRefresh: () => {},
      },
    });
    expect(out.body).toContain("winget install Python.Python.3.12");
    expect(out.body).not.toContain("Thiết lập Python Runtime (.venv)");
  });

  it("hides setup card when backend, preprocessor, and all 4 models are READY", () => {
    const out = render(RuntimeSetupPanel, {
      props: {
        diagnostics: {
          ...baseDiagnostics,
          python_ready: true,
          python_executable: "C:\\venv\\python.exe",
          companion_status: "READY",
          ready_models: ["random_forest", "xgboost", "isolation_forest", "autoencoder"],
          demo_flows_exists: true,
          demo_labels_exists: true,
        },
        backendStatus: {
          ...offlineBackend,
          running: true,
          port: 8000,
          base_url: "http://127.0.0.1:8000",
        },
        preprocessorReady: true,
        readyModelsCount: 4,
        busy: false,
        isTauri: true,
        onSetupPython: () => {},
        onImportZip: () => {},
        onImportFolder: () => {},
        onRefresh: () => {},
      },
    });
    expect(out.body).not.toContain("Chuẩn bị Môi trường Chạy Cục bộ");
  });
});
