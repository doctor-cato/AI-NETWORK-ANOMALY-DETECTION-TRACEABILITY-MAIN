import { render } from "svelte/server";
import { describe, expect, it } from "vitest";
import DevLogsPanel from "./DevLogsPanel.svelte";
import ModelReadinessPanel from "./ModelReadinessPanel.svelte";
import OnboardingGuidePanel from "./OnboardingGuidePanel.svelte";
import { formatUserFriendlyError, getModelGovernanceInfo } from "../utils";
import type { BackendLogSnapshot, ModelStatusItem } from "../types";

const sampleModels: ModelStatusItem[] = [
  {
    model_key: "random_forest",
    display_name: "Random Forest",
    model_type: "RandomForest",
    ready: true,
    status: "READY",
    artifact_path: "artifacts/models/random_forest/random_forest_baseline.joblib",
    manifest_path: "reports/models/random_forest_manifest.json",
    artifact_sha256: "a".repeat(64),
    run_id: "rf-baseline-1",
    decision_threshold: 0.5,
    score_semantics: "attack_probability",
    reason: null,
  },
  {
    model_key: "xgboost",
    display_name: "XGBoost",
    model_type: "XGBoost",
    ready: true,
    status: "READY",
    artifact_path: "artifacts/models/xgboost/xgboost_baseline.joblib",
    manifest_path: "reports/models/xgboost_manifest.json",
    artifact_sha256: "b".repeat(64),
    run_id: "xgb-baseline-1",
    decision_threshold: 0.5,
    score_semantics: "attack_probability",
    reason: null,
  },
  {
    model_key: "isolation_forest",
    display_name: "Isolation Forest",
    model_type: "IsolationForest",
    ready: true,
    status: "READY",
    artifact_path: "artifacts/models/isolation_forest/isolation_forest.joblib",
    manifest_path: "reports/models/isolation_forest_manifest.json",
    artifact_sha256: "c".repeat(64),
    run_id: "if-1",
    decision_threshold: -0.0335,
    score_semantics: "anomaly_score_unsupervised",
    reason: null,
  },
  {
    model_key: "autoencoder",
    display_name: "Autoencoder",
    model_type: "Autoencoder",
    ready: true,
    status: "READY",
    artifact_path: "artifacts/models/autoencoder/autoencoder_model.joblib",
    manifest_path: "reports/models/autoencoder_manifest.json",
    artifact_sha256: "d".repeat(64),
    run_id: "ae-1",
    decision_threshold: 17234985.79,
    score_semantics: "reconstruction_error",
    reason: null,
  },
];

describe("Standalone v1.0.0 Onboarding & Model Governance UI", () => {
  it("renders 4-step workflow without Python or Companion Bundle setup prompts", () => {
    const out = render(OnboardingGuidePanel, {
      props: {
        hasFlows: false,
        hasAnalysis: false,
        hasComparison: false,
        hasEvaluation: false,
        hasExport: false,
        readyModelsCount: 4,
      },
    });
    expect(out.body).toContain("4/4 Mô hình AI");
    expect(out.body).toContain("Nạp luồng NetFlow CSV");
    expect(out.body).toContain("Quét bằng 4 Mô hình AI");
    expect(out.body).toContain("Xuất biên bản kiểm chứng");
    expect(out.body).not.toContain("NetFlow v3");
    expect(out.body).not.toContain("Companion Bundle");
    expect(out.body).not.toContain("winget install");
    expect(out.body).not.toContain(".venv");
  });

  it("distinguishes MODEL_VALIDATED vs RESEARCH_ONLY across all 4 model cards", () => {
    const out = render(ModelReadinessPanel, {
      props: {
        models: sampleModels,
        selectedModel: "random_forest",
        busy: false,
        onSelect: () => {},
      },
    });
    expect(out.body).toContain("Chính thức (Validated)");
    expect(out.body).toContain("Nghiên cứu (Research)");
    expect(out.body).toContain("Nghiên cứu (Unsupervised)");
    expect(out.body).toContain("Nghiên cứu (Deep Learning)");
    expect(getModelGovernanceInfo("random_forest").tier).toBe("MODEL_VALIDATED");
    expect(getModelGovernanceInfo("xgboost").tier).toBe("RESEARCH_ONLY");
    expect(getModelGovernanceInfo("isolation_forest").tier).toBe("RESEARCH_ONLY");
    expect(getModelGovernanceInfo("autoencoder").tier).toBe("RESEARCH_ONLY");
  });

  it("formats technical backend errors into user-friendly Vietnamese messages", () => {
    expect(formatUserFriendlyError("Input data is missing 3 required baseline ML feature(s)")).toContain(
      "Tệp CSV chưa đúng định dạng NetFlow v3",
    );
    expect(formatUserFriendlyError("HTTP 503 — Model not ready")).toContain(
      "Hệ thống mô hình AI chưa sẵn sàng",
    );
    expect(formatUserFriendlyError("UNC or network share CSV paths are blocked")).toContain(
      "đường dẫn mạng chia sẻ",
    );
  });

  it("renders DevLogsPanel (Shift+F9) with sidecar startup stage and captured log lines", () => {
    const logs: BackendLogSnapshot = {
      starting: true,
      running: false,
      backend_mode: "embedded_sidecar",
      startup_stage: "unpacking_and_booting",
      startup_elapsed_ms: 14500,
      port: 0,
      pid: null,
      log_file_path: "C:\\Users\\Admin\\AppData\\Local\\NetFlowSentinel\\logs\\backend.log",
      last_error: null,
      lines: [
        "[+  0.01s] [tauri] Spawning embedded_sidecar on 127.0.0.1:8000",
        "[+ 10.02s] [tauri] Still waiting for /health (10s / 120s)...",
      ],
    };
    const out = render(DevLogsPanel, {
      props: {
        logs,
        backendStatus: null,
        diagnostics: null,
        onRefresh: () => {},
        onClose: () => {},
      },
    });
    expect(out.body).toContain("Nhật ký Kỹ thuật Backend / Dev Logs");
    expect(out.body).toContain("Shift+F9");
    expect(out.body).toContain("unpacking_and_booting");
    expect(out.body).toContain("14.5s");
    expect(out.body).toContain("Spawning embedded_sidecar");
  });
});
