import { invoke } from "@tauri-apps/api/core";
import type {
  BackendLogSnapshot,
  BackendStatus,
  BehavioralCorrelationResponse,
  BehavioralSimilarityResponse,
  BehavioralVectorDetailResponse,
  BehavioralVectorListResponse,
  CryptoStatusResponse,
  CsvAnalyzeResponse,
  CsvEvaluateResponse,
  CsvExportResponse,
  CsvFlowPredictionItem,
  CsvInspectResponse,
  DemoPaths,
  HealthResponse,
  IncidentItem,
  InvestigationReportResponse,
  LiveAlertsResponse,
  LiveResultsResponse,
  LiveStatusResponse,
  ModelStatusItem,
  PaginatedIncidentsResponse,
  PaginatedSecuritySimulationsResponse,
  RuntimeDiagnostics,
  SecurityResponseSimulationResponse,
  SecuritySimulationExportResponse,
  TimelineStageItem,
  TraceGraphResponse,
  TraceTimelineResponse,
} from "./types";

export function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export function isLocalhostHttpUrl(raw: string): boolean {
  try {
    const parsed = new URL(raw);
    return (
      parsed.protocol === "http:" &&
      parsed.username === "" &&
      parsed.password === "" &&
      (parsed.hostname === "127.0.0.1" || parsed.hostname === "localhost")
    );
  } catch {
    return false;
  }
}

function resolveLocalhostFallbackUrl(): string {
  if (typeof window !== "undefined") {
    const param = new URLSearchParams(window.location.search).get("api");
    if (param && isLocalhostHttpUrl(param)) {
      return param.replace(/\/+$/, "");
    }
  }
  const envUrl = import.meta.env?.VITE_API_BASE_URL;
  if (typeof envUrl === "string" && isLocalhostHttpUrl(envUrl)) {
    return envUrl.replace(/\/+$/, "");
  }
  return "http://127.0.0.1:8000";
}

async function httpJson<T>(path: string, init?: RequestInit): Promise<T> {
  const url = `${resolveLocalhostFallbackUrl()}${path}`;
  const resp = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers ?? {}),
    },
  });
  const text = await resp.text();
  let parsed: unknown = {};
  try {
    parsed = text ? JSON.parse(text) : {};
  } catch {
    parsed = { detail: text };
  }
  if (!resp.ok) {
    const msg =
      typeof parsed === "object" &&
      parsed !== null &&
      "detail" in parsed &&
      typeof (parsed as { detail: unknown }).detail === "string"
        ? (parsed as { detail: string }).detail
        : `HTTP ${resp.status}`;
    throw new Error(msg);
  }
  return parsed as T;
}

export async function getBackendStatus(): Promise<BackendStatus> {
  if (isTauriRuntime()) {
    return invoke<BackendStatus>("get_backend_status");
  }
  const baseUrl = resolveLocalhostFallbackUrl();
  const parsedPort = Number(new URL(baseUrl).port || 8000);
  try {
    await httpJson<HealthResponse>("/health");
    return {
      base_url: baseUrl,
      port: parsedPort,
      running: true,
      managed_child: false,
      pid: null,
      python_executable: "browser-dev-localhost",
      repo_root: ".",
      db_path: "data/network_anomaly.db",
      last_error: null,
    };
  } catch (err) {
    return {
      base_url: baseUrl,
      port: parsedPort,
      running: false,
      managed_child: false,
      pid: null,
      python_executable: "browser-dev-localhost",
      repo_root: ".",
      db_path: "data/network_anomaly.db",
      last_error: err instanceof Error ? err.message : String(err),
    };
  }
}

export async function restartBackend(): Promise<BackendStatus> {
  if (isTauriRuntime()) {
    return invoke<BackendStatus>("restart_backend");
  }
  return getBackendStatus();
}

export async function getBackendLogs(): Promise<BackendLogSnapshot> {
  if (isTauriRuntime()) {
    return invoke<BackendLogSnapshot>("get_backend_logs");
  }
  const status = await getBackendStatus();
  return {
    starting: Boolean(status.starting),
    running: status.running,
    backend_mode: status.backend_mode ?? "browser_dev",
    startup_stage: status.running ? "ready" : "offline",
    startup_elapsed_ms: status.startup_elapsed_ms ?? 0,
    port: status.port,
    pid: status.pid,
    log_file_path: "(chỉ khả dụng khi chạy bản Desktop Tauri)",
    last_error: status.last_error,
    lines: [
      `[dev] Browser preview mode -> ${status.base_url} (${status.running ? "online" : "offline"})`,
      ...(status.last_error ? [`[dev][error] ${status.last_error}`] : []),
    ],
  };
}

export async function getRuntimeDiagnostics(): Promise<RuntimeDiagnostics | null> {
  if (isTauriRuntime()) {
    return invoke<RuntimeDiagnostics>("get_runtime_diagnostics");
  }
  return null;
}

export async function getDemoPaths(): Promise<DemoPaths> {
  if (isTauriRuntime()) {
    return invoke<DemoPaths>("get_demo_paths");
  }
  return {
    flows_path: "data/demo/demo_flows.csv",
    labels_path: "data/demo/demo_labels.csv",
    flows_exists: true,
    labels_exists: true,
  };
}

export async function pickCsvFile(title?: string): Promise<string | null> {
  if (isTauriRuntime()) {
    return invoke<string | null>("pick_csv_file", { title });
  }
  return null;
}

export async function pickSaveCsvFile(defaultName?: string): Promise<string | null> {
  if (isTauriRuntime()) {
    return invoke<string | null>("pick_save_csv_file", { defaultName });
  }
  return `artifacts/exports/${defaultName ?? "predictions_export.csv"}`;
}

export async function fetchHealth(): Promise<HealthResponse> {
  if (isTauriRuntime()) {
    return invoke<HealthResponse>("fetch_health");
  }
  return httpJson<HealthResponse>("/health");
}

export async function fetchModelsStatus(): Promise<ModelStatusItem[]> {
  if (isTauriRuntime()) {
    return invoke<ModelStatusItem[]>("fetch_models_status");
  }
  return httpJson<ModelStatusItem[]>("/api/v1/models");
}

export async function inspectCsv(
  filePath: string,
  previewLimit = 20,
): Promise<CsvInspectResponse> {
  if (isTauriRuntime()) {
    return invoke<CsvInspectResponse>("inspect_csv", {
      filePath,
      previewLimit,
    });
  }
  return httpJson<CsvInspectResponse>("/api/v1/csv/inspect", {
    method: "POST",
    body: JSON.stringify({ file_path: filePath, preview_limit: previewLimit }),
  });
}

export async function analyzeCsv(params: {
  filePath: string;
  modelName: string;
  createIncidents?: boolean;
  batchSize?: number;
}): Promise<CsvAnalyzeResponse> {
  if (isTauriRuntime()) {
    return invoke<CsvAnalyzeResponse>("analyze_csv", {
      filePath: params.filePath,
      modelName: params.modelName,
      createIncidents: params.createIncidents ?? false,
      batchSize: params.batchSize ?? 500,
    });
  }
  return httpJson<CsvAnalyzeResponse>("/api/v1/csv/analyze", {
    method: "POST",
    body: JSON.stringify({
      file_path: params.filePath,
      model_name: params.modelName,
      create_incidents: params.createIncidents ?? false,
      batch_size: params.batchSize ?? 500,
      include_timeline: true,
      allow_research_only: true,
    }),
  });
}

export async function evaluateCsv(
  labelsPath: string,
  predictions: CsvFlowPredictionItem[],
): Promise<CsvEvaluateResponse> {
  if (isTauriRuntime()) {
    return invoke<CsvEvaluateResponse>("evaluate_csv", {
      labelsPath,
      predictions,
    });
  }
  return httpJson<CsvEvaluateResponse>("/api/v1/csv/evaluate", {
    method: "POST",
    body: JSON.stringify({ labels_path: labelsPath, predictions }),
  });
}

export async function exportCsv(payload: {
  output_path: string;
  analysis_id?: string | null;
  source_csv_path: string | null;
  model_key: string;
  model_type: string;
  run_id: string | null;
  model_sha256: string | null;
  preprocessor_sha256: string | null;
  results: CsvFlowPredictionItem[];
  evaluation: CsvEvaluateResponse | null;
}): Promise<CsvExportResponse> {
  if (isTauriRuntime()) {
    return invoke<CsvExportResponse>("export_csv", { payload });
  }
  return httpJson<CsvExportResponse>("/api/v1/csv/export", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function pickSaveJsonFile(defaultName?: string): Promise<string | null> {
  if (isTauriRuntime()) {
    return invoke<string | null>("pick_save_json_file", { defaultName });
  }
  return `artifacts/exports/${defaultName ?? "security_dry_run_evidence.json"}`;
}

export async function simulateSecurityResponse(payload: {
  analysis_id?: string | null;
  triggered_by?: string;
  dry_run?: boolean;
  source_csv_path?: string | null;
  model_key?: string | null;
  model_type?: string | null;
  run_id?: string | null;
  model_sha256?: string | null;
  preprocessor_sha256?: string | null;
  inference_mode?: string | null;
  results?: CsvFlowPredictionItem[] | null;
}): Promise<SecurityResponseSimulationResponse> {
  if (isTauriRuntime()) {
    return invoke<SecurityResponseSimulationResponse>("simulate_security_response", { payload });
  }
  return httpJson<SecurityResponseSimulationResponse>("/api/v1/security/simulate-response", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function listSecuritySimulations(
  limit = 20,
  offset = 0,
): Promise<PaginatedSecuritySimulationsResponse> {
  if (isTauriRuntime()) {
    return invoke<PaginatedSecuritySimulationsResponse>("list_security_simulations", {
      limit,
      offset,
    });
  }
  return httpJson<PaginatedSecuritySimulationsResponse>(
    `/api/v1/security/simulations?limit=${limit}&offset=${offset}`,
  );
}

export async function exportSecuritySimulation(payload: {
  output_path: string;
  simulation_id: string;
}): Promise<SecuritySimulationExportResponse> {
  if (isTauriRuntime()) {
    return invoke<SecuritySimulationExportResponse>("export_security_simulation", { payload });
  }
  return httpJson<SecuritySimulationExportResponse>("/api/v1/security/simulations/export", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function reportFrontendReady(summary: {
  connected: boolean;
  health_status: string | null;
  ready_models: string[];
  flows_exists: boolean;
  labels_exists: boolean;
  error_message: string | null;
}): Promise<void> {
  if (!isTauriRuntime()) return;
  try {
    await invoke<void>("report_frontend_ready", { summary });
  } catch {
    // Non-fatal diagnostics hook; ignore errors during normal interactive runs
  }
}

export async function fetchCryptoStatus(domain = "general"): Promise<CryptoStatusResponse> {
  if (isTauriRuntime()) {
    return invoke<CryptoStatusResponse>("fetch_crypto_status", { domain });
  }
  return httpJson<CryptoStatusResponse>(`/api/v1/crypto/status?domain=${encodeURIComponent(domain)}`);
}

export async function fetchTraceTimeline(campaignName?: string): Promise<TraceTimelineResponse> {
  if (isTauriRuntime()) {
    return invoke<TraceTimelineResponse>("fetch_trace_timeline", {
      campaignName: campaignName ?? null,
    });
  }
  const q = campaignName ? `?campaign_name=${encodeURIComponent(campaignName)}` : "";
  return httpJson<TraceTimelineResponse>(`/api/v1/trace/timeline${q}`);
}

export async function fetchTraceGraph(
  entityId?: string,
  depth = 2,
): Promise<TraceGraphResponse> {
  if (isTauriRuntime()) {
    return invoke<TraceGraphResponse>("fetch_trace_graph", {
      entityId: entityId ?? null,
      depth,
    });
  }
  const params = new URLSearchParams({ depth: String(depth) });
  if (entityId) params.set("entity_id", entityId);
  return httpJson<TraceGraphResponse>(`/api/v1/trace/graph?${params.toString()}`);
}

export async function startLiveTelemetry(params?: {
  host?: string;
  port?: number;
  demo_heuristics?: boolean;
}): Promise<LiveStatusResponse> {
  if (isTauriRuntime()) {
    return invoke<LiveStatusResponse>("start_live_telemetry", {
      host: params?.host ?? "127.0.0.1",
      port: params?.port ?? 0,
      demoHeuristics: params?.demo_heuristics ?? false,
    });
  }
  return httpJson<LiveStatusResponse>("/api/v1/live/start", {
    method: "POST",
    body: JSON.stringify({
      host: params?.host ?? "127.0.0.1",
      port: params?.port ?? 0,
      demo_heuristics: params?.demo_heuristics ?? false,
    }),
  });
}

export async function stopLiveTelemetry(): Promise<LiveStatusResponse> {
  if (isTauriRuntime()) {
    return invoke<LiveStatusResponse>("stop_live_telemetry");
  }
  return httpJson<LiveStatusResponse>("/api/v1/live/stop", {
    method: "POST",
    body: JSON.stringify({}),
  });
}

export async function fetchLiveStatus(): Promise<LiveStatusResponse> {
  if (isTauriRuntime()) {
    return invoke<LiveStatusResponse>("fetch_live_status");
  }
  return httpJson<LiveStatusResponse>("/api/v1/live/status");
}

export async function fetchLiveResults(limit = 50): Promise<LiveResultsResponse> {
  if (isTauriRuntime()) {
    return invoke<LiveResultsResponse>("fetch_live_results", { limit });
  }
  return httpJson<LiveResultsResponse>(`/api/v1/live/results?limit=${limit}`);
}

export async function fetchLiveAlerts(limit = 50): Promise<LiveAlertsResponse> {
  if (isTauriRuntime()) {
    return invoke<LiveAlertsResponse>("fetch_live_alerts", { limit });
  }
  return httpJson<LiveAlertsResponse>(`/api/v1/live/alerts?limit=${limit}`);
}

export async function fetchLiveGraph(): Promise<TraceGraphResponse> {
  if (isTauriRuntime()) {
    return invoke<TraceGraphResponse>("fetch_live_graph");
  }
  return httpJson<TraceGraphResponse>("/api/v1/live/graph");
}

export async function fetchBehavioralVectors(params?: {
  entityId?: string;
  limit?: number;
}): Promise<BehavioralVectorListResponse> {
  if (isTauriRuntime()) {
    return invoke<BehavioralVectorListResponse>("fetch_behavioral_vectors", {
      entityId: params?.entityId ?? null,
      limit: params?.limit ?? 50,
    });
  }
  const q = new URLSearchParams({ limit: String(params?.limit ?? 50) });
  if (params?.entityId) q.set("entity_id", params.entityId);
  return httpJson<BehavioralVectorListResponse>(`/api/v1/behavioral/vectors?${q.toString()}`);
}

export async function fetchBehavioralVectorDetail(
  vectorId: string,
): Promise<BehavioralVectorDetailResponse> {
  if (isTauriRuntime()) {
    return invoke<BehavioralVectorDetailResponse>("fetch_behavioral_vector_detail", {
      vectorId,
    });
  }
  return httpJson<BehavioralVectorDetailResponse>(
    `/api/v1/behavioral/vectors/${encodeURIComponent(vectorId)}`,
  );
}

export async function fetchBehavioralSimilarity(
  vectorAId: string,
  vectorBId: string,
): Promise<BehavioralSimilarityResponse> {
  if (isTauriRuntime()) {
    return invoke<BehavioralSimilarityResponse>("fetch_behavioral_similarity", {
      vectorAId,
      vectorBId,
    });
  }
  const q = new URLSearchParams({
    vector_a_id: vectorAId,
    vector_b_id: vectorBId,
  });
  return httpJson<BehavioralSimilarityResponse>(`/api/v1/behavioral/similarity?${q.toString()}`);
}

export async function fetchBehavioralCorrelation(params?: {
  matchThreshold?: number;
  limit?: number;
}): Promise<BehavioralCorrelationResponse> {
  if (isTauriRuntime()) {
    return invoke<BehavioralCorrelationResponse>("fetch_behavioral_correlation", {
      matchThreshold: params?.matchThreshold ?? 0.85,
      limit: params?.limit ?? 20,
    });
  }
  const q = new URLSearchParams({
    match_threshold: String(params?.matchThreshold ?? 0.85),
    limit: String(params?.limit ?? 20),
  });
  return httpJson<BehavioralCorrelationResponse>(`/api/v1/behavioral/correlate?${q.toString()}`);
}

export async function generateInvestigationReport(payload: {
  incident_id: string;
  title: string;
  severity?: string;
  root_cause_summary?: string;
  events?: Array<Record<string, unknown>>;
  evidence_records?: Array<Record<string, unknown>>;
}): Promise<InvestigationReportResponse> {
  if (isTauriRuntime()) {
    return invoke<InvestigationReportResponse>("generate_investigation_report", { payload });
  }
  return httpJson<InvestigationReportResponse>("/api/v1/trace/investigation/generate", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function fetchIncidents(params?: {
  limit?: number;
  offset?: number;
  severity?: string;
}): Promise<PaginatedIncidentsResponse> {
  if (isTauriRuntime()) {
    return invoke<PaginatedIncidentsResponse>("fetch_incidents", {
      limit: params?.limit ?? 50,
      offset: params?.offset ?? 0,
      severity: params?.severity ?? null,
    });
  }
  const query = new URLSearchParams();
  if (params?.limit) query.set("limit", String(params.limit));
  if (params?.offset) query.set("offset", String(params.offset));
  if (params?.severity && params.severity !== "ALL") query.set("severity", params.severity);
  const qStr = query.toString();
  return httpJson<PaginatedIncidentsResponse>(`/api/v1/incidents${qStr ? `?${qStr}` : ""}`);
}
