<script lang="ts">
  import { getCurrentWebview } from "@tauri-apps/api/webview";
  import { onMount } from "svelte";
  import {
    analyzeCsv,
    evaluateCsv,
    exportCsv,
    exportSecuritySimulation,
    fetchHealth,
    fetchModelsStatus,
    getBackendLogs,
    getBackendStatus,
    getDemoPaths,
    getRuntimeDiagnostics,
    inspectCsv,
    isTauriRuntime,
    listSecuritySimulations,
    pickCsvFile,
    pickSaveCsvFile,
    pickSaveJsonFile,
    reportFrontendReady,
    restartBackend,
    simulateSecurityResponse,
  } from "./lib/api";
  import ChartsPanel from "./lib/components/ChartsPanel.svelte";
  import CsvPreviewPanel from "./lib/components/CsvPreviewPanel.svelte";
  import DevLogsPanel from "./lib/components/DevLogsPanel.svelte";
  import EvaluationPanel from "./lib/components/EvaluationPanel.svelte";
  import ForensicTimelinePanel from "./lib/components/ForensicTimelinePanel.svelte";
  import Icons from "./lib/components/Icons.svelte";
  import logoUrl from "./assets/netflow-sentinel-logo.png";
  import ModelComparisonPanel from "./lib/components/ModelComparisonPanel.svelte";
  import OnboardingGuidePanel from "./lib/components/OnboardingGuidePanel.svelte";
  import PredictionsTable from "./lib/components/PredictionsTable.svelte";
  import LiveMonitoringPanel from "./lib/components/LiveMonitoringPanel.svelte";
  import BehavioralAnalysisPanel from "./lib/components/BehavioralAnalysisPanel.svelte";
  import AttackTimelinePanel from "./lib/components/AttackTimelinePanel.svelte";
  import CryptographyDashboardPanel from "./lib/components/CryptographyDashboardPanel.svelte";
  import {
    createInitialComparisonState,
    evaluateAllModelsWorkflow,
    evaluateSingleModelWorkflow,
    getBatchCoherentAnalyses,
    getBatchCoherentEvaluations,
    getBatchCoherentSimulations,
    invalidateForBackendRestart,
    invalidateForFlowsChange,
    invalidateForInspectResult,
    invalidateForLabelsChange,
    reconcileModelsReadiness,
    recordModelSimulation,
    runAllModelsComparisonWorkflow,
    runSingleModelAnalysisWorkflow,
    type ComparisonBatchState,
    type ComparisonWorkflowDeps,
  } from "./lib/comparisonState";
  import type {
    BackendLogSnapshot,
    BackendStatus,
    CsvAnalyzeResponse,
    CsvExportResponse,
    CsvInspectResponse,
    HealthResponse,
    ModelStatusItem,
    RuntimeDiagnostics,
    SecurityResponseSimulationResponse,
    SecuritySimulationExportResponse,
    SecuritySimulationHistoryItem,
  } from "./lib/types";
  import { formatUserFriendlyError, getDroppedCsvPath, shortDigest } from "./lib/utils";

  import type { IconName } from "./lib/components/Icons.svelte";

  type TabId =
    | "overview"
    | "predictions"
    | "evaluation"
    | "forensics"
    | "live"
    | "behavioral"
    | "attack_timeline"
    | "crypto";

  interface NavItemMeta {
    id: TabId;
    label: string;
    subtitle: string;
    groupLabel: string;
    icon: IconName;
  }

  const OFFLINE_TABS: TabId[] = ["overview", "predictions", "evaluation", "forensics"];

  const NAV_SECTIONS: Array<{ title: string; items: NavItemMeta[] }> = [
    {
      title: "PHÂN TÍCH TỆP (OFFLINE)",
      items: [
        {
          id: "overview",
          label: "Tổng quan & Phân tích",
          subtitle: "Nạp tệp lưu lượng NetFlow L4, chạy song song 4 mô hình AI và xem mức độ rủi ro tức thì.",
          groupLabel: "Phân tích Tệp (Offline)",
          icon: "chart",
        },
        {
          id: "predictions",
          label: "Danh sách Luồng (Flows)",
          subtitle: "Tra cứu từng luồng mạng, lọc Attack/Benign/OOD và xem giải thích chi tiết (Ctrl+F, ↑/↓).",
          groupLabel: "Phân tích Tệp (Offline)",
          icon: "table",
        },
        {
          id: "evaluation",
          label: "Đối chiếu Nhãn (Metric)",
          subtitle: "So sánh dự đoán AI với nhãn thực tế (Ground Truth) để tính Precision, Recall, F1 và FPR.",
          groupLabel: "Phân tích Tệp (Offline)",
          icon: "target",
        },
        {
          id: "forensics",
          label: "Mô phỏng Phản ứng",
          subtitle: "Kiểm thử khuyến nghị cách ly/chặn IP ở chế độ an toàn Dry-Run (không tự sửa tường lửa).",
          groupLabel: "Phân tích Tệp (Offline)",
          icon: "clock",
        },
      ],
    },
    {
      title: "GIÁM SÁT & TRUY VẾT",
      items: [
        {
          id: "live",
          label: "Giám sát Trực tiếp",
          subtitle: "Phát lại hoặc theo dõi luồng mạng theo thời gian thực qua WebSocket cục bộ.",
          groupLabel: "Giám sát & Truy vết",
          icon: "refresh",
        },
        {
          id: "behavioral",
          label: "Hồ sơ Hành vi Host",
          subtitle: "Phân tích vector hành vi 16 chiều của từng địa chỉ IP nguồn để phát hiện bất thường chuỗi.",
          groupLabel: "Giám sát & Truy vết",
          icon: "chart",
        },
        {
          id: "attack_timeline",
          label: "Chuỗi Tấn công",
          subtitle: "Truy vết tiến trình tấn công (Recon → Credential → Exfiltration) theo dòng thời gian.",
          groupLabel: "Giám sát & Truy vết",
          icon: "shield",
        },
      ],
    },
    {
      title: "BẢO MẬT DỮ LIỆU",
      items: [
        {
          id: "crypto",
          label: "Mã hóa & Quản lý Khóa",
          subtitle: "Bảo vệ dữ liệu phân tích và nhật ký truy vết bằng AES-256-GCM và xoay khóa an toàn.",
          groupLabel: "Bảo mật Dữ liệu",
          icon: "cpu",
        },
      ],
    },
  ];

  let theme = $state<"dark" | "light">("light");
  let showGuide = $state(false);
  let activeTab = $state<TabId>("overview");
  let isOfflineTab = $derived(OFFLINE_TABS.includes(activeTab));
  let activeNavMeta = $derived(
    NAV_SECTIONS.flatMap((s) => s.items).find((it) => it.id === activeTab) ?? NAV_SECTIONS[0].items[0],
  );

  let backendStatus = $state<BackendStatus | null>(null);
  let runtimeDiagnostics = $state<RuntimeDiagnostics | null>(null);
  let healthData = $state<HealthResponse | null>(null);
  let models = $state<ModelStatusItem[]>([]);
  let selectedModel = $state("random_forest");

  let flowsPath = $state("");
  let labelsPath = $state("");
  let inspectData = $state<CsvInspectResponse | null>(null);
  let comparisonState = $state<ComparisonBatchState>(createInitialComparisonState());
  let coherentAnalyses = $derived(getBatchCoherentAnalyses(comparisonState));
  let coherentEvaluations = $derived(getBatchCoherentEvaluations(comparisonState));
  let coherentSimulations = $derived(getBatchCoherentSimulations(comparisonState));
  let analysisData = $derived(coherentAnalyses[selectedModel] ?? null);
  let evalData = $derived(coherentEvaluations[selectedModel] ?? null);
  let exportData = $state<CsvExportResponse | null>(null);
  let simulationData = $derived(coherentSimulations[selectedModel] ?? null);
  let simulationHistory = $state<SecuritySimulationHistoryItem[]>([]);
  let simulationExportData = $state<SecuritySimulationExportResponse | null>(null);

  let initializing = $state(true);
  let dragDropUnavailable = $state(false);
  let busyMessage = $state<string | null>(null);
  let errorMessage = $state<string | null>(null);
  let simulationWarning = $state<string | null>(null);
  let evaluatedFlag = $state(false);
  let simulatingFlag = $state(false);
  let showDevLogs = $state(false);
  let devLogs = $state<BackendLogSnapshot | null>(null);

  let readyModelsCount = $derived(models.filter((m) => m.ready).length);

  function handleFlowsPathChange(nextPath: string) {
    if (nextPath !== flowsPath) {
      handleLabelsPathChange("");
    }
    flowsPath = nextPath;
    const nextState = invalidateForFlowsChange(comparisonState, nextPath);
    if (nextState !== comparisonState) {
      comparisonState = nextState;
      inspectData = null;
      exportData = null;
      simulationExportData = null;
      simulationWarning = null;
    }
  }

  function handleLabelsPathChange(nextPath: string) {
    labelsPath = nextPath;
    comparisonState = invalidateForLabelsChange(comparisonState, nextPath);
  }

  function ensureReadySelectedModel(modelList: ModelStatusItem[]) {
    const readyKeys = modelList.filter((m) => m.ready).map((m) => m.model_key);
    if (readyKeys.length > 0 && !readyKeys.includes(selectedModel)) {
      selectedModel = readyKeys[0];
    }
  }

  $effect(() => {
    if (typeof document !== "undefined") {
      document.documentElement.setAttribute("data-theme", theme);
    }
  });

  function toggleTheme() {
    theme = theme === "dark" ? "light" : "dark";
  }

  async function refreshDiagnosticsAndDemoPaths(): Promise<void> {
    try {
      const [diag] = await Promise.all([getRuntimeDiagnostics(), getDemoPaths()]);
      runtimeDiagnostics = diag;
    } catch {
      // Ignore secondary diagnostics error
    }
  }

  async function refreshStatus(): Promise<void> {
    errorMessage = null;
    try {
      const [bStatus, health, modelList] = await Promise.all([
        getBackendStatus(),
        fetchHealth(),
        fetchModelsStatus(),
      ]);
      backendStatus = bStatus;
      healthData = health;
      models = modelList;
      comparisonState = reconcileModelsReadiness(comparisonState, modelList);
      ensureReadySelectedModel(modelList);
      await Promise.all([refreshSimulationHistory(), refreshDiagnosticsAndDemoPaths()]);
    } catch (err) {
      errorMessage = formatUserFriendlyError(err);
      try {
        const [bStatus] = await Promise.all([
          getBackendStatus(),
          refreshDiagnosticsAndDemoPaths(),
        ]);
        backendStatus = bStatus;
      } catch {
        // Ignore secondary probe failure
      }
    }
  }

  async function refreshDevLogs(): Promise<void> {
    try {
      devLogs = await getBackendLogs();
    } catch {
      // Ignore secondary log fetch error
    }
  }

  $effect(() => {
    const shouldPollLogs = showDevLogs || Boolean(backendStatus?.starting);
    if (!shouldPollLogs) return;
    void refreshDevLogs();
    const timer = setInterval(() => {
      void refreshDevLogs();
      if (backendStatus?.starting && isTauriRuntime()) {
        void getBackendStatus()
          .then((st) => {
            backendStatus = st;
            if (st.running && !healthData) {
              void refreshStatus();
            }
          })
          .catch(() => {});
      }
    }, 1200);
    return () => clearInterval(timer);
  });

  onMount(() => {
    const unlistenDrop = isTauriRuntime()
      ? getCurrentWebview().onDragDropEvent(({ payload }) => {
          if (payload.type !== "drop" || initializing || busyMessage) return;
          const path = getDroppedCsvPath(payload.paths);
          if (path === null) {
            errorMessage = "Hãy thả một tệp NetFlow có đuôi .csv.";
            return;
          }
          void runInspectPath(path);
        }).catch(() => {
          dragDropUnavailable = true;
          return null;
        })
      : null;
    const handleKeydown = (e: KeyboardEvent) => {
      if (e.shiftKey && (e.key === "F9" || e.code === "F9")) {
        e.preventDefault();
        showDevLogs = !showDevLogs;
        if (showDevLogs) {
          void refreshDevLogs();
        }
      }
    };
    window.addEventListener("keydown", handleKeydown);

    void (async () => {
      try {
        // Poll up to 120s for cold-start PyInstaller extraction + AV scan on clean Windows machines.
        for (let attempt = 0; attempt < 300; attempt += 1) {
          try {
            await fetchHealth();
            break;
          } catch {
            if (isTauriRuntime()) {
              try {
                const probe = await getBackendStatus();
                backendStatus = probe;
                if (!probe.starting && !probe.running && probe.last_error) {
                  break;
                }
              } catch {
                // Ignore probe error
              }
            }
            await new Promise((r) => setTimeout(r, 400));
          }
        }
        await refreshStatus();
        await refreshDevLogs();
        const demo = await getDemoPaths();
        await reportFrontendReady({
          connected: !errorMessage && Boolean(healthData) && Boolean(backendStatus?.running),
          health_status: healthData?.status ?? null,
          ready_models: models.filter((m) => m.ready).map((m) => m.model_key),
          flows_exists: demo.flows_exists,
          labels_exists: demo.labels_exists,
          error_message: errorMessage,
        });
      } finally {
        initializing = false;
      }
    })();

    return () => {
      window.removeEventListener("keydown", handleKeydown);
      void unlistenDrop?.then((unlisten) => unlisten?.());
    };
  });

  async function handleRestartBackend() {
    busyMessage = "Đang khởi động lại dịch vụ phân tích cục bộ...";
    errorMessage = null;
    comparisonState = invalidateForBackendRestart(comparisonState);
    inspectData = null;
    exportData = null;
    simulationExportData = null;
    simulationWarning = null;
    try {
      backendStatus = await restartBackend();
      await refreshStatus();
    } catch (err) {
      errorMessage = formatUserFriendlyError(err);
    } finally {
      busyMessage = null;
    }
  }

  async function runInspectPath(path: string) {
    const trimmed = path.trim();
    if (!trimmed) return;
    handleFlowsPathChange(path);
    const preInspectEpoch = comparisonState.sessionEpoch;
    busyMessage = "Đang kiểm tra định dạng 18 đặc trưng NetFlow v2 & chỉ số an toàn OOD...";
    errorMessage = null;
    try {
      const inspected = await inspectCsv(trimmed, 20);
      if (comparisonState.sessionEpoch !== preInspectEpoch) return;
      let nextState = invalidateForInspectResult(comparisonState, inspected, trimmed);
      if (inspected.models_status.length > 0) {
        models = inspected.models_status;
        nextState = reconcileModelsReadiness(nextState, inspected.models_status);
        ensureReadySelectedModel(inspected.models_status);
      }
      comparisonState = nextState;
      inspectData = inspected;
      exportData = null;
      simulationExportData = null;
      simulationWarning = null;
    } catch (err) {
      if (comparisonState.sessionEpoch === preInspectEpoch) {
        errorMessage = formatUserFriendlyError(err);
      }
    } finally {
      busyMessage = null;
    }
  }

  async function handleBrowseFlowsCsv() {
    if (isTauriRuntime()) {
      const chosen = await pickCsvFile("Chọn tệp NetFlow CSV để phân tích");
      if (chosen) {
        handleFlowsPathChange(chosen);
        await runInspectPath(chosen);
      }
    } else if (flowsPath.trim()) {
      await runInspectPath(flowsPath);
    }
  }

  function deriveSiblingPath(basePath: string, targetFilename: string): string {
    const normalized = basePath.replace(/\\/g, "/");
    const lastSlash = normalized.lastIndexOf("/");
    if (lastSlash < 0) return targetFilename;
    return basePath.slice(0, lastSlash + 1) + targetFilename;
  }

  async function handleLoadDemoDataset() {
    busyMessage = "Đang nạp bộ dữ liệu Demo chuẩn (200 luồng mạng)...";
    errorMessage = null;
    try {
      const demo = await getDemoPaths();
      if (!demo.flows_exists) {
        errorMessage =
          "Không tìm thấy tệp dữ liệu demo tích hợp (data/demo/demo_flows.csv). Bạn vẫn có thể chọn tệp CSV của riêng mình từ máy.";
        busyMessage = null;
        return;
      }
      handleFlowsPathChange(demo.flows_path);
      if (demo.labels_exists) {
        handleLabelsPathChange(demo.labels_path);
      }
      await runInspectPath(demo.flows_path);
    } catch (err) {
      errorMessage = formatUserFriendlyError(err);
      busyMessage = null;
    }
  }

  async function handleLoadShowcaseDemo() {
    busyMessage = "Đang nạp kịch bản trình chiếu đa kịch bản & chạy 4 mô hình AI...";
    errorMessage = null;
    try {
      const demo = await getDemoPaths();
      if (!demo.flows_exists) {
        errorMessage =
          "Không tìm thấy thư mục dữ liệu demo tích hợp. Bạn vẫn có thể chọn tệp CSV của riêng mình từ máy.";
        busyMessage = null;
        return;
      }
      const showcaseFlows = deriveSiblingPath(demo.flows_path, "showcase_demo_flows.csv");
      const showcaseLabels = demo.labels_path
        ? deriveSiblingPath(demo.labels_path, "showcase_demo_labels.csv")
        : "";

      let targetFlows = showcaseFlows;
      let targetLabels = showcaseLabels;
      try {
        await inspectCsv(showcaseFlows, 1);
      } catch {
        targetFlows = demo.flows_path;
        targetLabels = demo.labels_exists ? demo.labels_path : "";
      }

      handleFlowsPathChange(targetFlows);
      if (targetLabels) {
        handleLabelsPathChange(targetLabels);
      }
      await runInspectPath(targetFlows);
      if (!errorMessage && flowsPath.trim()) {
        await handleRunAllComparison();
      }
    } catch (err) {
      errorMessage = formatUserFriendlyError(err);
      busyMessage = null;
    }
  }

  const MAX_SIMULATE_CLIENT_RESULTS = 10_000;

  async function runDryRunSimulationForAnalysis(
    res: CsvAnalyzeResponse,
    requestSessionEpoch = comparisonState.sessionEpoch,
  ): Promise<SecurityResponseSimulationResponse> {
    let simRes: SecurityResponseSimulationResponse;
    try {
      simRes = await simulateSecurityResponse({
        analysis_id: res.analysis_id,
        triggered_by: "desktop_operator",
        dry_run: true,
      });
    } catch (primaryErr) {
      if (comparisonState.sessionEpoch !== requestSessionEpoch) {
        throw primaryErr;
      }
      if (res.results.length > 0 && res.results.length <= MAX_SIMULATE_CLIENT_RESULTS) {
        simRes = await simulateSecurityResponse({
          analysis_id: res.analysis_id,
          results: res.results,
          triggered_by: "desktop_operator",
          dry_run: true,
        });
      } else {
        throw primaryErr;
      }
    }
    const recorded = recordModelSimulation(
      comparisonState,
      res.model_key,
      res.analysis_id,
      simRes,
      requestSessionEpoch,
    );
    if (recorded.accepted) {
      comparisonState = recorded.state;
    }
    return simRes;
  }

  const workflowDeps: ComparisonWorkflowDeps = {
    inspectCsv,
    analyzeCsv,
    evaluateCsv,
    simulateDryRun: (res) => runDryRunSimulationForAnalysis(res, comparisonState.sessionEpoch),
  };

  async function handleRunInference() {
    if (!flowsPath.trim()) {
      errorMessage = "Vui lòng chọn tệp NetFlow CSV hoặc nhấn 'Mở Demo Validation (200 flows)'.";
      return;
    }
    const targetModel = selectedModel;
    errorMessage = null;
    simulationWarning = null;
    exportData = null;
    simulationExportData = null;
    try {
      const result = await runSingleModelAnalysisWorkflow({
        deps: workflowDeps,
        getState: () => comparisonState,
        setState: (next) => {
          comparisonState = next;
        },
        onProgress: (msg) => {
          busyMessage = msg;
        },
        onInspectData: (inspected) => {
          inspectData = inspected;
          if (inspected && inspected.models_status.length > 0) {
            models = inspected.models_status;
            ensureReadySelectedModel(inspected.models_status);
          }
        },
        onAnalysisRecorded: () => {
          activeTab = "predictions";
        },
        flowsPath,
        modelKey: targetModel,
        inspectData,
      });
      if (result.aborted) return;
      if (result.error) {
        errorMessage = formatUserFriendlyError(result.error);
        return;
      }
      simulationWarning = result.simulationWarning;
      if (result.simulation) {
        await refreshSimulationHistory();
      }
    } finally {
      busyMessage = null;
    }
  }

  async function handleRunAllComparison() {
    if (!flowsPath.trim()) {
      errorMessage = "Vui lòng chọn tệp NetFlow CSV hoặc nhấn 'Mở Demo Validation (200 flows)'.";
      return;
    }
    const readyList = models.filter((m) => m.ready);
    if (readyList.length === 0) {
      errorMessage = "Hiện chưa có mô hình nào ở trạng thái READY để so sánh.";
      return;
    }
    errorMessage = null;
    simulationWarning = null;
    exportData = null;
    simulationExportData = null;
    try {
      const result = await runAllModelsComparisonWorkflow({
        deps: workflowDeps,
        getState: () => comparisonState,
        setState: (next) => {
          comparisonState = next;
        },
        onProgress: (msg) => {
          busyMessage = msg;
        },
        onInspectData: (inspected) => {
          inspectData = inspected;
          if (inspected && inspected.models_status.length > 0) {
            models = inspected.models_status;
            ensureReadySelectedModel(inspected.models_status);
          }
        },
        flowsPath,
        labelsPath,
        models,
        selectedModel,
        inspectData,
      });
      if (result.aborted) return;
      activeTab = "overview";
      if (result.activeAnalysis && !coherentAnalyses[selectedModel]) {
        selectedModel = result.activeAnalysis.model_key;
      }
      if (result.simulation) {
        await refreshSimulationHistory();
      }
      simulationWarning = result.simulationWarning;
      errorMessage = result.errorSummary ? formatUserFriendlyError(result.errorSummary) : null;
    } finally {
      busyMessage = null;
    }
  }

  async function handlePickLabelsFile() {
    if (!isTauriRuntime()) return;
    const chosen = await pickCsvFile("Chọn tệp Ground Truth Labels CSV");
    if (chosen) {
      handleLabelsPathChange(chosen);
    }
  }

  async function handleUseDemoLabels() {
    const demo = await getDemoPaths();
    if (flowsPath !== demo.flows_path) {
      errorMessage = "Nhãn demo chỉ dùng với dữ liệu demo. Hãy chọn tệp nhãn tương ứng với CSV của bạn.";
      return;
    }
    handleLabelsPathChange(demo.labels_path);
  }

  async function handleRunEvaluate() {
    if (!analysisData || !labelsPath.trim()) return;
    const targetModel = selectedModel;
    const targetAnalysis = analysisData;
    evaluatedFlag = true;
    errorMessage = null;
    try {
      const result = await evaluateSingleModelWorkflow({
        deps: workflowDeps,
        getState: () => comparisonState,
        setState: (next) => {
          comparisonState = next;
        },
        labelsPath,
        modelKey: targetModel,
        analysis: targetAnalysis,
      });
      if (result.aborted) return;
      if (result.error) {
        errorMessage = formatUserFriendlyError(result.error);
        return;
      }
      if (result.evaluation) {
        activeTab = "evaluation";
      }
    } finally {
      evaluatedFlag = false;
    }
  }

  async function handleEvaluateAllAnalyzed() {
    if (Object.keys(coherentAnalyses).length === 0 || !labelsPath.trim()) return;
    evaluatedFlag = true;
    errorMessage = null;
    try {
      const result = await evaluateAllModelsWorkflow({
        deps: workflowDeps,
        getState: () => comparisonState,
        setState: (next) => {
          comparisonState = next;
        },
        onProgress: (msg) => {
          busyMessage = msg;
        },
        labelsPath,
      });
      if (result.aborted) return;
      errorMessage = result.errorSummary ? formatUserFriendlyError(result.errorSummary) : null;
    } finally {
      busyMessage = null;
      evaluatedFlag = false;
    }
  }

  async function refreshSimulationHistory(): Promise<void> {
    try {
      const resp = await listSecuritySimulations(20, 0);
      simulationHistory = resp.items;
    } catch {
      // Non-fatal if backend is restarting
    }
  }

  async function handleRunSecuritySimulation() {
    if (!analysisData) return;
    const targetAnalysis = analysisData;
    const startEpoch = comparisonState.sessionEpoch;
    simulatingFlag = true;
    errorMessage = null;
    simulationWarning = null;
    simulationExportData = null;
    try {
      await runDryRunSimulationForAnalysis(targetAnalysis, startEpoch);
      if (comparisonState.sessionEpoch !== startEpoch) return;
      await refreshSimulationHistory();
    } catch (err) {
      if (comparisonState.sessionEpoch !== startEpoch) return;
      simulationWarning = `Không thể chạy mô phỏng Dry-Run: ${formatUserFriendlyError(err)}`;
    } finally {
      simulatingFlag = false;
    }
  }

  async function handleExportSecuritySimulation(simulationId: string) {
    const defaultName = `dry_run_${simulationId}.json`;
    const chosen = await pickSaveJsonFile(defaultName);
    if (!chosen) return;
    const startEpoch = comparisonState.sessionEpoch;
    simulatingFlag = true;
    errorMessage = null;
    try {
      const exported = await exportSecuritySimulation({
        output_path: chosen,
        simulation_id: simulationId,
      });
      if (comparisonState.sessionEpoch !== startEpoch) return;
      simulationExportData = exported;
    } catch (err) {
      if (comparisonState.sessionEpoch !== startEpoch) return;
      errorMessage = formatUserFriendlyError(err);
    } finally {
      simulatingFlag = false;
    }
  }

  async function handleExportResults() {
    if (!analysisData) return;
    const targetAnalysis = analysisData;
    const targetEval = evalData;
    const defaultName = `predictions_${targetAnalysis.model_key}.csv`;
    const chosen = await pickSaveCsvFile(defaultName);
    if (!chosen) return;

    const startEpoch = comparisonState.sessionEpoch;
    busyMessage = "Đang xuất tệp kết quả CSV và biên bản kiểm chứng SHA-256...";
    errorMessage = null;
    try {
      const exported = await exportCsv({
        output_path: chosen,
        analysis_id: targetAnalysis.analysis_id,
        source_csv_path: targetAnalysis.file_path,
        model_key: targetAnalysis.model_key,
        model_type: targetAnalysis.model_type,
        run_id: targetAnalysis.run_id,
        model_sha256: targetAnalysis.model_sha256,
        preprocessor_sha256: targetAnalysis.preprocessor_sha256,
        results: targetAnalysis.results,
        evaluation: targetEval,
      });
      if (comparisonState.sessionEpoch !== startEpoch) return;
      exportData = exported;
    } catch (err) {
      if (comparisonState.sessionEpoch !== startEpoch) return;
      errorMessage = formatUserFriendlyError(err);
    } finally {
      busyMessage = null;
    }
  }
</script>

<div class="soc-layout">
  <aside class="soc-rail" aria-label="Điều hướng NetFlow Sentinel">
    <div class="rail-brand">
      <img src={logoUrl} alt="NetFlow Sentinel" class="rail-brand-logo" />
      <div>
        <h1 class="rail-brand-title">NetFlow Sentinel</h1>
        <p class="rail-brand-sub">v2.1.0 · Đề tài 22</p>
      </div>
    </div>

    <div class="rail-pipeline" aria-label="Chuỗi xử lý 4 tầng">
      <button
        type="button"
        class="rail-pipeline-item"
        class:done={Boolean(inspectData)}
        onclick={() => (activeTab = "overview")}
      >
        <span class="rail-pipeline-dot"></span>
        <span>01 Nạp NetFlow L4</span>
      </button>
      <button
        type="button"
        class="rail-pipeline-item"
        class:done={Boolean(analysisData)}
        onclick={() => (activeTab = analysisData ? "predictions" : "overview")}
      >
        <span class="rail-pipeline-dot"></span>
        <span>02 Quét 4 Mô hình AI</span>
      </button>
      <button
        type="button"
        class="rail-pipeline-item"
        class:done={Boolean(simulationData) || activeTab === "behavioral" || activeTab === "attack_timeline"}
        onclick={() => (activeTab = "attack_timeline")}
      >
        <span class="rail-pipeline-dot"></span>
        <span>03 Truy vết &amp; Phản ứng</span>
      </button>
      <button
        type="button"
        class="rail-pipeline-item"
        class:done={Boolean(healthData?.preprocessor_ready)}
        onclick={() => (activeTab = "crypto")}
      >
        <span class="rail-pipeline-dot"></span>
        <span>04 Bảo mật &amp; Mật mã</span>
      </button>
    </div>

    <div class="rail-nav-groups" role="tablist" aria-orientation="vertical" aria-label="Phân vùng hiển thị">
      {#each NAV_SECTIONS as section (section.title)}
        <div class="rail-group">
          <div class="rail-group-label">{section.title}</div>
          {#each section.items as item (item.id)}
            <button
              type="button"
              role="tab"
              class="rail-nav-btn"
              aria-selected={activeTab === item.id}
              onclick={() => (activeTab = item.id)}
            >
              <span class="rail-nav-btn-inner">
                <Icons name={item.icon} size={14} />
                <span>{item.label}</span>
              </span>
              {#if item.id === "predictions"}
                <span class="rail-count-pill tabular">{analysisData?.total_rows ?? 0}</span>
              {/if}
            </button>
          {/each}
        </div>
      {/each}
    </div>
  </aside>

  <div class="soc-main-col">
    <header class="soc-topbar">
      <div class="topbar-context">
        <h2 class="topbar-title">{activeNavMeta.label}</h2>
        <p class="topbar-breadcrumb">{activeNavMeta.subtitle}</p>
      </div>

      <div class="header-controls">
        {#if isOfflineTab}
          <button
            type="button"
            class="btn btn-sm"
            class:btn-primary={showGuide}
            onclick={() => (showGuide = !showGuide)}
            title="Xem hướng dẫn 4 bước và giải thích thuật ngữ"
          >
            <Icons name="shield" size={14} />
            {showGuide ? "Ẩn hướng dẫn" : "Hướng dẫn"}
          </button>
        {/if}

        <button
          type="button"
          class="btn btn-sm"
          onclick={toggleTheme}
          aria-label="Chuyển giao diện Sáng / Tối"
        >
          <Icons name={theme === "dark" ? "sun" : "moon"} size={14} />
          {theme === "dark" ? "Sáng" : "Tối"}
        </button>

        <button
          type="button"
          class="btn btn-sm"
          onclick={() => {
            showDevLogs = !showDevLogs;
            if (showDevLogs) void refreshDevLogs();
          }}
          title="Bật/tắt nhật ký kỹ thuật backend (Shift+F9)"
        >
          <Icons name="cpu" size={14} />
          Logs
        </button>

        <button
          type="button"
          class="btn btn-sm"
          onclick={handleRestartBackend}
          disabled={Boolean(busyMessage)}
          title="Làm mới dịch vụ phân tích cục bộ"
          aria-label="Làm mới dịch vụ"
        >
          <Icons name="refresh" size={14} />
        </button>
      </div>
    </header>

    <main class="workspace-main">
      {#if errorMessage && !backendStatus?.starting}
        <div class="banner banner-error" role="alert">
          <Icons name="alert" size={18} />
          <div style="flex: 1;">
            <strong>Thông báo hệ thống:</strong> {errorMessage}
          </div>
          <button
            type="button"
            class="btn btn-sm"
            onclick={() => {
              showDevLogs = true;
              void refreshDevLogs();
            }}
          >
            Xem Dev Logs (Shift+F9)
          </button>
          <button type="button" class="btn btn-sm" onclick={() => (errorMessage = null)}>Đóng</button>
        </div>
      {/if}

      {#if simulationWarning}
        <div class="banner banner-warning" role="status">
          <Icons name="alert" size={18} />
          <div style="flex: 1;">
            <strong>Lưu ý mô phỏng phản ứng:</strong> {simulationWarning}
          </div>
          <button type="button" class="btn btn-sm" onclick={() => (simulationWarning = null)}>Đóng</button>
        </div>
      {/if}

      {#if busyMessage || initializing || (backendStatus?.starting && !backendStatus?.running)}
        <div class="banner banner-info" role="status">
          <Icons name="refresh" size={16} spin={true} />
          <div style="flex: 1;">
            {#if busyMessage}
              {busyMessage}
            {:else}
              Đang khởi tạo máy chủ AI cục bộ (lần đầu trên máy mới có thể mất 30–90 giây để giải nén runtime và Windows kiểm tra an toàn) — <strong>{Math.round((backendStatus?.startup_elapsed_ms ?? 0) / 1000)}s</strong> ({backendStatus?.startup_stage ?? "booting"}). Nhấn <strong>Shift+F9</strong> để xem chi tiết log dev.
            {/if}
          </div>
        </div>
      {/if}

      {#if showDevLogs}
        <DevLogsPanel
          logs={devLogs}
          {backendStatus}
          diagnostics={runtimeDiagnostics}
          onRefresh={() => void refreshDevLogs()}
          onClose={() => (showDevLogs = false)}
        />
      {/if}

      {#if isOfflineTab}
        {#if showGuide}
          <OnboardingGuidePanel
            hasFlows={Boolean(inspectData)}
            hasAnalysis={Boolean(analysisData)}
            hasComparison={Object.keys(coherentAnalyses).length >= 2}
            hasEvaluation={Object.keys(coherentEvaluations).length > 0}
            hasExport={Boolean(exportData)}
            {readyModelsCount}
            onClose={() => (showGuide = false)}
          />
        {/if}

        <section class="card action-card" aria-label="Điều khiển Dữ liệu NetFlow CSV">
          <div class="action-row-head">
            <span class="action-row-title">
              <Icons name="folder" size={15} />
              Nguồn dữ liệu NetFlow CSV (18 đặc trưng L4)
            </span>
            {#if isTauriRuntime() && !dragDropUnavailable}
              <span class="action-row-hint">Mẹo: Kéo thả tệp .csv trực tiếp vào cửa sổ</span>
            {/if}
          </div>
          <div class="input-bar">
            <input
              type="text"
              class="input mono"
              style="flex: 1; min-width: 220px;"
              placeholder="Chọn tệp NetFlow CSV từ máy hoặc bấm nút Demo bên phải..."
              value={flowsPath}
              oninput={(e) => handleFlowsPathChange((e.currentTarget as HTMLInputElement).value)}
              aria-label="Đường dẫn tệp NetFlow CSV"
            />
            <button type="button" class="btn" onclick={handleBrowseFlowsCsv} disabled={Boolean(busyMessage)}>
              <Icons name="folder" size={15} />
              {isTauriRuntime() ? "Chọn CSV" : "Kiểm tra CSV"}
            </button>
            <button
              type="button"
              class="btn btn-teal"
              onclick={handleLoadShowcaseDemo}
              disabled={Boolean(busyMessage)}
              title="Nạp 465 luồng mạng thật (Benign + 5 nhóm tấn công + OOD) và tự động quét 4 mô hình AI"
            >
              <Icons name="play" size={14} />
              Demo Trình chiếu (465 flows)
            </button>
            <button
              type="button"
              class="btn"
              onclick={handleLoadDemoDataset}
              disabled={Boolean(busyMessage)}
              title="Nạp bộ dữ liệu kiểm chứng chuẩn 200 luồng (100 Benign / 100 Attack)"
            >
              Demo Chuẩn (200)
            </button>
            <button
              type="button"
              class="btn btn-primary"
              onclick={handleRunAllComparison}
              disabled={!flowsPath.trim() || Boolean(busyMessage)}
            >
              <Icons name="target" size={15} />
              Phân tích 4 Mô hình AI
            </button>
            <button
              type="button"
              class="btn"
              onclick={handleExportResults}
              disabled={!analysisData || Boolean(busyMessage)}
              title="Xuất bảng kết quả CSV kèm biên bản toàn vẹn SHA-256"
            >
              <Icons name="download" size={15} />
              Xuất CSV
            </button>
          </div>

          {#if exportData}
            <div class="banner banner-success" style="margin-top: 10px;">
              <Icons name="check" size={16} />
              <div class="mono" style="font-size: 12px;">
                Đã xuất {exportData.rows_exported} dòng → {exportData.csv_path} (SHA-256: {shortDigest(exportData.csv_sha256)}) &amp; provenance → {exportData.metadata_path}
              </div>
            </div>
          {/if}
        </section>
      {/if}

      {#key activeTab}
        <div class="tab-panel">
          {#if activeTab === "overview"}
            {#if analysisData}
              <div class="grid-5">
                <div class="kpi-box">
                  <div class="kpi-label">Tổng số Luồng (Flows)</div>
                  <div class="kpi-value mono">{analysisData.total_rows}</div>
                  <div class="kpi-sub">Đang xem: <strong>{selectedModel}</strong></div>
                </div>
                <div class="kpi-box">
                  <div class="kpi-label">Nghi ngờ Tấn công</div>
                  <div class="kpi-value mono" style="color: var(--semantic-attack)">{analysisData.attack_count}</div>
                  <div class="kpi-sub">Nhãn Attack</div>
                </div>
                <div class="kpi-box">
                  <div class="kpi-label">Lưu lượng An toàn</div>
                  <div class="kpi-value mono" style="color: var(--semantic-benign)">{analysisData.benign_count}</div>
                  <div class="kpi-sub">Nhãn Benign</div>
                </div>
                <div class="kpi-box">
                  <div class="kpi-label">Ngoài phân phối (OOD)</div>
                  <div class="kpi-value mono" style="color: var(--semantic-ood)">
                    {analysisData.abstained_rows ?? analysisData.ood_flagged_count}
                  </div>
                  <div class="kpi-sub mono">
                    Phủ: {analysisData.evaluated_rows ?? analysisData.attack_count + analysisData.benign_count}/{analysisData.total_rows}
                    ({analysisData.prediction_coverage != null
                      ? `${(analysisData.prediction_coverage * 100).toFixed(1)}%`
                      : analysisData.total_rows > 0
                        ? `${(((analysisData.attack_count + analysisData.benign_count) / analysisData.total_rows) * 100).toFixed(1)}%`
                        : "0.0%"})
                  </div>
                </div>
                <div class="kpi-box" title={`Source: ${analysisData.compatibility_gate.source_id ?? "unknown"} | Compatibility: ${analysisData.compatibility_gate.compatibility_status}`}>
                  <div class="kpi-label">Cổng Kiểm định (Gate)</div>
                  <div class="kpi-value" style="font-size: 13.5px;">
                    {analysisData.compatibility_gate.eligibility_status === "PREDICTION_AVAILABLE"
                      ? "Đủ điều kiện dự đoán"
                      : analysisData.compatibility_gate.eligibility_status}
                  </div>
                  <div class="kpi-sub mono">
                    {analysisData.compatibility_gate.compatibility_status}
                  </div>
                </div>
              </div>
              <ChartsPanel analysis={analysisData} />
            {:else if !inspectData}
              <section class="card" aria-label="Bắt đầu nhanh">
                <div class="card-header" style="margin-bottom: 10px;">
                  <div>
                    <h3 class="card-title">
                      <Icons name="shield" size={16} />
                      Cách hoạt động của NetFlow Sentinel (3 bước)
                    </h3>
                    <p style="margin: 3px 0 0; font-size: 12.5px; color: var(--text-secondary);">
                      Chưa nạp tệp dữ liệu nào. Chọn <strong>Demo Trình chiếu (465 flows)</strong> hoặc <strong>Chọn CSV</strong> ở thanh trên cùng để bắt đầu.
                    </p>
                  </div>
                </div>
                <div class="welcome-grid">
                  <div class="welcome-step">
                    <span class="welcome-num">1</span>
                    <div>
                      <strong>Nạp lưu lượng NetFlow L4</strong>
                      <p>Đọc tệp CSV gồm 18 đặc trưng luồng mạng và tự động loại bỏ nhãn/PII chống rò rỉ dữ liệu.</p>
                    </div>
                  </div>
                  <div class="welcome-step">
                    <span class="welcome-num">2</span>
                    <div>
                      <strong>Quét song song 4 Mô hình AI</strong>
                      <p>Random Forest, XGBoost, Isolation Forest và Autoencoder chấm điểm rủi ro kèm cổng từ chối ngoài mẫu (OOD).</p>
                    </div>
                  </div>
                  <div class="welcome-step">
                    <span class="welcome-num">3</span>
                    <div>
                      <strong>Phân loại &amp; Truy vết tấn công</strong>
                      <p>Hiển thị trực quan tỷ lệ An toàn / Tấn công / OOD, lọc từng luồng nghi ngờ và xuất biên bản SHA-256.</p>
                    </div>
                  </div>
                </div>
              </section>
            {/if}

            {#if inspectData || analysisData}
              <ModelComparisonPanel
                {models}
                {selectedModel}
                analysesByModel={coherentAnalyses}
                evaluationsByModel={coherentEvaluations}
                errorsByModel={comparisonState.errorsByModel}
                batchFileSha256={comparisonState.activeFileSha256}
                batchLabelsSha256={comparisonState.activeLabelsSha256}
                defaultBenchmarkOpen={false}
                hideRunButton={true}
                canRunComparison={Boolean(flowsPath.trim())}
                hasLabelsPath={Boolean(labelsPath.trim())}
                busy={Boolean(busyMessage)}
                onSelectModel={(k) => (selectedModel = k)}
                onRunAllComparison={handleRunAllComparison}
                onEvaluateAllAnalyzed={handleEvaluateAllAnalyzed}
              />
            {/if}

            {#if inspectData}
              <CsvPreviewPanel {inspectData} />
            {/if}
          {:else if activeTab === "predictions"}
            {#if analysisData}
              <ChartsPanel analysis={analysisData} />
              <PredictionsTable analysis={analysisData} />
            {:else}
              <div class="empty-state">
                Chưa có kết quả dự đoán. Hãy chọn tệp CSV và nhấn <strong>Phân tích 4 Mô hình AI</strong>.
              </div>
            {/if}
          {:else if activeTab === "evaluation"}
            <EvaluationPanel
              {labelsPath}
              evaluating={evaluatedFlag}
              evalResult={evalData}
              canEvaluate={Boolean(analysisData)}
              onPickLabels={handlePickLabelsFile}
              onUseDemoLabels={handleUseDemoLabels}
              onRunEvaluate={handleRunEvaluate}
              onUpdateLabelsPath={(v) => handleLabelsPathChange(v)}
            />
          {:else if activeTab === "forensics"}
            <ForensicTimelinePanel
              timeline={analysisData?.timeline ?? []}
              behavioral={analysisData?.behavioral_summary ?? inspectData?.behavioral_summary ?? null}
              securityNotice={analysisData?.security_notice ?? "Localhost-only FastAPI (127.0.0.1), AES-256-GCM + DPAPI key protection active. Adaptive Security Response runs in DRY-RUN SIMULATION mode (executed=false); OS firewall automation remains disabled by policy."}
              simulation={simulationData}
              {simulationHistory}
              simulationExportInfo={simulationExportData}
              simulating={simulatingFlag}
              canSimulate={Boolean(analysisData)}
              onRunSimulation={handleRunSecuritySimulation}
              onRefreshHistory={refreshSimulationHistory}
              onExportSimulation={handleExportSecuritySimulation}
            />
          {:else if activeTab === "live"}
            <LiveMonitoringPanel />
          {:else if activeTab === "behavioral"}
            <BehavioralAnalysisPanel />
          {:else if activeTab === "attack_timeline"}
            <AttackTimelinePanel />
          {:else if activeTab === "crypto"}
            <CryptographyDashboardPanel />
          {/if}
        </div>
      {/key}
    </main>

    <footer class="soc-statusbar" aria-label="Trạng thái hệ thống NetFlow Sentinel">
      <div class="statusbar-group">
        <span class="statusbar-item">
          <span
            class="status-dot"
            class:status-dot-online={Boolean(backendStatus?.running)}
            class:status-dot-starting={!backendStatus?.running}
          ></span>
          <span>Backend: <strong class="mono">{backendStatus?.running ? "Online" : "Starting..."}</strong></span>
        </span>
        <span class="statusbar-sep">|</span>
        <span class="statusbar-item">
          <span>Mô hình AI:</span>
          <strong class="mono" style:color={readyModelsCount === 4 ? "var(--semantic-benign)" : "var(--semantic-warning)"}>
            {readyModelsCount}/4 READY
          </strong>
        </span>
        <span class="statusbar-sep">|</span>
        <span class="statusbar-item">
          <span>Đang xem:</span>
          <strong class="mono">{selectedModel}</strong>
        </span>
        <span class="statusbar-sep">|</span>
        <span class="statusbar-item">
          <span>OOD Gate:</span>
          <strong class="mono">
            {healthData?.preprocessor_ready ? "ACTIVE (Fail-Closed)" : "INIT"}
          </strong>
        </span>
      </div>
      <div class="statusbar-group mono">
        <span>v2.1.0 · Local Offline</span>
        <span class="statusbar-sep">|</span>
        <span>Shift+F9: Dev Logs</span>
      </div>
    </footer>
  </div>
</div>

<style>
  .input-bar {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
  }
</style>
