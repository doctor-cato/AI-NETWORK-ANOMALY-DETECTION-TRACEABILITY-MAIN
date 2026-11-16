<script lang="ts">
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
  import ModelComparisonPanel from "./lib/components/ModelComparisonPanel.svelte";
  import ModelReadinessPanel from "./lib/components/ModelReadinessPanel.svelte";
  import OnboardingGuidePanel from "./lib/components/OnboardingGuidePanel.svelte";
  import PredictionsTable from "./lib/components/PredictionsTable.svelte";
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
  import { formatUserFriendlyError, shortDigest } from "./lib/utils";

  type TabId = "overview" | "predictions" | "evaluation" | "forensics";

  let theme = $state<"dark" | "light">("dark");
  let activeTab = $state<TabId>("overview");

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
  let busyMessage = $state<string | null>(null);
  let errorMessage = $state<string | null>(null);
  let simulationWarning = $state<string | null>(null);
  let evaluatedFlag = $state(false);
  let simulatingFlag = $state(false);
  let showDevLogs = $state(false);
  let devLogs = $state<BackendLogSnapshot | null>(null);

  let readyModelsCount = $derived(models.filter((m) => m.ready).length);

  function handleFlowsPathChange(nextPath: string) {
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
      const [diag, demo] = await Promise.all([getRuntimeDiagnostics(), getDemoPaths()]);
      runtimeDiagnostics = diag;
      if (demo.flows_exists && !flowsPath.trim()) {
        handleFlowsPathChange(demo.flows_path);
      }
      if (demo.labels_exists && !labelsPath.trim()) {
        handleLabelsPathChange(demo.labels_path);
      }
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
        if (demo.flows_exists && !flowsPath.trim()) {
          handleFlowsPathChange(demo.flows_path);
        }
        if (demo.labels_exists && !labelsPath.trim()) {
          handleLabelsPathChange(demo.labels_path);
        }
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
    busyMessage = "Đang kiểm tra định dạng 47 đặc trưng NetFlow & chỉ số an toàn OOD...";
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
      simulationWarning = `Không thể chạy mô phỏng Dry-Run (#27): ${formatUserFriendlyError(err)}`;
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

<div class="app-shell">
  <header class="top-header">
    <div class="brand-group">
      <div class="brand-icon">
        <Icons name="shield" size={20} />
      </div>
      <div>
        <h1 class="brand-title">NetFlow Sentinel v1.0.0 — Phân tích Bất thường Lưu lượng Mạng</h1>
        <p class="brand-subtitle">
          Ứng dụng Windows Độc lập (Offline) • 4 Mô hình AI Tích hợp Sẵn • Dữ liệu chuẩn NF-UNSW-NB15-v3
        </p>
      </div>
    </div>

    <div class="header-controls">
      {#if healthData?.preprocessor_ready && readyModelsCount === 4}
        <span class="badge badge-benign">
          <Icons name="check" size={12} />
          Hệ thống AI Sẵn sàng (4/4)
        </span>
      {:else if healthData?.preprocessor_ready}
        <span class="badge badge-warning">
          <Icons name="alert" size={12} />
          Mô hình sẵn sàng: {readyModelsCount}/4
        </span>
      {:else}
        <span class="badge badge-attack">
          <Icons name="alert" size={12} />
          Chờ khởi tạo Mô hình
        </span>
      {/if}

      <span
        class="badge badge-info mono"
        class:badge-pulsing={!backendStatus?.running}
        title={runtimeDiagnostics?.sidecar_executable
          ? `Embedded Sidecar (${backendStatus?.port ?? "..."})`
          : `Localhost :${backendStatus?.port ?? "..."}`}
      >
        {backendStatus?.running ? "Dịch vụ Cục bộ Online" : "Đang khởi động dịch vụ..."}
      </span>

      <button type="button" class="btn btn-sm" onclick={handleRestartBackend} disabled={Boolean(busyMessage)}>
        <Icons name="refresh" size={14} />
        Làm mới Dịch vụ
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
        {showDevLogs ? "Ẩn Logs" : "Dev Logs (Shift+F9)"}
      </button>

      <button
        type="button"
        class="btn btn-sm"
        onclick={toggleTheme}
        aria-label="Chuyển giao diện Sáng / Tối"
      >
        <Icons name={theme === "dark" ? "sun" : "moon"} size={14} />
        {theme === "dark" ? "Chế độ Sáng" : "Chế độ Tối"}
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
          <strong>Lưu ý mô phỏng phản ứng (#27):</strong> {simulationWarning}
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

    <OnboardingGuidePanel
      hasFlows={Boolean(inspectData)}
      hasAnalysis={Boolean(analysisData)}
      hasComparison={Object.keys(coherentAnalyses).length >= 2}
      hasEvaluation={Object.keys(coherentEvaluations).length > 0}
      hasExport={Boolean(exportData)}
      {readyModelsCount}
      onLoadDemo={handleLoadDemoDataset}
      onBrowseCsv={handleBrowseFlowsCsv}
      busy={Boolean(busyMessage) || initializing}
    />

    <section class="card" aria-label="Điều khiển Dữ liệu NetFlow CSV">
      <div class="input-bar">
        <input
          type="text"
          class="input mono"
          style="flex: 1; min-width: 260px;"
          placeholder="Đường dẫn tới tệp NetFlow CSV..."
          value={flowsPath}
          oninput={(e) => handleFlowsPathChange((e.currentTarget as HTMLInputElement).value)}
          aria-label="Đường dẫn tệp NetFlow CSV"
        />
        <button type="button" class="btn" onclick={handleBrowseFlowsCsv} disabled={Boolean(busyMessage)}>
          <Icons name="folder" size={15} />
          {isTauriRuntime() ? "Chọn CSV từ máy" : "Kiểm tra CSV"}
        </button>
        <button type="button" class="btn" onclick={handleLoadDemoDataset} disabled={Boolean(busyMessage)}>
          Mở Demo Validation (200 flows)
        </button>
        <button
          type="button"
          class="btn btn-primary"
          onclick={handleRunInference}
          disabled={!flowsPath.trim() || Boolean(busyMessage)}
        >
          <Icons name="play" size={15} />
          Chạy Phân tích AI ({selectedModel})
        </button>
        <button
          type="button"
          class="btn"
          onclick={handleRunAllComparison}
          disabled={!flowsPath.trim() || Boolean(busyMessage)}
        >
          <Icons name="target" size={15} />
          So sánh 4 Model READY
        </button>
        <button
          type="button"
          class="btn"
          onclick={handleExportResults}
          disabled={!analysisData || Boolean(busyMessage)}
        >
          <Icons name="download" size={15} />
          Xuất CSV + Metadata
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

    <ModelReadinessPanel
      {models}
      {selectedModel}
      busy={Boolean(busyMessage)}
      onSelect={(k) => (selectedModel = k)}
    />

    <div class="tab-bar" role="tablist" aria-label="Phân vùng hiển thị">
      <button
        type="button"
        role="tab"
        class="tab-btn"
        aria-selected={activeTab === "overview"}
        onclick={() => (activeTab = "overview")}
      >
        <Icons name="chart" size={15} />
        1. Tổng quan &amp; Kiểm tra CSV
      </button>
      <button
        type="button"
        role="tab"
        class="tab-btn"
        aria-selected={activeTab === "predictions"}
        onclick={() => (activeTab = "predictions")}
      >
        <Icons name="table" size={15} />
        2. Bảng Dự đoán ({analysisData?.total_rows ?? 0})
      </button>
      <button
        type="button"
        role="tab"
        class="tab-btn"
        aria-selected={activeTab === "evaluation"}
        onclick={() => (activeTab = "evaluation")}
      >
        <Icons name="target" size={15} />
        3. Đối chiếu Nhãn &amp; Độ chính xác
      </button>
      <button
        type="button"
        role="tab"
        class="tab-btn"
        aria-selected={activeTab === "forensics"}
        onclick={() => (activeTab = "forensics")}
      >
        <Icons name="clock" size={15} />
        4. Dòng thời gian &amp; Mô phỏng Phản ứng
      </button>
    </div>

    {#key activeTab}
      <div class="tab-panel">
        {#if activeTab === "overview"}
          <ModelComparisonPanel
            {models}
            {selectedModel}
            analysesByModel={coherentAnalyses}
            evaluationsByModel={coherentEvaluations}
            errorsByModel={comparisonState.errorsByModel}
            batchFileSha256={comparisonState.activeFileSha256}
            batchLabelsSha256={comparisonState.activeLabelsSha256}
            canRunComparison={Boolean(flowsPath.trim())}
            hasLabelsPath={Boolean(labelsPath.trim())}
            busy={Boolean(busyMessage)}
            onSelectModel={(k) => (selectedModel = k)}
            onRunAllComparison={handleRunAllComparison}
            onEvaluateAllAnalyzed={handleEvaluateAllAnalyzed}
          />

          {#if analysisData}
            <div class="grid-5">
              <div class="kpi-box">
                <div class="kpi-label">Tổng số Flow</div>
                <div class="kpi-value mono">{analysisData.total_rows}</div>
              </div>
              <div class="kpi-box">
                <div class="kpi-label">Dự đoán Attack</div>
                <div class="kpi-value mono" style="color: var(--semantic-attack)">{analysisData.attack_count}</div>
              </div>
              <div class="kpi-box">
                <div class="kpi-label">Dự đoán Benign</div>
                <div class="kpi-value mono" style="color: var(--semantic-benign)">{analysisData.benign_count}</div>
              </div>
              <div class="kpi-box">
                <div class="kpi-label">OOD Abstained</div>
                <div class="kpi-value mono" style="color: var(--semantic-warning)">
                  {analysisData.abstained_rows ?? analysisData.ood_flagged_count}
                </div>
                <div class="mono" style="font-size: 11px; color: var(--text-secondary);">
                  {analysisData.evaluated_rows ?? analysisData.attack_count + analysisData.benign_count}/{analysisData.total_rows}
                  ({analysisData.prediction_coverage != null
                    ? `${(analysisData.prediction_coverage * 100).toFixed(1)}%`
                    : analysisData.total_rows > 0
                      ? `${(((analysisData.attack_count + analysisData.benign_count) / analysisData.total_rows) * 100).toFixed(1)}%`
                      : "0.0%"})
                </div>
              </div>
              <div class="kpi-box" title={`Source: ${analysisData.compatibility_gate.source_id ?? "unknown"} | Compatibility: ${analysisData.compatibility_gate.compatibility_status}`}>
                <div class="kpi-label">Eligibility Gate</div>
                <div class="kpi-value" style="font-size: 13px;">{analysisData.compatibility_gate.eligibility_status}</div>
                <div class="mono" style="font-size: 11px; color: var(--text-secondary);">
                  {analysisData.compatibility_gate.compatibility_status}
                </div>
              </div>
            </div>
            <ChartsPanel analysis={analysisData} />
          {/if}

          {#if inspectData}
            <CsvPreviewPanel {inspectData} />
          {:else}
            <div class="empty-state">
              Nhấn <strong>Mở Demo Validation (200 flows)</strong> hoặc chọn tệp NetFlow CSV từ máy cục bộ để kiểm tra 47 ML features và bắt đầu phân tích.
            </div>
          {/if}
        {:else if activeTab === "predictions"}
          {#if analysisData}
            <ChartsPanel analysis={analysisData} />
            <PredictionsTable analysis={analysisData} />
          {:else}
            <div class="empty-state">
              Chưa có kết quả dự đoán. Hãy chọn mô hình READY và nhấn <strong>Chạy Phân tích AI</strong>.
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
            securityNotice={analysisData?.security_notice ?? "Localhost-only FastAPI (127.0.0.1), fail-closed SHA-256 artifact checks. Issue #27 Adaptive Security Response runs in DRY-RUN SIMULATION / RECOMMENDED mode (executed=false); OS firewall automation & AES-256-GCM keyring remain DEFERRED."}
            simulation={simulationData}
            {simulationHistory}
            simulationExportInfo={simulationExportData}
            simulating={simulatingFlag}
            canSimulate={Boolean(analysisData)}
            onRunSimulation={handleRunSecuritySimulation}
            onRefreshHistory={refreshSimulationHistory}
            onExportSimulation={handleExportSecuritySimulation}
          />
        {/if}
      </div>
    {/key}
  </main>
</div>

<style>
  .input-bar {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    align-items: center;
  }
</style>
