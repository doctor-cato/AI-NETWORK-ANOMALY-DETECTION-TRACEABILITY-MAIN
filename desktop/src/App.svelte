<script lang="ts">
  import { onMount } from "svelte";
  import {
    analyzeCsv,
    evaluateCsv,
    exportCsv,
    exportSecuritySimulation,
    fetchHealth,
    fetchModelsStatus,
    getBackendStatus,
    getDemoPaths,
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
  import EvaluationPanel from "./lib/components/EvaluationPanel.svelte";
  import ForensicTimelinePanel from "./lib/components/ForensicTimelinePanel.svelte";
  import Icons from "./lib/components/Icons.svelte";
  import ModelComparisonPanel from "./lib/components/ModelComparisonPanel.svelte";
  import ModelReadinessPanel from "./lib/components/ModelReadinessPanel.svelte";
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
    BackendStatus,
    CsvAnalyzeResponse,
    CsvExportResponse,
    CsvInspectResponse,
    HealthResponse,
    ModelStatusItem,
    SecurityResponseSimulationResponse,
    SecuritySimulationExportResponse,
    SecuritySimulationHistoryItem,
  } from "./lib/types";
  import { shortDigest } from "./lib/utils";

  type TabId = "overview" | "predictions" | "evaluation" | "forensics";

  let theme = $state<"dark" | "light">("dark");
  let activeTab = $state<TabId>("overview");

  let backendStatus = $state<BackendStatus | null>(null);
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
      await refreshSimulationHistory();
    } catch (err) {
      errorMessage =
        err instanceof Error
          ? `Không thể kết nối Python FastAPI localhost: ${err.message}`
          : String(err);
      try {
        backendStatus = await getBackendStatus();
      } catch {
        // Ignore secondary probe failure
      }
    }
  }

  onMount(async () => {
    try {
      // Poll up to 20s while Tauri child backend comes online (matches Rust startup budget)
      for (let attempt = 0; attempt < 50; attempt += 1) {
        try {
          await fetchHealth();
          break;
        } catch {
          await new Promise((r) => setTimeout(r, 400));
        }
      }
      await refreshStatus();
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
  });

  async function handleRestartBackend() {
    busyMessage = "Đang khởi động lại tiến trình Python FastAPI...";
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
      errorMessage = err instanceof Error ? err.message : String(err);
    } finally {
      busyMessage = null;
    }
  }

  async function runInspectPath(path: string) {
    const trimmed = path.trim();
    if (!trimmed) return;
    handleFlowsPathChange(path);
    const preInspectEpoch = comparisonState.sessionEpoch;
    busyMessage = "Đang kiểm tra schema 47 ML features & OOD...";
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
        errorMessage = err instanceof Error ? err.message : String(err);
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
    busyMessage = "Đang nạp bộ dữ liệu Demo Validation...";
    errorMessage = null;
    try {
      const demo = await getDemoPaths();
      handleFlowsPathChange(demo.flows_path);
      if (demo.labels_exists) {
        handleLabelsPathChange(demo.labels_path);
      }
      await runInspectPath(demo.flows_path);
    } catch (err) {
      errorMessage = err instanceof Error ? err.message : String(err);
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
      errorMessage = "Vui lòng chọn hoặc nhập đường dẫn tệp NetFlow CSV.";
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
        errorMessage = result.error;
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
      errorMessage = "Vui lòng chọn hoặc nhập đường dẫn tệp NetFlow CSV.";
      return;
    }
    const readyList = models.filter((m) => m.ready);
    if (readyList.length === 0) {
      errorMessage = "Không có mô hình nào ở trạng thái READY để so sánh.";
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
      errorMessage = result.errorSummary;
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
        errorMessage = result.error;
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
      errorMessage = result.errorSummary;
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
      const detail = err instanceof Error ? err.message : String(err);
      simulationWarning = `Không thể chạy mô phỏng Dry-Run (#27): ${detail}`;
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
      errorMessage = err instanceof Error ? err.message : String(err);
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
    busyMessage = "Đang xuất file predictions CSV và metadata SHA-256...";
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
      errorMessage = err instanceof Error ? err.message : String(err);
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
        <h1 class="brand-title">NetFlow Sentinel v0.6.0 — Phân tích Bất thường Lưu lượng Mạng</h1>
        <p class="brand-subtitle">
          Offline Desktop • Rust Tauri 2 + Svelte 5 + Python FastAPI (127.0.0.1 Only) • UNSW-NB15-v3
        </p>
      </div>
    </div>

    <div class="header-controls">
      {#if healthData?.preprocessor_ready}
        <span class="badge badge-benign">
          <Icons name="check" size={12} />
          Preprocessor READY
        </span>
      {:else}
        <span class="badge badge-attack">
          <Icons name="alert" size={12} />
          Preprocessor BLOCKED
        </span>
      {/if}

      <span class="badge badge-info mono">
        {backendStatus?.running ? `FastAPI :${backendStatus.port}` : "FastAPI Offline"}
      </span>

      <button type="button" class="btn btn-sm" onclick={handleRestartBackend} disabled={Boolean(busyMessage)}>
        <Icons name="refresh" size={14} />
        Làm mới Backend
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
    {#if errorMessage}
      <div class="banner banner-error" role="alert">
        <Icons name="alert" size={18} />
        <div style="flex: 1;">
          <strong>Lỗi hệ thống / Xác thực Fail-Closed:</strong> {errorMessage}
        </div>
        <button type="button" class="btn btn-sm" onclick={() => (errorMessage = null)}>Đóng</button>
      </div>
    {/if}

    {#if simulationWarning}
      <div class="banner banner-warning" role="status">
        <Icons name="alert" size={18} />
        <div style="flex: 1;">
          <strong>Cảnh báo Dry-Run (#27):</strong> {simulationWarning}
        </div>
        <button type="button" class="btn btn-sm" onclick={() => (simulationWarning = null)}>Đóng</button>
      </div>
    {/if}

    {#if busyMessage || initializing}
      <div class="banner banner-info" role="status">
        <Icons name="refresh" size={16} />
        <div>{busyMessage ?? "Đang khởi tạo ứng dụng và kết nối Python FastAPI..."}</div>
      </div>
    {/if}

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
          {isTauriRuntime() ? "Chọn CSV (Native)" : "Kiểm tra CSV"}
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
        1. Tổng quan & Kiểm tra CSV
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
        3. Ground Truth & Confusion Matrix
      </button>
      <button
        type="button"
        role="tab"
        class="tab-btn"
        aria-selected={activeTab === "forensics"}
        onclick={() => (activeTab = "forensics")}
      >
        <Icons name="clock" size={15} />
        4. Timeline (#24) & Hành vi (#28/#26/#27)
      </button>
    </div>

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
