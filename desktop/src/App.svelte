<script lang="ts">
  import { onMount } from "svelte";
  import {
    analyzeCsv,
    evaluateCsv,
    exportCsv,
    fetchHealth,
    fetchModelsStatus,
    getBackendStatus,
    getDemoPaths,
    inspectCsv,
    isTauriRuntime,
    pickCsvFile,
    pickSaveCsvFile,
    restartBackend,
  } from "./lib/api";
  import ChartsPanel from "./lib/components/ChartsPanel.svelte";
  import CsvPreviewPanel from "./lib/components/CsvPreviewPanel.svelte";
  import EvaluationPanel from "./lib/components/EvaluationPanel.svelte";
  import ForensicTimelinePanel from "./lib/components/ForensicTimelinePanel.svelte";
  import Icons from "./lib/components/Icons.svelte";
  import ModelReadinessPanel from "./lib/components/ModelReadinessPanel.svelte";
  import PredictionsTable from "./lib/components/PredictionsTable.svelte";
  import type {
    BackendStatus,
    CsvAnalyzeResponse,
    CsvEvaluateResponse,
    CsvExportResponse,
    CsvInspectResponse,
    HealthResponse,
    ModelStatusItem,
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
  let lastInspectedInputPath = $state("");
  let inspectData = $state<CsvInspectResponse | null>(null);
  let analysisData = $state<CsvAnalyzeResponse | null>(null);
  let evalData = $state<CsvEvaluateResponse | null>(null);
  let exportData = $state<CsvExportResponse | null>(null);

  let initializing = $state(true);
  let busyMessage = $state<string | null>(null);
  let errorMessage = $state<string | null>(null);
  let evaluatedFlag = $state(false);

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
      const readyKeys = modelList.filter((m) => m.ready).map((m) => m.model_key);
      if (readyKeys.length > 0 && !readyKeys.includes(selectedModel)) {
        selectedModel = readyKeys[0];
      }
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
      if (demo.flows_exists) {
        flowsPath = demo.flows_path;
      }
      if (demo.labels_exists) {
        labelsPath = demo.labels_path;
      }
    } finally {
      initializing = false;
    }
  });

  async function handleRestartBackend() {
    busyMessage = "Đang khởi động lại tiến trình Python FastAPI...";
    errorMessage = null;
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
    if (!path.trim()) return;
    busyMessage = "Đang kiểm tra schema 47 ML features & OOD...";
    errorMessage = null;
    try {
      const inspected = await inspectCsv(path, 20);
      lastInspectedInputPath = path.trim();
      inspectData = inspected;
      analysisData = null;
      evalData = null;
      exportData = null;
    } catch (err) {
      errorMessage = err instanceof Error ? err.message : String(err);
    } finally {
      busyMessage = null;
    }
  }

  async function handleBrowseFlowsCsv() {
    if (isTauriRuntime()) {
      const chosen = await pickCsvFile("Chọn tệp NetFlow CSV để phân tích");
      if (chosen) {
        flowsPath = chosen;
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
      flowsPath = demo.flows_path;
      if (demo.labels_exists) {
        labelsPath = demo.labels_path;
      }
      await runInspectPath(demo.flows_path);
    } catch (err) {
      errorMessage = err instanceof Error ? err.message : String(err);
      busyMessage = null;
    }
  }

  async function handleRunInference() {
    if (!flowsPath.trim()) {
      errorMessage = "Vui lòng chọn hoặc nhập đường dẫn tệp NetFlow CSV.";
      return;
    }
    busyMessage = `Đang chạy mô hình ${selectedModel} qua InferencePipeline...`;
    errorMessage = null;
    exportData = null;
    try {
      const trimmedFlowsPath = flowsPath.trim();
      if (
        !inspectData ||
        (inspectData.file_path !== trimmedFlowsPath && lastInspectedInputPath !== trimmedFlowsPath)
      ) {
        inspectData = await inspectCsv(trimmedFlowsPath, 20);
        lastInspectedInputPath = trimmedFlowsPath;
      }
      const res = await analyzeCsv({
        filePath: flowsPath,
        modelName: selectedModel,
        createIncidents: false,
        batchSize: 500,
      });
      analysisData = res;
      evalData = null;
      activeTab = "predictions";
    } catch (err) {
      errorMessage = err instanceof Error ? err.message : String(err);
    } finally {
      busyMessage = null;
    }
  }

  async function handlePickLabelsFile() {
    if (!isTauriRuntime()) return;
    const chosen = await pickCsvFile("Chọn tệp Ground Truth Labels CSV");
    if (chosen) {
      labelsPath = chosen;
    }
  }

  async function handleUseDemoLabels() {
    const demo = await getDemoPaths();
    labelsPath = demo.labels_path;
  }

  async function handleRunEvaluate() {
    if (!analysisData || !labelsPath.trim()) return;
    evaluatedFlag = true;
    errorMessage = null;
    try {
      evalData = await evaluateCsv(labelsPath, analysisData.results);
      activeTab = "evaluation";
    } catch (err) {
      errorMessage = err instanceof Error ? err.message : String(err);
    } finally {
      evaluatedFlag = false;
    }
  }

  async function handleExportResults() {
    if (!analysisData) return;
    const defaultName = `predictions_${analysisData.model_key}.csv`;
    const chosen = await pickSaveCsvFile(defaultName);
    if (!chosen) return;

    busyMessage = "Đang xuất file predictions CSV và metadata SHA-256...";
    errorMessage = null;
    try {
      exportData = await exportCsv({
        output_path: chosen,
        source_csv_path: analysisData.file_path,
        model_key: analysisData.model_key,
        model_type: analysisData.model_type,
        run_id: analysisData.run_id,
        model_sha256: analysisData.model_sha256,
        preprocessor_sha256: analysisData.preprocessor_sha256,
        results: analysisData.results,
        evaluation: evalData,
      });
    } catch (err) {
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
        <h1 class="brand-title">NetFlow Sentinel M6 — Phân tích Bất thường Lưu lượng Mạng</h1>
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
          bind:value={flowsPath}
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
            <div class="kpi-label">OOD Abstained (MIN_TTL=0)</div>
            <div class="kpi-value mono" style="color: var(--semantic-warning)">{analysisData.ood_flagged_count}</div>
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
        onUpdateLabelsPath={(v) => (labelsPath = v)}
      />
    {:else if activeTab === "forensics"}
      {#if analysisData}
        <ForensicTimelinePanel
          timeline={analysisData.timeline}
          behavioral={analysisData.behavioral_summary}
          securityNotice={analysisData.security_notice}
        />
      {:else if inspectData}
        <ForensicTimelinePanel
          timeline={[]}
          behavioral={inspectData.behavioral_summary}
          securityNotice="Localhost-only FastAPI (127.0.0.1), fail-closed SHA-256 artifact checks. Firewall automation & AES-256-GCM keyring remain DEFERRED (#26/#27)."
        />
      {:else}
        <div class="empty-state">
          Hãy kiểm tra hoặc chạy phân tích CSV để xem Evidence Timeline (#24) và Thống kê Hành vi NetFlow (#28).
        </div>
      {/if}
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
