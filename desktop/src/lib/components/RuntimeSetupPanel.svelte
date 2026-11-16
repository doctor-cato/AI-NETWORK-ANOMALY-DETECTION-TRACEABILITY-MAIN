<script lang="ts">
  import type { BackendStatus, RuntimeDiagnostics } from "../types";
  import Icons from "./Icons.svelte";

  interface Props {
    diagnostics: RuntimeDiagnostics | null;
    backendStatus: BackendStatus | null;
    preprocessorReady: boolean;
    readyModelsCount: number;
    busy: boolean;
    isTauri: boolean;
    onSetupPython: (wheelhouseDir?: string) => void;
    onImportZip: (expectedSha256?: string) => void;
    onImportFolder: () => void;
    onRefresh: () => void;
  }

  let {
    diagnostics,
    backendStatus,
    preprocessorReady,
    readyModelsCount,
    busy,
    isTauri,
    onSetupPython,
    onImportZip,
    onImportFolder,
    onRefresh,
  }: Props = $props();

  let expectedZipSha = $state("");
  let wheelhouseDir = $state("");
  let showAdvanced = $state(false);

  let backendRunning = $derived(Boolean(backendStatus?.running));
  let pythonReady = $derived(Boolean(diagnostics?.python_ready || backendRunning));
  let needsAttention = $derived(
    !backendRunning || !preprocessorReady || readyModelsCount < 4,
  );
</script>

{#if needsAttention}
  <section class="card setup-card" aria-label="Thiết lập Môi trường & Companion Bundle">
    <div class="card-header">
      <div>
        <h2 class="card-title">
          <Icons name="alert" size={17} />
          Chuẩn bị Môi trường Chạy Cục bộ (Cross-Machine Setup)
        </h2>
        <p class="setup-subtitle">
          Ứng dụng chạy hoàn toàn cục bộ trên Windows x64. Hoàn tất các mục chưa sẵn sàng bên dưới để bật đủ 4 mô hình AI.
        </p>
      </div>
      <div style="display: flex; gap: 8px; flex-wrap: wrap;">
        <button type="button" class="btn btn-sm" onclick={() => (showAdvanced = !showAdvanced)}>
          {showAdvanced ? "Ẩn tùy chọn Offline" : "Tùy chọn Offline / SHA-256"}
        </button>
        <button type="button" class="btn btn-sm" onclick={onRefresh} disabled={busy}>
          <Icons name="refresh" size={14} />
          Kiểm tra lại
        </button>
      </div>
    </div>

    <div class="setup-grid">
      <div class="setup-step">
        <div class="step-head">
          <strong>1. Tài nguyên Backend (FastAPI)</strong>
          {#if diagnostics?.repo_root_valid || backendRunning}
            <span class="badge badge-benign">READY</span>
          {:else}
            <span class="badge badge-attack">THIẾU</span>
          {/if}
        </div>
        <div class="step-detail mono">
          Code root: {diagnostics?.repo_root ?? backendStatus?.repo_root ?? "Chưa xác định"}
        </div>
        {#if diagnostics?.runtime_dir}
          <div class="step-detail mono">Runtime data: {diagnostics.runtime_dir}</div>
        {/if}
      </div>

      <div class="setup-step">
        <div class="step-head">
          <strong>2. Python Runtime &amp; Thư viện ML</strong>
          {#if diagnostics?.python_ready || backendRunning}
            <span class="badge badge-benign">READY</span>
          {:else}
            <span class="badge badge-warning">CHƯA ĐỦ</span>
          {/if}
        </div>
        {#if diagnostics?.python_executable || backendStatus?.python_executable}
          <div class="step-detail mono">
            {diagnostics?.python_executable ?? backendStatus?.python_executable}
          </div>
        {:else}
          <div class="step-detail">
            {diagnostics?.python_error ??
              "Cần Python >= 3.12 và các gói FastAPI, scikit-learn, xgboost, joblib."}
          </div>
          {#if isTauri}
            {#if diagnostics?.base_python_available}
              <div class="step-actions">
                <button
                  type="button"
                  class="btn btn-primary btn-sm"
                  disabled={busy}
                  onclick={() => onSetupPython(wheelhouseDir)}
                >
                  Thiết lập Python Runtime (.venv)
                </button>
              </div>
            {:else}
              <div class="step-detail">
                Cài Python 3.12 (x64): <code class="mono">winget install Python.Python.3.12</code> rồi bấm <strong>Kiểm tra lại</strong>.
              </div>
            {/if}
          {/if}
        {/if}
      </div>

      <div class="setup-step">
        <div class="step-head">
          <strong>3. Companion Bundle (4 Model + Preprocessor + Demo)</strong>
          {#if preprocessorReady && readyModelsCount === 4}
            <span class="badge badge-benign">4/4 READY</span>
          {:else}
            <span class="badge badge-warning">{readyModelsCount}/4 READY</span>
          {/if}
        </div>
        <div class="step-detail">
          Kiểm tra SHA-256 fail-closed cho Preprocessor, Random Forest, XGBoost, Isolation Forest, Autoencoder và bộ Validation demo.
        </div>
        {#if isTauri}
          {#if !pythonReady}
            <div class="step-detail">
              Hoàn tất <strong>Bước 2 (Python Runtime)</strong> trước khi nạp Companion Bundle.
            </div>
          {/if}
          <div class="step-actions">
            <button
              type="button"
              class="btn btn-primary btn-sm"
              disabled={busy || !pythonReady}
              onclick={() => onImportZip(expectedZipSha)}
            >
              <Icons name="folder" size={14} />
              Nạp Companion Bundle (.zip)
            </button>
            <button
              type="button"
              class="btn btn-sm"
              disabled={busy || !pythonReady}
              onclick={onImportFolder}
            >
              Nạp từ Thư mục
            </button>
          </div>
        {/if}
      </div>
    </div>

    {#if showAdvanced}
      <div class="advanced-box">
        <label class="adv-field">
          <span>SHA-256 mong đợi của Companion ZIP (tùy chọn, khuyến nghị 64 hex):</span>
          <input
            type="text"
            class="input mono"
            placeholder="Ví dụ: 64 ký tự hex SHA-256 từ COMPANION_SHA256..."
            bind:value={expectedZipSha}
          />
        </label>
        <label class="adv-field">
          <span>Thư mục Wheelhouse offline cho pip (tùy chọn khi máy không có Internet):</span>
          <input
            type="text"
            class="input mono"
            placeholder="Ví dụ: D:\offline-wheelhouse"
            bind:value={wheelhouseDir}
          />
        </label>
      </div>
    {/if}
  </section>
{/if}

<style>
  .setup-card {
    border-color: rgba(245, 158, 11, 0.45);
  }

  .setup-subtitle {
    margin: 4px 0 0;
    font-size: 12.5px;
    color: var(--text-secondary);
  }

  .setup-grid {
    display: grid;
    grid-template-columns: repeat(3, minmax(0, 1fr));
    gap: 12px;
  }

  @media (max-width: 1080px) {
    .setup-grid {
      grid-template-columns: 1fr;
    }
  }

  .setup-step {
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    padding: 12px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .step-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }

  .step-detail {
    font-size: 12px;
    color: var(--text-secondary);
    overflow-wrap: anywhere;
  }

  .step-actions {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-top: auto;
  }

  .advanced-box {
    margin-top: 12px;
    padding-top: 12px;
    border-top: 1px solid var(--border-subtle);
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
  }

  @media (max-width: 960px) {
    .advanced-box {
      grid-template-columns: 1fr;
    }
  }

  .adv-field {
    display: flex;
    flex-direction: column;
    gap: 5px;
    font-size: 12px;
    color: var(--text-secondary);
  }
</style>
