<script lang="ts">
  import type { BackendLogSnapshot, BackendStatus, RuntimeDiagnostics } from "../types";
  import Icons from "./Icons.svelte";

  interface Props {
    logs: BackendLogSnapshot | null;
    backendStatus: BackendStatus | null;
    diagnostics: RuntimeDiagnostics | null;
    onRefresh: () => void;
    onClose: () => void;
  }

  let { logs, backendStatus, diagnostics, onRefresh, onClose }: Props = $props();

  let copied = $state(false);
  let autoScroll = $state(true);
  let terminalEl = $state<HTMLDivElement | null>(null);

  $effect(() => {
    const count = logs?.lines.length ?? 0;
    if (autoScroll && terminalEl && count > 0) {
      terminalEl.scrollTop = terminalEl.scrollHeight;
    }
  });

  async function copyAllLogs() {
    const headerLines = [
      `NetFlow Sentinel Dev Logs`,
      `Mode: ${logs?.backend_mode ?? diagnostics?.backend_mode ?? "unknown"} | Stage: ${logs?.startup_stage ?? backendStatus?.startup_stage ?? "unknown"} | Running: ${logs?.running ?? backendStatus?.running ?? false}`,
      `Sidecar/Exe: ${diagnostics?.sidecar_executable ?? backendStatus?.python_executable ?? "(none)"}`,
      `Resource Root: ${diagnostics?.repo_root ?? backendStatus?.repo_root ?? "(none)"}`,
      `Runtime Dir: ${diagnostics?.runtime_dir ?? backendStatus?.runtime_dir ?? "(none)"}`,
      `Log File: ${logs?.log_file_path ?? "(memory)"}`,
      `---`,
    ];
    const body = [...headerLines, ...(logs?.lines ?? [])].join("\n");
    try {
      await navigator.clipboard.writeText(body);
      copied = true;
      setTimeout(() => (copied = false), 1800);
    } catch {
      copied = false;
    }
  }

  function formatElapsed(ms: number | undefined): string {
    if (!ms || ms <= 0) return "0.0s";
    return `${(ms / 1000).toFixed(1)}s`;
  }

  function lineClass(line: string): string {
    if (line.includes("[error]") || line.includes("[sidecar:stderr]") || line.includes("Traceback")) {
      return "log-line log-err";
    }
    if (line.includes("READY")) {
      return "log-line log-ok";
    }
    return "log-line";
  }
</script>

<section class="card dev-logs-card" aria-label="Nhật ký Kỹ thuật Dev Logs">
  <div class="card-header">
    <div>
      <h2 class="card-title">
        <Icons name="cpu" size={16} />
        Nhật ký Kỹ thuật Backend / Dev Logs
        <span class="badge badge-info mono">Shift+F9</span>
        {#if logs?.starting || backendStatus?.starting}
          <span class="badge badge-warning mono">
            Đang khởi tạo ({logs?.startup_stage ?? backendStatus?.startup_stage} • {formatElapsed(logs?.startup_elapsed_ms ?? backendStatus?.startup_elapsed_ms)})
          </span>
        {:else if logs?.running || backendStatus?.running}
          <span class="badge badge-benign mono">
            Running • PID {logs?.pid ?? backendStatus?.pid ?? "?"} • :{logs?.port ?? backendStatus?.port ?? "?"}
          </span>
        {:else}
          <span class="badge badge-attack mono">
            Stopped ({logs?.startup_stage ?? backendStatus?.startup_stage ?? "offline"})
          </span>
        {/if}
      </h2>
      <div class="dev-meta mono">
        <span><strong>Mode:</strong> {logs?.backend_mode ?? diagnostics?.backend_mode ?? "-"}</span>
        <span><strong>Exe:</strong> {diagnostics?.sidecar_executable ?? backendStatus?.python_executable ?? "-"}</span>
        <span><strong>Resource:</strong> {diagnostics?.repo_root ?? backendStatus?.repo_root ?? "-"}</span>
        <span><strong>Log file:</strong> {logs?.log_file_path ?? "-"}</span>
      </div>
    </div>

    <div class="dev-actions">
      <label class="scroll-toggle">
        <input type="checkbox" bind:checked={autoScroll} />
        Tự cuộn cuối
      </label>
      <button type="button" class="btn btn-sm" onclick={onRefresh}>
        <Icons name="refresh" size={13} />
        Làm mới Log
      </button>
      <button type="button" class="btn btn-sm" onclick={copyAllLogs}>
        {copied ? "Đã sao chép!" : "Sao chép Log"}
      </button>
      <button type="button" class="btn btn-sm" onclick={onClose}>
        Đóng (Shift+F9)
      </button>
    </div>
  </div>

  {#if logs?.last_error || backendStatus?.last_error}
    <div class="banner banner-error" style="margin-bottom: 10px;">
      <Icons name="alert" size={16} />
      <div class="mono" style="font-size: 12px; word-break: break-word;">
        {logs?.last_error ?? backendStatus?.last_error}
      </div>
    </div>
  {/if}

  <div class="log-terminal mono" bind:this={terminalEl} role="log" aria-live="polite">
    {#if !logs || logs.lines.length === 0}
      <div class="log-empty">Chưa có dòng log nào được ghi nhận. Nhấn Làm mới Log hoặc đợi tiến trình sidecar phản hồi...</div>
    {:else}
      {#each logs.lines as line, idx (idx)}
        <div class={lineClass(line)}>{line}</div>
      {/each}
    {/if}
  </div>
</section>

<style>
  .dev-logs-card {
    border-color: rgba(59, 130, 246, 0.45);
    animation: nf-fade-slide-in 180ms cubic-bezier(0.22, 1, 0.36, 1);
  }

  .dev-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 14px;
    font-size: 11.5px;
    color: var(--text-secondary);
    margin-top: 6px;
    word-break: break-all;
  }

  .dev-actions {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
  }

  .scroll-toggle {
    display: inline-flex;
    align-items: center;
    gap: 5px;
    font-size: 12px;
    color: var(--text-secondary);
    cursor: pointer;
    user-select: none;
  }

  .log-terminal {
    background: var(--bg-subtle);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    padding: 10px 12px;
    max-height: 280px;
    overflow-y: auto;
    overflow-x: auto;
    font-size: 11.5px;
    line-height: 1.55;
  }

  .log-line {
    white-space: pre-wrap;
    word-break: break-word;
    color: var(--text-primary);
  }

  .log-err {
    color: #fca5a5;
  }

  :global(:root[data-theme="light"]) .log-err {
    color: #b91c1c;
  }

  .log-ok {
    color: var(--semantic-benign);
  }

  .log-empty {
    color: var(--text-muted);
    font-style: italic;
  }
</style>
