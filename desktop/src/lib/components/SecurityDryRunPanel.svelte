<script lang="ts">
  import type {
    SecurityResponseSimulationResponse,
    SecuritySimulationExportResponse,
    SecuritySimulationHistoryItem,
  } from "../types";
  import {
    filterResponseRecommendations,
    getResponseActionBadgeClass,
    shortDigest,
    type ResponseActionFilter,
  } from "../utils";
  import Icons from "./Icons.svelte";

  interface Props {
    simulation: SecurityResponseSimulationResponse | null;
    history: SecuritySimulationHistoryItem[];
    exportInfo: SecuritySimulationExportResponse | null;
    simulating: boolean;
    canSimulate: boolean;
    onRunSimulation: () => void;
    onRefreshHistory: () => void;
    onExportSimulation: (simulationId: string) => void;
  }

  let {
    simulation,
    history,
    exportInfo,
    simulating,
    canSimulate,
    onRunSimulation,
    onRefreshHistory,
    onExportSimulation,
  }: Props = $props();

  let actionFilter = $state<ResponseActionFilter>("all");
  let query = $state("");

  let filteredRecs = $derived(
    simulation
      ? filterResponseRecommendations(simulation.recommendations, actionFilter, query)
      : [],
  );
  let visibleRecs = $derived(filteredRecs.slice(0, 80));
</script>

<section class="card" aria-labelledby="dry-run-heading">
  <div class="card-header">
    <div>
      <h2 id="dry-run-heading" class="card-title">
        <Icons name="shield" size={17} />
        Adaptive Security Response Simulation (#27 — Dry-Run Only)
      </h2>
    </div>
    <div style="display: flex; flex-wrap: wrap; gap: 6px; align-items: center;">
      <span class="badge badge-info">SIMULATED / RECOMMENDED ONLY</span>
      <span class="badge badge-warning">EXECUTED: FALSE • No OS Firewall</span>
      <button
        type="button"
        class="btn btn-primary btn-sm"
        disabled={!canSimulate || simulating}
        onclick={onRunSimulation}
      >
        <Icons name="play" size={13} />
        {simulating ? "Đang mô phỏng..." : "Chạy mô phỏng Dry-Run"}
      </button>
      <button
        type="button"
        class="btn btn-sm"
        disabled={!simulation || simulating}
        onclick={() => simulation && onExportSimulation(simulation.simulation_id)}
      >
        <Icons name="download" size={13} />
        Export Bằng chứng Dry-Run (JSON)
      </button>
    </div>
  </div>

  {#if !simulation}
    <div class="empty-state" style="padding: 20px;">
      Chạy phân tích NetFlow CSV để sinh khuyến nghị phản ứng tất định (<span class="mono">NO_ACTION</span>,
      <span class="mono">MONITOR</span>, <span class="mono">INVESTIGATE</span>,
      <span class="mono">ISOLATE_RECOMMENDED</span>) và quyết định mô phỏng xoay khóa thích ứng trong chế độ Dry-Run an toàn.
    </div>
  {:else}
    <div class="banner banner-info" style="margin-bottom: 12px;">
      <Icons name="lock" size={16} />
      <div>
        <div>
          <strong>Simulation ID:</strong> <span class="mono">{simulation.simulation_id}</span> •
          <strong>Mode:</strong> <span class="mono">{simulation.execution_mode}</span> •
          <strong>Action Status:</strong> <span class="mono">{simulation.action_status} / {simulation.recommendation_status}</span> •
          <strong>Executed:</strong> <span class="mono">{String(simulation.executed)}</span> •
          <strong>Provenance:</strong> <span class="mono">{simulation.provenance_verification}</span>
        </div>
        <div style="margin-top: 4px; color: var(--text-secondary);">
          {simulation.policy_summary}
        </div>
      </div>
    </div>

    <div class="grid-5" style="margin-bottom: 12px;">
      <div class="kpi-box">
        <div class="kpi-label">Khuyến nghị tổng thể</div>
        <div style="margin-top: 4px;">
          <span class={`badge ${getResponseActionBadgeClass(simulation.overall_recommendation)}`}>
            {simulation.overall_recommendation}
          </span>
        </div>
        <div class="mono" style="font-size: 11px; margin-top: 4px; color: var(--text-secondary);">
          Severity: {simulation.overall_severity} • NOT EXECUTED
        </div>
      </div>
      <div class="kpi-box">
        <div class="kpi-label">ISOLATE_RECOMMENDED</div>
        <div class="kpi-value mono" style="color: var(--semantic-attack)">
          {simulation.action_counts.ISOLATE_RECOMMENDED ?? 0}
        </div>
        <div class="mono" style="font-size: 11px; color: var(--text-secondary);">
          Chỉ khuyến nghị (executed=false)
        </div>
      </div>
      <div class="kpi-box">
        <div class="kpi-label">INVESTIGATE</div>
        <div class="kpi-value mono" style="color: var(--semantic-warning)">
          {simulation.action_counts.INVESTIGATE ?? 0}
        </div>
      </div>
      <div class="kpi-box">
        <div class="kpi-label">MONITOR / NO_ACTION</div>
        <div class="kpi-value mono">
          {simulation.action_counts.MONITOR ?? 0} / {simulation.action_counts.NO_ACTION ?? 0}
        </div>
      </div>
      <div class="kpi-box">
        <div class="kpi-label">Guard ABSTAINED_OOD</div>
        <div class="kpi-value mono" style="color: var(--semantic-warning)">
          {simulation.ood_abstained_flows}
        </div>
        <div class="mono" style="font-size: 11px; color: var(--text-secondary);">
          Chặn auto-containment 100%
        </div>
      </div>
    </div>

    <div class="card" style="background: var(--bg-elevated); margin-bottom: 12px;">
      <div class="card-header" style="margin-bottom: 8px;">
        <h3 class="card-title" style="font-size: 14px;">
          <Icons name="lock" size={15} />
          Adaptive Key Rotation Simulation (Metadata Policy Only — Real Crypto Keyring DEFERRED)
        </h3>
        <span
          class="badge"
          class:badge-warning={simulation.key_rotation_simulation.recommended}
          class:badge-benign={!simulation.key_rotation_simulation.recommended}
        >
          {simulation.key_rotation_simulation.decision}
        </span>
      </div>
      <div class="grid-4" style="gap: 8px; margin-bottom: 8px;">
        <div class="kpi-box" style="background: var(--bg-surface);">
          <div class="kpi-label">Active Metadata Key</div>
          <div class="mono" style="font-size: 12px;">
            {simulation.key_rotation_simulation.active_key_id ?? "N/A"} (v{simulation.key_rotation_simulation.active_key_version ?? "-"})
          </div>
        </div>
        <div class="kpi-box" style="background: var(--bg-surface);">
          <div class="kpi-label">Simulated Target Version</div>
          <div class="mono" style="font-size: 12px;">
            {simulation.key_rotation_simulation.simulated_next_version
              ? `v${simulation.key_rotation_simulation.simulated_next_version} (SIMULATED)`
              : "No rotation proposed"}
          </div>
        </div>
        <div class="kpi-box" style="background: var(--bg-surface);">
          <div class="kpi-label">Crypto Key Generated / Mutated</div>
          <div class="mono" style="font-size: 12px;">
            generated={String(simulation.key_rotation_simulation.key_material_generated)} • modified={String(simulation.key_rotation_simulation.real_key_modified)}
          </div>
        </div>
        <div class="kpi-box" style="background: var(--bg-surface);">
          <div class="kpi-label">AES-256-GCM Production Keyring</div>
          <div class="mono" style="font-size: 12px;">
            {simulation.key_rotation_simulation.keyring_status}
          </div>
        </div>
      </div>
      <div style="font-size: 12.5px; color: var(--text-secondary);">
        {simulation.key_rotation_simulation.reason}
      </div>
    </div>

    {#if exportInfo}
      <div class="banner banner-success" style="margin-bottom: 12px;">
        <Icons name="check" size={16} />
        <div class="mono" style="font-size: 12px;">
          Đã export bằng chứng #27 ({exportInfo.simulation_id}) → {exportInfo.json_path} (SHA-256: {shortDigest(exportInfo.json_sha256)}) &amp; {exportInfo.metadata_path}
        </div>
      </div>
    {/if}

    <div class="rec-toolbar">
      <div style="display: flex; flex-wrap: wrap; gap: 6px;">
        <button
          type="button"
          class="btn btn-sm"
          class:btn-primary={actionFilter === "all"}
          onclick={() => (actionFilter = "all")}
        >
          Tất cả ({simulation.recommendations.length})
        </button>
        <button
          type="button"
          class="btn btn-sm"
          class:btn-primary={actionFilter === "ISOLATE_RECOMMENDED"}
          onclick={() => (actionFilter = "ISOLATE_RECOMMENDED")}
        >
          ISOLATE_RECOMMENDED ({simulation.action_counts.ISOLATE_RECOMMENDED ?? 0})
        </button>
        <button
          type="button"
          class="btn btn-sm"
          class:btn-primary={actionFilter === "INVESTIGATE"}
          onclick={() => (actionFilter = "INVESTIGATE")}
        >
          INVESTIGATE ({simulation.action_counts.INVESTIGATE ?? 0})
        </button>
        <button
          type="button"
          class="btn btn-sm"
          class:btn-primary={actionFilter === "MONITOR"}
          onclick={() => (actionFilter = "MONITOR")}
        >
          MONITOR ({simulation.action_counts.MONITOR ?? 0})
        </button>
        <button
          type="button"
          class="btn btn-sm"
          class:btn-primary={actionFilter === "NO_ACTION"}
          onclick={() => (actionFilter = "NO_ACTION")}
        >
          NO_ACTION ({simulation.action_counts.NO_ACTION ?? 0})
        </button>
        <button
          type="button"
          class="btn btn-sm"
          class:btn-primary={actionFilter === "OOD"}
          onclick={() => (actionFilter = "OOD")}
        >
          ABSTAINED_OOD ({simulation.ood_abstained_flows})
        </button>
      </div>
      <input
        type="search"
        class="input"
        style="min-width: 220px;"
        placeholder="Tìm row_id, IP, lý do..."
        bind:value={query}
        aria-label="Lọc khuyến nghị dry-run"
      />
    </div>

    <div class="table-scroll" style="max-height: 310px; margin-bottom: 12px;">
      <table class="data-table">
        <thead>
          <tr>
            <th>Row ID</th>
            <th>Flow</th>
            <th>Prediction / Risk</th>
            <th>Khuyến nghị</th>
            <th>Trạng thái</th>
            <th>Lý do &amp; Provenance</th>
          </tr>
        </thead>
        <tbody>
          {#if visibleRecs.length === 0}
            <tr>
              <td colspan="6" style="text-align: center; color: var(--text-secondary);">
                Không có khuyến nghị nào khớp bộ lọc.
              </td>
            </tr>
          {:else}
            {#each visibleRecs as rec (`${rec.row_index}-${rec.row_id}`)}
              <tr>
                <td class="mono">{rec.row_id}</td>
                <td class="mono">
                  {rec.src_ip ?? "?"}:{rec.src_port ?? "-"} → {rec.dst_ip ?? "?"}:{rec.dst_port ?? "-"}
                </td>
                <td class="mono">
                  {rec.predicted_class} ({rec.risk_score !== null ? rec.risk_score.toFixed(1) : rec.risk_level})
                </td>
                <td>
                  <span class={`badge ${getResponseActionBadgeClass(rec.action)}`}>
                    {rec.action}
                  </span>
                </td>
                <td class="mono" style="font-size: 11.5px;">
                  {rec.action_status} • {rec.simulation_status} (executed={String(rec.executed)})
                </td>
                <td style="white-space: normal; min-width: 340px; font-size: 12px;">
                  <div>{rec.reason}</div>
                  <div class="mono" style="font-size: 11px; color: var(--text-secondary);">
                    model={rec.provenance.model_key} • source={rec.provenance.source_id} • verified={String(rec.provenance.provenance_verified)} • containment={String(rec.containment_allowed)}
                  </div>
                </td>
              </tr>
            {/each}
          {/if}
        </tbody>
      </table>
    </div>
    {#if filteredRecs.length > visibleRecs.length}
      <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 12px;">
        Đang hiển thị {visibleRecs.length}/{filteredRecs.length} dòng khuyến nghị. Export JSON để xem đầy đủ.
      </div>
    {/if}
  {/if}

  <div class="card" style="background: var(--bg-elevated);">
    <div class="card-header" style="margin-bottom: 8px;">
      <h3 class="card-title" style="font-size: 14px;">
        <Icons name="clock" size={15} />
        Lịch sử Mô phỏng Dry-Run (SQLite Persistent Audit Log — {history.length} bản ghi gần nhất)
      </h3>
      <button type="button" class="btn btn-sm" onclick={onRefreshHistory}>
        <Icons name="refresh" size={13} />
        Làm mới lịch sử
      </button>
    </div>

    {#if history.length === 0}
      <div style="font-size: 12.5px; color: var(--text-secondary);">
        Chưa có bản ghi mô phỏng nào trong cơ sở dữ liệu SQLite hiện tại.
      </div>
    {:else}
      <div class="table-scroll" style="max-height: 210px;">
        <table class="data-table">
          <thead>
            <tr>
              <th>Simulation ID</th>
              <th>Thời điểm (UTC)</th>
              <th>Model</th>
              <th>Khuyến nghị tổng</th>
              <th>Key Rotation Sim</th>
              <th>Trạng thái</th>
              <th>Bằng chứng</th>
            </tr>
          </thead>
          <tbody>
            {#each history as h (h.simulation_id)}
              <tr>
                <td class="mono">{h.simulation_id}</td>
                <td class="mono">{h.created_at_utc}</td>
                <td class="mono">{h.model_key}</td>
                <td>
                  <span class={`badge ${getResponseActionBadgeClass(h.overall_recommendation)}`}>
                    {h.overall_recommendation}
                  </span>
                </td>
                <td class="mono">{h.key_rotation_simulation.decision}</td>
                <td class="mono">{h.action_status} (executed={String(h.executed)})</td>
                <td>
                  <button
                    type="button"
                    class="btn btn-sm"
                    onclick={() => onExportSimulation(h.simulation_id)}
                  >
                    <Icons name="download" size={12} />
                    Export
                  </button>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>
    {/if}
  </div>
</section>

<style>
  .rec-toolbar {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
    margin-bottom: 10px;
  }
</style>
