<script lang="ts">
  import type {
    BehavioralSummary,
    CsvTimelineItem,
    SecurityResponseSimulationResponse,
    SecuritySimulationExportResponse,
    SecuritySimulationHistoryItem,
  } from "../types";
  import Icons from "./Icons.svelte";
  import SecurityDryRunPanel from "./SecurityDryRunPanel.svelte";

  interface Props {
    timeline: CsvTimelineItem[];
    behavioral: BehavioralSummary | null;
    securityNotice: string;
    simulation: SecurityResponseSimulationResponse | null;
    simulationHistory: SecuritySimulationHistoryItem[];
    simulationExportInfo: SecuritySimulationExportResponse | null;
    simulating: boolean;
    canSimulate: boolean;
    onRunSimulation: () => void;
    onRefreshHistory: () => void;
    onExportSimulation: (simulationId: string) => void;
  }

  let {
    timeline,
    behavioral,
    securityNotice,
    simulation,
    simulationHistory,
    simulationExportInfo,
    simulating,
    canSimulate,
    onRunSimulation,
    onRefreshHistory,
    onExportSimulation,
  }: Props = $props();

  let onlyAlerts = $state(false);
  let filteredTimeline = $derived(
    onlyAlerts
      ? timeline.filter((t) => t.predicted_class === "Attack" || t.is_ood_flagged)
      : timeline,
  );
  let visibleTimeline = $derived(filteredTimeline.slice(0, 80));
</script>

<div style="display: flex; flex-direction: column; gap: 16px;">
  <section class="card" aria-labelledby="security-posture-heading">
    <div class="card-header">
      <h2 id="security-posture-heading" class="card-title">
        <Icons name="shield" size={17} />
        Kiến trúc Bảo mật (#26 Local-Only &amp; #27 Dry-Run Simulation / Production Keyring DEFERRED)
      </h2>
      <span class="badge badge-info">SIMULATED / RECOMMENDED ONLY • No Auto-Firewall</span>
    </div>
    <div class="banner banner-info">
      <Icons name="lock" size={16} />
      <div>
        <div>{securityNotice}</div>
        <div style="margin-top: 4px; color: var(--text-secondary);">
          Mọi quyết định phản ứng (#27) chỉ chạy ở chế độ <strong>Dry-Run Simulation (RECOMMENDED / SIMULATED, executed=false)</strong>.
          <strong>AES-256-GCM keyring production</strong>, tự động xoay khóa thật và gọi firewall/PowerShell/OS commands vẫn giữ ở trạng thái <strong>DEFERRED</strong>.
        </div>
      </div>
    </div>
  </section>

  <SecurityDryRunPanel
    {simulation}
    history={simulationHistory}
    exportInfo={simulationExportInfo}
    {simulating}
    {canSimulate}
    {onRunSimulation}
    {onRefreshHistory}
    {onExportSimulation}
  />

  {#if behavioral}
  <section class="grid-2">
    <div class="card" aria-labelledby="behavioral-heading">
      <div class="card-header">
        <h2 id="behavioral-heading" class="card-title">
          <Icons name="chart" size={17} />
          Thống kê Hành vi NetFlow Metadata (#28)
        </h2>
        <span class="badge badge-benign">Ngoài 47 ML Features</span>
      </div>

      <div class="grid-2" style="margin-bottom: 12px; gap: 8px;">
        <div class="kpi-box">
          <div class="kpi-label">Src IP / Dst IP duy nhất</div>
          <div class="kpi-value mono">{behavioral.unique_src_ips} / {behavioral.unique_dst_ips}</div>
        </div>
        <div class="kpi-box">
          <div class="kpi-label">Src Port / Dst Port duy nhất</div>
          <div class="kpi-value mono">{behavioral.unique_src_ports} / {behavioral.unique_dst_ports}</div>
        </div>
      </div>

      <div class="sub-list">
        <div>
          <h4 class="sub-hdr">Top Source IP</h4>
          {#each behavioral.top_src_ips as item (item.key)}
            <div class="freq-row mono">
              <span>{item.key}</span>
              <strong>{item.count} ({(item.share * 100).toFixed(1)}%)</strong>
            </div>
          {/each}
        </div>
        <div>
          <h4 class="sub-hdr">Top Destination Port</h4>
          {#each behavioral.top_dst_ports as item (item.key)}
            <div class="freq-row mono">
              <span>Port {item.key}</span>
              <strong>{item.count} ({(item.share * 100).toFixed(1)}%)</strong>
            </div>
          {/each}
        </div>
      </div>

      <div class="banner banner-warning" style="margin-top: 12px;">
        <Icons name="alert" size={16} />
        <div>{behavioral.non_attribution_notice}</div>
      </div>
    </div>

    <div class="card" aria-labelledby="timeline-heading">
      <div class="card-header">
        <h2 id="timeline-heading" class="card-title">
          <Icons name="clock" size={17} />
          Evidence Timeline Deterministic (#24 — Theo Time + row_id)
        </h2>
        <div style="display: flex; align-items: center; gap: 8px;">
          <span class="badge badge-info mono">
            {visibleTimeline.length}/{filteredTimeline.length} sự kiện
          </span>
          <button
            type="button"
            class="btn btn-sm"
            class:btn-primary={onlyAlerts}
            onclick={() => (onlyAlerts = !onlyAlerts)}
          >
            {onlyAlerts ? "Đang lọc Attack / OOD" : "Chỉ hiện Attack / OOD"}
          </button>
        </div>
      </div>

      <div class="timeline-scroll">
        {#each visibleTimeline as evt (`${evt.sequence_index}-${evt.row_id}`)}
          <div class="tl-item">
            <div class="tl-head">
              <span class="mono" style="font-size: 12px; color: var(--text-secondary);">
                #{evt.sequence_index + 1} • row_id={evt.row_id} • {evt.timestamp_iso ?? "N/A"}
              </span>
              <span
                class="badge"
                class:badge-attack={evt.predicted_class === "Attack"}
                class:badge-blocked={evt.predicted_class === "ABSTAINED_OOD"}
                class:badge-benign={evt.predicted_class === "Benign"}
              >
                {evt.predicted_class}
              </span>
            </div>
            <div class="mono" style="font-size: 12.5px; margin-top: 4px;">
              {evt.evidence_summary}
            </div>
          </div>
        {/each}
      </div>
    </div>
  </section>
  {/if}
</div>

<style>
  .sub-list {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
  }

  .sub-hdr {
    margin: 0 0 6px;
    font-size: 12.5px;
    color: var(--text-secondary);
  }

  .freq-row {
    display: flex;
    justify-content: space-between;
    padding: 4px 8px;
    border-radius: 5px;
    background: var(--bg-elevated);
    margin-bottom: 4px;
    font-size: 12px;
  }

  .timeline-scroll {
    max-height: 410px;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding-right: 4px;
  }

  .tl-item {
    border: 1px solid var(--border-subtle);
    background: var(--bg-elevated);
    border-radius: 7px;
    padding: 8px 10px;
  }

  .tl-head {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }
</style>
