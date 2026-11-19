<script lang="ts">
  import { onDestroy, onMount } from "svelte";
  import {
    fetchIncidents,
    fetchLiveAlerts,
    fetchLiveStatus,
    startLiveTelemetry,
    stopLiveTelemetry,
  } from "../api";
  import type { IncidentItem, LiveStatusResponse, PanelDataState } from "../types";

  export let initialDemoMode: boolean = false;
  export let pollIntervalMs: number = 3000;
  export let initialAlerts: LiveAlertRow[] | null = null;
  export let initialLiveStatus: LiveStatusResponse | null = null;
  export let pageSize: number = 100;

  interface LiveAlertRow {
    alert_id: string;
    entity_id: string;
    risk_score: number;
    risk_level: string;
    trigger_reason: string;
    status: string;
    last_seen_utc: string;
    source: string;
    attack_type?: string | null;
    predicted_attack_category?: string | null;
    attack_category_confidence?: number | null;
  }

  const DEMO_ALERTS: LiveAlertRow[] = [
    {
      alert_id: "demo-alert-01",
      entity_id: "host:192.0.2.10",
      risk_score: 86.5,
      risk_level: "CRITICAL",
      trigger_reason: "[DEMO] High outbound byte asymmetry on port 445",
      status: "SIMULATED",
      last_seen_utc: "2026-11-17T10:00:00Z",
      source: "DEMO_PREVIEW",
    },
  ];

  let dataState: PanelDataState = initialDemoMode
    ? "DEMO"
    : initialAlerts !== null
      ? initialAlerts.length > 0
        ? "CONNECTED"
        : "EMPTY"
      : "LOADING";
  let errorMessage: string | null = null;
  let lastUpdatedAt: string | null = null;
  let demoEnabled = initialDemoMode;
  let liveStatus: LiveStatusResponse | null = initialLiveStatus;
  let alerts: LiveAlertRow[] = initialDemoMode ? DEMO_ALERTS : (initialAlerts ?? []);
  let filterSeverity = "ALL";
  let currentPage = 1;
  let actionBusy = false;
  let pollTimer: ReturnType<typeof setInterval> | null = null;

  function mapLiveAlert(raw: Record<string, unknown>, idx: number): LiveAlertRow {
    const score = Number(raw.risk_score ?? 0);
    return {
      alert_id: String(raw.alert_id ?? raw.event_id ?? `live-${idx}`),
      entity_id: String(raw.entity_id ?? "host:unknown"),
      risk_score: Number.isFinite(score) ? score : 0,
      risk_level: String(raw.risk_level ?? raw.severity ?? "MEDIUM"),
      trigger_reason: String(raw.trigger_reason ?? raw.reason ?? "Real-time risk threshold"),
      status: String(raw.status ?? "OPEN"),
      last_seen_utc: String(raw.last_seen_utc ?? raw.timestamp ?? new Date().toISOString()),
      source: "LIVE_ALERT_MANAGER",
      attack_type: typeof raw.attack_type === "string" ? raw.attack_type : null,
      predicted_attack_category:
        typeof raw.predicted_attack_category === "string" ? raw.predicted_attack_category : null,
      attack_category_confidence:
        typeof raw.attack_category_confidence === "number" &&
        Number.isFinite(raw.attack_category_confidence)
          ? raw.attack_category_confidence
          : null,
    };
  }

  function mapIncident(item: IncidentItem): LiveAlertRow {
    const score = item.anomaly_score <= 1.0 ? item.anomaly_score * 100.0 : item.anomaly_score;
    return {
      alert_id: item.incident_id,
      entity_id: item.source_ip ? `host:${item.source_ip}` : "host:persisted",
      risk_score: score,
      risk_level: item.severity,
      trigger_reason: item.title,
      status: item.status,
      last_seen_utc: item.created_at,
      source: "SQLITE_INCIDENTS",
      attack_type: item.attack_type ?? null,
      predicted_attack_category: item.attack_type ?? null,
      attack_category_confidence: null,
    };
  }

  export async function refreshLiveData() {
    if (demoEnabled) {
      dataState = "DEMO";
      errorMessage = null;
      alerts = DEMO_ALERTS;
      lastUpdatedAt = new Date().toISOString();
      return;
    }

    if (liveStatus === null && alerts.length === 0) {
      dataState = "LOADING";
    }
    errorMessage = null;

    try {
      const [statusResp, liveAlertsResp, incidentsResp] = await Promise.all([
        fetchLiveStatus(),
        fetchLiveAlerts(50),
        fetchIncidents({ limit: 50 }),
      ]);
      liveStatus = statusResp;
      const liveRows = (liveAlertsResp.items ?? []).map(mapLiveAlert);
      const persistedRows = (incidentsResp.items ?? []).map(mapIncident);
      alerts = liveRows.length > 0 ? liveRows : persistedRows;
      lastUpdatedAt = new Date().toISOString();

      if (statusResp.last_error) {
        dataState = "ERROR";
        errorMessage = statusResp.last_error;
      } else if (!statusResp.running && alerts.length === 0) {
        dataState = "DISCONNECTED";
      } else if (alerts.length === 0 && (statusResp.metrics?.events_processed ?? 0) === 0) {
        dataState = "EMPTY";
      } else {
        dataState = "CONNECTED";
      }
    } catch (err) {
      dataState = "ERROR";
      errorMessage = err instanceof Error ? err.message : String(err);
      liveStatus = null;
      alerts = [];
    }
  }

  async function handleStartLive() {
    if (demoEnabled) return;
    actionBusy = true;
    errorMessage = null;
    try {
      liveStatus = await startLiveTelemetry({ host: "127.0.0.1", port: 0, demo_heuristics: false });
      await refreshLiveData();
    } catch (err) {
      dataState = "ERROR";
      errorMessage = err instanceof Error ? err.message : String(err);
    } finally {
      actionBusy = false;
    }
  }

  async function handleStopLive() {
    if (demoEnabled) return;
    actionBusy = true;
    errorMessage = null;
    try {
      liveStatus = await stopLiveTelemetry();
      await refreshLiveData();
    } catch (err) {
      dataState = "ERROR";
      errorMessage = err instanceof Error ? err.message : String(err);
    } finally {
      actionBusy = false;
    }
  }

  function toggleDemoMode() {
    demoEnabled = !demoEnabled;
    void refreshLiveData();
  }

  onMount(() => {
    void refreshLiveData();
    if (pollIntervalMs > 0) {
      pollTimer = setInterval(() => {
        void refreshLiveData();
      }, pollIntervalMs);
    }
  });

  onDestroy(() => {
    if (pollTimer !== null) {
      clearInterval(pollTimer);
      pollTimer = null;
    }
  });

  $: isCollectorLive = Boolean(!demoEnabled && liveStatus?.running && liveStatus?.mode === "LIVE");
  $: throughputDisplay = demoEnabled
    ? "1,250.0 flow/s (DEMO)"
    : liveStatus?.running && liveStatus?.pipeline?.throughput_events_per_sec != null
      ? `${Number(liveStatus.pipeline.throughput_events_per_sec).toFixed(1)} flow/s`
      : "N/A";
  $: latencyDisplay = demoEnabled
    ? "0.42 ms (DEMO)"
    : liveStatus?.metrics?.avg_inference_latency_us != null &&
        (liveStatus.metrics.events_processed ?? 0) > 0
      ? `${(Number(liveStatus.metrics.avg_inference_latency_us) / 1000).toFixed(3)} ms`
      : "N/A";
  $: queueUtilDisplay = demoEnabled
    ? "4.0% (DEMO)"
    : liveStatus?.running && liveStatus?.pipeline?.queue_utilization_pct != null
      ? `${Number(liveStatus.pipeline.queue_utilization_pct).toFixed(2)}%`
      : "N/A";
  $: queueCapDisplay = liveStatus?.collector?.queue_capacity
    ? `Capacity: ${Number(liveStatus.collector.queue_capacity).toLocaleString()} events`
    : "Collector offline";
  $: aiReadinessDisplay = demoEnabled
    ? "DEMO (Simulated)"
    : liveStatus?.inference
      ? `${liveStatus.inference.ready_count ?? 0}/4 (${liveStatus.inference.inference_mode ?? "UNKNOWN"})`
      : "UNAVAILABLE";
  $: droppedEventsCount =
    (liveStatus?.collector?.events_dropped ?? 0) + (liveStatus?.pipeline?.total_dropped ?? 0);
  $: filteredAlerts = alerts.filter(
    (a) => filterSeverity === "ALL" || a.risk_level === filterSeverity
  );
  $: effectivePageSize = Math.max(1, pageSize);
  $: totalPages = Math.max(1, Math.ceil(filteredAlerts.length / effectivePageSize));
  $: if (currentPage > totalPages) currentPage = totalPages;
  $: pagedAlerts = filteredAlerts.slice(
    (currentPage - 1) * effectivePageSize,
    currentPage * effectivePageSize
  );
</script>

<div class="panel-container">
  <div class="panel-header">
    <div class="title-row">
      <div>
        <h2>Live Telemetry & Real-Time Alert Monitoring</h2>
        <p class="subtitle">
          UDP NetFlow/IPFIX collector, bounded ring buffer, 4-model inference dispatch, and risk-engine alerts.
        </p>
      </div>
      <div class="controls-row">
        <span class="badge state-badge state-{dataState.toLowerCase()}">
          STATE: {dataState}
        </span>
        <span class="badge {isCollectorLive ? 'badge-live' : 'badge-idle'}">
          {isCollectorLive ? `LIVE :${liveStatus?.bound_port ?? "?"}` : demoEnabled ? "DEMO PREVIEW" : "COLLECTOR STOPPED"}
        </span>
        <button type="button" class="btn-ctl" on:click={handleStartLive} disabled={actionBusy || isCollectorLive || demoEnabled}>
          Start UDP Collector
        </button>
        <button type="button" class="btn-ctl btn-stop" on:click={handleStopLive} disabled={actionBusy || !isCollectorLive || demoEnabled}>
          Stop
        </button>
        <button type="button" class="btn-ctl" on:click={refreshLiveData} disabled={actionBusy}>
          Refresh
        </button>
        <button type="button" class="btn-ctl btn-demo" on:click={toggleDemoMode}>
          {demoEnabled ? "Exit Demo" : "Demo Mode"}
        </button>
      </div>
    </div>
    <div class="meta-strip">
      <span>Last updated: <code>{lastUpdatedAt ?? "Never"}</code></span>
      <span>AI Readiness: <code>{aiReadinessDisplay}</code></span>
      <span>Decoded flows: <code>{liveStatus?.collector?.flows_decoded ?? 0}</code></span>
      <span>Malformed packets: <code>{liveStatus?.collector?.decoder?.malformed_packet_count ?? 0}</code></span>
      <span class:dropped-warning={droppedEventsCount > 0} data-testid="dropped-events-counter">
        Dropped events: <code>{droppedEventsCount}</code>
      </span>
    </div>
  </div>

  {#if dataState === "LOADING"}
    <div class="state-banner banner-loading">Loading live telemetry status from backend...</div>
  {:else if dataState === "DEMO"}
    <div class="state-banner banner-demo">DEMO MODE ACTIVE — Showing synthetic preview data. Exit Demo for real backend telemetry.</div>
  {:else if dataState === "ERROR"}
    <div class="state-banner banner-error">Backend telemetry error: {errorMessage ?? "Unknown error"}</div>
  {:else if dataState === "DISCONNECTED"}
    <div class="state-banner banner-disconnected">UDP collector is currently stopped (DISCONNECTED). Click "Start UDP Collector" to receive NetFlow/IPFIX packets.</div>
  {:else if dataState === "EMPTY"}
    <div class="state-banner banner-empty">Collector is listening on UDP port {liveStatus?.bound_port ?? "?"}, awaiting incoming NetFlow/IPFIX packets (0 events processed).</div>
  {/if}

  <div class="metrics-grid">
    <div class="metric-card">
      <span class="label">Ingestion Throughput</span>
      <span class="value">{throughputDisplay}</span>
      <span class="sub">Streaming Event Pipeline</span>
    </div>
    <div class="metric-card">
      <span class="label">Average Inference Latency</span>
      <span class="value">{latencyDisplay}</span>
      <span class="sub">{aiReadinessDisplay}</span>
    </div>
    <div class="metric-card">
      <span class="label">Ring Buffer Utilization</span>
      <span class="value">{queueUtilDisplay}</span>
      <span class="sub">{queueCapDisplay}</span>
    </div>
    <div class="metric-card">
      <span class="label">Active Security Alerts</span>
      <span class="value alert-count">{alerts.length}</span>
      <span class="sub">Events processed: {liveStatus?.metrics?.events_processed ?? 0}</span>
    </div>
  </div>

  <div class="filter-bar">
    <label for="filter">Filter Severity:</label>
    <select
      id="filter"
      bind:value={filterSeverity}
      on:change={() => {
        currentPage = 1;
      }}
    >
      <option value="ALL">All Severities</option>
      <option value="CRITICAL">Critical (Risk &gt;= 85)</option>
      <option value="HIGH">High (Risk &gt;= 70)</option>
      <option value="MEDIUM">Medium (Risk &gt;= 30)</option>
    </select>
    {#if filteredAlerts.length > effectivePageSize}
      <div class="pagination-controls" data-testid="alerts-pagination">
        <span class="page-info">
          Showing {(currentPage - 1) * effectivePageSize + 1}–{Math.min(
            currentPage * effectivePageSize,
            filteredAlerts.length
          )} of {filteredAlerts.length} (Page {currentPage}/{totalPages})
        </span>
        <button
          type="button"
          class="btn-ctl"
          disabled={currentPage <= 1}
          on:click={() => {
            currentPage = Math.max(1, currentPage - 1);
          }}
        >
          Prev
        </button>
        <button
          type="button"
          class="btn-ctl"
          disabled={currentPage >= totalPages}
          on:click={() => {
            currentPage = Math.min(totalPages, currentPage + 1);
          }}
        >
          Next
        </button>
      </div>
    {/if}
  </div>

  <div class="table-container">
    <table class="alert-table">
      <thead>
        <tr>
          <th>Alert ID</th>
          <th>Entity / Host</th>
          <th>Risk Score</th>
          <th>Severity</th>
          <th>Trigger Reason</th>
          <th>Source</th>
          <th>Last Seen (UTC)</th>
        </tr>
      </thead>
      <tbody>
        {#each pagedAlerts as alert (alert.alert_id)}
          <tr class="row-{alert.risk_level.toLowerCase()}">
            <td><code>{alert.alert_id}</code></td>
            <td><strong>{alert.entity_id}</strong></td>
            <td><span class="score-pill">{alert.risk_score.toFixed(1)}</span></td>
            <td><span class="badge badge-{alert.risk_level.toLowerCase()}">{alert.risk_level}</span></td>
            <td>
              {alert.trigger_reason}
              {#if alert.attack_type || alert.predicted_attack_category}
                <span class="status-tag">
                  {alert.predicted_attack_category ?? alert.attack_type}{#if alert.attack_category_confidence != null} ({(alert.attack_category_confidence * 100).toFixed(0)}%){/if}
                </span>
              {/if}
            </td>
            <td><span class="status-tag">{alert.source}</span></td>
            <td>{alert.last_seen_utc}</td>
          </tr>
        {/each}
        {#if filteredAlerts.length === 0}
          <tr>
            <td colspan="7" class="empty-state">No alerts recorded for the current state/filter.</td>
          </tr>
        {/if}
      </tbody>
    </table>
  </div>
</div>

<style>
  .panel-container { padding: 1.5rem; background: #0f172a; color: #f8fafc; border-radius: 8px; }
  .panel-header { margin-bottom: 1.25rem; border-bottom: 1px solid #1e293b; padding-bottom: 1rem; }
  .title-row { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; flex-wrap: wrap; }
  .controls-row { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
  .meta-strip { display: flex; gap: 1.5rem; flex-wrap: wrap; font-size: 0.75rem; color: #94a3b8; margin-top: 0.75rem; }
  .dropped-warning { color: #fca5a5; font-weight: 700; }
  .dropped-warning code { background: #7f1d1d; color: #fecaca; padding: 0.1rem 0.35rem; border-radius: 4px; }
  h2 { margin: 0; font-size: 1.25rem; font-weight: 700; color: #38bdf8; }
  .subtitle { color: #94a3b8; font-size: 0.875rem; margin-top: 0.25rem; }
  .btn-ctl { background: #1e293b; color: #e2e8f0; border: 1px solid #334155; padding: 0.35rem 0.75rem; border-radius: 4px; font-size: 0.75rem; cursor: pointer; font-weight: 600; }
  .btn-ctl:disabled { opacity: 0.45; cursor: not-allowed; }
  .btn-stop { border-color: #7f1d1d; color: #fca5a5; }
  .btn-demo { border-color: #854d0e; color: #fde047; }
  .badge { padding: 0.25rem 0.65rem; border-radius: 9999px; font-size: 0.72rem; font-weight: 700; }
  .badge-live { background: #065f46; color: #34d399; border: 1px solid #059669; }
  .badge-idle { background: #334155; color: #94a3b8; }
  .state-connected { background: #064e3b; color: #6ee7b7; }
  .state-loading { background: #1e3a8a; color: #93c5fd; }
  .state-disconnected, .state-empty { background: #334155; color: #cbd5e1; }
  .state-error { background: #7f1d1d; color: #fca5a5; }
  .state-demo { background: #713f12; color: #fde047; }
  .state-banner { padding: 0.75rem 1rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.85rem; font-weight: 600; }
  .banner-loading { background: #1e3a8a; color: #bfdbfe; }
  .banner-demo { background: #713f12; color: #fef08a; }
  .banner-error { background: #7f1d1d; color: #fecaca; }
  .banner-disconnected, .banner-empty { background: #1e293b; color: #cbd5e1; border: 1px solid #334155; }
  .badge-critical { background: #7f1d1d; color: #fca5a5; }
  .badge-high { background: #7c2d12; color: #fdba74; }
  .badge-medium { background: #713f12; color: #fde047; }
  .metrics-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.5rem; }
  .metric-card { background: #1e293b; padding: 1rem; border-radius: 6px; display: flex; flex-direction: column; }
  .metric-card .label { font-size: 0.75rem; color: #94a3b8; }
  .metric-card .value { font-size: 1.35rem; font-weight: 700; color: #f8fafc; margin: 0.25rem 0; }
  .metric-card .sub { font-size: 0.7rem; color: #64748b; }
  .alert-count { color: #f87171; }
  .filter-bar { margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; font-size: 0.875rem; color: #cbd5e1; }
  .pagination-controls { display: flex; align-items: center; gap: 0.5rem; margin-left: auto; font-size: 0.78rem; color: #94a3b8; }
  select { background: #1e293b; color: #f8fafc; border: 1px solid #334155; padding: 0.25rem 0.5rem; border-radius: 4px; }
  .table-container { overflow-x: auto; }
  .alert-table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; }
  th { background: #1e293b; padding: 0.75rem; color: #94a3b8; font-weight: 600; border-bottom: 1px solid #334155; }
  td { padding: 0.75rem; border-bottom: 1px solid #1e293b; }
  .score-pill { font-weight: 700; color: #f43f5e; }
  .status-tag { background: #334155; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.72rem; }
  .empty-state { text-align: center; color: #64748b; padding: 2rem; }
</style>
