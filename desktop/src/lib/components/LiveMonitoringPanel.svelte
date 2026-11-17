<script lang="ts">
  import { onMount } from "svelte";

  export let isLiveActive: boolean = false;

  interface LiveAlert {
    alert_id: string;
    entity_id: string;
    risk_score: number;
    risk_level: string;
    trigger_reason: string;
    status: string;
    last_seen_utc: string;
  }

  let alerts: LiveAlert[] = [
    {
      alert_id: "alert-98ab42c1ef01",
      entity_id: "host:192.168.1.10",
      risk_score: 86.5,
      risk_level: "CRITICAL",
      trigger_reason: "High Data Exfiltration Volume (> 50KB) on sensitive port 445",
      status: "NEW",
      last_seen_utc: new Date().toISOString(),
    },
    {
      alert_id: "alert-71bc54d2a133",
      entity_id: "host:192.168.1.105",
      risk_score: 72.0,
      risk_level: "HIGH",
      trigger_reason: "Apache Struts2 Web Exploit Pattern Detected",
      status: "INVESTIGATING",
      last_seen_utc: new Date().toISOString(),
    },
  ];

  let throughput = 12450;
  let avgLatencyMs = 12.4;
  let queueUtilization = 8.5;
  let filterSeverity = "ALL";

  $: filteredAlerts = alerts.filter(
    (a) => filterSeverity === "ALL" || a.risk_level === filterSeverity
  );
</script>

<div class="panel-container">
  <div class="panel-header">
    <div class="title-row">
      <h2>Live Telemetry & Real-Time Alert Monitoring</h2>
      <span class="badge {isLiveActive ? 'badge-live' : 'badge-idle'}">
        {isLiveActive ? "LIVE STREAMING ACTIVE" : "REPLAY / STANDBY"}
      </span>
    </div>
    <p class="subtitle">
      Streaming ring buffer, 4-model inference dispatch, and deduplicated multi-criteria security alerts.
    </p>
  </div>

  <div class="metrics-grid">
    <div class="metric-card">
      <span class="label">Ingestion Throughput</span>
      <span class="value">{throughput.toLocaleString()} flow/s</span>
      <span class="sub">Bounded Ring Buffer</span>
    </div>
    <div class="metric-card">
      <span class="label">Average Inference Latency</span>
      <span class="value">{avgLatencyMs} ms</span>
      <span class="sub">4 AI Models (RF, XGB, IF, AE)</span>
    </div>
    <div class="metric-card">
      <span class="label">Ring Buffer Utilization</span>
      <span class="value">{queueUtilization}%</span>
      <span class="sub">Capacity: 50,000 events</span>
    </div>
    <div class="metric-card">
      <span class="label">Active Security Alerts</span>
      <span class="value alert-count">{alerts.length}</span>
      <span class="sub">Deduplicated in 60s window</span>
    </div>
  </div>

  <div class="filter-bar">
    <label for="filter">Filter Severity:</label>
    <select id="filter" bind:value={filterSeverity}>
      <option value="ALL">All Severities</option>
      <option value="CRITICAL">Critical (Risk >= 85)</option>
      <option value="HIGH">High (Risk >= 70)</option>
      <option value="MEDIUM">Medium (Risk >= 45)</option>
    </select>
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
          <th>Status</th>
          <th>Last Seen (UTC)</th>
        </tr>
      </thead>
      <tbody>
        {#each filteredAlerts as alert}
          <tr class="row-{alert.risk_level.toLowerCase()}">
            <td><code>{alert.alert_id}</code></td>
            <td><strong>{alert.entity_id}</strong></td>
            <td><span class="score-pill">{alert.risk_score.toFixed(1)}</span></td>
            <td><span class="badge badge-{alert.risk_level.toLowerCase()}">{alert.risk_level}</span></td>
            <td>{alert.trigger_reason}</td>
            <td><span class="status-tag">{alert.status}</span></td>
            <td>{new Date(alert.last_seen_utc).toLocaleTimeString()}</td>
          </tr>
        {/each}
        {#if filteredAlerts.length === 0}
          <tr>
            <td colspan="7" class="empty-state">No alerts matching the selected filter.</td>
          </tr>
        {/if}
      </tbody>
    </table>
  </div>
</div>

<style>
  .panel-container { padding: 1.5rem; background: #0f172a; color: #f8fafc; border-radius: 8px; }
  .panel-header { margin-bottom: 1.5rem; border-bottom: 1px solid #1e293b; padding-bottom: 1rem; }
  .title-row { display: flex; justify-content: space-between; align-items: center; }
  h2 { margin: 0; font-size: 1.25rem; font-weight: 700; color: #38bdf8; }
  .subtitle { color: #94a3b8; font-size: 0.875rem; margin-top: 0.25rem; }
  .badge { padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 700; }
  .badge-live { background: #065f46; color: #34d399; border: 1px solid #059669; }
  .badge-idle { background: #334155; color: #94a3b8; }
  .badge-critical { background: #7f1d1d; color: #fca5a5; }
  .badge-high { background: #7c2d12; color: #fdba74; }
  .badge-medium { background: #713f12; color: #fde047; }
  .metrics-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.5rem; }
  .metric-card { background: #1e293b; padding: 1rem; border-radius: 6px; display: flex; flex-direction: column; }
  .metric-card .label { font-size: 0.75rem; color: #94a3b8; }
  .metric-card .value { font-size: 1.5rem; font-weight: 700; color: #f8fafc; margin: 0.25rem 0; }
  .metric-card .sub { font-size: 0.7rem; color: #64748b; }
  .alert-count { color: #f87171; }
  .filter-bar { margin-bottom: 1rem; display: flex; align-items: center; gap: 0.5rem; font-size: 0.875rem; color: #cbd5e1; }
  select { background: #1e293b; color: #f8fafc; border: 1px solid #334155; padding: 0.25rem 0.5rem; border-radius: 4px; }
  .table-container { overflow-x: auto; }
  .alert-table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; }
  th { background: #1e293b; padding: 0.75rem; color: #94a3b8; font-weight: 600; border-bottom: 1px solid #334155; }
  td { padding: 0.75rem; border-bottom: 1px solid #1e293b; }
  .score-pill { font-weight: 700; color: #f43f5e; }
  .status-tag { background: #334155; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.75rem; }
  .empty-state { text-align: center; color: #64748b; padding: 2rem; }
</style>
