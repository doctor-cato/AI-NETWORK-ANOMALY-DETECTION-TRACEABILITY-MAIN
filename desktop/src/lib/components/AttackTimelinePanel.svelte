<script lang="ts">
  interface TimelineStage {
    stage_name: string;
    stage_order: number;
    description: string;
    timestamp: string;
    entity: string;
    tactic_id: string;
    is_observed: boolean;
    confidence: number;
  }

  let stages: TimelineStage[] = [
    {
      stage_order: 1,
      stage_name: "RECONNAISSANCE",
      description: "Port scan and network sweep targeting Apache web service on port 80",
      timestamp: "2026-11-17T10:00:05Z",
      entity: "host:192.168.1.105",
      tactic_id: "TA0043 (Nmap Reconnaissance)",
      is_observed: true,
      confidence: 1.0,
    },
    {
      stage_order: 2,
      stage_name: "INITIAL_ACCESS",
      description: "Remote code execution attempt via HTTP POST to /api/upload.action",
      timestamp: "2026-11-17T10:00:10Z",
      entity: "host:192.168.1.105 -> host:192.168.1.10",
      tactic_id: "TA0001 (Apache Struts2 Exploit)",
      is_observed: true,
      confidence: 0.95,
    },
    {
      stage_order: 3,
      stage_name: "LATERAL_MOVEMENT",
      description: "SSH credential reuse attempt from compromised web server to intranet host",
      timestamp: "2026-11-17T10:00:15Z",
      entity: "host:192.168.1.10 -> host:192.168.1.20",
      tactic_id: "TA0008 (Lateral SSH Movement)",
      is_observed: false,
      confidence: 0.85,
    },
    {
      stage_order: 4,
      stage_name: "EXFILTRATION",
      description: "Critical volumetric data exfiltration over port 445 SMB to external IP 198.51.100.5",
      timestamp: "2026-11-17T10:00:20Z",
      entity: "host:192.168.1.10 -> host:198.51.100.5",
      tactic_id: "TA0010 (Exfiltration Over C2 Channel)",
      is_observed: true,
      confidence: 1.0,
    },
  ];

  let exportStatus = "";
  let reportHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

  function exportInvestigationReport() {
    exportStatus = "Report exported successfully to /reports/investigations/incident_001.json";
    reportHash = "a71d95b0826f1474249ce6a25a246b90db981879b0e707bfc4e4fbe7b646dc06";
  }
</script>

<div class="panel-container">
  <div class="panel-header">
    <div class="title-row">
      <h2>Attack Timeline Reconstruction & Threat Provenance</h2>
      <button class="btn-export" on:click={exportInvestigationReport}>
        Export Investigation Report
      </button>
    </div>
    <p class="subtitle">
      Multi-stage ATT&CK progression linking observed network flows with application and host events.
    </p>
  </div>

  {#if exportStatus}
    <div class="status-banner">
      <span>{exportStatus}</span>
      <span class="hash-tag">SHA-256: <code>{reportHash.substring(0, 24)}...</code></span>
    </div>
  {/if}

  <div class="timeline-container">
    {#each stages as stage}
      <div class="timeline-item">
        <div class="step-indicator">
          <div class="step-circle">{stage.stage_order}</div>
          <div class="step-line"></div>
        </div>
        <div class="stage-content">
          <div class="stage-header">
            <span class="stage-title">{stage.stage_name}</span>
            <span class="badge {stage.is_observed ? 'badge-observed' : 'badge-inferred'}">
              {stage.is_observed ? "OBSERVED TELEMETRY" : "INFERRED HYPOTHESIS"}
            </span>
            <span class="tactic">{stage.tactic_id}</span>
            <span class="timestamp">{stage.timestamp}</span>
          </div>
          <p class="desc">{stage.description}</p>
          <div class="meta-row">
            <span>Entity: <code>{stage.entity}</code></span>
            <span>Confidence: <strong>{(stage.confidence * 100).toFixed(0)}%</strong></span>
          </div>
        </div>
      </div>
    {/each}
  </div>
</div>

<style>
  .panel-container { padding: 1.5rem; background: #0f172a; color: #f8fafc; border-radius: 8px; }
  .panel-header { margin-bottom: 1.5rem; border-bottom: 1px solid #1e293b; padding-bottom: 1rem; }
  .title-row { display: flex; justify-content: space-between; align-items: center; }
  h2 { margin: 0; font-size: 1.25rem; font-weight: 700; color: #f43f5e; }
  .subtitle { color: #94a3b8; font-size: 0.875rem; margin-top: 0.25rem; }
  .btn-export { background: #e11d48; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; font-weight: 600; cursor: pointer; }
  .btn-export:hover { background: #be123c; }
  .status-banner { background: #064e3b; color: #6ee7b7; padding: 0.75rem; border-radius: 6px; margin-bottom: 1.5rem; font-size: 0.85rem; display: flex; justify-content: space-between; }
  .timeline-container { display: flex; flex-direction: column; gap: 1rem; }
  .timeline-item { display: flex; gap: 1.5rem; }
  .step-indicator { display: flex; flex-direction: column; align-items: center; }
  .step-circle { width: 32px; height: 32px; border-radius: 50%; background: #e11d48; color: white; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 0.85rem; }
  .step-line { width: 2px; flex: 1; background: #334155; margin-top: 0.25rem; }
  .stage-content { flex: 1; background: #1e293b; padding: 1rem; border-radius: 6px; margin-bottom: 0.5rem; }
  .stage-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; }
  .stage-title { font-weight: 700; color: #f8fafc; font-size: 0.95rem; }
  .tactic { color: #38bdf8; font-size: 0.75rem; }
  .timestamp { margin-left: auto; color: #64748b; font-size: 0.75rem; }
  .desc { font-size: 0.85rem; color: #cbd5e1; margin: 0 0 0.5rem; }
  .meta-row { display: flex; gap: 2rem; font-size: 0.75rem; color: #94a3b8; }
  .badge { padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 700; }
  .badge-observed { background: #065f46; color: #34d399; }
  .badge-inferred { background: #713f12; color: #fde047; }
</style>
