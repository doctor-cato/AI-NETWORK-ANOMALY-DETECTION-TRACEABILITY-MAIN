<script lang="ts">
  import { onMount } from "svelte";
  import { fetchTraceTimeline, generateInvestigationReport } from "../api";
  import type { PanelDataState, TimelineStageItem } from "../types";

  export let initialDemoMode: boolean = false;
  export let initialStages: TimelineStageRow[] | null = null;
  export let initialCampaign: string = "";

  interface TimelineStageRow {
    stage_order: number;
    stage_name: string;
    description: string;
    timestamp: string;
    entity: string;
    tactic_id: string;
    is_observed: boolean;
    confidence: number;
    evidence_ids: string[];
  }

  const DEMO_STAGES: TimelineStageRow[] = [
    {
      stage_order: 1,
      stage_name: "RECONNAISSANCE",
      description: "[DEMO] Port sweep targeting HTTP service",
      timestamp: "2026-11-17T10:00:05Z",
      entity: "host:192.0.2.10 -> host:192.0.2.20",
      tactic_id: "TA0043",
      is_observed: true,
      confidence: 0.95,
      evidence_ids: ["demo-ev-1"],
    },
    {
      stage_order: 2,
      stage_name: "LATERAL_MOVEMENT",
      description: "[DEMO] Inferred lateral movement hypothesis",
      timestamp: "2026-11-17T10:01:05Z",
      entity: "host:192.0.2.20 -> host:192.0.2.30",
      tactic_id: "TA0008",
      is_observed: false,
      confidence: 0.72,
      evidence_ids: [],
    },
  ];

  let dataState: PanelDataState = initialDemoMode
    ? "DEMO"
    : initialStages !== null
      ? initialStages.length > 0
        ? "CONNECTED"
        : "EMPTY"
      : "LOADING";
  let errorMessage: string | null = null;
  let demoEnabled = initialDemoMode;
  let availableCampaigns: string[] = initialDemoMode
    ? ["DEMO-CAMPAIGN-01"]
    : initialCampaign
      ? [initialCampaign]
      : [];
  let selectedCampaign: string = initialDemoMode ? "DEMO-CAMPAIGN-01" : initialCampaign;
  let stages: TimelineStageRow[] = initialDemoMode ? DEMO_STAGES : (initialStages ?? []);
  let overallConfidence: number | null = initialDemoMode ? 0.84 : null;
  let exportStatus: string = "";
  let exportError: string | null = null;
  let reportHash: string | null = null;
  let exportedMarkdown: string | null = null;
  let isExporting = false;
  let lastUpdatedAt: string | null = null;

  function mapStages(items: TimelineStageItem[]): TimelineStageRow[] {
    return items.map((s, idx) => ({
      stage_order: idx + 1,
      stage_name: s.phase,
      description: s.description || s.title,
      timestamp: s.timestamp,
      entity: `${s.source_entity} -> ${s.target_entity}`,
      tactic_id: s.indicators.length > 0 ? s.indicators[0] : s.title,
      is_observed: s.is_observed,
      confidence: s.confidence,
      evidence_ids: s.evidence_ids ?? [],
    }));
  }

  export async function loadTimeline(campaign?: string) {
    if (demoEnabled) {
      dataState = "DEMO";
      errorMessage = null;
      stages = DEMO_STAGES;
      availableCampaigns = ["DEMO-CAMPAIGN-01"];
      selectedCampaign = "DEMO-CAMPAIGN-01";
      overallConfidence = 0.84;
      lastUpdatedAt = new Date().toISOString();
      return;
    }

    dataState = "LOADING";
    errorMessage = null;

    try {
      const resp = await fetchTraceTimeline(campaign || undefined);
      availableCampaigns = resp.available_campaigns ?? [];
      if (!selectedCampaign && availableCampaigns.length > 0) {
        selectedCampaign = availableCampaigns[0];
      } else if (resp.campaign_name && resp.campaign_name !== "ALL") {
        selectedCampaign = resp.campaign_name;
      }
      stages = mapStages(resp.stages ?? []);
      overallConfidence = stages.length > 0 ? resp.overall_confidence : null;
      lastUpdatedAt = new Date().toISOString();

      if (resp.data_status === "DISCONNECTED") {
        dataState = "DISCONNECTED";
      } else if (stages.length === 0 || resp.data_status === "EMPTY") {
        dataState = "EMPTY";
      } else {
        dataState = "CONNECTED";
      }
    } catch (err) {
      dataState = "ERROR";
      errorMessage = err instanceof Error ? err.message : String(err);
      stages = [];
      overallConfidence = null;
    }
  }

  async function exportInvestigationReport() {
    if (demoEnabled) {
      exportError = "Exit Demo Mode before generating a real investigation report from the backend.";
      exportStatus = "";
      return;
    }
    if (stages.length === 0) {
      exportError = "Cannot export investigation report: no real timeline stages exist.";
      exportStatus = "";
      return;
    }

    try {
      isExporting = true;
      exportError = null;
      exportStatus = "";
      const incidentId = selectedCampaign || "incident-live-trace";
      const res = await generateInvestigationReport({
        incident_id: incidentId,
        title: `Investigation Report: ${incidentId}`,
        severity: "HIGH",
        root_cause_summary: `Reconstructed from ${stages.length} trace stage(s) via TraceEngine.`,
      });
      reportHash = res.artifact_hash;
      exportedMarkdown = res.markdown_content;
      exportStatus = `Report ${res.report_id} generated and verified by backend.`;
    } catch (err) {
      reportHash = null;
      exportedMarkdown = null;
      exportStatus = "";
      exportError = err instanceof Error ? err.message : String(err);
    } finally {
      isExporting = false;
    }
  }

  function toggleDemoMode() {
    demoEnabled = !demoEnabled;
    exportError = null;
    exportStatus = "";
    reportHash = null;
    exportedMarkdown = null;
    void loadTimeline(selectedCampaign);
  }

  onMount(() => {
    void loadTimeline();
  });

  $: observedStages = stages.filter((s) => s.is_observed);
  $: inferredStages = stages.filter((s) => !s.is_observed);
</script>

<div class="panel-container">
  <div class="panel-header">
    <div class="title-row">
      <div>
        <h2>Attack Timeline Reconstruction &amp; Threat Provenance</h2>
        <p class="subtitle">
          Multi-stage ATT&amp;CK progression separating observed telemetry from inferred relationships.
        </p>
      </div>
      <div class="controls-row">
        <span class="badge state-badge state-{dataState.toLowerCase()}">STATE: {dataState}</span>
        <button type="button" class="btn-ctl" on:click={() => loadTimeline(selectedCampaign)}>Refresh</button>
        <button type="button" class="btn-ctl btn-demo" on:click={toggleDemoMode}>
          {demoEnabled ? "Exit Demo" : "Demo Mode"}
        </button>
        <button
          type="button"
          class="btn-export"
          on:click={exportInvestigationReport}
          disabled={isExporting || demoEnabled || stages.length === 0}
        >
          {isExporting ? "Exporting..." : "Export Investigation Report"}
        </button>
      </div>
    </div>
    <div class="meta-strip">
      <span>Last updated: <code>{lastUpdatedAt ?? "Never"}</code></span>
      <span>Observed stages: <code>{observedStages.length}</code></span>
      <span>Inferred hypotheses: <code>{inferredStages.length}</code></span>
      <span>Overall confidence: <code>{overallConfidence !== null ? `${(overallConfidence * 100).toFixed(1)}%` : "N/A"}</code></span>
      {#if availableCampaigns.length > 0 && !demoEnabled}
        <label>
          Incident / Campaign:
          <select bind:value={selectedCampaign} on:change={() => loadTimeline(selectedCampaign)}>
            {#each availableCampaigns as camp}
              <option value={camp}>{camp}</option>
            {/each}
          </select>
        </label>
      {/if}
    </div>
  </div>

  {#if dataState === "LOADING"}
    <div class="state-banner banner-loading">Loading attack timeline from Trace Engine...</div>
  {:else if dataState === "DEMO"}
    <div class="state-banner banner-demo">DEMO MODE ACTIVE — Showing synthetic preview timeline. Exit Demo for real backend trace data.</div>
  {:else if dataState === "ERROR"}
    <div class="state-banner banner-error">Failed loading trace timeline: {errorMessage ?? "Unknown error"}</div>
  {:else if dataState === "DISCONNECTED"}
    <div class="state-banner banner-disconnected">Trace backend is disconnected.</div>
  {:else if dataState === "EMPTY"}
    <div class="state-banner banner-empty">No incidents or live telemetry events recorded yet to reconstruct an attack timeline.</div>
  {/if}

  {#if exportError}
    <div class="state-banner banner-error">Export failed: {exportError}</div>
  {:else if exportStatus && reportHash}
    <div class="status-banner">
      <span>{exportStatus}</span>
      <span class="hash-tag">SHA-256: <code>{reportHash}</code></span>
    </div>
  {/if}

  {#if stages.length > 0}
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
                {stage.is_observed ? "OBSERVED TELEMETRY" : "INFERRED RELATIONSHIP"}
              </span>
              <span class="tactic">{stage.tactic_id}</span>
              <span class="timestamp">{stage.timestamp}</span>
            </div>
            <p class="desc">{stage.description}</p>
            <div class="meta-row">
              <span>Entity: <code>{stage.entity}</code></span>
              <span>Confidence: <strong>{(stage.confidence * 100).toFixed(0)}%</strong></span>
              <span>Evidence IDs: <code>{stage.evidence_ids.length > 0 ? stage.evidence_ids.join(", ") : "None"}</code></span>
            </div>
          </div>
        </div>
      {/each}
    </div>
  {/if}

  {#if exportedMarkdown}
    <details class="report-preview" open>
      <summary>Generated Investigation Markdown Preview</summary>
      <pre>{exportedMarkdown}</pre>
    </details>
  {/if}
</div>

<style>
  .panel-container { padding: 1.5rem; background: #0f172a; color: #f8fafc; border-radius: 8px; }
  .panel-header { margin-bottom: 1.25rem; border-bottom: 1px solid #1e293b; padding-bottom: 1rem; }
  .title-row { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; flex-wrap: wrap; }
  .controls-row { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
  .meta-strip { display: flex; gap: 1.25rem; flex-wrap: wrap; font-size: 0.75rem; color: #94a3b8; margin-top: 0.75rem; align-items: center; }
  h2 { margin: 0; font-size: 1.25rem; font-weight: 700; color: #f43f5e; }
  .subtitle { color: #94a3b8; font-size: 0.875rem; margin-top: 0.25rem; }
  .btn-ctl { background: #1e293b; color: #e2e8f0; border: 1px solid #334155; padding: 0.35rem 0.75rem; border-radius: 4px; font-size: 0.75rem; cursor: pointer; font-weight: 600; }
  .btn-demo { border-color: #854d0e; color: #fde047; }
  .btn-export { background: #e11d48; color: white; border: none; padding: 0.45rem 0.9rem; border-radius: 4px; font-weight: 600; cursor: pointer; font-size: 0.78rem; }
  .btn-export:disabled { opacity: 0.45; cursor: not-allowed; }
  select { background: #1e293b; color: #f8fafc; border: 1px solid #334155; padding: 0.2rem 0.5rem; border-radius: 4px; margin-left: 0.35rem; }
  .badge { padding: 0.25rem 0.65rem; border-radius: 9999px; font-size: 0.72rem; font-weight: 700; }
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
  .status-banner { background: #064e3b; color: #6ee7b7; padding: 0.75rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.85rem; display: flex; justify-content: space-between; flex-wrap: wrap; gap: 0.5rem; }
  .timeline-container { display: flex; flex-direction: column; gap: 1rem; }
  .timeline-item { display: flex; gap: 1.5rem; }
  .step-indicator { display: flex; flex-direction: column; align-items: center; }
  .step-circle { width: 32px; height: 32px; border-radius: 50%; background: #e11d48; color: white; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 0.85rem; }
  .step-line { width: 2px; flex: 1; background: #334155; margin-top: 0.25rem; }
  .stage-content { flex: 1; background: #1e293b; padding: 1rem; border-radius: 6px; margin-bottom: 0.5rem; }
  .stage-header { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.5rem; flex-wrap: wrap; }
  .stage-title { font-weight: 700; color: #f8fafc; font-size: 0.95rem; }
  .tactic { color: #38bdf8; font-size: 0.75rem; }
  .timestamp { margin-left: auto; color: #64748b; font-size: 0.75rem; }
  .desc { font-size: 0.85rem; color: #cbd5e1; margin: 0 0 0.5rem; }
  .meta-row { display: flex; gap: 1.5rem; font-size: 0.75rem; color: #94a3b8; flex-wrap: wrap; }
  .badge-observed { background: #065f46; color: #34d399; }
  .badge-inferred { background: #713f12; color: #fde047; }
  .report-preview { margin-top: 1rem; background: #1e293b; padding: 0.75rem 1rem; border-radius: 6px; }
  .report-preview pre { white-space: pre-wrap; font-size: 0.78rem; color: #cbd5e1; margin-top: 0.5rem; }
</style>
