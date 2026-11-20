<script lang="ts">
  import { onMount } from "svelte";
  import { fetchCryptoStatus } from "../api";
  import type { CryptoStatusResponse, PanelDataState } from "../types";

  export let initialDemoMode: boolean = false;

  interface RotationRecordRow {
    rotation_id: string;
    trigger: string;
    decision: string;
    old_key_id: string;
    new_key_id: string;
    risk_score: number | null;
    timestamp: string;
    reason: string;
  }

  const DEMO_ROTATIONS: RotationRecordRow[] = [
    {
      rotation_id: "demo-rot-01",
      trigger: "ADAPTIVE_RISK",
      decision: "EXECUTED",
      old_key_id: "k-demo-v1",
      new_key_id: "k-demo-v2",
      risk_score: 88.0,
      timestamp: "2026-11-17T10:00:20Z",
      reason: "[DEMO] Adaptive rotation preview",
    },
  ];

  let dataState: PanelDataState = initialDemoMode ? "DEMO" : "LOADING";
  let errorMessage: string | null = null;
  let demoEnabled = initialDemoMode;
  let cryptoStatus: CryptoStatusResponse | null = null;
  let rotationHistory: RotationRecordRow[] = initialDemoMode ? DEMO_ROTATIONS : [];
  let lastUpdatedAt: string | null = null;

  export async function loadCryptoStatus() {
    if (demoEnabled) {
      dataState = "DEMO";
      errorMessage = null;
      rotationHistory = DEMO_ROTATIONS;
      lastUpdatedAt = new Date().toISOString();
      return;
    }

    dataState = "LOADING";
    errorMessage = null;

    try {
      const resp = await fetchCryptoStatus("general");
      cryptoStatus = resp;
      lastUpdatedAt = new Date().toISOString();

      rotationHistory = (resp.recent_rotations ?? []).map((r, idx) => ({
        rotation_id: r.rotation_id || `rot-${idx}`,
        trigger: r.trigger,
        decision: r.decision,
        old_key_id: r.old_key_id ?? "N/A",
        new_key_id: r.new_key_id ?? "N/A",
        risk_score: r.risk_score ?? null,
        timestamp: r.timestamp || "N/A",
        reason: r.reason || "",
      }));

      if (resp.data_status === "ERROR" || resp.storage_protection_status?.error) {
        dataState = "ERROR";
        errorMessage = resp.storage_protection_status?.error ?? "Key storage error";
      } else if (resp.data_status === "DISCONNECTED") {
        dataState = "DISCONNECTED";
      } else {
        dataState = "CONNECTED";
      }
    } catch (err) {
      dataState = "ERROR";
      errorMessage = err instanceof Error ? err.message : String(err);
      cryptoStatus = null;
      rotationHistory = [];
    }
  }

  function toggleDemoMode() {
    demoEnabled = !demoEnabled;
    void loadCryptoStatus();
  }

  onMount(() => {
    void loadCryptoStatus();
  });

  $: protectionMode = demoEnabled
    ? "DEMO_PREVIEW"
    : cryptoStatus?.storage_protection_status?.master_key_protection ?? "UNKNOWN";
  $: aclStatus = demoEnabled
    ? "N/A"
    : cryptoStatus?.storage_protection_status?.acl_hardening ?? "N/A";
  $: limitations = demoEnabled
    ? []
    : cryptoStatus?.storage_protection_status?.limitations ?? [];
</script>

<div class="panel-container">
  <div class="panel-header">
    <div class="title-row">
      <div>
        <h2>Adaptive Cryptography &amp; Key Lifecycle Governance</h2>
        <p class="subtitle">
          AES-256-GCM key lifecycle, DPAPI/POSIX master key storage protection, and fixed/adaptive key rotation audit trail.
        </p>
      </div>
      <div class="controls-row">
        <span class="badge state-badge state-{dataState.toLowerCase()}">STATE: {dataState}</span>
        <span class="badge badge-shield">{protectionMode}</span>
        <button type="button" class="btn-ctl" on:click={loadCryptoStatus}>Refresh</button>
        <button type="button" class="btn-ctl btn-demo" on:click={toggleDemoMode}>
          {demoEnabled ? "Exit Demo" : "Demo Mode"}
        </button>
      </div>
    </div>
    <div class="meta-strip">
      <span>Last updated: <code>{lastUpdatedAt ?? "Never"}</code></span>
      <span>ACL hardening: <code>{aclStatus}</code></span>
      <span>Total keys: <code>{demoEnabled ? 2 : cryptoStatus?.total_rotations ?? 0}</code></span>
    </div>
  </div>

  {#if dataState === "LOADING"}
    <div class="state-banner banner-loading">Loading key lifecycle and storage protection status...</div>
  {:else if dataState === "DEMO"}
    <div class="state-banner banner-demo">DEMO MODE ACTIVE — Showing synthetic preview rotation data. Exit Demo for real KeyManager state.</div>
  {:else if dataState === "ERROR"}
    <div class="state-banner banner-error">Keystore error (fail-closed): {errorMessage ?? "Unknown error"}</div>
  {:else if dataState === "DISCONNECTED"}
    <div class="state-banner banner-disconnected">Cryptographic backend disconnected.</div>
  {/if}

  {#if limitations.length > 0}
    <div class="state-banner banner-warning">
      Storage protection notice: {limitations.join(" | ")}
    </div>
  {/if}

  <div class="crypto-status-grid">
    <div class="status-box">
      <span class="box-label">Active Key Identifier</span>
      <span class="box-value"><code>{demoEnabled ? "k-demo-v2" : cryptoStatus?.active_key_id ?? "N/A"}</code></span>
      <span class="box-desc">
        Public File Fingerprint: {demoEnabled ? "DEMO" : cryptoStatus?.master_key_fingerprint ?? "N/A"}
      </span>
    </div>
    <div class="status-box">
      <span class="box-label">Authenticated Algorithm</span>
      <span class="box-value algo-text">
        {demoEnabled ? "AES-256-GCM (DEMO)" : cryptoStatus?.algorithm ?? "N/A"}
      </span>
      <span class="box-desc">
        DEK Wrapping: {cryptoStatus?.storage_protection_status?.dek_wrapping?.format ?? "N/A"}
      </span>
    </div>
    <div class="status-box">
      <span class="box-label">Rotation Policy Safeguards</span>
      <span class="box-value">
        Cooldown: {cryptoStatus?.cooldown_seconds ?? "N/A"}s
      </span>
      <span class="box-desc">
        Rate Limit: {cryptoStatus?.rotations_this_hour ?? 0}/{cryptoStatus?.max_rotations_per_hour ?? 10} per hour | Fixed {cryptoStatus?.rotation_interval_minutes ?? 30}m | Adaptive &ge; {cryptoStatus?.adaptive_risk_threshold ?? 85}
      </span>
    </div>
    <div class="status-box">
      <span class="box-label">Records Encrypted &amp; Nonces</span>
      <span class="box-value">
        {demoEnabled ? "N/A" : cryptoStatus?.total_records_encrypted ?? "N/A"}
      </span>
      <span class="box-desc">
        Nonce registry entries: {cryptoStatus?.storage_protection_status?.nonce_registry_entries ?? "N/A"}
      </span>
    </div>
  </div>

  <h3>Key Rotation Audit Trail</h3>
  <div class="table-container">
    <table class="rot-table">
      <thead>
        <tr>
          <th>Rotation ID</th>
          <th>Trigger Policy</th>
          <th>Decision</th>
          <th>Prior Key ID</th>
          <th>New Key ID</th>
          <th>Risk Score</th>
          <th>Timestamp (UTC)</th>
        </tr>
      </thead>
      <tbody>
        {#each rotationHistory as rot}
          <tr>
            <td><code>{rot.rotation_id}</code></td>
            <td>
              <span class="badge {rot.trigger.includes('ADAPTIVE') ? 'badge-adaptive' : 'badge-fixed'}">
                {rot.trigger}
              </span>
            </td>
            <td><span class="badge badge-success">{rot.decision}</span></td>
            <td><code>{rot.old_key_id}</code></td>
            <td><code>{rot.new_key_id}</code></td>
            <td>{rot.risk_score !== null ? rot.risk_score.toFixed(1) : "N/A"}</td>
            <td>{rot.timestamp}</td>
          </tr>
        {/each}
        {#if rotationHistory.length === 0}
          <tr>
            <td colspan="7" class="empty-state">No key rotation audit records recorded yet (EMPTY).</td>
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
  h2 { margin: 0; font-size: 1.25rem; font-weight: 700; color: #10b981; }
  h3 { font-size: 1rem; color: #cbd5e1; margin: 1.5rem 0 0.75rem; }
  .subtitle { color: #94a3b8; font-size: 0.875rem; margin-top: 0.25rem; }
  .btn-ctl { background: #1e293b; color: #e2e8f0; border: 1px solid #334155; padding: 0.35rem 0.75rem; border-radius: 4px; font-size: 0.75rem; cursor: pointer; font-weight: 600; }
  .btn-demo { border-color: #854d0e; color: #fde047; }
  .badge { padding: 0.25rem 0.65rem; border-radius: 9999px; font-size: 0.72rem; font-weight: 700; }
  .badge-shield { background: #064e3b; color: #34d399; border: 1px solid #059669; }
  .state-connected { background: #064e3b; color: #6ee7b7; }
  .state-loading { background: #1e3a8a; color: #93c5fd; }
  .state-disconnected, .state-empty { background: #334155; color: #cbd5e1; }
  .state-error { background: #7f1d1d; color: #fca5a5; }
  .state-demo { background: #713f12; color: #fde047; }
  .state-banner { padding: 0.75rem 1rem; border-radius: 6px; margin-bottom: 1rem; font-size: 0.85rem; font-weight: 600; }
  .banner-loading { background: #1e3a8a; color: #bfdbfe; }
  .banner-demo { background: #713f12; color: #fef08a; }
  .banner-error { background: #7f1d1d; color: #fecaca; }
  .banner-warning { background: #78350f; color: #fde68a; }
  .banner-disconnected { background: #1e293b; color: #cbd5e1; border: 1px solid #334155; }
  .crypto-status-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin-bottom: 1.5rem; }
  .status-box { background: #1e293b; padding: 1rem; border-radius: 6px; display: flex; flex-direction: column; }
  .box-label { font-size: 0.75rem; color: #94a3b8; }
  .box-value { font-size: 1.05rem; font-weight: 700; color: #f8fafc; margin: 0.35rem 0; word-break: break-all; }
  .algo-text { font-size: 0.85rem; color: #38bdf8; }
  .box-desc { font-size: 0.7rem; color: #64748b; }
  .rot-table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; }
  th { background: #1e293b; padding: 0.75rem; color: #94a3b8; font-weight: 600; border-bottom: 1px solid #334155; }
  td { padding: 0.75rem; border-bottom: 1px solid #1e293b; }
  .badge-adaptive { background: #7f1d1d; color: #fca5a5; }
  .badge-fixed { background: #1e3a8a; color: #93c5fd; }
  .badge-success { background: #065f46; color: #34d399; }
  .empty-state { text-align: center; color: #64748b; padding: 2rem; }
</style>
