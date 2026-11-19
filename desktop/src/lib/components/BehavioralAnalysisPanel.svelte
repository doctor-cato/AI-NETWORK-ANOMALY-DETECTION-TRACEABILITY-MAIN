<script lang="ts">
  import { onMount } from "svelte";
  import {
    fetchBehavioralCorrelation,
    fetchBehavioralSimilarity,
    fetchBehavioralVectorDetail,
    fetchBehavioralVectors,
  } from "../api";
  import type {
    BehavioralCorrelationClusterItem,
    BehavioralSimilarityResponse,
    BehavioralVectorDetailResponse,
    BehavioralVectorListItem,
    PanelDataState,
  } from "../types";

  export let initialDemoMode: boolean = false;
  export let initialSelectedDetail: BehavioralVectorDetailResponse | null = null;

  const DEMO_DIMENSIONS = [
    { index: 0, name: "log_duration", value: 0.42 },
    { index: 1, name: "log_bytes_in", value: 0.25 },
    { index: 2, name: "log_bytes_out", value: 0.68 },
    { index: 3, name: "bytes_ratio_clipped", value: 0.35 },
    { index: 4, name: "log_pkts_in", value: 0.18 },
    { index: 5, name: "log_pkts_out", value: 0.39 },
    { index: 6, name: "pkts_ratio_clipped", value: 0.21 },
    { index: 7, name: "unique_ports_norm", value: 0.08 },
    { index: 8, name: "unique_protocols_norm", value: 0.05 },
    { index: 9, name: "syn_flag_ratio", value: 0.12 },
    { index: 10, name: "rst_flag_ratio", value: 0.01 },
    { index: 11, name: "dns_intensity", value: 0.0 },
    { index: 12, name: "http_intensity", value: 0.0 },
    { index: 13, name: "auth_failure_ratio", value: 0.0 },
    { index: 14, name: "log_mean_iat", value: 0.19 },
    { index: 15, name: "log_std_iat", value: 0.04 },
  ];

  let dataState: PanelDataState = initialDemoMode
    ? "DEMO"
    : initialSelectedDetail !== null
      ? "CONNECTED"
      : "LOADING";
  let errorMessage: string | null = null;
  let demoEnabled = initialDemoMode;
  let vectors: BehavioralVectorListItem[] = [];
  let selectedVectorId: string = initialSelectedDetail?.vector_id ?? "";
  let compareVectorId: string = "";
  let selectedDetail: BehavioralVectorDetailResponse | null = initialSelectedDetail;
  let similarity: BehavioralSimilarityResponse | null = null;
  let clusters: BehavioralCorrelationClusterItem[] = [];
  let correlationVectorsCount = 0;
  let lastUpdatedAt: string | null = null;

  export async function loadBehavioralData() {
    if (demoEnabled) {
      dataState = "DEMO";
      errorMessage = null;
      lastUpdatedAt = new Date().toISOString();
      return;
    }

    dataState = "LOADING";
    errorMessage = null;

    try {
      const listResp = await fetchBehavioralVectors({ limit: 50 });
      vectors = listResp.items ?? [];
      lastUpdatedAt = new Date().toISOString();

      if (listResp.data_status === "DISCONNECTED") {
        dataState = "DISCONNECTED";
        selectedDetail = null;
        similarity = null;
        clusters = [];
        return;
      }

      if (vectors.length === 0 || listResp.data_status === "EMPTY") {
        dataState = "EMPTY";
        selectedDetail = null;
        similarity = null;
        clusters = [];
        return;
      }

      if (!selectedVectorId || !vectors.some((v) => v.vector_id === selectedVectorId)) {
        selectedVectorId = vectors[0].vector_id;
      }
      if (
        !compareVectorId ||
        !vectors.some((v) => v.vector_id === compareVectorId) ||
        (vectors.length > 1 && compareVectorId === selectedVectorId)
      ) {
        compareVectorId = vectors.length > 1 ? vectors[1].vector_id : vectors[0].vector_id;
      }

      const [detailResp, corrResp] = await Promise.all([
        fetchBehavioralVectorDetail(selectedVectorId),
        fetchBehavioralCorrelation({ matchThreshold: 0.85, limit: 20 }),
      ]);
      selectedDetail = detailResp;
      clusters = corrResp.clusters ?? [];
      correlationVectorsCount = corrResp.total_vectors_evaluated ?? 0;

      if (selectedVectorId && compareVectorId && vectors.length >= 2) {
        similarity = await fetchBehavioralSimilarity(selectedVectorId, compareVectorId);
      } else {
        similarity = null;
      }
      dataState = "CONNECTED";
    } catch (err) {
      dataState = "ERROR";
      errorMessage = err instanceof Error ? err.message : String(err);
      selectedDetail = null;
      similarity = null;
      clusters = [];
    }
  }

  async function onSelectionChange() {
    if (demoEnabled || !selectedVectorId) return;
    try {
      selectedDetail = await fetchBehavioralVectorDetail(selectedVectorId);
      if (compareVectorId) {
        similarity = await fetchBehavioralSimilarity(selectedVectorId, compareVectorId);
      }
      dataState = "CONNECTED";
    } catch (err) {
      dataState = "ERROR";
      errorMessage = err instanceof Error ? err.message : String(err);
    }
  }

  function toggleDemoMode() {
    demoEnabled = !demoEnabled;
    void loadBehavioralData();
  }

  onMount(() => {
    void loadBehavioralData();
  });

  $: dimensions = demoEnabled
    ? DEMO_DIMENSIONS
    : selectedDetail
      ? selectedDetail.features.map((val, idx) => ({
          index: idx,
          name: selectedDetail?.feature_names?.[idx] ?? `dim_${idx}`,
          value: val,
        }))
      : [];
</script>

<div class="panel-container">
  <div class="panel-header">
    <div class="title-row">
      <div>
        <h2>16-Dimensional Behavioral Intelligence &amp; Vector Profiling</h2>
        <p class="subtitle">
          Encrypted-at-rest 16-D behavioral vectors decrypted on demand, similarity metrics, and IP-independent session correlation.
        </p>
      </div>
      <div class="controls-row">
        <span class="badge state-badge state-{dataState.toLowerCase()}">STATE: {dataState}</span>
        <span class="badge badge-crypto">
          {#if demoEnabled}
            DEMO PREVIEW
          {:else if selectedDetail?.is_encrypted_at_rest}
            AES-256-GCM ENCRYPTED AT REST
          {:else}
            NO VECTOR LOADED
          {/if}
        </span>
        <button type="button" class="btn-ctl" on:click={loadBehavioralData}>Refresh</button>
        <button type="button" class="btn-ctl btn-demo" on:click={toggleDemoMode}>
          {demoEnabled ? "Exit Demo" : "Demo Mode"}
        </button>
      </div>
    </div>
    <div class="meta-strip">
      <span>Last updated: <code>{lastUpdatedAt ?? "Never"}</code></span>
      <span>Stored vectors: <code>{demoEnabled ? 2 : vectors.length}</code></span>
      <span>Correlated clusters: <code>{demoEnabled ? 1 : clusters.length}</code></span>
    </div>
  </div>

  {#if dataState === "LOADING"}
    <div class="state-banner banner-loading">Loading persisted behavioral vectors from backend...</div>
  {:else if dataState === "DEMO"}
    <div class="state-banner banner-demo">DEMO MODE ACTIVE — Displaying synthetic 16-D preview data. Exit Demo for real backend vectors.</div>
  {:else if dataState === "ERROR"}
    <div class="state-banner banner-error">Failed loading behavioral intelligence: {errorMessage ?? "Unknown error"}</div>
  {:else if dataState === "DISCONNECTED"}
    <div class="state-banner banner-disconnected">Behavioral vector database is disconnected (no persistent SQLite store attached).</div>
  {:else if dataState === "EMPTY"}
    <div class="state-banner banner-empty">No behavioral vectors persisted yet. Start Live Telemetry or ingest flows to generate 16-D session vectors.</div>
  {/if}

  {#if demoEnabled || selectedDetail}
    <div class="selector-bar">
      {#if !demoEnabled && vectors.length > 0}
        <label>
          Primary Vector:
          <select bind:value={selectedVectorId} on:change={onSelectionChange}>
            {#each vectors as v}
              <option value={v.vector_id}>{v.vector_id} ({v.entity_id})</option>
            {/each}
          </select>
        </label>
        <label>
          Compare With:
          <select bind:value={compareVectorId} on:change={onSelectionChange}>
            {#each vectors as v}
              <option value={v.vector_id}>{v.vector_id} ({v.entity_id})</option>
            {/each}
          </select>
        </label>
      {/if}
    </div>

    <div class="info-card">
      <div class="info-item">
        <span class="label">Entity ID:</span>
        <span class="val"><code>{demoEnabled ? "host:192.0.2.10 (DEMO)" : selectedDetail?.entity_id}</code></span>
      </div>
      <div class="info-item">
        <span class="label">Vector &amp; Key ID:</span>
        <span class="val">
          <code>{demoEnabled ? "bv-demo-01" : selectedDetail?.vector_id}</code>
          ({demoEnabled ? "k-demo-1" : selectedDetail?.key_id ?? "N/A"})
        </span>
      </div>
      <div class="info-item">
        <span class="label">Vector SHA-256 Digest:</span>
        <span class="val">
          <code class="hash">
            {demoEnabled
              ? "DEMO_DIGEST_NOT_REAL"
              : selectedDetail?.sha256_hash
                ? `${selectedDetail.sha256_hash.substring(0, 32)}...`
                : "N/A"}
          </code>
        </span>
      </div>
    </div>

    <h3>Normalized 16-D Feature Space (BehavioralVectorBuilder)</h3>
    <div class="vector-bars-grid">
      {#each dimensions as dim}
        <div class="dim-row">
          <span class="dim-name">{dim.name}</span>
          <div class="bar-track">
            <div class="bar-fill" style="width: {Math.min(100, Math.max(0, dim.value * 100))}%"></div>
          </div>
          <span class="dim-val">{dim.value.toFixed(3)}</span>
        </div>
      {/each}
    </div>

    <div class="comparison-section">
      <h3>Entity Baseline Profile (EntityBaselineProfiler)</h3>
      {#if demoEnabled}
        <div class="comp-card">
          <div class="comp-metrics">
            <div class="metric">
              <span class="m-label">Baseline Samples (DEMO):</span>
              <span class="m-val">8 / 50</span>
            </div>
            <div class="metric">
              <span class="m-label">Cosine Similarity vs Centroid (DEMO):</span>
              <span class="m-val">0.9410</span>
            </div>
            <div class="metric">
              <span class="m-label">Deviation Score (DEMO):</span>
              <span class="m-val">0.0590</span>
            </div>
          </div>
        </div>
      {:else if selectedDetail?.baseline_profile}
        <div class="comp-card" data-testid="entity-baseline-card">
          <div class="comp-row">
            <span>Entity Key: <strong><code>{selectedDetail.baseline_profile.entity_key}</code></strong></span>
            <span>
              Baseline Status:
              <strong>
                {selectedDetail.baseline_profile.has_baseline
                  ? `ACTIVE (${selectedDetail.baseline_profile.sample_count}/${selectedDetail.baseline_profile.window_size ?? 50} prior vectors)`
                  : "NO PRIOR BASELINE (first vector for entity)"}
              </strong>
            </span>
          </div>
          <div class="comp-metrics">
            <div class="metric">
              <span class="m-label">Cosine Similarity vs Entity Centroid:</span>
              <span class="m-val">{selectedDetail.baseline_profile.cosine_similarity.toFixed(4)}</span>
            </div>
            <div class="metric">
              <span class="m-label">Baseline Deviation Score (1 - cos):</span>
              <span class="m-val">{selectedDetail.baseline_profile.deviation_score.toFixed(4)}</span>
            </div>
          </div>
        </div>
      {:else}
        <div class="state-banner banner-empty">No EntityBaselineProfiler profile available for this vector dimension.</div>
      {/if}
    </div>

    <div class="comparison-section">
      <h3>Behavioral Similarity &amp; IPSpoofingSessionCorrelator</h3>
      {#if demoEnabled}
        <div class="comp-card">
          <div class="comp-metrics">
            <div class="metric">
              <span class="m-label">Cosine Similarity (DEMO):</span>
              <span class="m-val">0.892</span>
            </div>
            <div class="metric">
              <span class="m-label">Euclidean Distance (DEMO):</span>
              <span class="m-val">0.464</span>
            </div>
          </div>
        </div>
      {:else if similarity}
        <div class="comp-card">
          <div class="comp-row">
            <span>Vector A: <strong><code>{similarity.vector_a}</code></strong></span>
            <span>Vector B: <strong><code>{similarity.vector_b}</code></strong></span>
          </div>
          <div class="comp-metrics">
            <div class="metric">
              <span class="m-label">Cosine Similarity:</span>
              <span class="m-val">{similarity.cosine_similarity ?? "N/A"}</span>
            </div>
            <div class="metric">
              <span class="m-label">Euclidean Distance:</span>
              <span class="m-val">{similarity.euclidean_distance ?? "N/A"}</span>
            </div>
            <div class="metric">
              <span class="m-label">Manhattan Distance:</span>
              <span class="m-val">{similarity.manhattan_distance ?? "N/A"}</span>
            </div>
            <div class="metric">
              <span class="m-label">Interpretation:</span>
              <span class="m-val">{similarity.interpretation ?? "N/A"}</span>
            </div>
          </div>
        </div>
      {:else}
        <div class="state-banner banner-empty">At least 2 stored behavioral vectors are needed for pairwise similarity comparison.</div>
      {/if}

      {#if !demoEnabled && clusters.length > 0}
        <div class="comp-card" style="margin-top: 0.75rem;">
          <div class="comp-row">
            <span>Evaluated Vectors: <strong>{correlationVectorsCount}</strong></span>
            <span>Detected Correlation Clusters: <strong>{clusters.length}</strong></span>
          </div>
          {#each clusters as cl}
            <div class="cluster-row">
              <code>{cl.cluster_id}</code>
              <span>Members: {cl.member_vector_ids.length}</span>
              <span>Avg Similarity: <strong>{cl.average_similarity.toFixed(4)}</strong></span>
              <span>Observed IPs: <code>{cl.ip_addresses_observed.join(", ") || "N/A"}</code></span>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .panel-container { padding: 1.5rem; background: #0f172a; color: #f8fafc; border-radius: 8px; }
  .panel-header { margin-bottom: 1.25rem; border-bottom: 1px solid #1e293b; padding-bottom: 1rem; }
  .title-row { display: flex; justify-content: space-between; align-items: flex-start; gap: 1rem; flex-wrap: wrap; }
  .controls-row { display: flex; align-items: center; gap: 0.5rem; flex-wrap: wrap; }
  .meta-strip { display: flex; gap: 1.5rem; flex-wrap: wrap; font-size: 0.75rem; color: #94a3b8; margin-top: 0.75rem; }
  h2 { margin: 0; font-size: 1.25rem; font-weight: 700; color: #a855f7; }
  h3 { font-size: 1rem; color: #cbd5e1; margin: 1.5rem 0 0.75rem; }
  .subtitle { color: #94a3b8; font-size: 0.875rem; margin-top: 0.25rem; }
  .btn-ctl { background: #1e293b; color: #e2e8f0; border: 1px solid #334155; padding: 0.35rem 0.75rem; border-radius: 4px; font-size: 0.75rem; cursor: pointer; font-weight: 600; }
  .btn-demo { border-color: #854d0e; color: #fde047; }
  .badge { padding: 0.25rem 0.65rem; border-radius: 9999px; font-size: 0.72rem; font-weight: 700; }
  .badge-crypto { background: #581c87; color: #d8b4fe; border: 1px solid #7e22ce; }
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
  .selector-bar { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1rem; font-size: 0.8rem; color: #cbd5e1; }
  select { background: #1e293b; color: #f8fafc; border: 1px solid #334155; padding: 0.25rem 0.5rem; border-radius: 4px; margin-left: 0.4rem; }
  .info-card { background: #1e293b; padding: 1rem; border-radius: 6px; display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem; font-size: 0.85rem; }
  .info-item .label { color: #94a3b8; display: block; margin-bottom: 0.25rem; }
  .info-item .val { color: #f8fafc; font-weight: 600; }
  .hash { color: #38bdf8; font-size: 0.75rem; }
  .vector-bars-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 0.75rem 1.5rem; background: #1e293b; padding: 1rem; border-radius: 6px; }
  .dim-row { display: flex; align-items: center; gap: 0.75rem; font-size: 0.8rem; }
  .dim-name { width: 180px; color: #94a3b8; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .bar-track { flex: 1; height: 8px; background: #334155; border-radius: 4px; overflow: hidden; }
  .bar-fill { height: 100%; background: #c084fc; border-radius: 4px; }
  .dim-val { width: 48px; text-align: right; color: #f8fafc; font-family: monospace; }
  .comp-card { background: #1e293b; padding: 1rem; border-radius: 6px; }
  .comp-row { display: flex; justify-content: space-between; font-size: 0.85rem; margin-bottom: 1rem; color: #cbd5e1; flex-wrap: wrap; gap: 0.5rem; }
  .comp-metrics { display: flex; gap: 2rem; flex-wrap: wrap; }
  .metric { display: flex; flex-direction: column; }
  .m-label { font-size: 0.75rem; color: #94a3b8; }
  .m-val { font-size: 1.05rem; font-weight: 700; color: #f8fafc; }
  .cluster-row { display: flex; gap: 1.25rem; flex-wrap: wrap; font-size: 0.8rem; padding: 0.4rem 0; border-top: 1px solid #334155; }
</style>
