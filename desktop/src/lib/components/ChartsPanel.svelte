<script lang="ts">
  import type { CsvAnalyzeResponse } from "../types";
  import { computeRiskDistribution } from "../utils";
  import Icons from "./Icons.svelte";

  interface Props {
    analysis: CsvAnalyzeResponse;
  }

  let { analysis }: Props = $props();

  let benignPct = $derived(
    analysis.total_rows > 0 ? (analysis.benign_count / analysis.total_rows) * 100 : 0,
  );
  let attackPct = $derived(
    analysis.total_rows > 0 ? (analysis.attack_count / analysis.total_rows) * 100 : 0,
  );
  let oodPct = $derived(
    analysis.total_rows > 0 ? (analysis.ood_flagged_count / analysis.total_rows) * 100 : 0,
  );
  let riskBuckets = $derived(computeRiskDistribution(analysis.results));

  const R = 44;
  const CIRC = 2 * Math.PI * R;
  let attackStroke = $derived((attackPct / 100) * CIRC);
  let benignStroke = $derived((benignPct / 100) * CIRC);
  let oodStroke = $derived((oodPct / 100) * CIRC);

  function barColor(tone: string, label: string): string {
    if (label.startsWith("ABSTAINED") || tone === "blocked") return "var(--semantic-ood)";
    if (label.startsWith("HIGH")) return "var(--semantic-high)";
    if (tone === "attack") return "var(--semantic-attack)";
    if (tone === "warning") return "var(--semantic-warning)";
    return "var(--semantic-benign)";
  }
</script>

<section class="grid-2" aria-label="Biểu đồ phân bố phân lớp và điểm rủi ro">
  <div class="card">
    <div class="card-header">
      <h3 class="card-title">
        <Icons name="chart" size={16} />
        Phân bố Dự đoán Benign vs Attack
      </h3>
      <span class="badge badge-info">{analysis.model_type}</span>
    </div>

    <div class="donut-layout">
      <svg
        width="132"
        height="132"
        viewBox="0 0 120 120"
        role="img"
        aria-label={`Tỉ lệ Attack ${attackPct.toFixed(1)}% và Benign ${benignPct.toFixed(1)}%`}
      >
        <title>Tỉ lệ Benign ({analysis.benign_count}) vs Attack ({analysis.attack_count})</title>
        <circle cx="60" cy="60" r={R} fill="none" stroke="var(--bg-elevated)" stroke-width="16" />
        <circle
          cx="60"
          cy="60"
          r={R}
          fill="none"
          stroke="var(--semantic-benign)"
          stroke-width="16"
          stroke-dasharray={`${benignStroke} ${CIRC}`}
          transform="rotate(-90 60 60)"
        />
        <circle
          cx="60"
          cy="60"
          r={R}
          fill="none"
          stroke="var(--semantic-attack)"
          stroke-width="16"
          stroke-dasharray={`${attackStroke} ${CIRC}`}
          stroke-dashoffset={-benignStroke}
          transform="rotate(-90 60 60)"
        />
        <circle
          cx="60"
          cy="60"
          r={R}
          fill="none"
          stroke="var(--semantic-ood)"
          stroke-width="16"
          stroke-dasharray={`${oodStroke} ${CIRC}`}
          stroke-dashoffset={-(benignStroke + attackStroke)}
          transform="rotate(-90 60 60)"
        />
        <text x="60" y="56" text-anchor="middle" fill="var(--text-primary)" font-size="16" font-weight="700">
          {analysis.total_rows}
        </text>
        <text x="60" y="72" text-anchor="middle" fill="var(--text-secondary)" font-size="10">
          Flows
        </text>
      </svg>

      <div class="legend-list">
        <div class="legend-row">
          <span class="dot" style="background: var(--semantic-attack)"></span>
          <span>Attack</span>
          <strong class="mono">{analysis.attack_count} ({attackPct.toFixed(1)}%)</strong>
        </div>
        <div class="legend-row">
          <span class="dot" style="background: var(--semantic-benign)"></span>
          <span>Benign</span>
          <strong class="mono">{analysis.benign_count} ({benignPct.toFixed(1)}%)</strong>
        </div>
        <div class="legend-row">
          <span class="dot" style="background: var(--semantic-ood)"></span>
          <span>OOD Abstained (ABSTAINED_OOD)</span>
          <strong class="mono">{analysis.ood_flagged_count} ({oodPct.toFixed(1)}%)</strong>
        </div>
        <div class="semantic-note">
          {#if analysis.score_type === "attack_probability"}
            Mô hình có giám sát: hiển thị <strong>attack_probability</strong> từ {analysis.model_type}.
          {:else}
            Mô hình không giám sát: hiển thị <strong>raw_anomaly_score</strong> đối chiếu ngưỡng đông băng{" "}
            <span class="mono">{analysis.decision_threshold?.toFixed(4) ?? "N/A"}</span> (không ép xác suất).
          {/if}
        </div>
      </div>
    </div>
  </div>

  <div class="card">
    <div class="card-header">
      <h3 class="card-title">
        <Icons name="target" size={16} />
        Phân tầng Mức độ Rủi ro (Risk Priority)
      </h3>
    </div>

    <div class="bars-stack" role="img" aria-label="Biểu đồ thanh phân tầng Risk Priority">
      {#each riskBuckets as bucket (bucket.label)}
        <div class="bar-row">
          <div class="bar-label-col">{bucket.label}</div>
          <div class="bar-track">
            <div
              class="bar-fill"
              style={`width: ${Math.max(bucket.count > 0 ? 3 : 0, bucket.share * 100).toFixed(1)}%; background: ${barColor(bucket.tone, bucket.label)};`}
            ></div>
          </div>
          <div class="bar-val mono">
            {bucket.count} ({(bucket.share * 100).toFixed(1)}%)
          </div>
        </div>
      {/each}
    </div>
  </div>
</section>

<style>
  .donut-layout {
    display: flex;
    align-items: center;
    gap: 20px;
    flex-wrap: wrap;
  }

  .legend-list {
    flex: 1;
    min-width: 220px;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .legend-row {
    display: grid;
    grid-template-columns: 12px 1fr auto;
    align-items: center;
    gap: 8px;
    font-size: 13px;
  }

  .dot {
    width: 10px;
    height: 10px;
    border-radius: 3px;
  }

  .semantic-note {
    margin-top: 4px;
    padding: 8px 10px;
    border-radius: 6px;
    background: var(--bg-elevated);
    font-size: 12px;
    color: var(--text-secondary);
  }

  .bars-stack {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }

  .bar-row {
    display: grid;
    grid-template-columns: 125px 1fr 90px;
    align-items: center;
    gap: 10px;
    font-size: 12.5px;
  }

  .bar-track {
    height: 12px;
    background: var(--bg-elevated);
    border-radius: 999px;
    overflow: hidden;
    border: 1px solid var(--border-subtle);
  }

  .bar-fill {
    height: 100%;
    border-radius: 999px;
  }

  .bar-val {
    text-align: right;
    color: var(--text-secondary);
  }
</style>
