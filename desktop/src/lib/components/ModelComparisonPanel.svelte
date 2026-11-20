<script lang="ts">
  import { onMount } from "svelte";
  import { getModelBenchmarkReport } from "../api";
  import type {
    BenchmarkSplitMetricsItem,
    CsvAnalyzeResponse,
    CsvEvaluateResponse,
    ModelBenchmarkReportResponse,
    ModelStatusItem,
  } from "../types";
  import { getModelGovernanceInfo, shortDigest } from "../utils";
  import Icons from "./Icons.svelte";

  interface Props {
    models: ModelStatusItem[];
    selectedModel: string;
    analysesByModel: Record<string, CsvAnalyzeResponse>;
    evaluationsByModel: Record<string, CsvEvaluateResponse>;
    errorsByModel?: Record<string, string>;
    batchFileSha256?: string | null;
    batchLabelsSha256?: string | null;
    benchmarkReport?: ModelBenchmarkReportResponse | null;
    canRunComparison: boolean;
    hasLabelsPath: boolean;
    busy: boolean;
    onSelectModel: (modelKey: string) => void;
    onRunAllComparison: () => void;
    onEvaluateAllAnalyzed: () => void;
  }

  let {
    models,
    selectedModel,
    analysesByModel,
    evaluationsByModel,
    errorsByModel = {},
    batchFileSha256 = null,
    batchLabelsSha256 = null,
    benchmarkReport = undefined,
    canRunComparison,
    hasLabelsPath,
    busy,
    onSelectModel,
    onRunAllComparison,
    onEvaluateAllAnalyzed,
  }: Props = $props();

  let readyModelsCount = $derived(models.filter((m) => m.ready).length);
  let analyzedCount = $derived(
    models.filter((m) => m.ready && Boolean(analysesByModel[m.model_key])).length,
  );

  let fetchedBenchmark = $state<ModelBenchmarkReportResponse | null>(null);
  let benchmarkLoading = $state(false);
  let benchmarkError = $state<string | null>(null);

  let activeBenchmark = $derived(
    fetchedBenchmark ?? (benchmarkReport !== undefined ? benchmarkReport : null),
  );

  export async function refreshBenchmarkReport() {
    benchmarkLoading = true;
    benchmarkError = null;
    try {
      fetchedBenchmark = await getModelBenchmarkReport();
    } catch (err) {
      benchmarkError = err instanceof Error ? err.message : String(err);
    } finally {
      benchmarkLoading = false;
    }
  }

  onMount(() => {
    if (benchmarkReport === undefined) {
      void refreshBenchmarkReport();
    }
  });

  function fmtPct(v: number | null | undefined): string {
    return typeof v === "number" && Number.isFinite(v)
      ? `${(v * 100).toFixed(2)}%`
      : "—";
  }

  function fmtMetric(v: number | null | undefined, digits = 4): string {
    return typeof v === "number" && Number.isFinite(v) ? v.toFixed(digits) : "—";
  }

  function fmtThreshold(v: number | null | undefined): string {
    if (v === null || v === undefined || !Number.isFinite(v)) return "N/A";
    return Math.abs(v) >= 1000 ? v.toFixed(2) : v.toFixed(4);
  }

  function formatCrossSourceSummary(cs: BenchmarkSplitMetricsItem): string {
    const parts = [`F1 ${fmtPct(cs.f1)}`, `FPR ${fmtPct(cs.fpr)}`];
    if (typeof cs.roc_auc === "number" && Number.isFinite(cs.roc_auc)) {
      parts.push(`ROC ${cs.roc_auc.toFixed(4)}`);
    }
    return parts.join(" · ");
  }
</script>

<section class="card" aria-labelledby="compare-heading" style="margin-bottom: 14px;">
  <div class="card-header">
    <div>
      <h2 id="compare-heading" class="card-title">
        <Icons name="target" size={17} />
        So sánh 4 Mô hình Trên Cùng Batch CSV (Coverage / OOD / Metrics)
      </h2>
      {#if batchFileSha256 || batchLabelsSha256}
        <div class="batch-digests">
          {#if batchFileSha256}
            <span class="badge badge-info mono" title={batchFileSha256}>
              CSV SHA-256: {shortDigest(batchFileSha256)}
            </span>
          {/if}
          {#if batchLabelsSha256}
            <span class="badge badge-info mono" title={batchLabelsSha256}>
              Labels SHA-256: {shortDigest(batchLabelsSha256)}
            </span>
          {/if}
        </div>
      {/if}
    </div>
    <div style="display: flex; flex-wrap: wrap; gap: 8px;">
      <button
        type="button"
        class="btn btn-primary btn-sm"
        disabled={!canRunComparison || readyModelsCount === 0 || busy}
        onclick={onRunAllComparison}
      >
        <Icons name="play" size={14} />
        Chạy So sánh {readyModelsCount} Model READY
      </button>
      <button
        type="button"
        class="btn btn-sm"
        disabled={analyzedCount === 0 || !hasLabelsPath || busy}
        onclick={onEvaluateAllAnalyzed}
      >
        <Icons name="target" size={14} />
        Đối chiếu Ground Truth ({analyzedCount} đã chạy)
      </button>
    </div>
  </div>

  <div class="table-scroll">
    <table class="data-table">
      <thead>
        <tr>
          <th>Mô hình</th>
          <th>Trạng thái</th>
          <th>Ngữ nghĩa điểm</th>
          <th>Ngưỡng (Frozen)</th>
          <th>Attack / Benign</th>
          <th>Coverage (OOD)</th>
          <th>Precision</th>
          <th>Recall</th>
          <th>F1</th>
          <th>FPR</th>
          <th>CM (TP / FP / TN / FN)</th>
        </tr>
      </thead>
      <tbody>
        {#each models as m (m.model_key)}
          {@const az = analysesByModel[m.model_key]}
          {@const ev = evaluationsByModel[m.model_key]}
          {@const err = errorsByModel[m.model_key]}
          {@const isSelected = selectedModel === m.model_key}
          {@const gov = getModelGovernanceInfo(m.model_key)}
          <tr
            class="clickable-row"
            class:disabled-row={!m.ready || busy}
            class:row-selected={isSelected}
            onclick={() => !busy && m.ready && onSelectModel(m.model_key)}
          >
            <td>
              <strong>{m.display_name}</strong>
              {#if isSelected}
                <span class="badge badge-info" style="margin-left: 6px;">Đang xem</span>
              {/if}
              <span
                class="badge"
                class:badge-info={gov.tier === "MODEL_VALIDATED"}
                class:badge-warning={gov.tier === "RESEARCH_ONLY"}
                style="margin-left: 6px;"
                title={gov.explanation}
              >
                {gov.tier === "MODEL_VALIDATED" ? "Validated" : "Research"}
              </span>
            </td>
            <td>
              {#if m.ready}
                <span class="badge badge-benign">READY</span>
              {:else}
                <span class="badge badge-blocked" title={m.reason ?? "Blocked"}>BLOCKED</span>
              {/if}
              {#if err}
                <span class="badge badge-attack" title={err} style="margin-left: 6px;">LỖI API</span>
              {/if}
            </td>
            <td class="mono" style="font-size: 12px;">
              {m.score_semantics === "attack_probability"
                ? "attack_probability [0..1]"
                : m.score_semantics ?? "raw_anomaly_score"}
            </td>
            <td class="mono">{fmtThreshold(az?.decision_threshold ?? m.decision_threshold)}</td>
            <td class="mono">
              {#if az}
                <span style="color: var(--semantic-attack)">{az.attack_count}</span>
                /
                <span style="color: var(--semantic-benign)">{az.benign_count}</span>
              {:else if err}
                <span class="model-error-text" title={err}>{err}</span>
              {:else}
                Chưa chạy
              {/if}
            </td>
            <td class="mono">
              {#if az}
                {@const cov =
                  az.prediction_coverage ??
                  (az.total_rows > 0
                    ? (az.attack_count + az.benign_count) / az.total_rows
                    : 0)}
                {(cov * 100).toFixed(1)}% ({az.abstained_rows ?? az.ood_flagged_count} OOD)
              {:else}
                —
              {/if}
            </td>
            <td class="mono">{fmtPct(ev?.precision)}</td>
            <td class="mono">{fmtPct(ev?.recall)}</td>
            <td class="mono">{fmtPct(ev?.f1)}</td>
            <td class="mono">{fmtPct(ev?.false_positive_rate)}</td>
            <td class="mono">
              {#if ev}
                {ev.confusion_matrix.tp} / {ev.confusion_matrix.fp} / {ev.confusion_matrix.tn} / {ev.confusion_matrix.fn}
              {:else if az && err}
                <span class="model-error-text" title={err}>{err}</span>
              {:else}
                —
              {/if}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
</section>

<section
  class="card"
  aria-labelledby="official-benchmark-heading"
  data-testid="official-benchmark-section"
  style="margin-bottom: 14px;"
>
  <div class="card-header">
    <div>
      <h3 id="official-benchmark-heading" class="card-title">
        <Icons name="chart" size={17} />
        Báo cáo Benchmark Chính thức (AIT-NDS-v2 Test &amp; Cross-Source CTU/UWF)
      </h3>
      <div class="benchmark-meta-row">
        {#if activeBenchmark?.evaluation_partition}
          <span class="badge badge-info mono">Split: {activeBenchmark.evaluation_partition}</span>
        {/if}
        {#if activeBenchmark?.dataset_provenance}
          <span class="badge badge-blocked">{activeBenchmark.dataset_provenance}</span>
        {/if}
        {#if activeBenchmark?.sources_loaded?.length}
          <span class="badge badge-benign mono">
            Sources: {activeBenchmark.sources_loaded.join(", ")}
          </span>
        {/if}
        {#if activeBenchmark?.data_status}
          <span
            class="badge"
            class:badge-benign={activeBenchmark.data_status === "CONNECTED"}
            class:badge-warning={activeBenchmark.data_status !== "CONNECTED"}
          >
            {activeBenchmark.data_status}
          </span>
        {/if}
      </div>
    </div>
    <button
      type="button"
      class="btn btn-sm"
      disabled={benchmarkLoading}
      onclick={() => void refreshBenchmarkReport()}
    >
      <Icons name="refresh" size={14} spin={benchmarkLoading} />
      {benchmarkLoading ? "Đang tải..." : "Làm mới Benchmark"}
    </button>
  </div>

  {#if benchmarkError}
    <div class="banner banner-warning" role="status" style="margin-bottom: 10px;">
      <Icons name="alert" size={16} />
      <div>
        <strong>Không nạp được Báo cáo Benchmark Chính thức:</strong> {benchmarkError}. Tính năng so sánh CSV batch phía trên vẫn hoạt động bình thường.
      </div>
    </div>
  {/if}

  {#if benchmarkLoading && !activeBenchmark}
    <div class="banner banner-info" role="status">
      <Icons name="refresh" size={16} spin={true} />
      <span>Đang tải báo cáo benchmark chính thức từ backend...</span>
    </div>
  {:else if !activeBenchmark || activeBenchmark.data_status === "EMPTY" || activeBenchmark.models.length === 0}
    <div class="banner banner-info" role="status" data-testid="benchmark-empty-banner">
      <Icons name="alert" size={16} />
      <span>
        Chưa có dữ liệu Báo cáo Benchmark Chính thức (trạng thái: {activeBenchmark?.data_status ?? "EMPTY"}). Vui lòng kiểm tra artifact trong <code>reports/experiments/ml/</code>.
      </span>
    </div>
  {:else}
    <div class="table-scroll">
      <table class="data-table">
        <thead>
          <tr>
            <th>Mô hình</th>
            <th>Deployment Tier</th>
            <th>AIT-Test ROC-AUC</th>
            <th>PR-AUC</th>
            <th>AIT-Test F1</th>
            <th>AIT-Test FPR</th>
            <th>Cross-Source Zero-Shot (CTU-Echo, CTU-Win7AD, UWF-ZeekData24)</th>
            <th>Top Features (tree_feature_importances / validation_permutation_importance)</th>
          </tr>
        </thead>
        <tbody>
          {#each activeBenchmark.models as entry (entry.model_key)}
            <tr>
              <td>
                <strong>{entry.display_name}</strong>
                <div class="benchmark-sub mono">
                  {entry.model_type} · Ngưỡng: {fmtThreshold(entry.decision_threshold)}
                  {#if entry.threshold_source}
                    ({entry.threshold_source})
                  {/if}
                </div>
              </td>
              <td>
                <span
                  class="badge"
                  class:badge-warning={entry.deployment_tier === "RESEARCH_ONLY"}
                  class:badge-info={entry.deployment_tier !== "RESEARCH_ONLY"}
                >
                  {entry.deployment_tier}
                </span>
              </td>
              <td class="mono">{fmtMetric(entry.in_domain?.roc_auc)}</td>
              <td class="mono">{fmtMetric(entry.in_domain?.pr_auc)}</td>
              <td class="mono">{fmtPct(entry.in_domain?.f1)}</td>
              <td class="mono">{fmtPct(entry.in_domain?.fpr)}</td>
              <td>
                {#if entry.cross_source.length === 0}
                  <span class="mono">—</span>
                {:else}
                  <div class="cross-source-list">
                    {#each entry.cross_source as cs (cs.dataset)}
                      <div class="cross-source-item mono">
                        <strong>{cs.dataset}:</strong> {formatCrossSourceSummary(cs)}
                      </div>
                    {/each}
                  </div>
                {/if}
              </td>
              <td>
                {#if entry.top_features.length === 0}
                  <span class="mono">—</span>
                {:else}
                  <div class="feature-list">
                    {#each entry.top_features.slice(0, 5) as feat (feat.feature)}
                      <div class="feature-item mono">
                        <span>{feat.feature}</span>
                        <span class="feature-val">{feat.importance.toFixed(4)}</span>
                        {#if feat.method}
                          <span class="badge badge-blocked">{feat.method}</span>
                        {/if}
                      </div>
                    {/each}
                  </div>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>

    {#if activeBenchmark.limitations.length > 0}
      <div class="limitations-box">
        <strong>Giới hạn khoa học (Limitations):</strong>
        <ul>
          {#each activeBenchmark.limitations as lim, idx (idx)}
            <li>{lim}</li>
          {/each}
        </ul>
      </div>
    {/if}
  {/if}
</section>

<style>
  .batch-digests {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 6px;
  }

  .benchmark-meta-row {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 6px;
  }

  .benchmark-sub {
    font-size: 11.5px;
    color: var(--text-secondary);
    margin-top: 2px;
  }

  .cross-source-list,
  .feature-list {
    display: flex;
    flex-direction: column;
    gap: 4px;
    white-space: normal;
  }

  .cross-source-item,
  .feature-item {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 6px;
    font-size: 11.5px;
    line-height: 1.35;
  }

  .feature-val {
    color: var(--accent-primary);
    font-weight: 600;
  }

  .limitations-box {
    margin-top: 10px;
    padding: 10px 12px;
    border-radius: 8px;
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    font-size: 12px;
    color: var(--text-secondary);
  }

  .limitations-box ul {
    margin: 6px 0 0;
    padding-left: 18px;
  }

  .limitations-box li {
    margin-bottom: 3px;
  }

  .model-error-text {
    display: inline-block;
    max-width: 240px;
    white-space: normal;
    color: var(--semantic-attack);
    font-size: 11.5px;
    line-height: 1.35;
  }

  .clickable-row {
    cursor: pointer;
  }

  .disabled-row {
    cursor: not-allowed;
    opacity: 0.72;
  }

  .row-selected {
    background: var(--accent-primary-soft);
  }
</style>
