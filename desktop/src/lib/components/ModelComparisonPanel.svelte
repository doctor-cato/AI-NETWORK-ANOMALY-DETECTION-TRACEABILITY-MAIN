<script lang="ts">
  import type {
    CsvAnalyzeResponse,
    CsvEvaluateResponse,
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

  function fmtPct(v: number | undefined): string {
    return typeof v === "number" && Number.isFinite(v)
      ? `${(v * 100).toFixed(2)}%`
      : "—";
  }

  function fmtThreshold(v: number | null): string {
    if (v === null || !Number.isFinite(v)) return "N/A";
    return Math.abs(v) >= 1000 ? v.toFixed(2) : v.toFixed(4);
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

<style>
  .batch-digests {
    display: flex;
    flex-wrap: wrap;
    gap: 6px;
    margin-top: 6px;
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
