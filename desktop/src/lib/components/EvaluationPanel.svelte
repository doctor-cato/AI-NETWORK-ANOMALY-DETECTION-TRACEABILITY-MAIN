<script lang="ts">
  import type { CsvEvaluateResponse } from "../types";
  import { shortDigest } from "../utils";
  import Icons from "./Icons.svelte";

  interface Props {
    labelsPath: string;
    evaluating: boolean;
    evalResult: CsvEvaluateResponse | null;
    canEvaluate: boolean;
    onPickLabels: () => void;
    onUseDemoLabels: () => void;
    onRunEvaluate: () => void;
    onUpdateLabelsPath: (val: string) => void;
  }

  let {
    labelsPath,
    evaluating,
    evalResult,
    canEvaluate,
    onPickLabels,
    onUseDemoLabels,
    onRunEvaluate,
    onUpdateLabelsPath,
  }: Props = $props();

  function pct(val: number): string {
    return `${(val * 100).toFixed(2)}%`;
  }
</script>

<section class="card" aria-labelledby="eval-heading">
  <div class="card-header">
    <h2 id="eval-heading" class="card-title">
      <Icons name="target" size={17} />
      Đánh giá Ground Truth Tách Rời (Không Rò Rỉ Vào ML Input)
    </h2>
    <div style="display: flex; flex-wrap: wrap; gap: 8px;">
      <button type="button" class="btn btn-sm" onclick={onPickLabels}>
        <Icons name="folder" size={14} />
        Chọn file Labels CSV
      </button>
      <button type="button" class="btn btn-sm" onclick={onUseDemoLabels}>
        Dùng demo_labels.csv
      </button>
      <button
        type="button"
        class="btn btn-primary btn-sm"
        disabled={!canEvaluate || !labelsPath.trim() || evaluating}
        onclick={onRunEvaluate}
      >
        <Icons name="play" size={14} />
        {evaluating ? "Đang đối chiếu..." : "Chạy Đánh giá Ground Truth"}
      </button>
    </div>
  </div>

  <div style="margin-bottom: 12px;">
    <input
      type="text"
      class="input mono"
      style="width: 100%;"
      placeholder="Đường dẫn tới tệp Ground Truth CSV (ví dụ: data/demo/demo_labels.csv)"
      value={labelsPath}
      oninput={(e) => onUpdateLabelsPath((e.currentTarget as HTMLInputElement).value)}
      aria-label="Đường dẫn file Ground Truth CSV"
    />
  </div>

  {#if !canEvaluate}
    <div class="empty-state">
      Hãy chạy suy luận trên một tệp NetFlow CSV trước, sau đó tải tệp nhãn thực tế (Ground Truth) để tính Confusion Matrix và Accuracy/Precision/Recall/F1/FPR.
    </div>
  {:else if !evalResult}
    <div class="empty-state">
      Đã có kết quả dự đoán. Nhấn <strong>Chạy Đánh giá Ground Truth</strong> để đối chiếu theo <span class="mono">row_id</span>.
    </div>
  {:else}
    <div class="grid-5" style="margin-bottom: 14px;">
      <div class="kpi-box">
        <div class="kpi-label">Accuracy</div>
        <div class="kpi-value mono">{pct(evalResult.accuracy)}</div>
      </div>
      <div class="kpi-box">
        <div class="kpi-label">Precision (Attack)</div>
        <div class="kpi-value mono">{pct(evalResult.precision)}</div>
      </div>
      <div class="kpi-box">
        <div class="kpi-label">Recall (Detection)</div>
        <div class="kpi-value mono">{pct(evalResult.recall)}</div>
      </div>
      <div class="kpi-box">
        <div class="kpi-label">F1-Score</div>
        <div class="kpi-value mono">{pct(evalResult.f1)}</div>
      </div>
      <div class="kpi-box">
        <div class="kpi-label">False Positive Rate</div>
        <div class="kpi-value mono">{pct(evalResult.false_positive_rate)}</div>
      </div>
    </div>

    <div class="grid-2">
      <div class="card" style="background: var(--bg-elevated);">
        <div class="card-header">
          <h3 class="card-title">
            Confusion Matrix ({evalResult.matched_rows} dòng đánh giá{evalResult.abstained_rows ? `, ${evalResult.abstained_rows} dòng OOD từ chối` : ""})
          </h3>
          <span class="badge badge-info mono">SHA-256: {shortDigest(evalResult.labels_sha256)}</span>
        </div>
        <div class="cm-grid">
          <div class="cm-cell"></div>
          <div class="cm-hdr">Dự đoán Benign (0)</div>
          <div class="cm-hdr">Dự đoán Attack (1)</div>

          <div class="cm-hdr">Thực tế Benign (0)</div>
          <div class="cm-val cm-ok mono">
            <span>TN</span>
            <strong>{evalResult.confusion_matrix.tn}</strong>
          </div>
          <div class="cm-val cm-warn mono">
            <span>FP</span>
            <strong>{evalResult.confusion_matrix.fp}</strong>
          </div>

          <div class="cm-hdr">Thực tế Attack (1)</div>
          <div class="cm-val cm-warn mono">
            <span>FN</span>
            <strong>{evalResult.confusion_matrix.fn}</strong>
          </div>
          <div class="cm-val cm-ok mono">
            <span>TP</span>
            <strong>{evalResult.confusion_matrix.tp}</strong>
          </div>
        </div>
      </div>

      <div class="card" style="background: var(--bg-elevated);">
        <div class="card-header">
          <h3 class="card-title">Phân tích theo Loại Tấn công (Attack Categories)</h3>
        </div>
        {#if evalResult.attack_breakdown.length === 0}
          <p style="font-size: 13px; color: var(--text-secondary);">
            Tệp nhãn không chứa cột <span class="mono">Attack</span> chi tiết.
          </p>
        {:else}
          <div class="table-scroll" style="max-height: 240px;">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Nhóm</th>
                  <th>Tổng</th>
                  <th>Đúng (TP/TN)</th>
                  <th>Bỏ sót/Nhầm</th>
                  <th>Tỉ lệ đúng</th>
                </tr>
              </thead>
              <tbody>
                {#each evalResult.attack_breakdown as row (row.attack_category)}
                  <tr>
                    <td><strong>{row.attack_category}</strong></td>
                    <td class="mono">{row.total_count}</td>
                    <td class="mono">{row.tp_count}</td>
                    <td class="mono">{row.fn_count}</td>
                    <td class="mono">{pct(row.detection_rate)}</td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      </div>
    </div>

    <div class="banner banner-info" style="margin-top: 12px;">
      <Icons name="alert" size={16} />
      <div>{evalResult.scientific_notice}</div>
    </div>
  {/if}
</section>

<style>
  .cm-grid {
    display: grid;
    grid-template-columns: 140px 1fr 1fr;
    gap: 8px;
    align-items: center;
  }

  .cm-hdr {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    text-align: center;
  }

  .cm-val {
    border-radius: 8px;
    padding: 12px;
    text-align: center;
    border: 1px solid var(--border-subtle);
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .cm-val strong {
    font-size: 20px;
  }

  .cm-ok {
    background: var(--semantic-benign-soft);
    border-color: rgba(34, 197, 94, 0.35);
  }

  .cm-warn {
    background: var(--semantic-attack-soft);
    border-color: rgba(239, 68, 68, 0.35);
  }
</style>
