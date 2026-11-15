<script lang="ts">
  import type { CsvInspectResponse } from "../types";
  import { formatBytes, shortDigest } from "../utils";
  import Icons from "./Icons.svelte";

  interface Props {
    inspectData: CsvInspectResponse;
  }

  let { inspectData }: Props = $props();
  let visibleCols = $derived(inspectData.preview_columns.slice(0, 10));
</script>

<section class="card" aria-labelledby="csv-inspect-heading">
  <div class="card-header">
    <h2 id="csv-inspect-heading" class="card-title">
      <Icons name="table" size={17} />
      Kiểm tra Schema & Xem trước CSV ({inspectData.file_name})
    </h2>
    <div style="display: flex; flex-wrap: wrap; gap: 6px;">
      {#if inspectData.ml_features_valid}
        <span class="badge badge-benign">
          <Icons name="check" size={12} />
          Hợp lệ {inspectData.ml_feature_count}/47 ML Features
        </span>
      {:else}
        <span class="badge badge-attack">
          <Icons name="alert" size={12} />
          Thiếu {inspectData.missing_ml_features.length} Feature
        </span>
      {/if}
      <span class="badge badge-info mono">SHA-256: {shortDigest(inspectData.file_sha256)}</span>
      <span class="badge badge-info tabular">{inspectData.row_count} dòng • {formatBytes(inspectData.file_size_bytes)}</span>
    </div>
  </div>

  <div class="guard-grid">
    <div class="banner banner-info">
      <Icons name="lock" size={16} />
      <div>
        <strong>Cách ly chống rò rỉ dữ liệu (No Target/PII Leakage):</strong>
        Cột nhãn bị loại khỏi đầu vào ML:
        <span class="mono">{inspectData.target_columns_excluded.length ? inspectData.target_columns_excluded.join(", ") : "Không có"}</span>
        • Trace metadata loại khỏi 47 ML features:
        <span class="mono">{inspectData.trace_metadata_excluded.length} cột</span>
        • Giá trị non-finite thô do <span class="mono">DURATION=0</span> được TrainOnlyPreprocessor nội suy từ thống kê tập Train:
        <strong class="mono">{inspectData.non_finite_feature_cells}</strong> ô.
      </div>
    </div>

    {#if inspectData.ood_report.has_ood_warning}
      <div class="banner banner-warning">
        <Icons name="alert" size={16} />
        <div>
          <strong>
            Cảnh báo OOD / Telemetry Drift ({inspectData.ood_report.zero_ttl_count} MIN_TTL=0,
            {inspectData.ood_report.hard_violation_count} vi phạm bất biến vật lý):
          </strong>
          {#each inspectData.ood_report.ood_flags as flag}
            <div>{flag}</div>
          {/each}
        </div>
      </div>
    {/if}
  </div>

  <div class="table-scroll" style="margin-top: 12px; max-height: 290px;">
    <table class="data-table">
      <thead>
        <tr>
          {#each visibleCols as col}
            <th class="mono">{col}</th>
          {/each}
        </tr>
      </thead>
      <tbody>
        {#each inspectData.preview_rows as row, idx (idx)}
          <tr>
            {#each visibleCols as col}
              <td class="mono">{row[col] ?? "null"}</td>
            {/each}
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
  {#if inspectData.preview_columns.length > visibleCols.length}
    <p style="margin: 6px 0 0; font-size: 12px; color: var(--text-secondary);">
      Đang hiển thị {visibleCols.length}/{inspectData.preview_columns.length} cột đầu tiên ({inspectData.preview_rows.length} dòng mẫu).
    </p>
  {/if}
</section>

<style>
  .guard-grid {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
</style>
