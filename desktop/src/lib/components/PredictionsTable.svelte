<script lang="ts">
  import type { CsvAnalyzeResponse, CsvFlowPredictionItem } from "../types";
  import {
    filterAndSortPredictions,
    formatRiskDisplay,
    formatScoreSemantically,
    type PredictionClassFilter,
    type SortDirection,
    type SortField,
  } from "../utils";
  import Icons from "./Icons.svelte";

  interface Props {
    analysis: CsvAnalyzeResponse;
  }

  let { analysis }: Props = $props();

  let search = $state("");
  let classFilter = $state<PredictionClassFilter>("all");
  let riskTier = $state("all");
  let sortBy = $state<SortField>("row_index");
  let sortDir = $state<SortDirection>("asc");
  let page = $state(1);
  let pageSize = $state(25);
  let selectedItem = $state<CsvFlowPredictionItem | null>(null);

  let filteredItems = $derived(
    filterAndSortPredictions(analysis.results, {
      search,
      classFilter,
      riskTier,
      sortBy,
      sortDir,
    }),
  );

  let totalPages = $derived(Math.max(1, Math.ceil(filteredItems.length / pageSize)));
  let safePage = $derived(Math.min(page, totalPages));
  let pagedItems = $derived(
    filteredItems.slice((safePage - 1) * pageSize, safePage * pageSize),
  );

  function toggleSort(col: SortField) {
    if (sortBy === col) {
      sortDir = sortDir === "asc" ? "desc" : "asc";
    } else {
      sortBy = col;
      sortDir = col === "row_index" ? "asc" : "desc";
    }
    page = 1;
  }

  function setClassFilter(next: PredictionClassFilter) {
    classFilter = next;
    page = 1;
  }
</script>

<section class="card" aria-labelledby="predictions-heading">
  <div class="card-header">
    <h2 id="predictions-heading" class="card-title">
      <Icons name="table" size={17} />
      Bảng Dự đoán Chi tiết ({filteredItems.length}/{analysis.total_rows} luồng)
    </h2>
    <div style="display: flex; flex-wrap: wrap; gap: 6px; align-items: center;">
      <button
        type="button"
        class="btn btn-sm"
        class:btn-primary={classFilter === "all"}
        onclick={() => setClassFilter("all")}
      >
        Tất cả ({analysis.total_rows})
      </button>
      <button
        type="button"
        class="btn btn-sm"
        class:btn-primary={classFilter === "Attack"}
        onclick={() => setClassFilter("Attack")}
      >
        Attack ({analysis.attack_count})
      </button>
      <button
        type="button"
        class="btn btn-sm"
        class:btn-primary={classFilter === "Benign"}
        onclick={() => setClassFilter("Benign")}
      >
        Benign ({analysis.benign_count})
      </button>
      <button
        type="button"
        class="btn btn-sm"
        class:btn-primary={classFilter === "OOD"}
        onclick={() => setClassFilter("OOD")}
      >
        OOD ({analysis.ood_flagged_count})
      </button>
    </div>
  </div>

  <div class="toolbar-row">
    <input
      type="search"
      class="input search-input"
      placeholder="Tìm row_id, IP nguồn/đích, cổng (vd: 443)..."
      bind:value={search}
      oninput={() => (page = 1)}
      aria-label="Tìm kiếm luồng mạng"
    />

    <select
      class="input"
      bind:value={riskTier}
      onchange={() => (page = 1)}
      aria-label="Lọc theo tầng Risk"
    >
      <option value="all">Mọi Risk Tier</option>
      <option value="CRITICAL">CRITICAL (80+)</option>
      <option value="HIGH">HIGH (50-79)</option>
      <option value="MEDIUM">MEDIUM (25-49)</option>
      <option value="LOW">LOW (&lt;25)</option>
      <option value="ABSTAINED_OOD">ABSTAINED_OOD</option>
    </select>

    <select
      class="input"
      bind:value={pageSize}
      onchange={() => (page = 1)}
      aria-label="Số dòng mỗi trang"
    >
      <option value={25}>25 dòng / trang</option>
      <option value={50}>50 dòng / trang</option>
      <option value={100}>100 dòng / trang</option>
    </select>
  </div>

  <div class="table-scroll" style="max-height: 460px;">
    <table class="data-table">
      <thead>
        <tr>
          <th>
            <button type="button" class="sort-btn" onclick={() => toggleSort("row_index")}>
              Row ID {sortBy === "row_index" ? (sortDir === "asc" ? "↑" : "↓") : ""}
            </button>
          </th>
          <th>Phân lớp</th>
          <th>Src → Dst</th>
          <th>
            <button type="button" class="sort-btn" onclick={() => toggleSort("attack_probability")}>
              Xác suất Attack {sortBy === "attack_probability" ? (sortDir === "asc" ? "↑" : "↓") : ""}
            </button>
          </th>
          <th>
            <button type="button" class="sort-btn" onclick={() => toggleSort("raw_anomaly_score")}>
              Raw Anomaly Score {sortBy === "raw_anomaly_score" ? (sortDir === "asc" ? "↑" : "↓") : ""}
            </button>
          </th>
          <th>Norm. Score (Val Rank)</th>
          <th>Ngưỡng (Frozen)</th>
          <th>
            <button type="button" class="sort-btn" onclick={() => toggleSort("risk_score")}>
              Risk Priority (#32) {sortBy === "risk_score" ? (sortDir === "asc" ? "↑" : "↓") : ""}
            </button>
          </th>
          <th>OOD</th>
        </tr>
      </thead>
      <tbody>
        {#if pagedItems.length === 0}
          <tr>
            <td colspan="9" style="text-align: center; padding: 20px; color: var(--text-secondary);">
              Không có dòng nào khớp bộ lọc hiện tại.
            </td>
          </tr>
        {:else}
          {#each pagedItems as item (item.row_index)}
            {@const scores = formatScoreSemantically(item)}
            <tr
              class="clickable-row"
              class:row-selected={selectedItem?.row_index === item.row_index}
              onclick={() => (selectedItem = item)}
            >
              <td class="mono">{item.row_id}</td>
              <td>
                {#if item.predicted_class === "ABSTAINED_OOD" || item.predicted_label === null || item.is_ood_flagged}
                  <span class="badge badge-blocked" title={item.ood_reason ?? "Abstained due to OOD invariant violation"}>
                    ABSTAINED_OOD
                  </span>
                {:else if item.predicted_class === "Attack"}
                  <span class="badge badge-attack">
                    <Icons name="alert" size={12} />
                    Attack
                  </span>
                {:else}
                  <span class="badge badge-benign">
                    <Icons name="check" size={12} />
                    Benign
                  </span>
                {/if}
              </td>
              <td class="mono">
                {item.src_ip ?? "?"}:{item.src_port ?? "?"} → {item.dst_ip ?? "?"}:{item.dst_port ?? "?"}
              </td>
              <td class="mono">{scores.probabilityText}</td>
              <td class="mono">{scores.anomalyScoreText}</td>
              <td class="mono">{scores.normalizedScoreText}</td>
              <td class="mono">{scores.thresholdText}</td>
              <td>
                {#if item.is_ood_flagged || item.risk_score === null}
                  <span class="badge badge-blocked">{formatRiskDisplay(item)}</span>
                {:else if item.risk_level === "CRITICAL"}
                  <span class="badge badge-attack mono">{formatRiskDisplay(item)}</span>
                {:else if item.risk_level === "HIGH" || item.risk_level === "MEDIUM"}
                  <span class="badge badge-warning mono">{formatRiskDisplay(item)}</span>
                {:else}
                  <span class="badge badge-benign mono">{formatRiskDisplay(item)}</span>
                {/if}
              </td>
              <td>
                {#if item.is_ood_flagged}
                  <span class="badge badge-warning" title={item.ood_reason ?? "OOD abstained"}>
                    {item.min_ttl === 0 && !(item.ood_reason ?? "").includes("Hard protocol")
                      ? "MIN_TTL=0"
                      : "OOD_HARD"}
                  </span>
                {:else}
                  <span class="badge badge-info">OK</span>
                {/if}
              </td>
            </tr>
          {/each}
        {/if}
      </tbody>
    </table>
  </div>

  <div class="pager-row">
    <span class="mono" style="font-size: 12px; color: var(--text-secondary);">
      Trang {safePage} / {totalPages}
    </span>
    <div style="display: flex; gap: 6px;">
      <button
        type="button"
        class="btn btn-sm"
        disabled={safePage <= 1}
        onclick={() => (page = safePage - 1)}
      >
        Trang trước
      </button>
      <button
        type="button"
        class="btn btn-sm"
        disabled={safePage >= totalPages}
        onclick={() => (page = safePage + 1)}
      >
        Trang sau
      </button>
    </div>
  </div>

  {#if selectedItem}
    <div class="detail-drawer" role="region" aria-label="Chi tiết flow đã chọn">
      <div class="card-header" style="margin-bottom: 6px;">
        <strong>Chi tiết Flow row_id={selectedItem.row_id} (#{selectedItem.row_index})</strong>
        <button type="button" class="btn btn-sm" onclick={() => (selectedItem = null)}>
          Đóng
        </button>
      </div>
      <div class="detail-grid mono">
        <div>Score Type: {selectedItem.score_type} ({selectedItem.score_direction})</div>
        <div>Norm. Score: {formatScoreSemantically(selectedItem).normalizedScoreText}</div>
        <div>Duration: {selectedItem.flow_duration_ms ?? "N/A"} ms</div>
        <div>MIN_TTL: {selectedItem.min_ttl ?? "N/A"}</div>
        <div>Protocol: {selectedItem.protocol ?? "N/A"}</div>
        <div>OOD Reason: {selectedItem.ood_reason ?? "Không có vi phạm"}</div>
      </div>
    </div>
  {/if}
</section>

<style>
  .toolbar-row {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
    margin-bottom: 10px;
  }

  .search-input {
    flex: 1;
    min-width: 240px;
  }

  .sort-btn {
    background: none;
    border: none;
    padding: 0;
    font: inherit;
    font-weight: 600;
    color: inherit;
    cursor: pointer;
  }

  .clickable-row {
    cursor: pointer;
  }

  .row-selected {
    background: var(--accent-primary-soft);
  }

  .pager-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-top: 10px;
  }

  .detail-drawer {
    margin-top: 12px;
    padding: 12px;
    border-radius: 8px;
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
  }

  .detail-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    gap: 6px;
    font-size: 12px;
  }
</style>
