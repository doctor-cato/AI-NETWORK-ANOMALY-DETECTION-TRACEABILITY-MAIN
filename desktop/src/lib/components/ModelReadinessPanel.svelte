<script lang="ts">
  import type { ModelStatusItem } from "../types";
  import { shortDigest } from "../utils";
  import Icons from "./Icons.svelte";

  interface Props {
    models: ModelStatusItem[];
    selectedModel: string;
    onSelect: (modelKey: string) => void;
  }

  let { models, selectedModel, onSelect }: Props = $props();

  function semanticsLabel(semantics: string | null): string {
    if (semantics === "attack_probability") return "Xác suất phân lớp [0..1]";
    if (semantics === "anomaly_score_unsupervised") return "Điểm bất thường thô (không ép xác suất)";
    if (semantics === "reconstruction_error") return "Sai số tái tạo MSE (Autoencoder)";
    return semantics ?? "Chưa xác định";
  }
</script>

<section class="card" aria-labelledby="models-heading">
  <div class="card-header">
    <h2 id="models-heading" class="card-title">
      <Icons name="cpu" size={17} />
      Trạng thái 4 Mô hình AI (Xác thực SHA-256 Fail-Closed)
    </h2>
    <span class="badge badge-info">Hợp đồng: 47 ML Features • UNSW-NB15-v3</span>
  </div>

  {#if models.length === 0}
    <div class="empty-state">Đang tải thông tin artifact từ FastAPI /api/v1/models...</div>
  {:else}
    <div class="grid-4" role="radiogroup" aria-label="Chọn mô hình AI">
      {#each models as model (model.model_key)}
        {@const isSelected = selectedModel === model.model_key}
        <button
          type="button"
          class="model-card"
          class:selected={isSelected}
          class:blocked={!model.ready}
          disabled={!model.ready}
          aria-checked={isSelected}
          role="radio"
          onclick={() => model.ready && onSelect(model.model_key)}
        >
          <div class="model-top">
            <span class="model-name">{model.display_name}</span>
            {#if model.ready}
              <span class="badge badge-benign">
                <Icons name="check" size={12} />
                READY
              </span>
            {:else}
              <span class="badge badge-blocked">
                <Icons name="ban" size={12} />
                BLOCKED
              </span>
            {/if}
          </div>

          <div class="model-meta">
            <div>Ngữ nghĩa: <strong>{semanticsLabel(model.score_semantics)}</strong></div>
            {#if model.ready}
              <div class="mono">Run ID: {model.run_id ?? "N/A"}</div>
              <div class="mono">SHA-256: {shortDigest(model.artifact_sha256)}</div>
              {#if model.decision_threshold !== null}
                <div class="mono">Ngưỡng đông băng: {model.decision_threshold.toFixed(6)}</div>
              {/if}
            {:else}
              <div class="blocked-reason">
                Thiếu artifact hoặc chưa kiểm chứng — không tự fallback giả lập.
              </div>
            {/if}
          </div>
        </button>
      {/each}
    </div>
  {/if}
</section>

<style>
  .model-card {
    text-align: left;
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    border-radius: 9px;
    padding: 12px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    cursor: pointer;
    transition: border-color 140ms ease, background-color 140ms ease;
  }

  .model-card:hover:not(:disabled) {
    border-color: var(--accent-primary);
  }

  .model-card.selected {
    border-color: var(--accent-primary);
    box-shadow: inset 0 0 0 1px var(--accent-primary);
    background: var(--accent-primary-soft);
  }

  .model-card.blocked {
    opacity: 0.72;
    cursor: not-allowed;
  }

  .model-top {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 6px;
  }

  .model-name {
    font-weight: 700;
    font-size: 14px;
  }

  .model-meta {
    font-size: 12px;
    color: var(--text-secondary);
    display: flex;
    flex-direction: column;
    gap: 3px;
  }

  .blocked-reason {
    color: var(--semantic-warning);
    font-size: 11.5px;
  }
</style>
