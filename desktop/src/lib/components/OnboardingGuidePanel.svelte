<script lang="ts">
  import Icons from "./Icons.svelte";

  interface Props {
    hasFlows: boolean;
    hasAnalysis: boolean;
    hasComparison: boolean;
    hasEvaluation: boolean;
    hasExport: boolean;
    readyModelsCount: number;
    onLoadDemo: () => void;
    onBrowseCsv: () => void;
    busy: boolean;
  }

  let {
    hasFlows,
    hasAnalysis,
    hasComparison,
    hasEvaluation,
    hasExport,
    readyModelsCount,
    onLoadDemo,
    onBrowseCsv,
    busy,
  }: Props = $props();

  let showGlossary = $state(false);
</script>

<section class="card onboarding-card" aria-labelledby="guide-heading">
  <div class="card-header">
    <div>
      <h2 id="guide-heading" class="card-title">
        <Icons name="shield" size={17} />
        Quy trình Phân tích Lưu lượng Mạng (Offline &amp; Tích hợp sẵn {readyModelsCount}/4 Mô hình AI)
      </h2>
      <p class="guide-sub">
        Không cần cài Python hay cấu hình thủ công. Chọn dữ liệu NetFlow CSV bên dưới để phân tích, so sánh 4 mô hình AI và xuất báo cáo kiểm chứng.
      </p>
    </div>
    <div style="display: flex; gap: 8px; flex-wrap: wrap;">
      <button type="button" class="btn btn-sm" onclick={() => (showGlossary = !showGlossary)}>
        {showGlossary ? "Ẩn giải thích & Bản quyền" : "Hiểu kết quả (Benign / Attack / OOD) & Bản quyền"}
      </button>
    </div>
  </div>

  <div class="steps-strip">
    <div class="step-pill" class:step-done={hasFlows}>
      <span class="step-num">1</span>
      <div>
        <strong>Nhập dữ liệu CSV</strong>
        <div class="step-hint">Dùng dữ liệu Demo (200 dòng) hoặc chọn tệp NetFlow v3</div>
      </div>
    </div>
    <div class="step-pill" class:step-done={hasAnalysis || hasComparison}>
      <span class="step-num">2</span>
      <div>
        <strong>Phân tích với 4 AI</strong>
        <div class="step-hint">Chạy từng mô hình hoặc so sánh cả 4 mô hình cùng lúc</div>
      </div>
    </div>
    <div class="step-pill" class:step-done={hasEvaluation}>
      <span class="step-num">3</span>
      <div>
        <strong>Đánh giá &amp; Đối chiếu</strong>
        <div class="step-hint">Xem Benign/Attack/OOD, độ tin cậy &amp; Confusion Matrix</div>
      </div>
    </div>
    <div class="step-pill" class:step-done={hasExport}>
      <span class="step-num">4</span>
      <div>
        <strong>Xuất báo cáo</strong>
        <div class="step-hint">Lưu CSV kết quả kèm biên bản SHA-256 minh bạch</div>
      </div>
    </div>
  </div>

  {#if !hasFlows}
    <div class="quick-start-bar">
      <span>Bắt đầu nhanh cho người mới:</span>
      <button type="button" class="btn btn-primary btn-sm" onclick={onLoadDemo} disabled={busy}>
        <Icons name="play" size={14} />
        Mở ngay Dữ liệu Demo Chuẩn (200 flows)
      </button>
      <button type="button" class="btn btn-sm" onclick={onBrowseCsv} disabled={busy}>
        <Icons name="folder" size={14} />
        Chọn tệp CSV từ máy
      </button>
    </div>
  {/if}

  {#if showGlossary}
    <div class="glossary-grid">
      <div class="glossary-item">
        <strong style="color: var(--semantic-benign);">Benign (Bình thường)</strong>
        <p>
          Lưu lượng mạng hợp lệ, hành vi khớp với mô hình lưu lượng thông thường trong dữ liệu huấn luyện.
        </p>
      </div>
      <div class="glossary-item">
        <strong style="color: var(--semantic-attack);">Attack (Nghi ngờ tấn công)</strong>
        <p>
          Lưu lượng mang dấu hiệu bất thường hoặc khớp với mẫu tấn công đã học (DoS, Exploits, Fuzzers, Reconnaissance...).
        </p>
      </div>
      <div class="glossary-item">
        <strong style="color: var(--semantic-warning);">OOD (ABSTAINED_OOD — Từ chối dự đoán)</strong>
        <p>
          Dữ liệu thiếu thông số quan trọng (ví dụ <code>MIN_TTL = 0</code>) hoặc bất hợp lý vật lý. Hệ thống chủ động từ chối gán nhãn và không tính điểm rủi ro để tránh báo nhầm.
        </p>
      </div>
      <div class="glossary-item">
        <strong>Mức độ tin cậy &amp; Chính thức vs Nghiên cứu</strong>
        <p>
          <strong>Random Forest</strong> là mô hình chính thức (<code>MODEL_VALIDATED</code>) xuất xác suất tấn công 0–100%. <strong>XGBoost</strong>, <strong>Isolation Forest</strong> và <strong>Autoencoder</strong> ở nhóm <code>RESEARCH_ONLY</code> để đối chiếu khoa học; các mô hình không giám sát dùng điểm bất thường thô + ngưỡng cố định.
        </p>
      </div>
    </div>

    <div class="banner banner-info" style="margin-top: 10px; font-size: 12px;">
      <Icons name="lock" size={15} />
      <div>
        <strong>Nguồn dữ liệu &amp; Giới hạn Khoa học:</strong>
        Dữ liệu demo và trọng số mô hình được xây dựng từ bộ dữ liệu nghiên cứu
        <strong>NF-UNSW-NB15-v3</strong> (The University of Queensland, DOI:
        <span class="mono">10.48610/6E0EDA1</span>, Luay et al. <span class="mono">arXiv:2503.04404</span>)
        theo điều khoản <em>Permitted Re-Use with Commercial Use Restriction</em> (chỉ dùng cho mục đích học thuật, nghiên cứu và phi thương mại).
        Mô hình có độ chính xác cao trong phân phối testbed nhưng có thể suy giảm trên lưu lượng mạng khác; mọi khuyến nghị phản ứng (#27) chỉ chạy ở chế độ mô phỏng <strong>Dry-Run (executed=false)</strong> và không tự can thiệp tường lửa thật.
      </div>
    </div>
  {/if}
</section>

<style>
  .onboarding-card {
    border-color: rgba(59, 130, 246, 0.35);
  }

  .guide-sub {
    margin: 4px 0 0;
    font-size: 12.5px;
    color: var(--text-secondary);
  }

  .steps-strip {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 10px;
  }

  @media (max-width: 1080px) {
    .steps-strip {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
  }

  @media (max-width: 640px) {
    .steps-strip {
      grid-template-columns: 1fr;
    }
  }

  .step-pill {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 12px;
    border-radius: 8px;
    border: 1px solid var(--border-subtle);
    background: var(--bg-elevated);
    font-size: 12.5px;
    transition: border-color 160ms ease, background-color 160ms ease, transform 150ms ease;
  }

  .step-pill.step-done {
    border-color: rgba(34, 197, 94, 0.45);
    background: var(--semantic-benign-soft);
  }

  .step-num {
    width: 22px;
    height: 22px;
    border-radius: 999px;
    background: var(--accent-primary-soft);
    color: var(--accent-primary);
    font-weight: 700;
    font-size: 12px;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    transition: background-color 160ms ease, color 160ms ease, transform 160ms ease;
  }

  .step-done .step-num {
    background: var(--semantic-benign);
    color: #ffffff;
  }

  .step-hint {
    font-size: 11.5px;
    color: var(--text-secondary);
    margin-top: 2px;
  }

  .quick-start-bar {
    margin-top: 10px;
    padding-top: 10px;
    border-top: 1px dashed var(--border-subtle);
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 8px;
    font-size: 12.5px;
    color: var(--text-secondary);
  }

  .glossary-grid {
    margin-top: 12px;
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 10px;
    animation: nf-fade-slide-in 180ms cubic-bezier(0.22, 1, 0.36, 1);
  }

  @media (max-width: 820px) {
    .glossary-grid {
      grid-template-columns: 1fr;
    }
  }

  .glossary-item {
    background: var(--bg-elevated);
    border: 1px solid var(--border-subtle);
    border-radius: 8px;
    padding: 10px 12px;
    font-size: 12.5px;
  }

  .glossary-item p {
    margin: 4px 0 0;
    color: var(--text-secondary);
    line-height: 1.45;
  }
</style>
