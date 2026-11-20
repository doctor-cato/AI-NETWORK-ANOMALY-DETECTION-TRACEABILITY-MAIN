<script lang="ts">
  import Icons from "./Icons.svelte";

  interface Props {
    hasFlows: boolean;
    hasAnalysis: boolean;
    hasComparison: boolean;
    hasEvaluation: boolean;
    hasExport: boolean;
    readyModelsCount: number;
    onClose?: () => void;
  }

  let {
    hasFlows,
    hasAnalysis,
    hasComparison,
    hasEvaluation,
    hasExport,
    readyModelsCount,
    onClose,
  }: Props = $props();

  let showGlossary = $state(false);
</script>

<section class="card onboarding-card" aria-labelledby="guide-heading">
  <div class="card-header" style="margin-bottom: 10px;">
    <div>
      <h2 id="guide-heading" class="card-title">
        <Icons name="shield" size={16} />
        Hướng dẫn Quy trình 4 Bước (Tích hợp sẵn {readyModelsCount}/4 Mô hình AI)
      </h2>
      <p class="guide-sub">
        Ứng dụng phát hiện bất thường lưu lượng mạng L4 (18 đặc trưng) &amp; truy vết tấn công — hoàn toàn cục bộ, không gửi dữ liệu ra ngoài.
      </p>
    </div>
    <div style="display: flex; gap: 6px; flex-wrap: wrap;">
      <button type="button" class="btn btn-sm" onclick={() => (showGlossary = !showGlossary)}>
        {showGlossary ? "Ẩn chú giải thuật ngữ" : "Giải thích Benign / Attack / OOD"}
      </button>
      {#if onClose}
        <button type="button" class="btn btn-sm" onclick={onClose}>Đóng</button>
      {/if}
    </div>
  </div>

  <div class="steps-strip">
    <div class="step-pill" class:step-done={hasFlows}>
      <span class="step-num">1</span>
      <div>
        <strong>Nạp luồng NetFlow CSV</strong>
        <div class="step-hint">Bấm Demo Trình chiếu (465 flows), Demo Chuẩn (200) hoặc chọn tệp NetFlow v2</div>
      </div>
    </div>
    <div class="step-pill" class:step-done={hasAnalysis || hasComparison}>
      <span class="step-num">2</span>
      <div>
        <strong>Quét bằng 4 Mô hình AI</strong>
        <div class="step-hint">Random Forest, XGBoost, Isolation Forest và Autoencoder chạy song song</div>
      </div>
    </div>
    <div class="step-pill" class:step-done={hasEvaluation}>
      <span class="step-num">3</span>
      <div>
        <strong>Đọc kết quả &amp; Truy vết</strong>
        <div class="step-hint">Xem biểu đồ rủi ro, danh sách luồng nghi ngờ và đối chiếu nhãn thực tế</div>
      </div>
    </div>
    <div class="step-pill" class:step-done={hasExport}>
      <span class="step-num">4</span>
      <div>
        <strong>Xuất biên bản kiểm chứng</strong>
        <div class="step-hint">Lưu CSV kết quả kèm chữ ký toàn vẹn SHA-256 phục vụ báo cáo</div>
      </div>
    </div>
  </div>

  {#if showGlossary}
    <div class="glossary-grid">
      <div class="glossary-item">
        <strong style="color: var(--semantic-benign);">Benign (Bình thường)</strong>
        <p>
          Lưu lượng được mô hình đánh giá là bình thường.
        </p>
      </div>
      <div class="glossary-item">
        <strong style="color: var(--semantic-attack);">Attack (Nghi ngờ tấn công)</strong>
        <p>
          Lưu lượng được mô hình đánh giá là nghi ngờ tấn công. Cần xem xét thêm để xác định sự cố.
        </p>
      </div>
      <div class="glossary-item">
        <strong style="color: var(--semantic-ood);">OOD (ABSTAINED_OOD — Từ chối dự đoán)</strong>
        <p>
          Dữ liệu vi phạm bất biến vật lý (âm thời lượng/byte/gói tin hoặc giá trị không hữu hạn). Hệ thống chủ động từ chối gán nhãn và không tính điểm rủi ro để tránh báo nhầm.
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
        <strong>Nguồn dữ liệu &amp; Giới hạn Khoa học (v2):</strong>
        Dữ liệu demo và trọng số mô hình được huấn luyện từ bộ dữ liệu
        <strong>AIT NetFlow Data Set v2</strong> (DOI: <span class="mono">10.5281/zenodo.13168643</span>,
        giấy phép <span class="mono">CC BY 4.0</span>, sinh từ PCAP AIT-LDS-v2.0) và kiểm chứng mở rộng trên dữ liệu thu thập thực tế
        <strong>CTU-SME-11</strong> (DOI: <span class="mono">10.5281/zenodo.7958258</span>, <span class="mono">CC BY 4.0</span>).
        Hiệu năng ngoài phân phối (domain shift) giữa dữ liệu mô phỏng và mạng thực tế có thể suy giảm; mọi khuyến nghị phản ứng chỉ chạy ở chế độ mô phỏng <strong>Dry-Run (executed=false)</strong> và không tự can thiệp tường lửa thật.
      </div>
    </div>
  {/if}
</section>

<style>
  .onboarding-card {
    border-color: var(--border-subtle);
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
