import type {
  CsvEvaluateResponse,
  CsvFlowPredictionItem,
  ResponseFlowRecommendationItem,
} from "./types";

export type PredictionClassFilter = "all" | "Attack" | "Benign" | "OOD";
export type SortField =
  | "row_index"
  | "risk_score"
  | "attack_probability"
  | "raw_anomaly_score"
  | "flow_start_ms";
export type SortDirection = "asc" | "desc";

export interface FilterSortOptions {
  search: string;
  classFilter: PredictionClassFilter;
  riskTier: string;
  sortBy: SortField;
  sortDir: SortDirection;
}

export function getDroppedCsvPath(paths: string[]): string | null {
  return paths.length === 1 && paths[0].toLowerCase().endsWith(".csv") ? paths[0] : null;
}

export function formatScoreSemantically(item: CsvFlowPredictionItem): {
  probabilityText: string;
  anomalyScoreText: string;
  normalizedScoreText: string;
  thresholdText: string;
} {
  const thresholdText =
    item.decision_threshold !== null && Number.isFinite(item.decision_threshold)
      ? item.decision_threshold.toFixed(4)
      : "N/A";

  if (
    item.is_ood_flagged ||
    item.predicted_label === null ||
    item.predicted_class === "ABSTAINED_OOD"
  ) {
    return {
      probabilityText: "ABSTAINED (OOD)",
      anomalyScoreText: "ABSTAINED (OOD)",
      normalizedScoreText: "ABSTAINED (OOD)",
      thresholdText,
    };
  }

  const probabilityText =
    item.attack_probability !== null && Number.isFinite(item.attack_probability)
      ? `${(item.attack_probability * 100).toFixed(2)}%`
      : "N/A (Unsupervised)";

  const anomalyScoreText =
    item.raw_anomaly_score !== null && Number.isFinite(item.raw_anomaly_score)
      ? item.raw_anomaly_score.toFixed(4)
      : "N/A";

  const normalizedScoreText =
    item.attack_probability !== null
      ? "N/A (Supervised)"
      : item.normalized_anomaly_score !== null && Number.isFinite(item.normalized_anomaly_score)
        ? `${item.normalized_anomaly_score.toFixed(4)} (Val quantile)`
        : "Chưa hiệu chuẩn";

  return { probabilityText, anomalyScoreText, normalizedScoreText, thresholdText };
}

export function formatRiskDisplay(item: CsvFlowPredictionItem): string {
  if (item.is_ood_flagged || item.risk_score === null) {
    return item.risk_level || "ABSTAINED_OOD";
  }
  return `${item.risk_score.toFixed(1)} (${item.risk_level})`;
}

export function filterAndSortPredictions(
  items: CsvFlowPredictionItem[],
  opts: FilterSortOptions,
): CsvFlowPredictionItem[] {
  const query = opts.search.trim().toLowerCase();
  const filtered = items.filter((item) => {
    if (opts.classFilter === "Attack" && item.predicted_class !== "Attack") return false;
    if (opts.classFilter === "Benign" && item.predicted_class !== "Benign") return false;
    if (opts.classFilter === "OOD" && !item.is_ood_flagged) return false;
    if (opts.riskTier !== "all" && item.risk_level !== opts.riskTier) return false;

    if (!query) return true;
    const haystack = [
      String(item.row_id),
      item.src_ip ?? "",
      item.dst_ip ?? "",
      item.src_port !== null ? String(item.src_port) : "",
      item.dst_port !== null ? String(item.dst_port) : "",
      item.predicted_class,
      item.risk_level,
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(query);
  });

  const sorted = [...filtered].sort((a, b) => {
    const getVal = (it: CsvFlowPredictionItem): number => {
      switch (opts.sortBy) {
        case "risk_score":
          return it.risk_score ?? -Infinity;
        case "attack_probability":
          return it.attack_probability ?? -Infinity;
        case "raw_anomaly_score":
          return it.raw_anomaly_score ?? -Infinity;
        case "flow_start_ms":
          return it.flow_start_ms ?? Number.MAX_SAFE_INTEGER;
        case "row_index":
        default:
          return it.row_index;
      }
    };
    const va = getVal(a);
    const vb = getVal(b);
    if (va === vb) {
      return a.row_index - b.row_index;
    }
    return opts.sortDir === "asc" ? va - vb : vb - va;
  });

  return sorted;
}

export interface RiskBucketStat {
  label: string;
  count: number;
  share: number;
  tone: "benign" | "warning" | "attack" | "blocked";
}

export function computeRiskDistribution(items: CsvFlowPredictionItem[]): RiskBucketStat[] {
  const total = items.length || 1;
  const counts: Record<string, number> = {
    LOW: 0,
    MEDIUM: 0,
    HIGH: 0,
    CRITICAL: 0,
    ABSTAINED_OOD: 0,
  };
  for (const item of items) {
    if (item.risk_level in counts) {
      counts[item.risk_level] += 1;
    } else {
      counts.ABSTAINED_OOD += 1;
    }
  }
  return [
    { label: "LOW (<25)", count: counts.LOW, share: counts.LOW / total, tone: "benign" },
    { label: "MEDIUM (25-49)", count: counts.MEDIUM, share: counts.MEDIUM / total, tone: "warning" },
    { label: "HIGH (50-79)", count: counts.HIGH, share: counts.HIGH / total, tone: "warning" },
    { label: "CRITICAL (80+)", count: counts.CRITICAL, share: counts.CRITICAL / total, tone: "attack" },
    {
      label: "ABSTAINED (OOD)",
      count: counts.ABSTAINED_OOD,
      share: counts.ABSTAINED_OOD / total,
      tone: "blocked",
    },
  ];
}

export interface EvaluationCoverageSummary {
  evaluatedRows: number;
  abstainedRows: number;
  matchedLabelRows: number;
  unmatchedRows: number;
  totalPredictionRows: number;
  labelMatchRate: number;
  postOodCoverage: number;
  hasPartialLabelMatch: boolean;
}

export function summarizeEvaluationCoverage(
  evalResult: CsvEvaluateResponse,
): EvaluationCoverageSummary {
  const evaluatedRows = evalResult.evaluated_rows ?? evalResult.matched_rows;
  const abstainedRows = evalResult.abstained_rows ?? 0;
  const matchedLabelRows = evalResult.matched_label_rows ?? evaluatedRows + abstainedRows;
  const unmatchedRows = evalResult.unmatched_rows ?? 0;
  const totalPredictionRows =
    evalResult.total_prediction_rows && evalResult.total_prediction_rows > 0
      ? evalResult.total_prediction_rows
      : matchedLabelRows + unmatchedRows;
  const labelMatchRate =
    evalResult.label_match_rate ??
    (totalPredictionRows > 0 ? matchedLabelRows / totalPredictionRows : 0);
  const postOodCoverage =
    evalResult.prediction_coverage ??
    (matchedLabelRows > 0 ? evaluatedRows / matchedLabelRows : 0);
  const hasPartialLabelMatch =
    unmatchedRows > 0 || (totalPredictionRows > 0 && matchedLabelRows < totalPredictionRows);
  return {
    evaluatedRows,
    abstainedRows,
    matchedLabelRows,
    unmatchedRows,
    totalPredictionRows,
    labelMatchRate,
    postOodCoverage,
    hasPartialLabelMatch,
  };
}

export function formatBlockedModelReason(reason: string | null | undefined): string {
  const trimmed = typeof reason === "string" ? reason.trim() : "";
  return trimmed || "Thiếu artifact hoặc chưa kiểm chứng — không tự fallback giả lập.";
}

export interface ModelGovernanceInfo {
  tier: "MODEL_VALIDATED" | "RESEARCH_ONLY";
  badgeLabel: string;
  shortRole: string;
  explanation: string;
}

export function getModelGovernanceInfo(modelKey: string): ModelGovernanceInfo {
  if (modelKey === "random_forest") {
    return {
      tier: "MODEL_VALIDATED",
      badgeLabel: "Chính thức (Validated)",
      shortRole: "Baseline đã kiểm chứng",
      explanation:
        "Mô hình chuẩn đã được kiểm chứng trên tập dữ liệu AIT-NDS-v2 (canonical-flow-v2-18). Hỗ trợ đầy đủ phân loại và khuyến nghị phản ứng (dry-run).",
    };
  }
  if (modelKey === "xgboost") {
    return {
      tier: "RESEARCH_ONLY",
      badgeLabel: "Nghiên cứu (Research)",
      shortRole: "So sánh hiệu năng Gradient Boosting",
      explanation:
        "Mô hình có giám sát dùng để đối chiếu độ chính xác với Random Forest; không tự kích hoạt khuyến nghị cách ly.",
    };
  }
  if (modelKey === "isolation_forest") {
    return {
      tier: "RESEARCH_ONLY",
      badgeLabel: "Nghiên cứu (Unsupervised)",
      shortRole: "Phát hiện bất thường không nhãn",
      explanation:
        "Học từ lưu lượng bình thường để phát hiện mẫu lạ bằng điểm bất thường thô và ngưỡng Validation đóng băng.",
    };
  }
  return {
    tier: "RESEARCH_ONLY",
    badgeLabel: "Nghiên cứu (Deep Learning)",
    shortRole: "Sai số tái tạo (FPR ≤ 5%)",
    explanation:
      "Học tái tạo lưu lượng bình thường (MLP Autoencoder); độ lệch tái tạo vượt ngưỡng cố định sẽ được gắn cờ bất thường.",
  };
}

export function formatUserFriendlyError(raw: unknown): string {
  const msg = raw instanceof Error ? raw.message : String(raw ?? "");
  const lower = msg.toLowerCase();
  if (!msg.trim()) {
    return "Đã xảy ra lỗi không xác định khi xử lý yêu cầu. Vui lòng thử lại hoặc nhấn 'Làm mới Dịch vụ'.";
  }
  if (lower.includes("missing") && lower.includes("baseline ml feature")) {
    return `Tệp CSV chưa đúng định dạng NetFlow v3 (thiếu cột đặc trưng bắt buộc). Vui lòng chọn tệp CSV hợp lệ hoặc dùng dữ liệu Demo. (${msg})`;
  }
  if (lower.includes("0 bytes") || lower.includes("empty")) {
    return "Tệp CSV đang trống (không có dòng dữ liệu). Vui lòng chọn tệp CSV có ít nhất 1 dòng lưu lượng.";
  }
  if (lower.includes("only .csv")) {
    return "Ứng dụng chỉ hỗ trợ tệp định dạng .csv. Vui lòng chọn đúng tệp CSV.";
  }
  if (lower.includes("unc or network share")) {
    return "Vì lý do bảo mật offline, ứng dụng không đọc/ghi trực tiếp qua đường dẫn mạng chia sẻ (UNC). Hãy sao chép tệp vào ổ đĩa cục bộ.";
  }
  if (lower.includes("protected system directory")) {
    return "Không được phép đọc hoặc xuất tệp vào thư mục hệ thống Windows. Vui lòng chọn thư mục cá nhân như Documents hoặc Desktop.";
  }
  if (lower.includes("overwrite the input csv")) {
    return "Không thể ghi đè trực tiếp lên tệp CSV đầu vào. Vui lòng đặt tên tệp xuất khác.";
  }
  if (lower.includes("http 503") || lower.includes("not ready")) {
    return `Hệ thống mô hình AI chưa sẵn sàng hoặc đang bị khóa kiểm chứng SHA-256 (${msg}). Hãy nhấn 'Làm mới Dịch vụ' hoặc kiểm tra lại cài đặt.`;
  }
  if (lower.includes("http 401") || lower.includes("unauthorized")) {
    return "Phiên kết nối nội bộ hết hạn hoặc chưa hợp lệ. Hãy nhấn 'Làm mới Dịch vụ' để khôi phục kết nối an toàn.";
  }
  if (lower.includes("unreachable") || lower.includes("timed out")) {
    return "Dịch vụ phân tích cục bộ đang khởi động hoặc chưa phản hồi. Vui lòng đợi vài giây hoặc nhấn 'Làm mới Dịch vụ'.";
  }
  return msg;
}

export function shortDigest(sha: string | null | undefined): string {
  if (!sha) return "N/A";
  return sha.length > 14 ? `${sha.slice(0, 12)}...` : sha;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "0 B";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

export type ResponseActionFilter =
  | "all"
  | "ISOLATE_RECOMMENDED"
  | "INVESTIGATE"
  | "MONITOR"
  | "NO_ACTION"
  | "OOD";

export function filterResponseRecommendations(
  items: ResponseFlowRecommendationItem[],
  actionFilter: ResponseActionFilter,
  query = "",
): ResponseFlowRecommendationItem[] {
  const q = query.trim().toLowerCase();
  return items.filter((item) => {
    if (actionFilter === "OOD" && !item.is_ood_flagged) return false;
    if (
      actionFilter !== "all" &&
      actionFilter !== "OOD" &&
      item.action !== actionFilter
    ) {
      return false;
    }
    if (!q) return true;
    const haystack = [
      String(item.row_id),
      item.action,
      item.severity,
      item.src_ip ?? "",
      item.dst_ip ?? "",
      item.dst_port !== null ? String(item.dst_port) : "",
      item.reason,
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(q);
  });
}

export function getResponseActionBadgeClass(
  action: string,
): "badge-attack" | "badge-warning" | "badge-info" | "badge-benign" {
  switch (action) {
    case "ISOLATE_RECOMMENDED":
      return "badge-attack";
    case "INVESTIGATE":
      return "badge-warning";
    case "MONITOR":
      return "badge-info";
    default:
      return "badge-benign";
  }
}
