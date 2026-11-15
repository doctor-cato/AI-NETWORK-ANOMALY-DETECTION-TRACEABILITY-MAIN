import type { CsvEvaluateResponse, CsvFlowPredictionItem } from "./types";

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

export function formatScoreSemantically(item: CsvFlowPredictionItem): {
  probabilityText: string;
  anomalyScoreText: string;
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

  return { probabilityText, anomalyScoreText, thresholdText };
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
