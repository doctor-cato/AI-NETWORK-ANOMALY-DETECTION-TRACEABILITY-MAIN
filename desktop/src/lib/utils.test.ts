import { describe, expect, it } from "vitest";
import type { CsvEvaluateResponse, CsvFlowPredictionItem } from "./types";
import { isLocalhostHttpUrl } from "./api";
import {
  computeRiskDistribution,
  filterAndSortPredictions,
  formatRiskDisplay,
  formatScoreSemantically,
  summarizeEvaluationCoverage,
} from "./utils";

function makeItem(overrides: Partial<CsvFlowPredictionItem>): CsvFlowPredictionItem {
  return {
    row_id: 1,
    row_index: 0,
    predicted_label: 0,
    predicted_class: "Benign",
    attack_probability: 0.1,
    raw_anomaly_score: 0.1,
    decision_threshold: 0.5,
    score_type: "attack_probability",
    score_direction: "higher_is_more_anomalous",
    risk_score: 10,
    risk_level: "LOW",
    is_ood_flagged: false,
    ood_reason: null,
    flow_start_ms: 1700000001000,
    flow_end_ms: 1700000002000,
    src_ip: "10.0.0.1",
    dst_ip: "192.168.1.5",
    src_port: 51000,
    dst_port: 443,
    protocol: 6,
    flow_duration_ms: 1000,
    min_ttl: 62,
    ...overrides,
  };
}

describe("score semantics and OOD abstention display", () => {
  it("distinguishes supervised probability from unsupervised raw anomaly score", () => {
    const rf = makeItem({ attack_probability: 0.9125, raw_anomaly_score: 0.9125, decision_threshold: 0.5 });
    expect(formatScoreSemantically(rf).probabilityText).toBe("91.25%");

    const iso = makeItem({
      attack_probability: null,
      raw_anomaly_score: -0.0715,
      decision_threshold: -0.0335,
      score_type: "isolation_forest_anomaly_score",
    });
    const fmt = formatScoreSemantically(iso);
    expect(fmt.probabilityText).toBe("N/A (Unsupervised)");
    expect(fmt.anomalyScoreText).toBe("-0.0715");
    expect(fmt.thresholdText).toBe("-0.0335");
  });

  it("never renders synthetic score or prediction when row is OOD abstained", () => {
    const oodRow = makeItem({
      predicted_label: null,
      predicted_class: "ABSTAINED_OOD",
      attack_probability: null,
      raw_anomaly_score: null,
      is_ood_flagged: true,
      risk_score: null,
      risk_level: "ABSTAINED_OOD",
    });
    expect(formatRiskDisplay(oodRow)).toBe("ABSTAINED_OOD");
    const fmt = formatScoreSemantically(oodRow);
    expect(fmt.probabilityText).toBe("ABSTAINED (OOD)");
    expect(fmt.anomalyScoreText).toBe("ABSTAINED (OOD)");
  });
});

describe("prediction filtering and sorting", () => {
  it("filters by class, search query, and sorts descending by risk_score", () => {
    const items = [
      makeItem({ row_id: 10, row_index: 0, predicted_label: 0, predicted_class: "Benign", risk_score: 5, risk_level: "LOW", src_ip: "10.0.0.1" }),
      makeItem({ row_id: 20, row_index: 1, predicted_label: 1, predicted_class: "Attack", risk_score: 94, risk_level: "CRITICAL", src_ip: "172.16.0.8" }),
      makeItem({ row_id: 25, row_index: 2, predicted_label: 1, predicted_class: "Attack", risk_score: 62, risk_level: "HIGH", src_ip: "172.16.0.9" }),
      makeItem({ row_id: 30, row_index: 3, predicted_label: null, predicted_class: "ABSTAINED_OOD", attack_probability: null, raw_anomaly_score: null, risk_score: null, risk_level: "ABSTAINED_OOD", is_ood_flagged: true, src_ip: "172.16.0.10" }),
    ];

    const attacks = filterAndSortPredictions(items, {
      search: "172.16",
      classFilter: "Attack",
      riskTier: "all",
      sortBy: "risk_score",
      sortDir: "desc",
    });
    expect(attacks.map((x) => x.row_id)).toEqual([20, 25]);

    const oodOnly = filterAndSortPredictions(items, {
      search: "",
      classFilter: "OOD",
      riskTier: "all",
      sortBy: "row_index",
      sortDir: "asc",
    });
    expect(oodOnly.map((x) => x.row_id)).toEqual([30]);

    const dist = computeRiskDistribution(items);
    expect(dist.find((b) => b.label.startsWith("CRITICAL"))?.count).toBe(1);
    expect(dist.find((b) => b.label.startsWith("ABSTAINED"))?.count).toBe(1);
  });

  it("validates strict localhost-only HTTP fallback URLs", () => {
    expect(isLocalhostHttpUrl("http://127.0.0.1:8000")).toBe(true);
    expect(isLocalhostHttpUrl("http://localhost:8015")).toBe(true);
    expect(isLocalhostHttpUrl("http://127.0.0.1:8000@evil.com")).toBe(false);
    expect(isLocalhostHttpUrl("https://127.0.0.1:8000")).toBe(false);
    expect(isLocalhostHttpUrl("http://10.0.0.5:8000")).toBe(false);
  });

  it("separates label match rate from post-OOD prediction coverage on partial label matches", () => {
    const partialEval: CsvEvaluateResponse = {
      labels_path: "labels.csv",
      labels_sha256: "a".repeat(64),
      total_prediction_rows: 3,
      matched_label_rows: 1,
      matched_rows: 1,
      evaluated_rows: 1,
      unmatched_rows: 2,
      abstained_rows: 0,
      label_match_rate: 0.3333,
      prediction_coverage: 1.0,
      accuracy: 1.0,
      precision: 1.0,
      recall: 1.0,
      f1: 1.0,
      false_positive_rate: 0.0,
      true_negative_rate: 1.0,
      confusion_matrix: { tn: 0, fp: 0, fn: 0, tp: 1 },
      attack_breakdown: [],
      scientific_notice: "partial",
    };

    const summary = summarizeEvaluationCoverage(partialEval);
    expect(summary.totalPredictionRows).toBe(3);
    expect(summary.matchedLabelRows).toBe(1);
    expect(summary.unmatchedRows).toBe(2);
    expect(summary.evaluatedRows).toBe(1);
    expect(summary.abstainedRows).toBe(0);
    expect(summary.labelMatchRate).toBeCloseTo(0.3333, 4);
    expect(summary.postOodCoverage).toBe(1.0);
    expect(summary.hasPartialLabelMatch).toBe(true);

    // Also verify legacy fallback when older payload omits total_prediction_rows/label_match_rate
    const legacyPayload: CsvEvaluateResponse = {
      ...partialEval,
      total_prediction_rows: undefined,
      matched_label_rows: undefined,
      label_match_rate: undefined,
      abstained_rows: 1,
      prediction_coverage: 0.5,
    };
    const legacySummary = summarizeEvaluationCoverage(legacyPayload);
    expect(legacySummary.matchedLabelRows).toBe(2);
    expect(legacySummary.totalPredictionRows).toBe(4);
    expect(legacySummary.labelMatchRate).toBe(0.5);
    expect(legacySummary.postOodCoverage).toBe(0.5);
    expect(legacySummary.hasPartialLabelMatch).toBe(true);
  });
});
