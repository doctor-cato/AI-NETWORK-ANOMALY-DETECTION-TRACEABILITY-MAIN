import { describe, expect, it } from "vitest";
import type { CsvFlowPredictionItem } from "./types";
import {
  computeRiskDistribution,
  filterAndSortPredictions,
  formatRiskDisplay,
  formatScoreSemantically,
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

  it("never renders synthetic score when row is OOD abstained", () => {
    const oodRow = makeItem({
      is_ood_flagged: true,
      risk_score: null,
      risk_level: "ABSTAINED_OOD",
    });
    expect(formatRiskDisplay(oodRow)).toBe("ABSTAINED_OOD");
  });
});

describe("prediction filtering and sorting", () => {
  it("filters by class, search query, and sorts descending by risk_score", () => {
    const items = [
      makeItem({ row_id: 10, row_index: 0, predicted_label: 0, predicted_class: "Benign", risk_score: 5, risk_level: "LOW", src_ip: "10.0.0.1" }),
      makeItem({ row_id: 20, row_index: 1, predicted_label: 1, predicted_class: "Attack", risk_score: 94, risk_level: "CRITICAL", src_ip: "172.16.0.8" }),
      makeItem({ row_id: 30, row_index: 2, predicted_label: 1, predicted_class: "Attack", risk_score: null, risk_level: "ABSTAINED_OOD", is_ood_flagged: true, src_ip: "172.16.0.9" }),
    ];

    const attacks = filterAndSortPredictions(items, {
      search: "172.16",
      classFilter: "Attack",
      riskTier: "all",
      sortBy: "risk_score",
      sortDir: "desc",
    });
    expect(attacks.map((x) => x.row_id)).toEqual([20, 30]);

    const dist = computeRiskDistribution(items);
    expect(dist.find((b) => b.label.startsWith("CRITICAL"))?.count).toBe(1);
    expect(dist.find((b) => b.label.startsWith("ABSTAINED"))?.count).toBe(1);
  });
});
