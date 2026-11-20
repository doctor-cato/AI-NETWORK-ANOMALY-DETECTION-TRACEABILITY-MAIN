import { render } from "svelte/server";
import { describe, expect, it, vi } from "vitest";
import EvaluationPanel from "./components/EvaluationPanel.svelte";
import ModelComparisonPanel from "./components/ModelComparisonPanel.svelte";
import ModelReadinessPanel from "./components/ModelReadinessPanel.svelte";
import {
  createInitialComparisonState,
  evaluateAllModelsWorkflow,
  getBatchCoherentAnalyses,
  getBatchCoherentEvaluations,
  getBatchCoherentSimulations,
  invalidateForBackendRestart,
  invalidateForFlowsChange,
  invalidateForInspectResult,
  invalidateForLabelsChange,
  normalizeDesktopPath,
  reconcileModelsReadiness,
  recordModelAnalysis,
  recordModelError,
  recordModelEvaluation,
  recordModelSimulation,
  runAllModelsComparisonWorkflow,
  runSingleModelAnalysisWorkflow,
  type ComparisonBatchState,
  type ComparisonWorkflowDeps,
} from "./comparisonState";
import type {
  BehavioralSummary,
  CsvAnalyzeResponse,
  CsvEvaluateResponse,
  CsvFlowPredictionItem,
  CsvInspectResponse,
  ModelStatusItem,
  OodSummary,
  SecurityResponseSimulationResponse,
} from "./types";
import { formatScoreSemantically, shortDigest } from "./utils";

const SHA_CSV_A = "a1".repeat(32);
const SHA_CSV_B = "b2".repeat(32);
const SHA_LABELS_1 = "c3".repeat(32);
const SHA_LABELS_2 = "d4".repeat(32);
const SHA_PREP = "e5".repeat(32);

const MODEL_META: Record<
  string,
  {
    display_name: string;
    model_type: string;
    score_semantics: string;
    score_type: string;
    score_direction: string;
    threshold: number;
    artifact_sha256: string;
    run_id: string;
  }
> = {
  random_forest: {
    display_name: "Random Forest",
    model_type: "RandomForest",
    score_semantics: "attack_probability",
    score_type: "attack_probability",
    score_direction: "higher_is_more_anomalous",
    threshold: 0.5,
    artifact_sha256: "11".repeat(32),
    run_id: "rf-run-2026",
  },
  xgboost: {
    display_name: "XGBoost",
    model_type: "XGBoost",
    score_semantics: "attack_probability",
    score_type: "attack_probability",
    score_direction: "higher_is_more_anomalous",
    threshold: 0.52,
    artifact_sha256: "22".repeat(32),
    run_id: "xgb-run-2026",
  },
  isolation_forest: {
    display_name: "Isolation Forest",
    model_type: "IsolationForest",
    score_semantics: "anomaly_score_unsupervised",
    score_type: "isolation_forest_anomaly_score",
    score_direction: "lower_is_more_anomalous",
    threshold: -0.0335,
    artifact_sha256: "33".repeat(32),
    run_id: "if-run-2026",
  },
  autoencoder: {
    display_name: "Autoencoder",
    model_type: "Autoencoder",
    score_semantics: "reconstruction_error",
    score_type: "reconstruction_error_mse",
    score_direction: "higher_is_more_anomalous",
    threshold: 0.1842,
    artifact_sha256: "44".repeat(32),
    run_id: "ae-run-2026",
  },
};

function makeModelStatus(
  modelKey: string,
  overrides: Partial<ModelStatusItem> = {},
): ModelStatusItem {
  const meta = MODEL_META[modelKey];
  return {
    model_key: modelKey,
    display_name: meta.display_name,
    model_type: meta.model_type,
    ready: true,
    status: "READY",
    artifact_path: `artifacts/models/${modelKey}/model.joblib`,
    manifest_path: `reports/models/${modelKey}_manifest.json`,
    artifact_sha256: meta.artifact_sha256,
    run_id: meta.run_id,
    decision_threshold: meta.threshold,
    score_semantics: meta.score_semantics,
    reason: null,
    ...overrides,
  };
}

function makeAllFourModels(): ModelStatusItem[] {
  return [
    makeModelStatus("random_forest"),
    makeModelStatus("xgboost"),
    makeModelStatus("isolation_forest"),
    makeModelStatus("autoencoder"),
  ];
}

function makeOodSummary(overrides: Partial<OodSummary> = {}): OodSummary {
  return {
    total_rows: 200,
    has_ood_warning: true,
    hard_violation_count: 1,
    shortcut_shift_count: 1,
    zero_ttl_count: 1,
    affected_rows_count: 2,
    shortcut_drift_ratio: 0.005,
    zero_ttl_ratio: 0.005,
    abstention_rate: 0.01,
    prediction_coverage: 0.99,
    ood_flags: ["ZERO_TTL_DRIFT", "PHYSICAL_INVARIANT"],
    hard_violation_indices: [10],
    zero_ttl_indices: [20],
    out_of_range_details: {},
    ...overrides,
  };
}

function makeBehavioralSummary(): BehavioralSummary {
  return {
    total_flows: 200,
    unique_src_ips: 8,
    unique_dst_ips: 4,
    unique_src_ports: 120,
    unique_dst_ports: 6,
    time_window_start_ms: 1700000000000,
    time_window_end_ms: 1700000050000,
    duration_ms: 50000,
    top_src_ips: [{ key: "10.0.0.1", count: 80, share: 0.4 }],
    top_dst_ips: [{ key: "192.168.1.10", count: 140, share: 0.7 }],
    top_dst_ports: [{ key: "443", count: 100, share: 0.5 }],
    protocol_counts: [{ key: "6", count: 180, share: 0.9 }],
    excluded_from_ml_features: ["src_ip", "dst_ip"],
    non_attribution_notice: "Non-attribution behavioral summary",
  };
}

function makeFlowPrediction(
  modelKey: string,
  overrides: Partial<CsvFlowPredictionItem> = {},
): CsvFlowPredictionItem {
  const meta = MODEL_META[modelKey];
  const isSupervised = meta.score_semantics === "attack_probability";
  return {
    row_id: 1,
    row_index: 0,
    predicted_label: 1,
    predicted_class: "Attack",
    attack_probability: isSupervised ? 0.91 : null,
    raw_anomaly_score: isSupervised ? 0.91 : modelKey === "isolation_forest" ? -0.0715 : 0.425,
    normalized_anomaly_score: isSupervised ? 0.91 : 0.88,
    decision_threshold: meta.threshold,
    score_type: meta.score_type,
    score_direction: meta.score_direction,
    risk_score: 91,
    risk_level: "CRITICAL",
    is_ood_flagged: false,
    ood_kind: null,
    ood_reason: null,
    flow_start_ms: 1700000000000,
    flow_end_ms: 1700000001000,
    src_ip: "10.0.0.5",
    dst_ip: "192.168.1.20",
    src_port: 51000,
    dst_port: 443,
    protocol: 6,
    flow_duration_ms: 1000,
    min_ttl: null,
    ...overrides,
  };
}

function makeInspectResponse(overrides: Partial<CsvInspectResponse> = {}): CsvInspectResponse {
  return {
    file_path: "data/demo/demo_flows.csv",
    file_name: "demo_flows.csv",
    file_sha256: SHA_CSV_A,
    file_size_bytes: 20480,
    row_count: 200,
    column_count: 24,
    ml_feature_count: 18,
    ml_features_valid: true,
    missing_ml_features: [],
    target_columns_excluded: [],
    trace_metadata_excluded: ["src_ip", "dst_ip"],
    other_extra_columns_excluded: [],
    non_finite_feature_cells: 0,
    ood_report: makeOodSummary(),
    behavioral_summary: makeBehavioralSummary(),
    models_status: makeAllFourModels(),
    preview_columns: ["row_id"],
    preview_rows: [{ row_id: 1 }],
    ...overrides,
  };
}

function makeAnalyzeResponse(
  modelKey: string,
  overrides: Partial<CsvAnalyzeResponse> = {},
): CsvAnalyzeResponse {
  const meta = MODEL_META[modelKey];
  const attackItem = makeFlowPrediction(modelKey, {
    row_id: 1,
    row_index: 0,
    predicted_label: 1,
    predicted_class: "Attack",
  });
  const benignItem = makeFlowPrediction(modelKey, {
    row_id: 2,
    row_index: 1,
    predicted_label: 0,
    predicted_class: "Benign",
    attack_probability: meta.score_semantics === "attack_probability" ? 0.08 : null,
    raw_anomaly_score:
      meta.score_semantics === "attack_probability"
        ? 0.08
        : modelKey === "isolation_forest"
          ? 0.045
          : 0.032,
    normalized_anomaly_score: meta.score_semantics === "attack_probability" ? 0.08 : 0.12,
    risk_score: 12,
    risk_level: "LOW",
  });
  const oodItem = makeFlowPrediction(modelKey, {
    row_id: 3,
    row_index: 2,
    predicted_label: null,
    predicted_class: "ABSTAINED_OOD",
    attack_probability: null,
    raw_anomaly_score: null,
    normalized_anomaly_score: null,
    risk_score: null,
    risk_level: "ABSTAINED_OOD",
    is_ood_flagged: true,
    ood_kind: "PHYSICAL_INVARIANT",
    ood_reason: "Hard physical flow invariant violation",
    min_ttl: null,
  });

  const defaultsByModel: Record<string, { attack: number; benign: number }> = {
    random_forest: { attack: 45, benign: 153 },
    xgboost: { attack: 48, benign: 150 },
    isolation_forest: { attack: 39, benign: 159 },
    autoencoder: { attack: 41, benign: 157 },
  };
  const counts = defaultsByModel[modelKey] ?? { attack: 40, benign: 158 };

  return {
    analysis_id: `csvrun_${modelKey}_1`,
    analyzed_at_utc: "2026-11-15T19:00:00Z",
    file_path: "data/demo/demo_flows.csv",
    file_sha256: SHA_CSV_A,
    model_key: modelKey,
    model_type: meta.model_type,
    run_id: meta.run_id,
    model_sha256: meta.artifact_sha256,
    preprocessor_sha256: SHA_PREP,
    inference_mode: "verified_pipeline",
    total_rows: 200,
    evaluated_rows: 198,
    abstained_rows: 2,
    prediction_coverage: 0.99,
    benign_count: counts.benign,
    attack_count: counts.attack,
    ood_flagged_count: 2,
    abstained_risk_count: 2,
    decision_threshold: meta.threshold,
    score_type: meta.score_type,
    score_direction: meta.score_direction,
    compatibility_gate: {
      source_id: "source:nf-v3",
      provenance_verified: true,
      model_key: modelKey,
      model_identifier: meta.run_id,
      eligible: true,
      eligibility_status: "ELIGIBLE",
      compatibility_status: "COMPATIBLE",
      reasons: [],
      warnings: [],
      missing_features: [],
    },
    ood_report: makeOodSummary(),
    behavioral_summary: makeBehavioralSummary(),
    security_notice: "Local-only verified inference",
    results: [attackItem, benignItem, oodItem],
    timeline: [],
    ...overrides,
  };
}

function makeEvaluateResponse(overrides: Partial<CsvEvaluateResponse> = {}): CsvEvaluateResponse {
  return {
    labels_path: "data/demo/demo_labels.csv",
    labels_sha256: SHA_LABELS_1,
    total_prediction_rows: 200,
    matched_label_rows: 200,
    matched_rows: 198,
    evaluated_rows: 198,
    unmatched_rows: 0,
    abstained_rows: 2,
    label_match_rate: 1.0,
    prediction_coverage: 0.99,
    accuracy: 0.9596,
    precision: 0.9375,
    recall: 0.9,
    f1: 0.9184,
    false_positive_rate: 0.0188,
    true_negative_rate: 0.9812,
    confusion_matrix: { tp: 45, fp: 3, tn: 145, fn: 5 },
    attack_breakdown: [
      { attack_category: "Exploits", total_count: 30, tp_count: 28, fn_count: 2, detection_rate: 0.9333 },
    ],
    scientific_notice: "OOD abstained rows excluded from confusion matrix.",
    ...overrides,
  };
}

function makeSimulationResponse(
  modelKey: string,
  analysisId: string,
  overrides: Partial<SecurityResponseSimulationResponse> = {},
): SecurityResponseSimulationResponse {
  const meta = MODEL_META[modelKey];
  return {
    simulation_id: `sim_${modelKey}_1`,
    created_at_utc: "2026-11-15T19:01:00Z",
    analysis_id: analysisId,
    source_csv_path: "data/demo/demo_flows.csv",
    source_csv_sha256: SHA_CSV_A,
    model_key: modelKey,
    model_type: meta.model_type,
    run_id: meta.run_id,
    model_sha256: meta.artifact_sha256,
    preprocessor_sha256: SHA_PREP,
    triggered_by: "desktop_operator",
    provenance_verification: "server_verified_analysis",
    execution_mode: "DRY_RUN_SIMULATION",
    action_status: "SIMULATED",
    recommendation_status: "RECOMMENDED",
    execution_status: "NOT_EXECUTED",
    executed: false,
    os_firewall_touched: false,
    real_key_rotated: false,
    overall_recommendation: "ISOLATE_RECOMMENDED",
    overall_severity: "CRITICAL",
    total_flows: 200,
    evaluated_flows: 198,
    ood_abstained_flows: 2,
    action_counts: {
      NO_ACTION: 150,
      MONITOR: 10,
      INVESTIGATE: 12,
      ISOLATE_RECOMMENDED: 28,
    },
    key_rotation_simulation: {
      decision: "SIMULATED_ROTATION_RECOMMENDED",
      recommended: true,
      would_rotate: true,
      simulation_status: "SIMULATED",
      executed: false,
      key_material_generated: false,
      real_key_modified: false,
      keyring_status: "DEFERRED_PRODUCTION_KEYRING",
      active_key_id: "key_v1",
      active_key_version: 1,
      simulated_next_version: 2,
      cooldown_seconds: 1,
      cooldown_remaining_seconds: 0,
      trigger_metrics: {},
      reason: "Dry-run only",
    },
    policy_summary: "Dry-run simulated",
    security_notice: "Dry-run notice",
    deferred_capabilities: ["os_firewall_command_execution"],
    provenance: {},
    recommendations: [],
    ...overrides,
  };
}

function createDeferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("F-04 Svelte 5 component rendering for ModelComparisonPanel, ModelReadinessPanel & EvaluationPanel", () => {
  it("1. renders all 4 models with READY status, score semantics, frozen thresholds, Attack/Benign, 99.0% (2 OOD), metrics, CM, batch SHA-256 badges, and switches Đang xem badge", () => {
    const models = makeAllFourModels();
    const analysesByModel: Record<string, CsvAnalyzeResponse> = {
      random_forest: makeAnalyzeResponse("random_forest"),
      xgboost: makeAnalyzeResponse("xgboost"),
      isolation_forest: makeAnalyzeResponse("isolation_forest"),
      autoencoder: makeAnalyzeResponse("autoencoder"),
    };
    const evaluationsByModel: Record<string, CsvEvaluateResponse> = {
      random_forest: makeEvaluateResponse(),
      xgboost: makeEvaluateResponse({
        precision: 0.9184,
        recall: 0.9,
        f1: 0.9091,
        false_positive_rate: 0.0256,
        confusion_matrix: { tp: 45, fp: 4, tn: 144, fn: 5 },
      }),
      isolation_forest: makeEvaluateResponse({
        precision: 0.8205,
        recall: 0.64,
        f1: 0.7191,
        false_positive_rate: 0.0473,
        confusion_matrix: { tp: 32, fp: 7, tn: 141, fn: 18 },
      }),
      autoencoder: makeEvaluateResponse({
        precision: 0.8537,
        recall: 0.7,
        f1: 0.7692,
        false_positive_rate: 0.0405,
        confusion_matrix: { tp: 35, fp: 6, tn: 142, fn: 15 },
      }),
    };

    const rfSelected = render(ModelComparisonPanel, {
      props: {
        models,
        selectedModel: "random_forest",
        analysesByModel,
        evaluationsByModel,
        errorsByModel: {},
        batchFileSha256: SHA_CSV_A,
        batchLabelsSha256: SHA_LABELS_1,
        canRunComparison: true,
        hasLabelsPath: true,
        busy: false,
        onSelectModel: () => {},
        onRunAllComparison: () => {},
        onEvaluateAllAnalyzed: () => {},
      },
    });

    expect(rfSelected.body).toContain("Random Forest");
    expect(rfSelected.body).toContain("XGBoost");
    expect(rfSelected.body).toContain("Isolation Forest");
    expect(rfSelected.body).toContain("Autoencoder");
    expect(rfSelected.body).toContain("Chạy So sánh 4 Model READY");
    expect(rfSelected.body).toContain("Đối chiếu Ground Truth (4 đã chạy)");
    expect(rfSelected.body).toContain("attack_probability [0..1]");
    expect(rfSelected.body).toContain("anomaly_score_unsupervised");
    expect(rfSelected.body).toContain("reconstruction_error");
    expect(rfSelected.body).toContain("0.5000");
    expect(rfSelected.body).toContain("0.5200");
    expect(rfSelected.body).toContain("-0.0335");
    expect(rfSelected.body).toContain("0.1842");
    expect(rfSelected.body).toContain("99.0% (2 OOD)");
    expect(rfSelected.body).toContain("93.75%");
    expect(rfSelected.body).toContain("90.00%");
    expect(rfSelected.body).toContain("91.84%");
    expect(rfSelected.body).toContain("1.88%");
    expect(rfSelected.body).toContain("45 / 3 / 145 / 5");
    expect(rfSelected.body).toContain(`CSV SHA-256: ${shortDigest(SHA_CSV_A)}`);
    expect(rfSelected.body).toContain(`Labels SHA-256: ${shortDigest(SHA_LABELS_1)}`);
    expect(rfSelected.body).toMatch(/<strong>Random Forest<\/strong>[\s\S]{0,120}Đang xem/);

    const aeSelected = render(ModelComparisonPanel, {
      props: {
        models,
        selectedModel: "autoencoder",
        analysesByModel,
        evaluationsByModel,
        errorsByModel: {},
        batchFileSha256: SHA_CSV_A,
        batchLabelsSha256: SHA_LABELS_1,
        canRunComparison: true,
        hasLabelsPath: true,
        busy: false,
        onSelectModel: () => {},
        onRunAllComparison: () => {},
        onEvaluateAllAnalyzed: () => {},
      },
    });

    expect(aeSelected.body).not.toMatch(/<strong>Random Forest<\/strong>[\s\S]{0,120}Đang xem/);
    expect(aeSelected.body).toMatch(/<strong>Autoencoder<\/strong>[\s\S]{0,120}Đang xem/);

    const readinessOut = render(ModelReadinessPanel, {
      props: { models, selectedModel: "isolation_forest", onSelect: () => {} },
    });
    expect(readinessOut.body).toContain("Random Forest");
    expect(readinessOut.body).toContain("Autoencoder");
    expect(readinessOut.body).toContain("Sai số tái tạo MSE (Autoencoder)");

    const evalOut = render(EvaluationPanel, {
      props: {
        labelsPath: "data/demo/demo_labels.csv",
        evaluating: false,
        evalResult: evaluationsByModel.random_forest,
        canEvaluate: true,
        onPickLabels: () => {},
        onUseDemoLabels: () => {},
        onRunEvaluate: () => {},
        onUpdateLabelsPath: () => {},
      },
    });
    expect(evalOut.body).toContain("45");
    expect(evalOut.body).toContain("Exploits");
    expect(evalOut.body).toContain(`SHA-256: ${shortDigest(SHA_LABELS_1)}`);
  });

  it("2. renders BLOCKED model, disabled-row, accurate READY button count, and partial failure LỖI API details", () => {
    const models = [
      makeModelStatus("random_forest"),
      makeModelStatus("xgboost"),
      makeModelStatus("isolation_forest"),
      makeModelStatus("autoencoder", {
        ready: false,
        status: "BLOCKED",
        artifact_sha256: null,
        run_id: null,
        decision_threshold: null,
        reason: "Missing autoencoder_manifest.json",
      }),
    ];

    const out = render(ModelComparisonPanel, {
      props: {
        models,
        selectedModel: "random_forest",
        analysesByModel: {
          random_forest: makeAnalyzeResponse("random_forest"),
          isolation_forest: makeAnalyzeResponse("isolation_forest"),
        },
        evaluationsByModel: {
          random_forest: makeEvaluateResponse(),
        },
        errorsByModel: {
          xgboost: "XGBoost artifact SHA-256 mismatch",
          isolation_forest: "Labels row_id lookup failed",
        },
        batchFileSha256: SHA_CSV_A,
        batchLabelsSha256: SHA_LABELS_1,
        canRunComparison: true,
        hasLabelsPath: true,
        busy: false,
        onSelectModel: () => {},
        onRunAllComparison: () => {},
        onEvaluateAllAnalyzed: () => {},
      },
    });

    expect(out.body).toContain("BLOCKED");
    expect(out.body).toContain("disabled-row");
    expect(out.body).toContain("Chạy So sánh 3 Model READY");
    expect(out.body).toContain("Đối chiếu Ground Truth (2 đã chạy)");
    expect(out.body).toContain("LỖI API");
    expect(out.body).toContain("XGBoost artifact SHA-256 mismatch");
    expect(out.body).toContain("Labels row_id lookup failed");
    // Isolation Forest kept its valid inference counts despite evaluate error
    expect(out.body).toContain(">39<");
    expect(out.body).toContain(">159<");
  });
});

describe("F-02 ComparisonBatchState, workflows, cache invalidation, and race conditions", () => {
  it("3. runs full 4-model comparison + evaluate + dry-run workflow and preserves coherent per-model slices", async () => {
    const models = makeAllFourModels();
    let state = createInitialComparisonState();
    let inspectData: CsvInspectResponse | null = null;

    const inspectCsv = vi.fn(async () => makeInspectResponse());
    const analyzeCsv = vi.fn(async ({ modelName }: { modelName: string }) =>
      makeAnalyzeResponse(modelName),
    );
    const evaluateCsv = vi.fn(async () => makeEvaluateResponse());
    const simulateDryRun = vi.fn(async (res: CsvAnalyzeResponse) =>
      makeSimulationResponse(res.model_key, res.analysis_id),
    );
    const deps: ComparisonWorkflowDeps = { inspectCsv, analyzeCsv, evaluateCsv, simulateDryRun };

    const result = await runAllModelsComparisonWorkflow({
      deps,
      getState: () => state,
      setState: (next) => {
        state = next;
      },
      onInspectData: (inspected) => {
        inspectData = inspected;
      },
      flowsPath: "data/demo/demo_flows.csv",
      labelsPath: "data/demo/demo_labels.csv",
      models,
      selectedModel: "random_forest",
      inspectData,
    });

    expect(result.aborted).toBe(false);
    expect(result.failures).toEqual([]);
    expect(result.errorSummary).toBeNull();
    expect(inspectCsv).toHaveBeenCalledTimes(1);
    expect(analyzeCsv).toHaveBeenCalledTimes(4);
    expect(evaluateCsv).toHaveBeenCalledTimes(4);
    expect(simulateDryRun).toHaveBeenCalledTimes(1);

    const coherentAnalyses = getBatchCoherentAnalyses(state);
    const coherentEvaluations = getBatchCoherentEvaluations(state);
    const coherentSims = getBatchCoherentSimulations(state);

    expect(Object.keys(coherentAnalyses)).toEqual([
      "random_forest",
      "xgboost",
      "isolation_forest",
      "autoencoder",
    ]);
    expect(Object.keys(coherentEvaluations)).toEqual([
      "random_forest",
      "xgboost",
      "isolation_forest",
      "autoencoder",
    ]);
    expect(state.evaluationAnalysisIdByModel.xgboost).toBe("csvrun_xgboost_1");
    expect(coherentSims.random_forest?.analysis_id).toBe("csvrun_random_forest_1");
  });

  it("4. clears all batch caches when CSV changes via path edit, inspect, or same-path disk SHA-256 change", () => {
    expect(normalizeDesktopPath("  ./data\\demo//demo_flows.csv/ ")).toBe("data/demo/demo_flows.csv");
    expect(normalizeDesktopPath("C:\\NetFlow\\Batch_A.csv")).toBe("c:/NetFlow/Batch_A.csv");
    expect(normalizeDesktopPath("/Tmp/CaseSensitive.csv")).toBe("/Tmp/CaseSensitive.csv");

    let state = createInitialComparisonState();
    state = invalidateForInspectResult(state, makeInspectResponse(), "data/demo/demo_flows.csv");
    state = invalidateForLabelsChange(state, "data/demo/demo_labels.csv");

    const rfA = makeAnalyzeResponse("random_forest", { file_sha256: SHA_CSV_A });
    const xgbA = makeAnalyzeResponse("xgboost", { file_sha256: SHA_CSV_A });
    state = recordModelAnalysis(state, rfA, "data/demo/demo_flows.csv", state.sessionEpoch).state;
    state = recordModelAnalysis(state, xgbA, "data/demo/demo_flows.csv", state.sessionEpoch).state;
    state = recordModelEvaluation(
      state,
      "random_forest",
      rfA.analysis_id,
      makeEvaluateResponse(),
      "data/demo/demo_labels.csv",
      state.sessionEpoch,
      state.labelsEpoch,
    ).state;
    state = recordModelSimulation(
      state,
      "random_forest",
      rfA.analysis_id,
      makeSimulationResponse("random_forest", rfA.analysis_id),
      state.sessionEpoch,
    ).state;

    // Equivalent normalized path must NOT invalidate cache
    const samePathState = invalidateForFlowsChange(state, "./data\\demo\\demo_flows.csv");
    expect(samePathState.sessionEpoch).toBe(state.sessionEpoch);
    expect(Object.keys(getBatchCoherentAnalyses(samePathState))).toEqual([
      "random_forest",
      "xgboost",
    ]);

    // Different CSV path wipes all cached batch artifacts and bumps both epochs
    const changedPathState = invalidateForFlowsChange(state, "data/other/batch_b.csv");
    expect(changedPathState.sessionEpoch).toBe(state.sessionEpoch + 1);
    expect(changedPathState.labelsEpoch).toBe(state.labelsEpoch + 1);
    expect(changedPathState.activeFileSha256).toBeNull();
    expect(changedPathState.analysesByModel).toEqual({});
    expect(changedPathState.evaluationsByModel).toEqual({});
    expect(changedPathState.evaluationAnalysisIdByModel).toEqual({});
    expect(changedPathState.simulationsByModel).toEqual({});
    expect(changedPathState.errorsByModel).toEqual({});
    expect(getBatchCoherentAnalyses(changedPathState)).toEqual({});
    expect(getBatchCoherentEvaluations(changedPathState)).toEqual({});

    // Re-inspecting clears prior caches and updates SHA
    const inspectedB = invalidateForInspectResult(
      state,
      makeInspectResponse({ file_sha256: SHA_CSV_B, file_path: "data/demo/demo_flows.csv" }),
      "data/demo/demo_flows.csv",
    );
    expect(inspectedB.activeFileSha256).toBe(SHA_CSV_B);
    expect(inspectedB.analysesByModel).toEqual({});

    // Same path on disk modified silently (file_sha256 changed from SHA_CSV_A to SHA_CSV_B)
    const isoB = makeAnalyzeResponse("isolation_forest", {
      analysis_id: "csvrun_iso_b",
      file_sha256: SHA_CSV_B,
    });
    const diskChanged = recordModelAnalysis(
      state,
      isoB,
      "data/demo/demo_flows.csv",
      state.sessionEpoch,
    );
    expect(diskChanged.accepted).toBe(true);
    expect(diskChanged.resetDueToFileShaChange).toBe(true);
    expect(diskChanged.state.activeFileSha256).toBe(SHA_CSV_B);
    expect(Object.keys(diskChanged.state.analysesByModel)).toEqual(["isolation_forest"]);
    expect(diskChanged.state.evaluationsByModel).toEqual({});
    expect(diskChanged.state.simulationsByModel).toEqual({});
    expect(Object.keys(getBatchCoherentAnalyses(diskChanged.state))).toEqual(["isolation_forest"]);
  });

  it("5. invalidates evaluations on labels change, disk labels_sha256 change, or new analysis_id without losing CSV analyses", () => {
    let state = createInitialComparisonState();
    state = invalidateForInspectResult(state, makeInspectResponse(), "data/demo/demo_flows.csv");
    state = invalidateForLabelsChange(state, "data/demo/demo_labels.csv");

    const rf1 = makeAnalyzeResponse("random_forest", { analysis_id: "run_rf_1" });
    const xgb1 = makeAnalyzeResponse("xgboost", { analysis_id: "run_xgb_1" });
    state = recordModelAnalysis(state, rf1, "data/demo/demo_flows.csv", state.sessionEpoch).state;
    state = recordModelAnalysis(state, xgb1, "data/demo/demo_flows.csv", state.sessionEpoch).state;
    state = recordModelEvaluation(
      state,
      "random_forest",
      "run_rf_1",
      makeEvaluateResponse({ labels_sha256: SHA_LABELS_1 }),
      "data/demo/demo_labels.csv",
      state.sessionEpoch,
      state.labelsEpoch,
    ).state;
    state = recordModelSimulation(
      state,
      "random_forest",
      "run_rf_1",
      makeSimulationResponse("random_forest", "run_rf_1"),
      state.sessionEpoch,
    ).state;

    // 5a. Changing labels path clears evaluations while preserving analyses and simulations
    const afterLabelPathChange = invalidateForLabelsChange(state, "data/demo/other_labels.csv");
    expect(afterLabelPathChange.labelsEpoch).toBe(state.labelsEpoch + 1);
    expect(afterLabelPathChange.sessionEpoch).toBe(state.sessionEpoch);
    expect(afterLabelPathChange.activeLabelsSha256).toBeNull();
    expect(afterLabelPathChange.evaluationsByModel).toEqual({});
    expect(afterLabelPathChange.evaluationAnalysisIdByModel).toEqual({});
    expect(Object.keys(afterLabelPathChange.analysesByModel)).toEqual(["random_forest", "xgboost"]);
    expect(Object.keys(afterLabelPathChange.simulationsByModel)).toEqual(["random_forest"]);

    // 5b. Keeping same labels path, disk labels_sha256 changes -> wipes prior model's old-SHA eval
    const afterDiskLabelsChange = recordModelEvaluation(
      state,
      "xgboost",
      "run_xgb_1",
      makeEvaluateResponse({ labels_sha256: SHA_LABELS_2 }),
      "data/demo/demo_labels.csv",
      state.sessionEpoch,
      state.labelsEpoch,
    );
    expect(afterDiskLabelsChange.accepted).toBe(true);
    expect(afterDiskLabelsChange.state.activeLabelsSha256).toBe(SHA_LABELS_2);
    expect(Object.keys(afterDiskLabelsChange.state.evaluationsByModel)).toEqual(["xgboost"]);
    expect(Object.keys(afterDiskLabelsChange.state.analysesByModel)).toEqual([
      "random_forest",
      "xgboost",
    ]);

    // 5c. Re-running RF produces run_rf_2 -> clears RF's old eval/sim and rejects late run_rf_1 eval
    const rf2 = makeAnalyzeResponse("random_forest", { analysis_id: "run_rf_2" });
    const afterRerun = recordModelAnalysis(
      state,
      rf2,
      "data/demo/demo_flows.csv",
      state.sessionEpoch,
    ).state;
    expect(afterRerun.evaluationsByModel.random_forest).toBeUndefined();
    expect(afterRerun.simulationsByModel.random_forest).toBeUndefined();

    const staleEvalAttempt = recordModelEvaluation(
      afterRerun,
      "random_forest",
      "run_rf_1",
      makeEvaluateResponse({ labels_sha256: SHA_LABELS_1 }),
      "data/demo/demo_labels.csv",
      afterRerun.sessionEpoch,
      afterRerun.labelsEpoch,
    );
    expect(staleEvalAttempt.accepted).toBe(false);
  });

  it("6. isolates partial API failures in both analyzeCsv and evaluateCsv while clearing stale cache on failed model", async () => {
    const models = makeAllFourModels();
    let state = createInitialComparisonState();
    const inspectRes = makeInspectResponse();
    state = invalidateForInspectResult(state, inspectRes, "data/demo/demo_flows.csv");
    state = invalidateForLabelsChange(state, "data/demo/demo_labels.csv");

    // Pre-populate stale XGBoost cache that should be wiped when XGBoost fails analyzeCsv
    const staleXgb = makeAnalyzeResponse("xgboost", { analysis_id: "old_xgb" });
    state = recordModelAnalysis(state, staleXgb, "data/demo/demo_flows.csv", state.sessionEpoch).state;
    state = recordModelEvaluation(
      state,
      "xgboost",
      "old_xgb",
      makeEvaluateResponse(),
      "data/demo/demo_labels.csv",
      state.sessionEpoch,
      state.labelsEpoch,
    ).state;

    const deps: ComparisonWorkflowDeps = {
      inspectCsv: vi.fn(async () => inspectRes),
      analyzeCsv: vi.fn(async ({ modelName }) => {
        if (modelName === "xgboost") {
          throw new Error("XGBoost artifact missing");
        }
        return makeAnalyzeResponse(modelName);
      }),
      evaluateCsv: vi.fn(async (_labelsPath, predictions) => {
        if (predictions[0]?.score_type === "isolation_forest_anomaly_score") {
          throw new Error("Labels row_id mismatch for isolation_forest");
        }
        return makeEvaluateResponse();
      }),
      simulateDryRun: vi.fn(async (res) => makeSimulationResponse(res.model_key, res.analysis_id)),
    };

    const result = await runAllModelsComparisonWorkflow({
      deps,
      getState: () => state,
      setState: (next) => {
        state = next;
      },
      flowsPath: "data/demo/demo_flows.csv",
      labelsPath: "data/demo/demo_labels.csv",
      models,
      selectedModel: "random_forest",
      inspectData: inspectRes,
    });

    expect(result.aborted).toBe(false);
    expect(result.failures).toEqual([
      { modelKey: "xgboost", stage: "analyze", message: "XGBoost artifact missing" },
      {
        modelKey: "isolation_forest",
        stage: "evaluate",
        message: "Labels row_id mismatch for isolation_forest",
      },
    ]);
    expect(result.errorSummary).toContain("xgboost (analyze)");
    expect(result.errorSummary).toContain("isolation_forest (evaluate)");

    // XGBoost stale cache was wiped; RF, IF, AE analyses remain; RF & AE evals succeed
    expect(state.analysesByModel.xgboost).toBeUndefined();
    expect(state.evaluationsByModel.xgboost).toBeUndefined();
    expect(Object.keys(state.analysesByModel)).toEqual([
      "random_forest",
      "isolation_forest",
      "autoencoder",
    ]);
    expect(Object.keys(state.evaluationsByModel)).toEqual(["random_forest", "autoencoder"]);
    expect(state.errorsByModel).toEqual({
      xgboost: "XGBoost artifact missing",
      isolation_forest: "Labels row_id mismatch for isolation_forest",
    });

    // Also test evaluateAllModelsWorkflow isolating a single evaluation failure and clearing stale eval
    state = recordModelEvaluation(
      state,
      "isolation_forest",
      state.analysesByModel.isolation_forest.analysis_id,
      makeEvaluateResponse(),
      "data/demo/demo_labels.csv",
      state.sessionEpoch,
      state.labelsEpoch,
    ).state;

    const evalAllResult = await evaluateAllModelsWorkflow({
      deps,
      getState: () => state,
      setState: (next) => {
        state = next;
      },
      labelsPath: "data/demo/demo_labels.csv",
    });

    expect(evalAllResult.aborted).toBe(false);
    expect(evalAllResult.evaluatedCount).toBe(2);
    expect(evalAllResult.failures).toEqual([
      {
        modelKey: "isolation_forest",
        stage: "evaluate",
        message: "Labels row_id mismatch for isolation_forest",
      },
    ]);
    expect(state.evaluationsByModel.isolation_forest).toBeUndefined();
    expect(state.errorsByModel.isolation_forest).toBe(
      "Labels row_id mismatch for isolation_forest",
    );
  });

  it("7. prevents async race conditions across epoch changes, backend restart, and model readiness updates", async () => {
    const inspectRes = makeInspectResponse();

    // 7a. Late analyzeCsv response after flows path changed
    let state: ComparisonBatchState = createInitialComparisonState();
    state = invalidateForInspectResult(state, inspectRes, "data/demo/csv_a.csv");
    const analyzeDeferred = createDeferred<CsvAnalyzeResponse>();
    const workflowPromise = runSingleModelAnalysisWorkflow({
      deps: {
        inspectCsv: vi.fn(async () => inspectRes),
        analyzeCsv: vi.fn(() => analyzeDeferred.promise),
        evaluateCsv: vi.fn(async () => makeEvaluateResponse()),
        simulateDryRun: vi.fn(async (res) => makeSimulationResponse(res.model_key, res.analysis_id)),
      },
      getState: () => state,
      setState: (next) => {
        state = next;
      },
      flowsPath: "data/demo/csv_a.csv",
      modelKey: "random_forest",
      inspectData: inspectRes,
    });

    state = invalidateForFlowsChange(state, "data/demo/csv_b.csv");
    analyzeDeferred.resolve(makeAnalyzeResponse("random_forest"));
    const workflowOutcome = await workflowPromise;
    expect(workflowOutcome.aborted).toBe(true);
    expect(state.analysesByModel).toEqual({});

    // 7b. Late evaluateCsv response after labels path changed
    state = invalidateForInspectResult(state, inspectRes, "data/demo/csv_b.csv");
    state = invalidateForLabelsChange(state, "data/demo/labels_1.csv");
    state = recordModelAnalysis(
      state,
      makeAnalyzeResponse("random_forest"),
      "data/demo/csv_b.csv",
      state.sessionEpoch,
    ).state;

    const evalDeferred = createDeferred<CsvEvaluateResponse>();
    const evalPromise = evaluateAllModelsWorkflow({
      deps: {
        inspectCsv: vi.fn(async () => inspectRes),
        analyzeCsv: vi.fn(async () => makeAnalyzeResponse("random_forest")),
        evaluateCsv: vi.fn(() => evalDeferred.promise),
        simulateDryRun: vi.fn(async (res) => makeSimulationResponse(res.model_key, res.analysis_id)),
      },
      getState: () => state,
      setState: (next) => {
        state = next;
      },
      labelsPath: "data/demo/labels_1.csv",
    });

    state = invalidateForLabelsChange(state, "data/demo/labels_2.csv");
    evalDeferred.resolve(makeEvaluateResponse({ labels_sha256: SHA_LABELS_1 }));
    const evalOutcome = await evalPromise;
    expect(evalOutcome.aborted).toBe(true);
    expect(state.evaluationsByModel).toEqual({});

    // 7c. Late simulation response after backend restart
    const rfRes = makeAnalyzeResponse("random_forest");
    state = recordModelAnalysis(state, rfRes, "data/demo/csv_b.csv", state.sessionEpoch).state;
    const simEpoch = state.sessionEpoch;
    const restarted = invalidateForBackendRestart(state);
    expect(restarted.sessionEpoch).toBe(simEpoch + 1);
    expect(restarted.activeFileSha256).toBeNull();
    expect(restarted.activeLabelsSha256).toBeNull();
    expect(restarted.analysesByModel).toEqual({});
    expect(restarted.activeFlowsPath).toBe("data/demo/csv_b.csv");
    expect(restarted.activeLabelsPath).toBe("data/demo/labels_2.csv");

    const lateSim = recordModelSimulation(
      restarted,
      "random_forest",
      rfRes.analysis_id,
      makeSimulationResponse("random_forest", rfRes.analysis_id),
      simEpoch,
    );
    expect(lateSim.accepted).toBe(false);

    // 7d. reconcileModelsReadiness drops models becoming BLOCKED or changing artifact_sha256
    let recState = invalidateForInspectResult(
      createInitialComparisonState(),
      inspectRes,
      "data/demo/demo_flows.csv",
    );
    recState = invalidateForLabelsChange(recState, "data/demo/demo_labels.csv");
    for (const k of ["random_forest", "xgboost", "isolation_forest"]) {
      const r = makeAnalyzeResponse(k);
      recState = recordModelAnalysis(recState, r, "data/demo/demo_flows.csv", recState.sessionEpoch)
        .state;
      recState = recordModelEvaluation(
        recState,
        k,
        r.analysis_id,
        makeEvaluateResponse(),
        "data/demo/demo_labels.csv",
        recState.sessionEpoch,
        recState.labelsEpoch,
      ).state;
    }
    recState = recordModelError(
      recState,
      "autoencoder",
      "transient error",
      recState.sessionEpoch,
      true,
    ).state;

    const updatedModels = [
      makeModelStatus("random_forest"),
      makeModelStatus("xgboost", { artifact_sha256: "99".repeat(32) }),
      makeModelStatus("isolation_forest", { ready: false, status: "BLOCKED" }),
      makeModelStatus("autoencoder", { ready: false, status: "BLOCKED" }),
    ];
    const reconciled = reconcileModelsReadiness(recState, updatedModels);
    expect(Object.keys(reconciled.analysesByModel)).toEqual(["random_forest"]);
    expect(Object.keys(reconciled.evaluationsByModel)).toEqual(["random_forest"]);
    expect(reconciled.errorsByModel.autoencoder).toBeUndefined();
  });

  it("8. preserves OOD abstention counts & coverage and never assigns attack_probability to unsupervised models", async () => {
    const models = makeAllFourModels();
    const inspectRes = makeInspectResponse();
    let state = createInitialComparisonState();

    const deps: ComparisonWorkflowDeps = {
      inspectCsv: vi.fn(async () => inspectRes),
      analyzeCsv: vi.fn(async ({ modelName }) => makeAnalyzeResponse(modelName)),
      evaluateCsv: vi.fn(async () => makeEvaluateResponse()),
      simulateDryRun: vi.fn(async (res) => makeSimulationResponse(res.model_key, res.analysis_id)),
    };

    await runAllModelsComparisonWorkflow({
      deps,
      getState: () => state,
      setState: (next) => {
        state = next;
      },
      flowsPath: "data/demo/demo_flows.csv",
      labelsPath: "data/demo/demo_labels.csv",
      models,
      selectedModel: "isolation_forest",
      inspectData: null,
    });

    const coherent = getBatchCoherentAnalyses(state);
    for (const key of ["random_forest", "xgboost", "isolation_forest", "autoencoder"]) {
      const az = coherent[key];
      expect(az.abstained_rows).toBe(2);
      expect(az.ood_flagged_count).toBe(2);
      expect(az.prediction_coverage).toBe(0.99);

      const oodRow = az.results.find((item) => item.is_ood_flagged);
      expect(oodRow?.predicted_class).toBe("ABSTAINED_OOD");
      expect(oodRow?.predicted_label).toBeNull();
      expect(oodRow?.attack_probability).toBeNull();
      expect(oodRow?.risk_score).toBeNull();
    }

    for (const unsupKey of ["isolation_forest", "autoencoder"]) {
      const az = coherent[unsupKey];
      expect(az.score_type).not.toBe("attack_probability");
      for (const item of az.results) {
        expect(item.attack_probability).toBeNull();
      }
      const nonOodAttack = az.results.find((r) => !r.is_ood_flagged && r.predicted_class === "Attack");
      expect(nonOodAttack).toBeDefined();
      expect(formatScoreSemantically(nonOodAttack!).probabilityText).toBe("N/A (Unsupervised)");
    }

    const rendered = render(ModelComparisonPanel, {
      props: {
        models,
        selectedModel: "isolation_forest",
        analysesByModel: coherent,
        evaluationsByModel: getBatchCoherentEvaluations(state),
        errorsByModel: state.errorsByModel,
        batchFileSha256: state.activeFileSha256,
        batchLabelsSha256: state.activeLabelsSha256,
        canRunComparison: true,
        hasLabelsPath: true,
        busy: false,
        onSelectModel: () => {},
        onRunAllComparison: () => {},
        onEvaluateAllAnalyzed: () => {},
      },
    });
    expect(rendered.body).toContain("99.0% (2 OOD)");
    expect(rendered.body).toContain("anomaly_score_unsupervised");
    expect(rendered.body).toContain("reconstruction_error");
  });
});
