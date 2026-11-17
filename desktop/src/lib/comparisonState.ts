import type {
  CsvAnalyzeResponse,
  CsvEvaluateResponse,
  CsvFlowPredictionItem,
  CsvInspectResponse,
  ModelStatusItem,
  SecurityResponseSimulationResponse,
} from "./types";

export interface ComparisonBatchState {
  sessionEpoch: number;
  labelsEpoch: number;
  activeFlowsPath: string;
  activeFileSha256: string | null;
  activeLabelsPath: string;
  activeLabelsSha256: string | null;
  analysesByModel: Record<string, CsvAnalyzeResponse>;
  evaluationsByModel: Record<string, CsvEvaluateResponse>;
  evaluationAnalysisIdByModel: Record<string, string>;
  simulationsByModel: Record<string, SecurityResponseSimulationResponse>;
  errorsByModel: Record<string, string>;
}

export interface StateTransitionResult {
  state: ComparisonBatchState;
  accepted: boolean;
}

export interface AnalysisRecordResult extends StateTransitionResult {
  resetDueToFileShaChange: boolean;
}

export interface ComparisonWorkflowDeps {
  inspectCsv: (filePath: string, previewLimit?: number) => Promise<CsvInspectResponse>;
  analyzeCsv: (params: {
    filePath: string;
    modelName: string;
    createIncidents?: boolean;
    batchSize?: number;
  }) => Promise<CsvAnalyzeResponse>;
  evaluateCsv: (
    labelsPath: string,
    predictions: CsvFlowPredictionItem[],
  ) => Promise<CsvEvaluateResponse>;
  simulateDryRun: (res: CsvAnalyzeResponse) => Promise<SecurityResponseSimulationResponse>;
}

export interface WorkflowContext {
  deps: ComparisonWorkflowDeps;
  getState: () => ComparisonBatchState;
  setState: (next: ComparisonBatchState) => void;
  onProgress?: (message: string | null) => void;
  onInspectData?: (inspected: CsvInspectResponse | null) => void;
}

export interface ModelFailureItem {
  modelKey: string;
  stage: "analyze" | "evaluate";
  message: string;
}

export interface RunSingleModelParams extends WorkflowContext {
  flowsPath: string;
  modelKey: string;
  inspectData: CsvInspectResponse | null;
  onAnalysisRecorded?: (res: CsvAnalyzeResponse) => void;
}

export interface RunSingleModelResult {
  aborted: boolean;
  analysis: CsvAnalyzeResponse | null;
  simulation: SecurityResponseSimulationResponse | null;
  simulationWarning: string | null;
  error: string | null;
}

export interface RunAllModelsParams extends WorkflowContext {
  flowsPath: string;
  labelsPath?: string;
  models: ModelStatusItem[];
  selectedModel: string;
  inspectData: CsvInspectResponse | null;
}

export interface RunAllModelsResult {
  aborted: boolean;
  failures: ModelFailureItem[];
  errorSummary: string | null;
  activeAnalysis: CsvAnalyzeResponse | null;
  simulation: SecurityResponseSimulationResponse | null;
  simulationWarning: string | null;
}

export interface EvaluateAllModelsParams extends WorkflowContext {
  labelsPath: string;
}

export interface EvaluateAllModelsResult {
  aborted: boolean;
  evaluatedCount: number;
  failures: ModelFailureItem[];
  errorSummary: string | null;
}

export interface EvaluateSingleModelParams extends WorkflowContext {
  labelsPath: string;
  modelKey: string;
  analysis: CsvAnalyzeResponse;
}

export interface EvaluateSingleModelResult {
  aborted: boolean;
  evaluation: CsvEvaluateResponse | null;
  error: string | null;
}

function formatErr(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

function omitKey<T>(record: Record<string, T>, key: string): Record<string, T> {
  if (!(key in record)) return record;
  const { [key]: _removed, ...rest } = record;
  return rest;
}

function formatFailuresSummary(failures: ModelFailureItem[]): string | null {
  if (failures.length === 0) return null;
  return failures.map((f) => `${f.modelKey} (${f.stage}): ${f.message}`).join(" | ");
}

export function normalizeDesktopPath(p: string): string {
  const trimmed = p.trim().replace(/\\/g, "/").replace(/\/+/g, "/");
  if (!trimmed) return "";

  const withoutLeadingDot =
    trimmed.length > 2 && trimmed.startsWith("./")
      ? trimmed.replace(/^(\.\/)+/, "")
      : trimmed;

  const withNormalizedDrive = withoutLeadingDot.replace(
    /^([A-Za-z]):/,
    (_, drive: string) => `${drive.toLowerCase()}:`,
  );

  if (withNormalizedDrive.length > 1 && !/^[a-z]:\/$/.test(withNormalizedDrive)) {
    return withNormalizedDrive.replace(/\/+$/, "");
  }
  return withNormalizedDrive;
}

export function createInitialComparisonState(): ComparisonBatchState {
  return {
    sessionEpoch: 0,
    labelsEpoch: 0,
    activeFlowsPath: "",
    activeFileSha256: null,
    activeLabelsPath: "",
    activeLabelsSha256: null,
    analysesByModel: {},
    evaluationsByModel: {},
    evaluationAnalysisIdByModel: {},
    simulationsByModel: {},
    errorsByModel: {},
  };
}

export function invalidateForFlowsChange(
  state: ComparisonBatchState,
  nextFlowsPath: string,
): ComparisonBatchState {
  const trimmedNext = nextFlowsPath.trim();
  if (normalizeDesktopPath(trimmedNext) === normalizeDesktopPath(state.activeFlowsPath)) {
    if (trimmedNext === state.activeFlowsPath) return state;
    return {
      ...state,
      activeFlowsPath: trimmedNext,
    };
  }

  return {
    ...state,
    sessionEpoch: state.sessionEpoch + 1,
    labelsEpoch: state.labelsEpoch + 1,
    activeFlowsPath: trimmedNext,
    activeFileSha256: null,
    analysesByModel: {},
    evaluationsByModel: {},
    evaluationAnalysisIdByModel: {},
    simulationsByModel: {},
    errorsByModel: {},
  };
}

export function invalidateForInspectResult(
  state: ComparisonBatchState,
  inspected: CsvInspectResponse,
  rawInputPath: string,
): ComparisonBatchState {
  return {
    ...state,
    sessionEpoch: state.sessionEpoch + 1,
    labelsEpoch: state.labelsEpoch + 1,
    activeFlowsPath: rawInputPath.trim(),
    activeFileSha256: inspected.file_sha256,
    analysesByModel: {},
    evaluationsByModel: {},
    evaluationAnalysisIdByModel: {},
    simulationsByModel: {},
    errorsByModel: {},
  };
}

export function invalidateForLabelsChange(
  state: ComparisonBatchState,
  nextLabelsPath: string,
): ComparisonBatchState {
  const trimmedNext = nextLabelsPath.trim();
  if (normalizeDesktopPath(trimmedNext) === normalizeDesktopPath(state.activeLabelsPath)) {
    if (trimmedNext === state.activeLabelsPath) return state;
    return {
      ...state,
      activeLabelsPath: trimmedNext,
    };
  }

  // Drop prior evaluation-only errors for already-analyzed models when switching labels files,
  // while keeping analysis errors for models that failed inference.
  let nextErrors = state.errorsByModel;
  for (const key of Object.keys(state.errorsByModel)) {
    if (key in state.analysesByModel) {
      if (nextErrors === state.errorsByModel) {
        nextErrors = { ...state.errorsByModel };
      }
      delete nextErrors[key];
    }
  }

  return {
    ...state,
    labelsEpoch: state.labelsEpoch + 1,
    activeLabelsPath: trimmedNext,
    activeLabelsSha256: null,
    evaluationsByModel: {},
    evaluationAnalysisIdByModel: {},
    errorsByModel: nextErrors,
  };
}

export function invalidateForBackendRestart(
  state: ComparisonBatchState,
): ComparisonBatchState {
  return {
    ...state,
    sessionEpoch: state.sessionEpoch + 1,
    labelsEpoch: state.labelsEpoch + 1,
    activeFileSha256: null,
    activeLabelsSha256: null,
    analysesByModel: {},
    evaluationsByModel: {},
    evaluationAnalysisIdByModel: {},
    simulationsByModel: {},
    errorsByModel: {},
  };
}

export function reconcileModelsReadiness(
  state: ComparisonBatchState,
  models: ModelStatusItem[],
): ComparisonBatchState {
  const byKey = new Map(models.map((m) => [m.model_key, m]));
  const allCachedKeys = new Set([
    ...Object.keys(state.analysesByModel),
    ...Object.keys(state.evaluationsByModel),
    ...Object.keys(state.evaluationAnalysisIdByModel),
    ...Object.keys(state.simulationsByModel),
    ...Object.keys(state.errorsByModel),
  ]);

  const invalidKeys = new Set<string>();
  for (const key of allCachedKeys) {
    const status = byKey.get(key);
    if (!status || !status.ready) {
      invalidKeys.add(key);
      continue;
    }
    const az = state.analysesByModel[key];
    if (az && (status.artifact_sha256 ?? null) !== (az.model_sha256 ?? null)) {
      invalidKeys.add(key);
    }
  }

  if (invalidKeys.size === 0) {
    return state;
  }

  const nextAnalyses = { ...state.analysesByModel };
  const nextEvaluations = { ...state.evaluationsByModel };
  const nextEvalIds = { ...state.evaluationAnalysisIdByModel };
  const nextSimulations = { ...state.simulationsByModel };
  const nextErrors = { ...state.errorsByModel };

  for (const key of invalidKeys) {
    delete nextAnalyses[key];
    delete nextEvaluations[key];
    delete nextEvalIds[key];
    delete nextSimulations[key];
    delete nextErrors[key];
  }

  return {
    ...state,
    analysesByModel: nextAnalyses,
    evaluationsByModel: nextEvaluations,
    evaluationAnalysisIdByModel: nextEvalIds,
    simulationsByModel: nextSimulations,
    errorsByModel: nextErrors,
  };
}

export function recordModelAnalysis(
  state: ComparisonBatchState,
  res: CsvAnalyzeResponse,
  requestFlowsPath: string,
  requestSessionEpoch: number,
): AnalysisRecordResult {
  const normalizedActive = normalizeDesktopPath(state.activeFlowsPath);
  const normalizedReq = normalizeDesktopPath(requestFlowsPath);

  if (
    requestSessionEpoch !== state.sessionEpoch ||
    !normalizedActive ||
    normalizedReq !== normalizedActive
  ) {
    return { state, accepted: false, resetDueToFileShaChange: false };
  }

  const diskFileShaChanged = Boolean(
    state.activeFileSha256 && state.activeFileSha256 !== res.file_sha256,
  );

  if (diskFileShaChanged) {
    return {
      state: {
        ...state,
        activeFileSha256: res.file_sha256,
        analysesByModel: { [res.model_key]: res },
        evaluationsByModel: {},
        evaluationAnalysisIdByModel: {},
        simulationsByModel: {},
        errorsByModel: {},
      },
      accepted: true,
      resetDueToFileShaChange: true,
    };
  }

  return {
    state: {
      ...state,
      activeFileSha256: state.activeFileSha256 ?? res.file_sha256,
      analysesByModel: {
        ...state.analysesByModel,
        [res.model_key]: res,
      },
      evaluationsByModel: omitKey(state.evaluationsByModel, res.model_key),
      evaluationAnalysisIdByModel: omitKey(state.evaluationAnalysisIdByModel, res.model_key),
      simulationsByModel: omitKey(state.simulationsByModel, res.model_key),
      errorsByModel: omitKey(state.errorsByModel, res.model_key),
    },
    accepted: true,
    resetDueToFileShaChange: false,
  };
}

export function recordModelEvaluation(
  state: ComparisonBatchState,
  modelKey: string,
  analysisId: string,
  ev: CsvEvaluateResponse,
  requestLabelsPath: string,
  requestSessionEpoch: number,
  requestLabelsEpoch: number,
): StateTransitionResult {
  const normalizedActiveLabels = normalizeDesktopPath(state.activeLabelsPath);
  const normalizedReqLabels = normalizeDesktopPath(requestLabelsPath);
  const currentAnalysis = state.analysesByModel[modelKey];

  if (
    requestSessionEpoch !== state.sessionEpoch ||
    requestLabelsEpoch !== state.labelsEpoch ||
    !normalizedActiveLabels ||
    normalizedReqLabels !== normalizedActiveLabels ||
    !analysisId ||
    !currentAnalysis ||
    currentAnalysis.analysis_id !== analysisId
  ) {
    return { state, accepted: false };
  }

  const diskLabelsShaChanged = Boolean(
    state.activeLabelsSha256 && state.activeLabelsSha256 !== ev.labels_sha256,
  );

  if (diskLabelsShaChanged) {
    let nextErrors = omitKey(state.errorsByModel, modelKey);
    for (const key of Object.keys(nextErrors)) {
      if (key in state.analysesByModel) {
        if (nextErrors === state.errorsByModel) {
          nextErrors = { ...nextErrors };
        }
        delete nextErrors[key];
      }
    }
    return {
      state: {
        ...state,
        activeLabelsSha256: ev.labels_sha256,
        evaluationsByModel: { [modelKey]: ev },
        evaluationAnalysisIdByModel: { [modelKey]: analysisId },
        errorsByModel: nextErrors,
      },
      accepted: true,
    };
  }

  return {
    state: {
      ...state,
      activeLabelsSha256: state.activeLabelsSha256 ?? ev.labels_sha256,
      evaluationsByModel: {
        ...state.evaluationsByModel,
        [modelKey]: ev,
      },
      evaluationAnalysisIdByModel: {
        ...state.evaluationAnalysisIdByModel,
        [modelKey]: analysisId,
      },
      errorsByModel: omitKey(state.errorsByModel, modelKey),
    },
    accepted: true,
  };
}

export function recordModelSimulation(
  state: ComparisonBatchState,
  modelKey: string,
  analysisId: string,
  sim: SecurityResponseSimulationResponse,
  requestSessionEpoch: number,
): StateTransitionResult {
  const currentAnalysis = state.analysesByModel[modelKey];
  if (
    requestSessionEpoch !== state.sessionEpoch ||
    !analysisId ||
    !currentAnalysis ||
    currentAnalysis.analysis_id !== analysisId ||
    (sim.analysis_id !== null && sim.analysis_id !== analysisId)
  ) {
    return { state, accepted: false };
  }

  return {
    state: {
      ...state,
      simulationsByModel: {
        ...state.simulationsByModel,
        [modelKey]: sim,
      },
    },
    accepted: true,
  };
}

export function recordModelError(
  state: ComparisonBatchState,
  modelKey: string,
  errMessage: string,
  requestSessionEpoch: number,
  clearAnalysis: boolean,
  clearEvaluation = false,
): StateTransitionResult {
  if (requestSessionEpoch !== state.sessionEpoch) {
    return { state, accepted: false };
  }

  const nextErrors = {
    ...state.errorsByModel,
    [modelKey]: errMessage,
  };

  if (clearAnalysis) {
    return {
      state: {
        ...state,
        analysesByModel: omitKey(state.analysesByModel, modelKey),
        evaluationsByModel: omitKey(state.evaluationsByModel, modelKey),
        evaluationAnalysisIdByModel: omitKey(state.evaluationAnalysisIdByModel, modelKey),
        simulationsByModel: omitKey(state.simulationsByModel, modelKey),
        errorsByModel: nextErrors,
      },
      accepted: true,
    };
  }

  if (clearEvaluation) {
    return {
      state: {
        ...state,
        evaluationsByModel: omitKey(state.evaluationsByModel, modelKey),
        evaluationAnalysisIdByModel: omitKey(state.evaluationAnalysisIdByModel, modelKey),
        errorsByModel: nextErrors,
      },
      accepted: true,
    };
  }

  return {
    state: {
      ...state,
      errorsByModel: nextErrors,
    },
    accepted: true,
  };
}

export function getBatchCoherentAnalyses(
  state: ComparisonBatchState,
): Record<string, CsvAnalyzeResponse> {
  if (!state.activeFileSha256) return {};
  const coherent: Record<string, CsvAnalyzeResponse> = {};
  for (const [modelKey, az] of Object.entries(state.analysesByModel)) {
    if (az && az.model_key === modelKey && az.file_sha256 === state.activeFileSha256) {
      coherent[modelKey] = az;
    }
  }
  return coherent;
}

export function getBatchCoherentEvaluations(
  state: ComparisonBatchState,
): Record<string, CsvEvaluateResponse> {
  if (!state.activeLabelsSha256) return {};
  const coherentAnalyses = getBatchCoherentAnalyses(state);
  const coherent: Record<string, CsvEvaluateResponse> = {};
  for (const [modelKey, ev] of Object.entries(state.evaluationsByModel)) {
    const az = coherentAnalyses[modelKey];
    if (
      az &&
      ev &&
      state.evaluationAnalysisIdByModel[modelKey] === az.analysis_id &&
      ev.labels_sha256 === state.activeLabelsSha256
    ) {
      coherent[modelKey] = ev;
    }
  }
  return coherent;
}

export function getBatchCoherentSimulations(
  state: ComparisonBatchState,
): Record<string, SecurityResponseSimulationResponse> {
  const coherentAnalyses = getBatchCoherentAnalyses(state);
  const coherent: Record<string, SecurityResponseSimulationResponse> = {};
  for (const [modelKey, sim] of Object.entries(state.simulationsByModel)) {
    const az = coherentAnalyses[modelKey];
    if (az && sim && (sim.analysis_id === null || sim.analysis_id === az.analysis_id)) {
      coherent[modelKey] = sim;
    }
  }
  return coherent;
}

async function ensureBatchInspected(params: {
  flowsPath: string;
  inspectData: CsvInspectResponse | null;
  deps: Pick<ComparisonWorkflowDeps, "inspectCsv">;
  getState: () => ComparisonBatchState;
  setState: (next: ComparisonBatchState) => void;
  onProgress?: (message: string | null) => void;
  onInspectData?: (inspected: CsvInspectResponse | null) => void;
}): Promise<{ aborted: boolean; error: string | null }> {
  const trimmedFlowsPath = params.flowsPath.trim();
  const state = params.getState();

  const needsInspect =
    !params.inspectData ||
    !state.activeFileSha256 ||
    params.inspectData.file_sha256 !== state.activeFileSha256 ||
    normalizeDesktopPath(state.activeFlowsPath) !== normalizeDesktopPath(trimmedFlowsPath);

  if (!needsInspect) {
    return { aborted: false, error: null };
  }

  const preInspectEpoch = state.sessionEpoch;
  params.onProgress?.("Đang kiểm tra schema 18 ML features (v2) & OOD...");
  try {
    const inspected = await params.deps.inspectCsv(trimmedFlowsPath, 20);
    if (params.getState().sessionEpoch !== preInspectEpoch) {
      return { aborted: true, error: null };
    }
    let nextState = invalidateForInspectResult(params.getState(), inspected, trimmedFlowsPath);
    if (inspected.models_status.length > 0) {
      nextState = reconcileModelsReadiness(nextState, inspected.models_status);
    }
    params.setState(nextState);
    params.onInspectData?.(inspected);
    return { aborted: false, error: null };
  } catch (err) {
    if (params.getState().sessionEpoch !== preInspectEpoch) {
      return { aborted: true, error: null };
    }
    return { aborted: false, error: formatErr(err) };
  }
}

export async function runSingleModelAnalysisWorkflow(
  params: RunSingleModelParams,
): Promise<RunSingleModelResult> {
  const trimmedFlowsPath = params.flowsPath.trim();
  if (!trimmedFlowsPath) {
    return {
      aborted: false,
      analysis: null,
      simulation: null,
      simulationWarning: null,
      error: "Vui lòng chọn hoặc nhập đường dẫn tệp NetFlow CSV.",
    };
  }

  if (
    normalizeDesktopPath(params.getState().activeFlowsPath) !==
    normalizeDesktopPath(trimmedFlowsPath)
  ) {
    params.setState(invalidateForFlowsChange(params.getState(), trimmedFlowsPath));
    params.onInspectData?.(null);
  }

  const inspectStep = await ensureBatchInspected({
    flowsPath: trimmedFlowsPath,
    inspectData: params.inspectData,
    deps: params.deps,
    getState: params.getState,
    setState: params.setState,
    onProgress: params.onProgress,
    onInspectData: params.onInspectData,
  });
  if (inspectStep.aborted) {
    return {
      aborted: true,
      analysis: null,
      simulation: null,
      simulationWarning: null,
      error: null,
    };
  }
  if (inspectStep.error) {
    return {
      aborted: false,
      analysis: null,
      simulation: null,
      simulationWarning: null,
      error: inspectStep.error,
    };
  }

  const workEpoch = params.getState().sessionEpoch;
  params.onProgress?.(`Đang chạy mô hình ${params.modelKey} qua InferencePipeline...`);

  let res: CsvAnalyzeResponse;
  try {
    res = await params.deps.analyzeCsv({
      filePath: trimmedFlowsPath,
      modelName: params.modelKey,
      createIncidents: false,
      batchSize: 500,
    });
  } catch (err) {
    const msg = formatErr(err);
    const errRecorded = recordModelError(
      params.getState(),
      params.modelKey,
      msg,
      workEpoch,
      true,
    );
    if (!errRecorded.accepted) {
      return {
        aborted: true,
        analysis: null,
        simulation: null,
        simulationWarning: null,
        error: null,
      };
    }
    params.setState(errRecorded.state);
    return {
      aborted: false,
      analysis: null,
      simulation: null,
      simulationWarning: null,
      error: msg,
    };
  }

  const recorded = recordModelAnalysis(params.getState(), res, trimmedFlowsPath, workEpoch);
  if (!recorded.accepted) {
    return {
      aborted: true,
      analysis: null,
      simulation: null,
      simulationWarning: null,
      error: null,
    };
  }
  params.setState(recorded.state);
  if (recorded.resetDueToFileShaChange) {
    params.onInspectData?.(null);
  }
  params.onAnalysisRecorded?.(res);

  try {
    const simRes = await params.deps.simulateDryRun(res);
    const simRecorded = recordModelSimulation(
      params.getState(),
      params.modelKey,
      res.analysis_id,
      simRes,
      workEpoch,
    );
    if (!simRecorded.accepted) {
      return {
        aborted: true,
        analysis: res,
        simulation: null,
        simulationWarning: null,
        error: null,
      };
    }
    params.setState(simRecorded.state);
    return {
      aborted: false,
      analysis: res,
      simulation: simRes,
      simulationWarning: null,
      error: null,
    };
  } catch (simErr) {
    if (params.getState().sessionEpoch !== workEpoch) {
      return {
        aborted: true,
        analysis: res,
        simulation: null,
        simulationWarning: null,
        error: null,
      };
    }
    return {
      aborted: false,
      analysis: res,
      simulation: null,
      simulationWarning: `Phân tích CSV đã hoàn tất, nhưng mô phỏng Dry-Run (#27) chưa thể chạy: ${formatErr(simErr)}`,
      error: null,
    };
  }
}

export async function runAllModelsComparisonWorkflow(
  params: RunAllModelsParams,
): Promise<RunAllModelsResult> {
  const trimmedFlowsPath = params.flowsPath.trim();
  if (!trimmedFlowsPath) {
    return {
      aborted: false,
      failures: [],
      errorSummary: "Vui lòng chọn hoặc nhập đường dẫn tệp NetFlow CSV.",
      activeAnalysis: null,
      simulation: null,
      simulationWarning: null,
    };
  }

  const readyList = params.models.filter((m) => m.ready);
  if (readyList.length === 0) {
    return {
      aborted: false,
      failures: [],
      errorSummary: "Không có mô hình nào ở trạng thái READY để so sánh.",
      activeAnalysis: null,
      simulation: null,
      simulationWarning: null,
    };
  }

  if (
    normalizeDesktopPath(params.getState().activeFlowsPath) !==
    normalizeDesktopPath(trimmedFlowsPath)
  ) {
    params.setState(invalidateForFlowsChange(params.getState(), trimmedFlowsPath));
    params.onInspectData?.(null);
  }

  if (params.labelsPath !== undefined) {
    const trimmedLabelsPath = params.labelsPath.trim();
    if (
      normalizeDesktopPath(params.getState().activeLabelsPath) !==
      normalizeDesktopPath(trimmedLabelsPath)
    ) {
      params.setState(invalidateForLabelsChange(params.getState(), trimmedLabelsPath));
    }
  }

  const inspectStep = await ensureBatchInspected({
    flowsPath: trimmedFlowsPath,
    inspectData: params.inspectData,
    deps: params.deps,
    getState: params.getState,
    setState: params.setState,
    onProgress: params.onProgress,
    onInspectData: params.onInspectData,
  });
  if (inspectStep.aborted) {
    return {
      aborted: true,
      failures: [],
      errorSummary: null,
      activeAnalysis: null,
      simulation: null,
      simulationWarning: null,
    };
  }
  if (inspectStep.error) {
    return {
      aborted: false,
      failures: [],
      errorSummary: inspectStep.error,
      activeAnalysis: null,
      simulation: null,
      simulationWarning: null,
    };
  }

  const batchEpoch = params.getState().sessionEpoch;
  const failures: ModelFailureItem[] = [];

  for (const m of readyList) {
    if (params.getState().sessionEpoch !== batchEpoch) {
      return {
        aborted: true,
        failures,
        errorSummary: formatFailuresSummary(failures),
        activeAnalysis: null,
        simulation: null,
        simulationWarning: null,
      };
    }

    params.onProgress?.(`Đang chạy suy luận ${m.display_name} (${m.model_key})...`);
    let res: CsvAnalyzeResponse;
    try {
      res = await params.deps.analyzeCsv({
        filePath: trimmedFlowsPath,
        modelName: m.model_key,
        createIncidents: false,
        batchSize: 500,
      });
    } catch (analyzeErr) {
      if (params.getState().sessionEpoch !== batchEpoch) {
        return {
          aborted: true,
          failures,
          errorSummary: formatFailuresSummary(failures),
          activeAnalysis: null,
          simulation: null,
          simulationWarning: null,
        };
      }
      const msg = formatErr(analyzeErr);
      const errRecorded = recordModelError(
        params.getState(),
        m.model_key,
        msg,
        batchEpoch,
        true,
      );
      if (errRecorded.accepted) {
        params.setState(errRecorded.state);
      }
      failures.push({ modelKey: m.model_key, stage: "analyze", message: msg });
      continue;
    }

    if (params.getState().sessionEpoch !== batchEpoch) {
      return {
        aborted: true,
        failures,
        errorSummary: formatFailuresSummary(failures),
        activeAnalysis: null,
        simulation: null,
        simulationWarning: null,
      };
    }

    const recorded = recordModelAnalysis(params.getState(), res, trimmedFlowsPath, batchEpoch);
    if (!recorded.accepted) {
      return {
        aborted: true,
        failures,
        errorSummary: formatFailuresSummary(failures),
        activeAnalysis: null,
        simulation: null,
        simulationWarning: null,
      };
    }
    params.setState(recorded.state);
    if (recorded.resetDueToFileShaChange) {
      params.onInspectData?.(null);
    }

    const stateBeforeEval = params.getState();
    const evalLabelsPath = stateBeforeEval.activeLabelsPath;
    const evalLabelsEpoch = stateBeforeEval.labelsEpoch;

    if (evalLabelsPath.trim()) {
      params.onProgress?.(`Đang đối chiếu Ground Truth cho ${m.display_name}...`);
      try {
        const ev = await params.deps.evaluateCsv(evalLabelsPath, res.results);
        if (params.getState().sessionEpoch !== batchEpoch) {
          return {
            aborted: true,
            failures,
            errorSummary: formatFailuresSummary(failures),
            activeAnalysis: null,
            simulation: null,
            simulationWarning: null,
          };
        }
        const evRecorded = recordModelEvaluation(
          params.getState(),
          m.model_key,
          res.analysis_id,
          ev,
          evalLabelsPath,
          batchEpoch,
          evalLabelsEpoch,
        );
        if (evRecorded.accepted) {
          params.setState(evRecorded.state);
        }
      } catch (evalErr) {
        if (params.getState().sessionEpoch !== batchEpoch) {
          return {
            aborted: true,
            failures,
            errorSummary: formatFailuresSummary(failures),
            activeAnalysis: null,
            simulation: null,
            simulationWarning: null,
          };
        }
        if (params.getState().labelsEpoch === evalLabelsEpoch) {
          const msg = formatErr(evalErr);
          const errRecorded = recordModelError(
            params.getState(),
            m.model_key,
            msg,
            batchEpoch,
            false,
            true,
          );
          if (errRecorded.accepted) {
            params.setState(errRecorded.state);
          }
          failures.push({ modelKey: m.model_key, stage: "evaluate", message: msg });
        }
      }
    }
  }

  const finalState = params.getState();
  if (finalState.sessionEpoch !== batchEpoch) {
    return {
      aborted: true,
      failures,
      errorSummary: formatFailuresSummary(failures),
      activeAnalysis: null,
      simulation: null,
      simulationWarning: null,
    };
  }

  const coherent = getBatchCoherentAnalyses(finalState);
  const activeRes =
    coherent[params.selectedModel] ??
    readyList.map((m) => coherent[m.model_key]).find(Boolean) ??
    null;

  let simulation: SecurityResponseSimulationResponse | null = null;
  let simulationWarning: string | null = null;

  if (activeRes) {
    try {
      const simRes = await params.deps.simulateDryRun(activeRes);
      const simRecorded = recordModelSimulation(
        params.getState(),
        activeRes.model_key,
        activeRes.analysis_id,
        simRes,
        batchEpoch,
      );
      if (!simRecorded.accepted) {
        return {
          aborted: true,
          failures,
          errorSummary: formatFailuresSummary(failures),
          activeAnalysis: activeRes,
          simulation: null,
          simulationWarning: null,
        };
      }
      params.setState(simRecorded.state);
      simulation = simRes;
    } catch (simErr) {
      if (params.getState().sessionEpoch !== batchEpoch) {
        return {
          aborted: true,
          failures,
          errorSummary: formatFailuresSummary(failures),
          activeAnalysis: activeRes,
          simulation: null,
          simulationWarning: null,
        };
      }
      simulationWarning = `So sánh ${readyList.length} model đã hoàn tất, nhưng mô phỏng Dry-Run (#27) chưa thể chạy: ${formatErr(simErr)}`;
    }
  }

  return {
    aborted: false,
    failures,
    errorSummary: formatFailuresSummary(failures),
    activeAnalysis: activeRes,
    simulation,
    simulationWarning,
  };
}

export async function evaluateAllModelsWorkflow(
  params: EvaluateAllModelsParams,
): Promise<EvaluateAllModelsResult> {
  const trimmedLabelsPath = params.labelsPath.trim();
  if (!trimmedLabelsPath) {
    return {
      aborted: false,
      evaluatedCount: 0,
      failures: [],
      errorSummary: null,
    };
  }

  if (
    normalizeDesktopPath(params.getState().activeLabelsPath) !==
    normalizeDesktopPath(trimmedLabelsPath)
  ) {
    params.setState(invalidateForLabelsChange(params.getState(), trimmedLabelsPath));
  }

  const startState = params.getState();
  const startSessionEpoch = startState.sessionEpoch;
  const startLabelsEpoch = startState.labelsEpoch;
  const coherentEntries = Object.entries(getBatchCoherentAnalyses(startState));

  if (coherentEntries.length === 0) {
    return {
      aborted: false,
      evaluatedCount: 0,
      failures: [],
      errorSummary: null,
    };
  }

  const failures: ModelFailureItem[] = [];
  let evaluatedCount = 0;

  for (const [modelKey, az] of coherentEntries) {
    const beforeState = params.getState();
    if (
      beforeState.sessionEpoch !== startSessionEpoch ||
      beforeState.labelsEpoch !== startLabelsEpoch
    ) {
      return {
        aborted: true,
        evaluatedCount,
        failures,
        errorSummary: formatFailuresSummary(failures),
      };
    }

    if (beforeState.analysesByModel[modelKey]?.analysis_id !== az.analysis_id) {
      continue;
    }

    params.onProgress?.(`Đang đối chiếu Ground Truth cho ${modelKey}...`);
    try {
      const ev = await params.deps.evaluateCsv(trimmedLabelsPath, az.results);
      const afterState = params.getState();
      if (
        afterState.sessionEpoch !== startSessionEpoch ||
        afterState.labelsEpoch !== startLabelsEpoch
      ) {
        return {
          aborted: true,
          evaluatedCount,
          failures,
          errorSummary: formatFailuresSummary(failures),
        };
      }

      const recorded = recordModelEvaluation(
        afterState,
        modelKey,
        az.analysis_id,
        ev,
        trimmedLabelsPath,
        startSessionEpoch,
        startLabelsEpoch,
      );
      if (recorded.accepted) {
        params.setState(recorded.state);
        evaluatedCount += 1;
      }
    } catch (err) {
      const afterErrState = params.getState();
      if (
        afterErrState.sessionEpoch !== startSessionEpoch ||
        afterErrState.labelsEpoch !== startLabelsEpoch
      ) {
        return {
          aborted: true,
          evaluatedCount,
          failures,
          errorSummary: formatFailuresSummary(failures),
        };
      }
      const msg = formatErr(err);
      const errRecorded = recordModelError(
        afterErrState,
        modelKey,
        msg,
        startSessionEpoch,
        false,
        true,
      );
      if (errRecorded.accepted) {
        params.setState(errRecorded.state);
      }
      failures.push({ modelKey, stage: "evaluate", message: msg });
    }
  }

  return {
    aborted: false,
    evaluatedCount,
    failures,
    errorSummary: formatFailuresSummary(failures),
  };
}

export async function evaluateSingleModelWorkflow(
  params: EvaluateSingleModelParams,
): Promise<EvaluateSingleModelResult> {
  const trimmedLabelsPath = params.labelsPath.trim();
  if (!trimmedLabelsPath) {
    return { aborted: false, evaluation: null, error: null };
  }

  if (
    normalizeDesktopPath(params.getState().activeLabelsPath) !==
    normalizeDesktopPath(trimmedLabelsPath)
  ) {
    params.setState(invalidateForLabelsChange(params.getState(), trimmedLabelsPath));
  }

  const startState = params.getState();
  const startSessionEpoch = startState.sessionEpoch;
  const startLabelsEpoch = startState.labelsEpoch;

  try {
    const ev = await params.deps.evaluateCsv(trimmedLabelsPath, params.analysis.results);
    const afterState = params.getState();
    if (
      afterState.sessionEpoch !== startSessionEpoch ||
      afterState.labelsEpoch !== startLabelsEpoch
    ) {
      return { aborted: true, evaluation: null, error: null };
    }
    const recorded = recordModelEvaluation(
      afterState,
      params.modelKey,
      params.analysis.analysis_id,
      ev,
      trimmedLabelsPath,
      startSessionEpoch,
      startLabelsEpoch,
    );
    if (!recorded.accepted) {
      return { aborted: true, evaluation: null, error: null };
    }
    params.setState(recorded.state);
    return { aborted: false, evaluation: ev, error: null };
  } catch (err) {
    const afterErrState = params.getState();
    if (
      afterErrState.sessionEpoch !== startSessionEpoch ||
      afterErrState.labelsEpoch !== startLabelsEpoch
    ) {
      return { aborted: true, evaluation: null, error: null };
    }
    const msg = formatErr(err);
    const errRecorded = recordModelError(
      afterErrState,
      params.modelKey,
      msg,
      startSessionEpoch,
      false,
      true,
    );
    if (errRecorded.accepted) {
      params.setState(errRecorded.state);
    }
    return { aborted: false, evaluation: null, error: msg };
  }
}
