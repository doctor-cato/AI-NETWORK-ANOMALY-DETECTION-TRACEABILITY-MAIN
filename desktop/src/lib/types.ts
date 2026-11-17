export interface BackendStatus {
  base_url: string;
  port: number;
  running: boolean;
  starting?: boolean;
  startup_stage?: string;
  startup_elapsed_ms?: number;
  managed_child: boolean;
  pid: number | null;
  backend_mode?: string;
  python_executable: string;
  repo_root: string;
  runtime_dir?: string;
  db_path: string;
  last_error: string | null;
}

export interface BackendLogSnapshot {
  starting: boolean;
  running: boolean;
  backend_mode: string;
  startup_stage: string;
  startup_elapsed_ms: number;
  port: number;
  pid: number | null;
  log_file_path: string;
  last_error: string | null;
  lines: string[];
}

export interface RuntimeDiagnostics {
  repo_root: string;
  repo_root_valid: boolean;
  runtime_dir: string;
  db_path: string;
  backend_mode: string;
  sidecar_ready: boolean;
  sidecar_executable: string | null;
  python_ready: boolean;
  python_executable: string | null;
  python_error: string | null;
  embedded_status: string;
  ready_models: string[];
  demo_flows_exists: boolean;
  demo_labels_exists: boolean;
}

export interface DemoPaths {
  flows_path: string;
  labels_path: string;
  flows_exists: boolean;
  labels_exists: boolean;
}

export interface HealthResponse {
  status: string;
  process_alive: boolean;
  model_ready: boolean;
  preprocessor_ready: boolean;
  db_ready: boolean;
  version: string;
  git_commit: string;
  timestamp: string;
  details: {
    db_backend: string;
    db_path: string;
    preprocessor_status: string;
    default_model: string;
    models_ready: Record<string, boolean>;
    [key: string]: unknown;
  };
}

export interface ModelStatusItem {
  model_key: string;
  display_name: string;
  model_type: string;
  ready: boolean;
  status: string;
  artifact_path: string | null;
  manifest_path: string | null;
  artifact_sha256: string | null;
  run_id: string | null;
  decision_threshold: number | null;
  score_semantics: string | null;
  reason: string | null;
}

export interface OodSummary {
  total_rows: number;
  has_ood_warning: boolean;
  hard_violation_count: number;
  shortcut_shift_count: number;
  zero_ttl_count: number;
  affected_rows_count: number;
  shortcut_drift_ratio: number;
  zero_ttl_ratio: number;
  abstention_rate: number;
  prediction_coverage: number;
  ood_flags: string[];
  hard_violation_indices: number[];
  zero_ttl_indices: number[];
  out_of_range_details: Record<string, number>;
}

export interface CompatibilityGateSummary {
  source_id?: string;
  provenance_verified?: boolean;
  model_key: string;
  model_identifier: string | null;
  eligible: boolean;
  eligibility_status: string;
  compatibility_status: string;
  reasons: string[];
  warnings: string[];
  missing_features: string[];
}

export interface BehavioralTopItem {
  key: string;
  count: number;
  share: number;
}

export interface BehavioralSummary {
  total_flows: number;
  unique_src_ips: number;
  unique_dst_ips: number;
  unique_src_ports: number;
  unique_dst_ports: number;
  time_window_start_ms: number | null;
  time_window_end_ms: number | null;
  duration_ms: number | null;
  top_src_ips: BehavioralTopItem[];
  top_dst_ips: BehavioralTopItem[];
  top_dst_ports: BehavioralTopItem[];
  protocol_counts: BehavioralTopItem[];
  excluded_from_ml_features: string[];
  non_attribution_notice: string;
}

export interface CsvInspectResponse {
  file_path: string;
  file_name: string;
  file_sha256: string;
  file_size_bytes: number;
  row_count: number;
  column_count: number;
  ml_feature_count: number;
  ml_features_valid: boolean;
  missing_ml_features: string[];
  target_columns_excluded: string[];
  trace_metadata_excluded: string[];
  other_extra_columns_excluded: string[];
  non_finite_feature_cells: number;
  ood_report: OodSummary;
  behavioral_summary: BehavioralSummary;
  models_status: ModelStatusItem[];
  preview_columns: string[];
  preview_rows: Record<string, unknown>[];
}

export interface CsvFlowPredictionItem {
  row_id: number | string;
  row_index: number;
  predicted_label: number | null;
  predicted_class: "Benign" | "Attack" | "ABSTAINED_OOD";
  attack_probability: number | null;
  raw_anomaly_score: number | null;
  normalized_anomaly_score: number | null;
  decision_threshold: number | null;
  score_type: string;
  score_direction: string;
  risk_score: number | null;
  risk_level: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "ABSTAINED_OOD" | "UNAVAILABLE";
  is_ood_flagged: boolean;
  ood_kind?: "ZERO_TTL_DRIFT" | "PHYSICAL_INVARIANT" | "COMBINED_OOD" | null;
  ood_reason: string | null;
  flow_start_ms: number | null;
  flow_end_ms: number | null;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: number | null;
  flow_duration_ms: number | null;
  min_ttl: number | null;
}

export interface CsvTimelineItem {
  sequence_index: number;
  row_id: number | string;
  flow_start_ms: number | null;
  flow_end_ms: number | null;
  timestamp_iso: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  predicted_class: string;
  risk_score: number | null;
  risk_level: string;
  is_ood_flagged: boolean;
  evidence_summary: string;
}

export interface CsvAnalyzeResponse {
  analysis_id: string;
  analyzed_at_utc: string;
  file_path: string;
  file_sha256: string;
  model_key: string;
  model_type: string;
  run_id: string | null;
  model_sha256: string | null;
  preprocessor_sha256: string | null;
  inference_mode: string;
  total_rows: number;
  evaluated_rows?: number;
  abstained_rows?: number;
  prediction_coverage?: number;
  benign_count: number;
  attack_count: number;
  ood_flagged_count: number;
  abstained_risk_count: number;
  decision_threshold: number | null;
  score_type: string;
  score_direction: string;
  compatibility_gate: CompatibilityGateSummary;
  ood_report: OodSummary;
  behavioral_summary: BehavioralSummary;
  security_notice: string;
  results: CsvFlowPredictionItem[];
  timeline: CsvTimelineItem[];
}

export interface AttackBreakdownRow {
  attack_category: string;
  total_count: number;
  tp_count: number;
  fn_count: number;
  detection_rate: number;
}

export interface CsvEvaluateResponse {
  labels_path: string;
  labels_sha256: string;
  total_prediction_rows?: number;
  matched_label_rows?: number;
  matched_rows: number;
  evaluated_rows?: number;
  unmatched_rows: number;
  abstained_rows?: number;
  label_match_rate?: number;
  prediction_coverage?: number;
  accuracy: number;
  precision: number;
  recall: number;
  f1: number;
  false_positive_rate: number;
  true_negative_rate: number;
  confusion_matrix: {
    tn: number;
    fp: number;
    fn: number;
    tp: number;
  };
  attack_breakdown: AttackBreakdownRow[];
  scientific_notice: string;
}

export interface CsvExportResponse {
  csv_path: string;
  metadata_path: string;
  csv_sha256: string;
  metadata_sha256: string;
  rows_exported: number;
  exported_at_utc: string;
}

export type ResponseAction = "NO_ACTION" | "MONITOR" | "INVESTIGATE" | "ISOLATE_RECOMMENDED";

export interface ResponseFlowRecommendationItem {
  row_id: number | string;
  row_index: number;
  predicted_class: string;
  is_ood_flagged: boolean;
  risk_score: number | null;
  risk_level: string;
  action: ResponseAction;
  severity: string;
  action_status: string;
  simulation_status: string;
  executed: boolean;
  execution_status: string;
  containment_allowed: boolean;
  reason: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  flow_start_ms: number | null;
  provenance: Record<string, unknown>;
}

export interface AdaptiveKeyRotationSimulation {
  decision: string;
  recommended: boolean;
  would_rotate: boolean;
  simulation_status: string;
  executed: boolean;
  key_material_generated: boolean;
  real_key_modified: boolean;
  keyring_status: string;
  active_key_id: string | null;
  active_key_version: number | null;
  simulated_next_version: number | null;
  cooldown_seconds: number;
  cooldown_remaining_seconds: number;
  trigger_metrics: Record<string, unknown>;
  reason: string;
}

export interface SecurityResponseSimulationResponse {
  simulation_id: string;
  created_at_utc: string;
  analysis_id: string | null;
  source_csv_path: string | null;
  source_csv_sha256: string | null;
  model_key: string;
  model_type: string;
  run_id: string | null;
  model_sha256: string | null;
  preprocessor_sha256: string | null;
  triggered_by: string;
  provenance_verification: string;
  execution_mode: string;
  action_status: string;
  recommendation_status: string;
  execution_status: string;
  executed: boolean;
  os_firewall_touched: boolean;
  real_key_rotated: boolean;
  overall_recommendation: ResponseAction;
  overall_severity: string;
  total_flows: number;
  evaluated_flows: number;
  ood_abstained_flows: number;
  action_counts: Record<string, number>;
  key_rotation_simulation: AdaptiveKeyRotationSimulation;
  policy_summary: string;
  security_notice: string;
  deferred_capabilities: string[];
  provenance: Record<string, unknown>;
  recommendations: ResponseFlowRecommendationItem[];
}

export interface SecuritySimulationHistoryItem {
  simulation_id: string;
  created_at_utc: string;
  analysis_id: string | null;
  source_csv_path: string | null;
  source_csv_sha256: string | null;
  model_key: string;
  model_type: string;
  run_id: string | null;
  triggered_by: string;
  provenance_verification: string;
  execution_mode: string;
  action_status: string;
  recommendation_status: string;
  execution_status: string;
  executed: boolean;
  os_firewall_touched: boolean;
  real_key_rotated: boolean;
  overall_recommendation: ResponseAction;
  overall_severity: string;
  total_flows: number;
  evaluated_flows: number;
  ood_abstained_flows: number;
  action_counts: Record<string, number>;
  key_rotation_simulation: AdaptiveKeyRotationSimulation;
  policy_summary: string;
}

export interface PaginatedSecuritySimulationsResponse {
  items: SecuritySimulationHistoryItem[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface SecuritySimulationExportResponse {
  simulation_id: string;
  json_path: string;
  metadata_path: string;
  json_sha256: string;
  metadata_sha256: string;
  exported_at_utc: string;
}

export interface TimelineStageItem {
  stage_id: string;
  phase: string;
  timestamp: string;
  source_entity: string;
  target_entity: string;
  title: string;
  description: string;
  confidence: number;
  is_observed: boolean;
  evidence_ids: string[];
  indicators: string[];
}

export interface TraceTimelineResponse {
  timeline_id: string;
  campaign_name: string;
  overall_confidence: number;
  start_time: string;
  end_time: string;
  entities_involved: string[];
  total_stages: number;
  stages: TimelineStageItem[];
}

export interface InvestigationReportResponse {
  report_id: string;
  incident_id: string;
  title: string;
  generated_at: string;
  severity: string;
  root_cause_summary: string;
  artifact_hash: string;
  timeline: TraceTimelineResponse;
  evidence_provenance: Array<Record<string, unknown>>;
  recommended_actions: string[];
  markdown_content: string;
}

export interface CryptoStatusResponse {
  active_key_id: string;
  algorithm: string;
  rotation_interval_minutes: number;
  adaptive_risk_threshold: number;
  cooldown_seconds: number;
  total_rotations: number;
  total_records_encrypted: number;
  recent_rotations: Array<{
    rotation_id: string;
    trigger: string;
    decision: string;
    new_key_id?: string;
    timestamp: string;
    reason?: string;
  }>;
}

export interface IncidentItem {
  incident_id: string;
  title: string;
  severity: string;
  status: string;
  anomaly_score: number;
  attack_type: string | null;
  created_at: string;
  updated_at: string;
  source_ip?: string;
  dest_ip?: string;
}

export interface PaginatedIncidentsResponse {
  items: IncidentItem[];
  total: number;
  limit: number;
  offset: number;
  has_more: boolean;
}

export interface EntityGraphNodeItem {
  node_id: string;
  kind: string;
  label: string;
  properties: Record<string, unknown>;
}

export interface EntityGraphEdgeItem {
  edge_id: string;
  source_id: string;
  target_id: string;
  relation_type: string;
  confidence: number;
  is_observed: boolean;
  evidence_id: string | null;
}

export interface TraceGraphResponse {
  node_count: number;
  edge_count: number;
  nodes: EntityGraphNodeItem[];
  edges: EntityGraphEdgeItem[];
}
