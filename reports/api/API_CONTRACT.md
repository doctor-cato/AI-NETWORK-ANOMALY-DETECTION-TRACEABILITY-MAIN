# FastAPI Service Integration Contract

**API Title**: AI Network Anomaly Detection & Traceability API
**Version**: 0.1.0
**Total Endpoints**: 18

## Endpoints Specification

| Method | Path | Summary | Tags |
|---|---|---|---|
| `POST` | `/api/v1/analyze` | Run anomaly detection on network flows | Analysis |
| `POST` | `/api/v1/csv/analyze` | Run verified batch inference on local NetFlow CSV with OOD, timeline, and risk scoring | Models & CSV |
| `POST` | `/api/v1/csv/evaluate` | Evaluate CSV predictions against a separate Ground Truth CSV | Models & CSV |
| `POST` | `/api/v1/csv/export` | Export predictions CSV and companion SHA-256 provenance JSON | Models & CSV |
| `POST` | `/api/v1/csv/inspect` | Validate CSV contract, exclude leakage targets/metadata, and preview rows | Models & CSV |
| `GET` | `/api/v1/health` | System and artifact health check (v1) | System |
| `GET` | `/api/v1/incidents` | List detected security incidents | Incidents |
| `POST` | `/api/v1/incidents` | Create an incident alert manually | Incidents |
| `GET` | `/api/v1/incidents/{incident_id}` | Get incident details by ID | Incidents |
| `PATCH` | `/api/v1/incidents/{incident_id}` | Update incident status or details | Incidents |
| `POST` | `/api/v1/ingest` | Ingest network flow telemetry events | Ingestion |
| `GET` | `/api/v1/keys` | List cryptographic key metadata | Key Lifecycle |
| `GET` | `/api/v1/models` | List readiness and provenance status for all 4 M6 models | Models & CSV |
| `POST` | `/api/v1/rotation` | Trigger key metadata rotation audit lifecycle (dry-run safe) | Key Lifecycle |
| `GET` | `/api/v1/rotation/audit` | Query key rotation audit log | Key Lifecycle |
| `POST` | `/api/v1/security/simulate-response` | Simulate deterministic adaptive security response & key rotation decision (dry-run) | Security Dry-Run |
| `GET` | `/api/v1/security/simulations` | List persisted Issue #27 dry-run security response simulations | Security Dry-Run |
| `POST` | `/api/v1/security/simulations/export` | Export Issue #27 dry-run simulation evidence JSON and metadata | Security Dry-Run |
| `GET` | `/api/v1/timeline` | Chronological timeline of events, alerts, and key rotations | Timeline |
| `GET` | `/health` | System and artifact health check | System |

## Key Deliverables & Design Rules
- **Zero Secret Leaks**: Key metadata endpoints only return non-sensitive fields (`key_id`, `version`, `algorithm`, `status`). Key secrets are never stored.
- **Fail-Closed Artifact Health**: `/health` verifies preprocessor and model artifacts independently (`preprocessor_ready` vs `model_ready`) against companion manifests before declaring readiness; missing or mismatched target model artifacts report `degraded`.
- **Strict Model Identity**: `/api/v1/analyze` enforces an explicit 4-model allowlist (`random_forest`, `xgboost`, `isolation_forest`, `autoencoder`), rejects invalid `model_name` selectors with HTTP `422` without silent fallback, and binds `model_used` to the canonical verified model family.
- **Anomaly Score Semantics & Verified Decision Policy**: `/api/v1/analyze` preserves the verified model's binary prediction and frozen `decision_threshold`, returns unclamped `raw_anomaly_score`/`anomaly_score` (`higher_is_more_anomalous`), emits `attack_probability` and `probabilities` only for supervised probabilistic models (`null` for Isolation Forest and Autoencoder), and sets `normalized_anomaly_score` to `null` unless a valid Train/Validation calibration contract exists. Request `threshold` applies only to an explicitly enabled heuristic fallback.
- **Key Metadata Scope**: Key and rotation endpoints record metadata and audit events only. They do not encrypt flow payloads; `algorithm` describes a planned key policy, not active AES-GCM encryption.
- **Adaptive Response Dry-Run Scope (#27)**: `/api/v1/security/simulate-response` and `/api/v1/security/simulations/*` generate deterministic policy recommendations (`NO_ACTION`, `MONITOR`, `INVESTIGATE`, `ISOLATE_RECOMMENDED`) and simulated adaptive key-rotation readiness with `executed=false`. `ISOLATE_RECOMMENDED` and adaptive key-rotation escalation are granted ONLY when `analysis_id` is verified in the bounded in-memory CSV analysis registry (volatile across restarts; old IDs fail closed with HTTP `400`) AND the gate is `MODEL_VALIDATED` + `PREDICTION_AVAILABLE` (`client_supplied_unverified` and `RESEARCH_ONLY` inputs downgrade to `INVESTIGATE` and `HOLD_*`); `ABSTAINED_OOD` flows never receive containment recommendations; SQLite durably persists simulation history with bounded recommendations; OS firewall commands and production AES-256-GCM keyring operations remain disabled/DEFERRED.
- **SQLite Durability**: Ingestion, incidents, timeline, and audit logs persist durably across restarts.
- **Idempotent Ingestion & Rotation**: Supported via `X-Idempotency-Key` or `idempotency_key` payload property.
- **Sanitized Errors**: Exception handlers prevent Python tracebacks or sensitive server details from leaking in 4xx/5xx responses.
