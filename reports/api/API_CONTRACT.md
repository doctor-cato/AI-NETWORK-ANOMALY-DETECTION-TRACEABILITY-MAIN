# FastAPI Service Integration Contract

**API Title**: AI Network Anomaly Detection & Traceability API
**Version**: 0.1.0
**Total Endpoints**: 10

## Endpoints Specification

| Method | Path | Summary | Tags |
|---|---|---|---|
| `POST` | `/api/v1/analyze` | Run anomaly detection on network flows | Analysis |
| `GET` | `/api/v1/health` | System and artifact health check (v1) | System |
| `GET` | `/api/v1/incidents` | List detected security incidents | Incidents |
| `POST` | `/api/v1/incidents` | Create an incident alert manually | Incidents |
| `GET` | `/api/v1/incidents/{incident_id}` | Get incident details by ID | Incidents |
| `PATCH` | `/api/v1/incidents/{incident_id}` | Update incident status or details | Incidents |
| `POST` | `/api/v1/ingest` | Ingest network flow telemetry events | Ingestion |
| `GET` | `/api/v1/keys` | List cryptographic key metadata | Key Lifecycle |
| `POST` | `/api/v1/rotation` | Trigger key metadata rotation audit lifecycle (dry-run safe) | Key Lifecycle |
| `GET` | `/api/v1/rotation/audit` | Query key rotation audit log | Key Lifecycle |
| `GET` | `/api/v1/timeline` | Chronological timeline of events, alerts, and key rotations | Timeline |
| `GET` | `/health` | System and artifact health check | System |

## Key Deliverables & Design Rules
- **Zero Secret Leaks**: Key metadata endpoints only return non-sensitive fields (`key_id`, `version`, `algorithm`, `status`). Key secrets are never stored.
- **Fail-Closed Artifact Health**: `/health` strictly checks model/preprocessor artifact existence on disk before declaring `model_ready: true`.
- **SQLite Durability**: Ingestion, incidents, timeline, and audit logs persist durably across restarts.
- **Idempotent Ingestion & Rotation**: Supported via `X-Idempotency-Key` or `idempotency_key` payload property.
- **Sanitized Errors**: Exception handlers prevent Python tracebacks or sensitive server details from leaking in 4xx/5xx responses.
