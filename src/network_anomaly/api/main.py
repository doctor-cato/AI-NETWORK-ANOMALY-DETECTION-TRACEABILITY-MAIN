"""FastAPI application entrypoint for AI Network Anomaly Detection & Traceability.

Exposes RESTful endpoints for ingestion, analysis, incident tracking,
event timeline, key rotation lifecycle, and system health checks.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from network_anomaly.api.db import DatabaseManager
from network_anomaly.api.desktop_csv import (
    analyze_csv_file,
    collect_models_status,
    evaluate_predictions_with_ground_truth,
    export_predictions_csv,
    inspect_csv_file,
)
from network_anomaly.api.errors import register_error_handlers
from network_anomaly.api.live_runtime import CONNECTED, DISCONNECTED, EMPTY, LiveRuntime
from network_anomaly.api.repositories import EventRepository, IncidentRepository
from network_anomaly.api.response_policy import (
    export_security_simulation_evidence,
    list_security_simulations,
    simulate_security_response,
)
from network_anomaly.api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    BehavioralCorrelationClusterItem,
    BehavioralCorrelationResponse,
    BehavioralSimilarityResponse,
    BehavioralVectorDetailResponse,
    BehavioralVectorListItem,
    BehavioralVectorListResponse,
    BenchmarkSplitMetricsItem,
    BenchmarkTopFeatureItem,
    CryptoStatusResponse,
    CsvAnalyzeRequest,
    CsvAnalyzeResponse,
    CsvEvaluateRequest,
    CsvEvaluateResponse,
    CsvExportRequest,
    CsvExportResponse,
    CsvInspectRequest,
    CsvInspectResponse,
    EntityGraphEdgeItem,
    EntityGraphNodeItem,
    GenerateInvestigationReportRequest,
    HealthResponse,
    IncidentCreateRequest,
    IncidentResponse,
    IncidentUpdateRequest,
    IngestBatchRequest,
    IngestResponse,
    InvestigationReportResponse,
    KeyMetadataResponse,
    KeyRotationRequest,
    KeyRotationResponse,
    LiveAlertsResponse,
    LiveResultsResponse,
    LiveStartRequest,
    LiveStatusResponse,
    ModelBenchmarkEntry,
    ModelBenchmarkReportResponse,
    ModelStatusItem,
    PaginatedIncidentsResponse,
    PaginatedRotationAuditResponse,
    PaginatedSecuritySimulationsResponse,
    PaginatedTimelineResponse,
    SecurityResponseSimulateRequest,
    SecurityResponseSimulationResponse,
    SecuritySimulationExportRequest,
    SecuritySimulationExportResponse,
    TimelineStageItem,
    TraceGraphResponse,
    TraceTimelineResponse,
)
from network_anomaly.api.service import ApiService
from network_anomaly.config import PROJECT_ROOT
from network_anomaly.trace.engine import TraceEngine
from network_anomaly.trace.graph import (
    EntityKind,
    EntityRelationshipGraph,
    RelationType,
)
from network_anomaly.trace.investigation import InvestigationReportGenerator
from network_anomaly.trace.timeline import AttackTimelineReconstructor

logger = logging.getLogger(__name__)


def _load_json_dict(path: Path) -> Optional[Dict[str, Any]]:
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Failed to load benchmark report '%s': %s", path, exc)
        return None
    return payload if isinstance(payload, dict) else None


def _build_split_metrics(dataset_label: str, raw: Any) -> Optional[BenchmarkSplitMetricsItem]:
    if not isinstance(raw, dict):
        return None
    raw_count = raw.get("sample_count", raw.get("total_rows"))
    sample_count = int(raw_count) if raw_count is not None else None
    fpr_val = raw.get("false_positive_rate")
    if fpr_val is None:
        fpr_val = raw.get("fpr")
    return BenchmarkSplitMetricsItem(
        dataset=dataset_label,
        f1=float(raw["f1"]) if raw.get("f1") is not None else None,
        precision=float(raw["precision"]) if raw.get("precision") is not None else None,
        recall=float(raw["recall"]) if raw.get("recall") is not None else None,
        fpr=float(fpr_val) if fpr_val is not None else None,
        roc_auc=float(raw["roc_auc"]) if raw.get("roc_auc") is not None else None,
        pr_auc=float(raw["pr_auc"]) if raw.get("pr_auc") is not None else None,
        sample_count=sample_count,
    )


def _load_model_benchmark_report(
    reports_dir: Optional[Path] = None,
) -> ModelBenchmarkReportResponse:
    """Load official 4-model in-domain and cross-source benchmark reports safely."""
    base_dir = reports_dir or (PROJECT_ROOT / "reports" / "experiments" / "ml")
    comparison = _load_json_dict(base_dir / "model_comparison_report.json")
    if comparison is None:
        return ModelBenchmarkReportResponse(data_status=EMPTY)

    sources_loaded = ["reports/experiments/ml/model_comparison_report.json"]

    ctu_raw = _load_json_dict(base_dir / "ctu_cross_source_eval.json")
    ctu_models: Dict[str, Any] = {}
    if ctu_raw is not None:
        sources_loaded.append("reports/experiments/ml/ctu_cross_source_eval.json")
        if isinstance(ctu_raw.get("zero_shot_ait_models"), dict):
            ctu_models = ctu_raw["zero_shot_ait_models"]

    uwf_raw = _load_json_dict(base_dir / "uwf_zeekdata24_cross_source_eval.json")
    uwf_models: Dict[str, Any] = {}
    if uwf_raw is not None:
        sources_loaded.append("reports/experiments/ml/uwf_zeekdata24_cross_source_eval.json")
        if isinstance(uwf_raw.get("zero_shot_eval_full_zeek_unset_zero"), dict):
            uwf_models = uwf_raw["zero_shot_eval_full_zeek_unset_zero"]

    raw_prov = comparison.get("dataset_provenance")
    if isinstance(raw_prov, dict):
        dataset_id = raw_prov.get("dataset_id", "AIT-NetFlow-v2-Suite")
        split_proto = raw_prov.get("split_protocol")
        dataset_provenance = f"{dataset_id} ({split_proto})" if split_proto else str(dataset_id)
    elif raw_prov is not None:
        dataset_provenance = str(raw_prov)
    else:
        dataset_provenance = None

    raw_models = comparison.get("models")
    models_dict = raw_models if isinstance(raw_models, dict) else {}
    entries: List[ModelBenchmarkEntry] = []

    for model_key, model_data in models_dict.items():
        if not isinstance(model_data, dict):
            continue
        in_domain = _build_split_metrics("AIT-NDS-v2 (test)", model_data.get("metrics"))
        cross_source: List[BenchmarkSplitMetricsItem] = []

        ctu_entry = ctu_models.get(model_key)
        if isinstance(ctu_entry, dict):
            for split_key, label in (
                ("ctu_echo", "CTU-Echo"),
                ("ctu_windows7ad", "CTU-Win7AD"),
            ):
                item = _build_split_metrics(label, ctu_entry.get(split_key))
                if item is not None:
                    cross_source.append(item)

        uwf_entry = uwf_models.get(model_key)
        if isinstance(uwf_entry, dict):
            item = _build_split_metrics("UWF-ZeekData24", uwf_entry)
            if item is not None:
                cross_source.append(item)

        explain = model_data.get("explainability")
        raw_top = explain.get("top_features", []) if isinstance(explain, dict) else []
        top_features = [
            BenchmarkTopFeatureItem(
                feature=str(feat["feature"]),
                importance=float(feat["importance"]),
                method=str(feat.get("method", "")),
            )
            for feat in raw_top
            if isinstance(feat, dict) and "feature" in feat and "importance" in feat
        ]

        raw_thresh = model_data.get("decision_threshold")
        entries.append(
            ModelBenchmarkEntry(
                model_key=str(model_key),
                display_name=str(model_data.get("display_name", model_key)),
                model_type=str(model_data.get("model_type", model_key)),
                deployment_tier="RESEARCH_ONLY",
                decision_threshold=float(raw_thresh) if raw_thresh is not None else None,
                threshold_source=(
                    str(model_data["threshold_source"])
                    if model_data.get("threshold_source") is not None
                    else None
                ),
                in_domain=in_domain,
                cross_source=cross_source,
                top_features=top_features,
            )
        )

    raw_limitations = comparison.get("limitations")
    limitations = (
        [str(item) for item in raw_limitations] if isinstance(raw_limitations, list) else []
    )

    return ModelBenchmarkReportResponse(
        data_status=CONNECTED if entries else EMPTY,
        generated_at_utc=(
            str(comparison["generated_at_utc"])
            if comparison.get("generated_at_utc") is not None
            else None
        ),
        dataset_provenance=dataset_provenance,
        evaluation_partition=(
            str(comparison["evaluation_partition"])
            if comparison.get("evaluation_partition") is not None
            else None
        ),
        models=entries,
        limitations=limitations,
        sources_loaded=sources_loaded,
    )


def create_app(
    db_path: Optional[Union[str, Path]] = None,
    *,
    runtime_mode: Optional[str] = None,
    require_ood_gate: Optional[bool] = None,
    expected_ood_gate_sha256: Optional[str] = None,
) -> FastAPI:
    """Application factory creating a configured FastAPI instance.

    Parameters
    ----------
    db_path : str or Path, optional
        Custom SQLite database path or ':memory:'. Defaults to standard project DB.
    runtime_mode : str, optional
        Explicit OOD runtime policy (``'deployment'`` or ``'research'``).
        Defaults fail-closed to ``NETFLOW_RUNTIME_MODE`` or ``'deployment'``.
    require_ood_gate : bool, optional
        Explicit OOD gate requirement flag (cannot be ``False`` in ``'deployment'``).
    expected_ood_gate_sha256 : str, optional
        Trusted expected SHA-256 hex digest for persisted ``ood_reference_gate.json``.
    """
    db_manager = DatabaseManager(db_path=db_path)
    service = ApiService(db=db_manager)
    keystore_dir = None if db_path == ":memory:" else db_manager.db_path.parent / "keys"
    live_runtime = LiveRuntime(
        db_path=db_path,
        keystore_dir=keystore_dir,
        runtime_mode=runtime_mode,
        require_ood_gate=require_ood_gate,
        expected_ood_gate_sha256=expected_ood_gate_sha256,
    )

    @asynccontextmanager
    async def _lifespan(_app: FastAPI):
        try:
            yield
        finally:
            live_runtime.shutdown()

    app = FastAPI(
        title="AI Network Anomaly Detection & Traceability API",
        description=(
            "RESTful API providing network flow telemetry ingestion, machine learning "
            "anomaly analysis, incident response tracking, timeline correlation, "
            "and cryptographic key rotation audit contracts."
        ),
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=_lifespan,
    )

    # Attach db_manager, service, and live_runtime to app state for lifecycle/test inspection
    app.state.db_manager = db_manager
    app.state.service = service
    app.state.live_runtime = live_runtime

    # Register error sanitization handlers
    register_error_handlers(app)

    # Restrict CORS strictly to localhost / Tauri WebView2 origins (#26)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://127.0.0.1:1420",
            "http://localhost:1420",
            "http://127.0.0.1:5173",
            "http://localhost:5173",
            "http://tauri.localhost",
            "https://tauri.localhost",
            "tauri://localhost",
        ],
        allow_origin_regex=r"^https?://(127\.0\.0\.1|localhost)(:\d+)?$",
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["Content-Type", "X-Idempotency-Key", "X-Sentinel-Session-Token"],
    )

    session_token = os.environ.get("NETWORK_ANOMALY_API_TOKEN", "").strip()
    if session_token:

        @app.middleware("http")
        async def _enforce_session_token(request: Request, call_next):
            # Allow CORS preflight and lightweight /health liveness probe without exposing API routes
            if request.method == "OPTIONS" or request.url.path == "/health":
                return await call_next(request)
            presented = request.headers.get("X-Sentinel-Session-Token", "")
            if not hmac.compare_digest(presented.encode("utf-8"), session_token.encode("utf-8")):
                return JSONResponse(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    content={
                        "error": "Unauthorized",
                        "detail": "Missing or invalid X-Sentinel-Session-Token.",
                    },
                )
            return await call_next(request)

    else:
        logger.warning(
            "NETWORK_ANOMALY_API_TOKEN is not set; API routes are running without authentication on loopback."
        )

    # Dependency getters
    def get_service() -> ApiService:
        return app.state.service

    def get_live_runtime() -> LiveRuntime:
        return app.state.live_runtime

    # --- Endpoints ---

    @app.get(
        "/health",
        response_model=HealthResponse,
        tags=["System"],
        summary="System and artifact health check",
    )
    @app.get(
        "/api/v1/health",
        response_model=HealthResponse,
        tags=["System"],
        summary="System and artifact health check (v1)",
    )
    def health_check(svc: ApiService = Depends(get_service)) -> HealthResponse:
        """Inspect server process, SQLite persistence, and ML model artifact readiness."""
        return svc.check_health()

    @app.post(
        "/api/v1/ingest",
        response_model=IngestResponse,
        tags=["Ingestion"],
        summary="Ingest network flow telemetry events",
    )
    def ingest_events(
        payload: IngestBatchRequest,
        x_idempotency_key: Optional[str] = Header(None, alias="X-Idempotency-Key"),
        svc: ApiService = Depends(get_service),
    ) -> IngestResponse:
        """Atomically persist a batch of flow telemetry events into SQLite."""
        eff_idempotency = payload.idempotency_key or x_idempotency_key
        event_dicts = [e.model_dump() for e in payload.events]

        count, ids, session_id = svc.ingest_events(
            events=event_dicts,
            session_id=payload.session_id,
            idempotency_key=eff_idempotency,
        )
        return IngestResponse(
            status="ok",
            ingested_count=count,
            event_ids=ids,
            session_id=session_id,
        )

    @app.post(
        "/api/v1/analyze",
        response_model=AnalyzeResponse,
        tags=["Analysis"],
        summary="Run anomaly detection on network flows",
    )
    def analyze_flows(
        payload: AnalyzeRequest,
        response: Response,
        svc: ApiService = Depends(get_service),
    ) -> AnalyzeResponse:
        """Run ML inference or baseline behavioral detection on input flows."""
        res = svc.analyze_flows(
            events=payload.events,
            model_name=payload.model_name or "random_forest",
            threshold=payload.threshold if payload.threshold is not None else 0.5,
            create_incidents=payload.create_incidents,
            allow_heuristic_fallback=payload.allow_heuristic_fallback,
        )
        if not res.model_ready or res.inference_mode == "heuristic_fallback":
            response.headers["X-Inference-Degraded"] = "true"
        return res

    @app.get(
        "/api/v1/incidents",
        response_model=PaginatedIncidentsResponse,
        tags=["Incidents"],
        summary="List detected security incidents",
    )
    def list_incidents(
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        severity: Optional[str] = Query(None, description="LOW, MEDIUM, HIGH, CRITICAL"),
        status: Optional[str] = Query(None, description="OPEN, INVESTIGATING, RESOLVED, CLOSED"),
        svc: ApiService = Depends(get_service),
    ) -> PaginatedIncidentsResponse:
        """Retrieve paginated security incident alerts."""
        return svc.list_incidents(limit=limit, offset=offset, severity=severity, status=status)

    @app.post(
        "/api/v1/incidents",
        response_model=IncidentResponse,
        status_code=status.HTTP_201_CREATED,
        tags=["Incidents"],
        summary="Create an incident alert manually",
    )
    def create_incident(
        payload: IncidentCreateRequest,
        svc: ApiService = Depends(get_service),
    ) -> IncidentResponse:
        """Create a new incident alert record."""
        with svc.db.transaction() as conn:
            inc = IncidentRepository.create(conn, payload.model_dump())
        return IncidentResponse.model_validate(inc)

    @app.get(
        "/api/v1/incidents/{incident_id}",
        response_model=IncidentResponse,
        tags=["Incidents"],
        summary="Get incident details by ID",
    )
    def get_incident(
        incident_id: str,
        svc: ApiService = Depends(get_service),
    ) -> IncidentResponse:
        """Fetch a specific incident alert by ID."""
        with svc.db.transaction() as conn:
            inc = IncidentRepository.get_by_id(conn, incident_id)
        if not inc:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{incident_id}' not found.",
            )
        return IncidentResponse.model_validate(inc)

    @app.patch(
        "/api/v1/incidents/{incident_id}",
        response_model=IncidentResponse,
        tags=["Incidents"],
        summary="Update incident status or details",
    )
    def update_incident(
        incident_id: str,
        payload: IncidentUpdateRequest,
        svc: ApiService = Depends(get_service),
    ) -> IncidentResponse:
        """Update incident status (OPEN, INVESTIGATING, RESOLVED, CLOSED) or severity."""
        with svc.db.transaction() as conn:
            updated = IncidentRepository.update(
                conn, incident_id, payload.model_dump(exclude_unset=True)
            )
        if not updated:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Incident '{incident_id}' not found.",
            )
        return IncidentResponse.model_validate(updated)

    @app.get(
        "/api/v1/timeline",
        response_model=PaginatedTimelineResponse,
        tags=["Timeline"],
        summary="Chronological timeline of events, alerts, and key rotations",
    )
    def get_timeline(
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        svc: ApiService = Depends(get_service),
    ) -> PaginatedTimelineResponse:
        """Retrieve unified chronological audit and operational timeline."""
        return svc.get_timeline(limit=limit, offset=offset)

    @app.post(
        "/api/v1/rotation",
        response_model=KeyRotationResponse,
        tags=["Key Lifecycle"],
        summary="Trigger key metadata rotation audit lifecycle (dry-run safe)",
        description=(
            "Execute key metadata lifecycle rotation subject to cooldown limits and idempotency. "
            "NOTE: Manages Audit Trail Metadata only; external KMS integration is required for "
            "active payload encryption. In production environments, this endpoint requires "
            "API Key / RBAC authentication."
        ),
    )
    def trigger_key_rotation(
        payload: KeyRotationRequest,
        x_idempotency_key: Optional[str] = Header(None, alias="X-Idempotency-Key"),
        svc: ApiService = Depends(get_service),
    ) -> KeyRotationResponse:
        """Execute key rotation subject to cooldown limits and idempotency."""
        eff_idempotency = payload.idempotency_key or x_idempotency_key
        return svc.rotate_key(
            triggered_by=payload.triggered_by,
            dry_run=payload.dry_run,
            reason=payload.reason,
            idempotency_key=eff_idempotency,
        )

    @app.get(
        "/api/v1/rotation/audit",
        response_model=PaginatedRotationAuditResponse,
        tags=["Key Lifecycle"],
        summary="Query key rotation audit log",
    )
    def list_rotation_audits(
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        svc: ApiService = Depends(get_service),
    ) -> PaginatedRotationAuditResponse:
        """List historical key rotation audit entries."""
        return svc.list_rotation_audits(limit=limit, offset=offset)

    @app.get(
        "/api/v1/keys",
        response_model=List[KeyMetadataResponse],
        tags=["Key Lifecycle"],
        summary="List cryptographic key metadata",
    )
    def list_keys(
        limit: int = Query(50, ge=1, le=100),
        offset: int = Query(0, ge=0),
        svc: ApiService = Depends(get_service),
    ) -> List[KeyMetadataResponse]:
        """List active and retired key metadata (secrets are never exposed)."""
        return svc.list_keys(limit=limit, offset=offset)

    @app.get(
        "/api/v1/models",
        response_model=List[ModelStatusItem],
        tags=["Models & CSV"],
        summary="List readiness and provenance status for all 4 M6 models",
    )
    def list_models_status(
        svc: ApiService = Depends(get_service),
    ) -> List[ModelStatusItem]:
        """Return genuine readiness, artifact digest, and threshold metadata."""
        return collect_models_status(svc)

    @app.get(
        "/api/v1/models/benchmark-report",
        response_model=ModelBenchmarkReportResponse,
        tags=["Models & CSV"],
        summary="Get official 4-model benchmark and cross-source evaluation report",
    )
    def get_model_benchmark_report() -> ModelBenchmarkReportResponse:
        """Return official AIT-NDS-v2 test, CTU-SME-11, and UWF-ZeekData24 benchmark metrics."""
        return _load_model_benchmark_report()

    @app.post(
        "/api/v1/csv/inspect",
        response_model=CsvInspectResponse,
        tags=["Models & CSV"],
        summary="Validate CSV contract, exclude leakage targets/metadata, and preview rows",
    )
    def inspect_csv(
        request: CsvInspectRequest,
        svc: ApiService = Depends(get_service),
    ) -> CsvInspectResponse:
        """Inspect local NetFlow CSV safely before ML inference."""
        return inspect_csv_file(
            svc,
            file_path=request.file_path,
            preview_limit=request.preview_limit,
        )

    @app.post(
        "/api/v1/csv/analyze",
        response_model=CsvAnalyzeResponse,
        tags=["Models & CSV"],
        summary="Run verified batch inference on local NetFlow CSV with OOD, timeline, and risk scoring",
    )
    def analyze_csv(
        request: CsvAnalyzeRequest,
        svc: ApiService = Depends(get_service),
    ) -> CsvAnalyzeResponse:
        """Execute verified ML inference, deterministic risk scoring (#32), and timeline (#24)."""
        return analyze_csv_file(
            svc,
            file_path=request.file_path,
            model_name=request.model_name,
            create_incidents=request.create_incidents,
            batch_size=request.batch_size,
            include_timeline=request.include_timeline,
            allow_research_only=request.allow_research_only,
        )

    @app.post(
        "/api/v1/csv/evaluate",
        response_model=CsvEvaluateResponse,
        tags=["Models & CSV"],
        summary="Evaluate CSV predictions against a separate Ground Truth CSV",
    )
    def evaluate_csv(request: CsvEvaluateRequest) -> CsvEvaluateResponse:
        """Compute confusion matrix and binary/per-attack metrics using Ground Truth CSV."""
        return evaluate_predictions_with_ground_truth(
            labels_path=request.labels_path,
            predictions=request.predictions,
        )

    @app.post(
        "/api/v1/csv/export",
        response_model=CsvExportResponse,
        tags=["Models & CSV"],
        summary="Export predictions CSV and companion SHA-256 provenance JSON",
    )
    def export_csv(
        request: CsvExportRequest,
        svc: ApiService = Depends(get_service),
    ) -> CsvExportResponse:
        """Export analyzed flow predictions safely without overwriting source CSV."""
        return export_predictions_csv(request, service=svc)

    @app.post(
        "/api/v1/security/simulate-response",
        response_model=SecurityResponseSimulationResponse,
        tags=["Security Dry-Run"],
        summary="Simulate deterministic adaptive security response & key rotation decision (dry-run)",
        description=(
            "Evaluate deterministic Issue #27 policy recommendations (NO_ACTION, MONITOR, "
            "INVESTIGATE, ISOLATE_RECOMMENDED) and adaptive key rotation readiness in strict "
            "dry-run simulation mode only (executed=false). ABSTAINED_OOD flows never receive "
            "containment recommendations; OS firewall and real crypto key modifications are disabled."
        ),
    )
    def run_security_response_simulation(
        request: SecurityResponseSimulateRequest,
        svc: ApiService = Depends(get_service),
    ) -> SecurityResponseSimulationResponse:
        """Run deterministic Issue #27 adaptive response dry-run simulation."""
        return simulate_security_response(svc, request)

    @app.get(
        "/api/v1/security/simulations",
        response_model=PaginatedSecuritySimulationsResponse,
        tags=["Security Dry-Run"],
        summary="List persisted Issue #27 dry-run security response simulations",
    )
    def get_security_simulations(
        limit: int = Query(20, ge=1, le=200),
        offset: int = Query(0, ge=0),
        svc: ApiService = Depends(get_service),
    ) -> PaginatedSecuritySimulationsResponse:
        """List SQLite-persisted dry-run response simulations ordered newest first."""
        return list_security_simulations(svc, limit=limit, offset=offset)

    @app.post(
        "/api/v1/security/simulations/export",
        response_model=SecuritySimulationExportResponse,
        tags=["Security Dry-Run"],
        summary="Export Issue #27 dry-run simulation evidence JSON and metadata",
    )
    def export_security_simulation(
        request: SecuritySimulationExportRequest,
        svc: ApiService = Depends(get_service),
    ) -> SecuritySimulationExportResponse:
        """Export a persisted simulation evidence bundle safely with SHA-256 metadata."""
        return export_security_simulation_evidence(svc, request)

    # ========================================================================
    # NetFlow Sentinel v2.0 Live Telemetry & Behavioral Endpoints
    # ========================================================================

    @app.post(
        "/api/v1/live/start",
        response_model=LiveStatusResponse,
        tags=["Live Telemetry"],
        summary="Start real UDP NetFlow/IPFIX collector and streaming worker",
    )
    def start_live_telemetry(
        request: LiveStartRequest = LiveStartRequest(),
        rt: LiveRuntime = Depends(get_live_runtime),
    ) -> LiveStatusResponse:
        try:
            payload = rt.start(
                host=request.host,
                port=request.port,
                demo_heuristics=request.demo_heuristics,
                queue_capacity=request.queue_capacity,
                batch_size=request.batch_size,
            )
            return LiveStatusResponse(**payload)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed starting live telemetry collector: {exc}",
            ) from exc

    @app.post(
        "/api/v1/live/stop",
        response_model=LiveStatusResponse,
        tags=["Live Telemetry"],
        summary="Stop live UDP collector and flush buffered events",
    )
    def stop_live_telemetry(
        rt: LiveRuntime = Depends(get_live_runtime),
    ) -> LiveStatusResponse:
        return LiveStatusResponse(**rt.stop())

    @app.get(
        "/api/v1/live/status",
        response_model=LiveStatusResponse,
        tags=["Live Telemetry"],
        summary="Get live collector, pipeline, and 4-model readiness status",
    )
    def get_live_status(
        rt: LiveRuntime = Depends(get_live_runtime),
    ) -> LiveStatusResponse:
        return LiveStatusResponse(**rt.status())

    @app.get(
        "/api/v1/live/results",
        response_model=LiveResultsResponse,
        tags=["Live Telemetry"],
        summary="Get recent live processed telemetry results",
    )
    def get_live_results(
        limit: int = Query(50, ge=1, le=500),
        rt: LiveRuntime = Depends(get_live_runtime),
    ) -> LiveResultsResponse:
        st = rt.status()
        items = rt.recent_results(limit=limit)
        data_status = st["data_status"] if items or not st["running"] else EMPTY
        return LiveResultsResponse(data_status=data_status, total=len(items), items=items)

    @app.get(
        "/api/v1/live/alerts",
        response_model=LiveAlertsResponse,
        tags=["Live Telemetry"],
        summary="Get recent live alerts raised by Risk Engine & Alert Manager",
    )
    def get_live_alerts(
        limit: int = Query(50, ge=1, le=500),
        rt: LiveRuntime = Depends(get_live_runtime),
    ) -> LiveAlertsResponse:
        st = rt.status()
        items = rt.recent_alerts(limit=limit)
        data_status = st["data_status"] if items or not st["running"] else EMPTY
        return LiveAlertsResponse(data_status=data_status, total=len(items), items=items)

    @app.get(
        "/api/v1/live/graph",
        response_model=TraceGraphResponse,
        tags=["Live Telemetry"],
        summary="Get live entity relationship graph from active telemetry",
    )
    def get_live_graph(
        rt: LiveRuntime = Depends(get_live_runtime),
    ) -> TraceGraphResponse:
        st = rt.status()
        raw_graph = rt.entity_graph()
        if not raw_graph or not raw_graph.get("nodes"):
            return TraceGraphResponse(
                node_count=0,
                edge_count=0,
                nodes=[],
                edges=[],
                data_status=DISCONNECTED if not st["running"] else EMPTY,
                provenance={"source": "live_runtime", "running": st["running"]},
            )
        nodes = [
            EntityGraphNodeItem(
                node_id=n["node_id"],
                kind=n["kind"],
                label=n["label"],
                properties=n.get("properties", {}),
            )
            for n in raw_graph.get("nodes", [])
        ]
        edges = [
            EntityGraphEdgeItem(
                edge_id=e["edge_id"],
                source_id=e["source_id"],
                target_id=e["target_id"],
                relation_type=e["relation_type"],
                confidence=e["confidence"],
                is_observed=e.get("is_observed", True),
                evidence_id=e.get("evidence_id"),
            )
            for e in raw_graph.get("edges", [])
        ]
        return TraceGraphResponse(
            node_count=len(nodes),
            edge_count=len(edges),
            nodes=nodes,
            edges=edges,
            data_status=CONNECTED,
            provenance={"source": "live_runtime", "running": st["running"]},
        )

    @app.get(
        "/api/v1/behavioral/vectors",
        response_model=BehavioralVectorListResponse,
        tags=["Behavioral Intelligence"],
        summary="List persisted 16-D behavioral vector metadata (ciphertext stays at rest)",
    )
    def list_behavioral_vectors(
        entity_id: Optional[str] = Query(None),
        limit: int = Query(50, ge=1, le=200),
        rt: LiveRuntime = Depends(get_live_runtime),
    ) -> BehavioralVectorListResponse:
        payload = rt.list_behavioral_vectors(entity_id=entity_id, limit=limit)
        items = [BehavioralVectorListItem(**item) for item in payload["items"]]
        return BehavioralVectorListResponse(
            data_status=payload["data_status"],
            total=payload["total"],
            items=items,
            reason=payload.get("reason"),
        )

    @app.get(
        "/api/v1/behavioral/vectors/{vector_id}",
        response_model=BehavioralVectorDetailResponse,
        tags=["Behavioral Intelligence"],
        summary="Decrypt and inspect a stored 16-D behavioral vector by ID",
    )
    def get_behavioral_vector_detail(
        vector_id: str,
        rt: LiveRuntime = Depends(get_live_runtime),
    ) -> BehavioralVectorDetailResponse:
        detail = rt.load_behavioral_vector(vector_id)
        if detail is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Behavioral vector '{vector_id}' not found.",
            )
        return BehavioralVectorDetailResponse(**detail)

    @app.get(
        "/api/v1/behavioral/similarity",
        response_model=BehavioralSimilarityResponse,
        tags=["Behavioral Intelligence"],
        summary="Compute real Cosine/Euclidean/Manhattan similarity between two stored vectors",
    )
    def get_behavioral_similarity(
        vector_a_id: str = Query(..., min_length=1),
        vector_b_id: str = Query(..., min_length=1),
        rt: LiveRuntime = Depends(get_live_runtime),
    ) -> BehavioralSimilarityResponse:
        result = rt.behavioral_similarity(vector_a_id=vector_a_id, vector_b_id=vector_b_id)
        if result is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="One or both behavioral vectors were not found.",
            )
        return BehavioralSimilarityResponse(**result)

    @app.get(
        "/api/v1/behavioral/correlate",
        response_model=BehavioralCorrelationResponse,
        tags=["Behavioral Intelligence"],
        summary="Run IPSpoofingSessionCorrelator over stored behavioral vectors",
    )
    def correlate_behavioral_vectors(
        match_threshold: float = Query(0.85, ge=0.0, le=1.0),
        limit: int = Query(20, ge=1, le=100),
        rt: LiveRuntime = Depends(get_live_runtime),
    ) -> BehavioralCorrelationResponse:
        payload = rt.behavioral_correlation(match_threshold=match_threshold, limit=limit)
        clusters = [BehavioralCorrelationClusterItem(**c) for c in payload["clusters"]]
        return BehavioralCorrelationResponse(
            data_status=payload["data_status"],
            match_threshold=payload["match_threshold"],
            total_vectors_evaluated=payload["total_vectors_evaluated"],
            clusters=clusters,
            reason=payload.get("reason"),
        )

    # ========================================================================
    # NetFlow Sentinel v2.0 Trace & Cryptography Endpoints (Issue #115)
    # ========================================================================

    def _collect_real_trace_events(
        svc: ApiService, rt: LiveRuntime, limit: int
    ) -> tuple[List[Dict[str, Any]], List[str]]:
        events_data: List[Dict[str, Any]] = []
        campaigns: List[str] = []
        seen_ids: set[str] = set()

        for res in rt.recent_results(limit=limit):
            ev_id = str(res.get("event_id") or "")
            if not ev_id or ev_id in seen_ids:
                continue
            src_ip = res.get("source_ip")
            dst_ip = res.get("dest_ip")
            if not src_ip and not dst_ip:
                continue
            seen_ids.add(ev_id)
            ent = str(res.get("entity_id") or "")
            if ent and ent not in campaigns:
                campaigns.append(ent)
            events_data.append(
                {
                    "event_id": ev_id,
                    "timestamp": res.get("timestamp") or "",
                    "source_ip": src_ip or ent.replace("host:", ""),
                    "dest_ip": dst_ip or "unknown",
                    "attack_type": res.get("attack_type") or res.get("risk_level") or "Suspicious",
                    "risk_score": float(res.get("risk_score", 0.0)),
                    "dest_port": res.get("dest_port"),
                    "confidence": min(1.0, max(0.0, float(res.get("risk_score", 50.0)) / 100.0)),
                    "campaign_key": ent,
                }
            )

        with svc.db.transaction() as conn:
            incidents = IncidentRepository.list_incidents(conn, limit=limit, offset=0)
            for inc in incidents:
                inc_id = str(inc["incident_id"])
                if inc_id not in campaigns:
                    campaigns.append(inc_id)
                ev_id = inc.get("event_id")
                linked_ev = EventRepository.get_by_id(conn, str(ev_id)) if ev_id else None
                row_key = str(ev_id or inc_id)
                if row_key in seen_ids:
                    continue
                seen_ids.add(row_key)
                score = float(inc.get("anomaly_score", 0.0))
                risk_score = score * 100.0 if score <= 1.0 else score
                events_data.append(
                    {
                        "event_id": row_key,
                        "incident_id": inc_id,
                        "session_id": inc.get("session_id"),
                        "timestamp": (linked_ev or {}).get("timestamp") or inc["created_at"],
                        "source_ip": (linked_ev or {}).get("source_ip") or "unknown",
                        "dest_ip": (linked_ev or {}).get("dest_ip") or "unknown",
                        "attack_type": inc.get("attack_type") or "Suspicious",
                        "risk_score": risk_score,
                        "dest_port": (linked_ev or {}).get("dest_port"),
                        "confidence": min(1.0, max(0.0, risk_score / 100.0)),
                        "campaign_key": inc_id,
                    }
                )
            for ev in EventRepository.list_events(conn, limit=limit, offset=0):
                ev_id = str(ev["event_id"])
                if ev_id in seen_ids:
                    continue
                seen_ids.add(ev_id)
                sess_id = ev.get("session_id")
                if sess_id and str(sess_id) not in campaigns:
                    campaigns.append(str(sess_id))
                events_data.append(
                    {
                        "event_id": ev_id,
                        "session_id": sess_id,
                        "timestamp": ev.get("timestamp") or ev.get("created_at") or "",
                        "source_ip": ev.get("source_ip") or "unknown",
                        "dest_ip": ev.get("dest_ip") or "unknown",
                        "attack_type": "ObservedFlow",
                        "dest_port": ev.get("dest_port"),
                        "confidence": 1.0,
                        "campaign_key": str(sess_id or ev_id),
                    }
                )

        return events_data, campaigns

    @app.get(
        "/api/v1/trace/timeline",
        response_model=TraceTimelineResponse,
        tags=["Trace & Investigation"],
        summary="Get reconstructed multi-stage attack timeline from real events/incidents",
    )
    def get_attack_timeline(
        campaign_name: Optional[str] = Query(None, min_length=1),
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        svc: ApiService = Depends(get_service),
        rt: LiveRuntime = Depends(get_live_runtime),
    ) -> TraceTimelineResponse:
        """Reconstruct multi-stage attack timeline from real stored/live security events."""
        all_events, campaigns = _collect_real_trace_events(svc, rt, limit=max(200, limit + offset))
        effective_campaign = campaign_name or (campaigns[0] if campaigns else "ALL")

        if campaign_name and campaign_name != "ALL":
            filtered = [
                ev
                for ev in all_events
                if campaign_name
                in {
                    ev.get("campaign_key"),
                    ev.get("incident_id"),
                    ev.get("session_id"),
                    ev.get("event_id"),
                    ev.get("source_ip"),
                    ev.get("dest_ip"),
                }
            ]
            events_data = filtered if filtered else all_events
            filter_mode = "matched_campaign" if filtered else "all_real_events"
        else:
            events_data = all_events
            filter_mode = "all_real_events"

        if not events_data:
            return TraceTimelineResponse(
                timeline_id=f"tl-{effective_campaign}",
                campaign_name=effective_campaign,
                overall_confidence=0.0,
                start_time="",
                end_time="",
                entities_involved=[],
                total_stages=0,
                stages=[],
                available_campaigns=[],
                data_status=EMPTY,
                provenance={
                    "source": "none",
                    "events_count": 0,
                    "filter": filter_mode,
                    "offset": offset,
                    "limit": limit,
                },
            )

        reconstructor = AttackTimelineReconstructor()
        timeline = reconstructor.reconstruct_timeline(effective_campaign, events_data)

        stage_items = [
            TimelineStageItem(
                stage_id=s.stage_id,
                phase=s.phase.value,
                timestamp=s.timestamp,
                source_entity=s.source_entity,
                target_entity=s.target_entity,
                title=s.title,
                description=s.description,
                confidence=s.confidence,
                is_observed=s.is_observed,
                evidence_ids=s.evidence_ids,
                indicators=s.indicators,
            )
            for s in timeline.stages
        ]
        paged_stages = stage_items[offset : offset + limit]

        return TraceTimelineResponse(
            timeline_id=timeline.timeline_id,
            campaign_name=timeline.campaign_name,
            overall_confidence=timeline.overall_confidence,
            start_time=timeline.start_time,
            end_time=timeline.end_time,
            entities_involved=timeline.entities_involved,
            total_stages=len(stage_items),
            stages=paged_stages,
            available_campaigns=campaigns,
            data_status=CONNECTED if stage_items else EMPTY,
            provenance={
                "source": "live_and_sqlite",
                "events_count": len(events_data),
                "filter": filter_mode,
                "offset": offset,
                "limit": limit,
            },
        )

    @app.get(
        "/api/v1/trace/graph",
        response_model=TraceGraphResponse,
        tags=["Trace & Investigation"],
        summary="Query entity relationship graph from real live or stored telemetry",
    )
    def get_entity_graph(
        entity_id: Optional[str] = Query(None, min_length=1),
        depth: int = Query(2, ge=1, le=5),
        svc: ApiService = Depends(get_service),
        rt: LiveRuntime = Depends(get_live_runtime),
    ) -> TraceGraphResponse:
        """Query and traverse entity relationship graph built from real telemetry."""
        graph = EntityRelationshipGraph()
        live_raw = rt.entity_graph()
        if live_raw:
            for node_dict in live_raw.get("nodes", []):
                graph.add_node(
                    node_id=node_dict["node_id"],
                    kind=EntityKind(node_dict["kind"]),
                    label=node_dict["label"],
                    properties=dict(node_dict.get("properties", {})),
                )
            for edge_dict in live_raw.get("edges", []):
                graph.add_edge(
                    source_id=edge_dict["source_id"],
                    target_id=edge_dict["target_id"],
                    relation_type=RelationType(edge_dict["relation_type"]),
                    confidence=float(edge_dict.get("confidence", 1.0)),
                    is_observed=bool(edge_dict.get("is_observed", True)),
                    evidence_id=edge_dict.get("evidence_id"),
                    attributes=dict(edge_dict.get("attributes", {})),
                )

        with svc.db.transaction() as conn:
            for ev in EventRepository.list_events(conn, limit=100, offset=0):
                src = ev.get("source_ip")
                dst = ev.get("dest_ip")
                dport = ev.get("dest_port")
                ev_id = ev.get("event_id")
                if src:
                    graph.add_node(str(src), EntityKind.IP, str(src))
                if dst:
                    graph.add_node(str(dst), EntityKind.IP, str(dst))
                if src and dst:
                    graph.add_edge(
                        str(src),
                        str(dst),
                        RelationType.CONNECTS_TO,
                        confidence=1.0,
                        is_observed=True,
                        evidence_id=str(ev_id) if ev_id else None,
                    )
                if dst and dport is not None:
                    port_node = f"port:{dport}"
                    graph.add_node(port_node, EntityKind.PORT, f"Port {dport}")
                    graph.add_edge(
                        str(dst),
                        port_node,
                        RelationType.CONNECTS_TO,
                        confidence=1.0,
                        is_observed=True,
                        evidence_id=str(ev_id) if ev_id else None,
                    )

        target_entity = entity_id
        if target_entity is None and graph.nodes:
            target_entity = next(iter(graph.nodes))

        if not target_entity or target_entity not in graph.nodes:
            return TraceGraphResponse(
                node_count=0,
                edge_count=0,
                nodes=[],
                edges=[],
                truncated=False,
                data_status=EMPTY,
                provenance={"source": "live_and_sqlite", "entity_found": False},
            )

        engine = TraceEngine(graph, max_depth=depth)
        res = engine.trace(target_entity)

        node_items = [
            EntityGraphNodeItem(
                node_id=n.node_id, kind=n.kind.value, label=n.label, properties=n.properties
            )
            for n in res.nodes_visited
        ]
        edge_items = [
            EntityGraphEdgeItem(
                edge_id=e.edge_id,
                source_id=e.source_id,
                target_id=e.target_id,
                relation_type=e.relation_type.value,
                confidence=e.confidence,
                is_observed=e.is_observed,
                evidence_id=e.evidence_id,
            )
            for e in res.edges_traversed
        ]

        return TraceGraphResponse(
            node_count=len(node_items),
            edge_count=len(edge_items),
            nodes=node_items,
            edges=edge_items,
            truncated=res.truncated,
            data_status=CONNECTED,
            provenance={"source": "live_and_sqlite", "entity_found": True},
        )

    @app.post(
        "/api/v1/trace/investigation/generate",
        response_model=InvestigationReportResponse,
        tags=["Trace & Investigation"],
        summary="Generate verifiable investigation report with provenance hash",
    )
    def generate_investigation_report(
        request: GenerateInvestigationReportRequest,
        svc: ApiService = Depends(get_service),
        rt: LiveRuntime = Depends(get_live_runtime),
    ) -> InvestigationReportResponse:
        """Generate full reproducible markdown investigation report."""
        events = list(request.events)
        if not events:
            real_events, _ = _collect_real_trace_events(svc, rt, limit=50)
            events = [
                ev
                for ev in real_events
                if request.incident_id
                in {
                    ev.get("incident_id"),
                    ev.get("campaign_key"),
                    ev.get("session_id"),
                }
            ] or real_events

        reconstructor = AttackTimelineReconstructor()
        timeline = reconstructor.reconstruct_timeline(request.incident_id, events)

        gen = InvestigationReportGenerator()
        rep = gen.generate_report(
            incident_id=request.incident_id,
            title=request.title,
            severity=request.severity,
            root_cause_summary=request.root_cause_summary,
            timeline=timeline,
            evidence_records=request.evidence_records,
        )

        stage_items = [
            TimelineStageItem(
                stage_id=s.stage_id,
                phase=s.phase.value,
                timestamp=s.timestamp,
                source_entity=s.source_entity,
                target_entity=s.target_entity,
                title=s.title,
                description=s.description,
                confidence=s.confidence,
                is_observed=s.is_observed,
                evidence_ids=s.evidence_ids,
                indicators=s.indicators,
            )
            for s in rep.timeline.stages
        ]

        tl_resp = TraceTimelineResponse(
            timeline_id=rep.timeline.timeline_id,
            campaign_name=rep.timeline.campaign_name,
            overall_confidence=rep.timeline.overall_confidence,
            start_time=rep.timeline.start_time,
            end_time=rep.timeline.end_time,
            entities_involved=rep.timeline.entities_involved,
            total_stages=len(stage_items),
            stages=stage_items,
            data_status=CONNECTED if stage_items else EMPTY,
        )

        return InvestigationReportResponse(
            report_id=rep.report_id,
            incident_id=rep.incident_id,
            title=rep.title,
            generated_at=rep.generated_at,
            severity=rep.severity,
            root_cause_summary=rep.root_cause_summary,
            artifact_hash=rep.artifact_hash,
            artifact_version=rep.artifact_version,
            timeline=tl_resp,
            evidence_provenance=rep.evidence_provenance,
            recommended_actions=rep.recommended_actions,
            markdown_content=rep.to_markdown(),
        )

    @app.get(
        "/api/v1/crypto/status",
        response_model=CryptoStatusResponse,
        tags=["Cryptography & Keys"],
        summary="Get active cryptographic key metadata, protection mode, and rotation history",
    )
    def get_crypto_status(
        domain: str = Query("general"),
        svc: ApiService = Depends(get_service),
        rt: LiveRuntime = Depends(get_live_runtime),
    ) -> CryptoStatusResponse:
        """Get live cryptographic status, DPAPI/POSIX protection, and real rotation history."""
        persisted = svc.list_rotation_audits(limit=20, offset=0)
        persisted_rows = [item.model_dump() for item in persisted.items]
        payload = rt.crypto_status(domain=domain, persisted_rotations=persisted_rows)
        return CryptoStatusResponse(**payload)

    return app


# Default ASGI application instance for uvicorn
app = create_app()
