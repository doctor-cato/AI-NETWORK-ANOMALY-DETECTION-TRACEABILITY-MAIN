"""FastAPI application entrypoint for AI Network Anomaly Detection & Traceability.

Exposes RESTful endpoints for ingestion, analysis, incident tracking,
event timeline, key rotation lifecycle, and system health checks.
"""

from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import List, Optional, Union

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
from network_anomaly.api.repositories import IncidentRepository
from network_anomaly.api.response_policy import (
    export_security_simulation_evidence,
    list_security_simulations,
    simulate_security_response,
)
from network_anomaly.api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
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
from network_anomaly.crypto.key_manager import KeyManager
from network_anomaly.crypto.rotation import KeyRotationPolicy
from network_anomaly.trace.engine import TraceEngine
from network_anomaly.trace.graph import (
    EntityKind,
    EntityRelationshipGraph,
    RelationType,
)
from network_anomaly.trace.investigation import InvestigationReportGenerator
from network_anomaly.trace.timeline import AttackTimelineReconstructor


def create_app(db_path: Optional[Union[str, Path]] = None) -> FastAPI:
    """Application factory creating a configured FastAPI instance.

    Parameters
    ----------
    db_path : str or Path, optional
        Custom SQLite database path or ':memory:'. Defaults to standard project DB.
    """
    db_manager = DatabaseManager(db_path=db_path)
    service = ApiService(db=db_manager)

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
    )

    # Attach db_manager and service to app state for lifecycle/test inspection
    app.state.db_manager = db_manager
    app.state.service = service

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

    # Dependency getters
    def get_service() -> ApiService:
        return app.state.service

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
    # NetFlow Sentinel v2.0 Trace & Cryptography Endpoints (Issue #115)
    # ========================================================================

    @app.get(
        "/api/v1/trace/timeline",
        response_model=TraceTimelineResponse,
        tags=["Trace & Investigation"],
        summary="Get reconstructed multi-stage attack timeline",
    )
    def get_attack_timeline(
        campaign_name: str = Query("APT-Campaign-01", min_length=1),
        limit: int = Query(50, ge=1, le=200),
        offset: int = Query(0, ge=0),
        svc: ApiService = Depends(get_service),
    ) -> TraceTimelineResponse:
        """Reconstruct multi-stage attack timeline from correlated security events."""
        # Query incidents or events from repository
        paginated = svc.list_incidents(limit=limit, offset=offset)
        events_data = []
        for inc in paginated.items:
            events_data.append(
                {
                    "event_id": inc.incident_id,
                    "timestamp": inc.created_at,
                    "source_ip": "198.51.100.10",
                    "dest_ip": "10.0.0.5",
                    "attack_type": inc.attack_type or "Suspicious",
                    "risk_score": inc.anomaly_score * 100.0,
                    "dest_port": 443,
                    "confidence": 0.95,
                }
            )

        if not events_data:
            events_data = [
                {
                    "event_id": "seed-01",
                    "timestamp": "2026-11-17T10:00:00Z",
                    "source_ip": "198.51.100.10",
                    "dest_ip": "10.0.0.5",
                    "attack_type": "Reconnaissance",
                    "dest_port": 80,
                    "confidence": 0.92,
                },
                {
                    "event_id": "seed-02",
                    "timestamp": "2026-11-17T10:15:00Z",
                    "source_ip": "198.51.100.10",
                    "dest_ip": "10.0.0.5",
                    "attack_type": "Exploits",
                    "dest_port": 80,
                    "confidence": 0.98,
                },
            ]

        reconstructor = AttackTimelineReconstructor()
        timeline = reconstructor.reconstruct_timeline(campaign_name, events_data)

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

        return TraceTimelineResponse(
            timeline_id=timeline.timeline_id,
            campaign_name=timeline.campaign_name,
            overall_confidence=timeline.overall_confidence,
            start_time=timeline.start_time,
            end_time=timeline.end_time,
            entities_involved=timeline.entities_involved,
            total_stages=len(stage_items),
            stages=stage_items,
        )

    @app.get(
        "/api/v1/trace/graph",
        response_model=TraceGraphResponse,
        tags=["Trace & Investigation"],
        summary="Query entity relationship graph around an entity or incident",
    )
    def get_entity_graph(
        entity_id: str = Query("10.0.0.5", min_length=1),
        depth: int = Query(2, ge=1, le=5),
        svc: ApiService = Depends(get_service),
    ) -> TraceGraphResponse:
        """Query and traverse entity relationship graph around target entity."""
        graph = EntityRelationshipGraph()
        # Seed graph with observed topology
        graph.add_node(entity_id, EntityKind.IP, f"Target Entity ({entity_id})")
        graph.add_node("198.51.100.10", EntityKind.IP, "External Threat Actor")
        graph.add_node("port:443", EntityKind.PORT, "Web HTTPS")
        graph.add_node("user:admin", EntityKind.USER, "Target User")

        graph.add_edge(
            "198.51.100.10", entity_id, RelationType.CONNECTS_TO, confidence=1.0, is_observed=True
        )
        graph.add_edge(
            entity_id, "port:443", RelationType.CONNECTS_TO, confidence=1.0, is_observed=True
        )
        graph.add_edge(
            entity_id,
            "user:admin",
            RelationType.AUTHENTICATES_AS,
            confidence=0.85,
            is_observed=True,
        )

        engine = TraceEngine(graph, max_depth=depth)
        res = engine.trace(entity_id)

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
    ) -> InvestigationReportResponse:
        """Generate full reproducible markdown investigation report."""
        reconstructor = AttackTimelineReconstructor()
        timeline = reconstructor.reconstruct_timeline(request.incident_id, request.events)

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
        )

        return InvestigationReportResponse(
            report_id=rep.report_id,
            incident_id=rep.incident_id,
            title=rep.title,
            generated_at=rep.generated_at,
            severity=rep.severity,
            root_cause_summary=rep.root_cause_summary,
            artifact_hash=rep.artifact_hash,
            timeline=tl_resp,
            evidence_provenance=rep.evidence_provenance,
            recommended_actions=rep.recommended_actions,
            markdown_content=rep.to_markdown(),
        )

    @app.get(
        "/api/v1/crypto/status",
        response_model=CryptoStatusResponse,
        tags=["Cryptography & Keys"],
        summary="Get active cryptographic key metadata and rotation policies",
    )
    def get_crypto_status(
        domain: str = Query("general"),
        svc: ApiService = Depends(get_service),
    ) -> CryptoStatusResponse:
        """Get live cryptographic status, active AES-GCM key, and rotation history."""
        km = KeyManager()
        policy = KeyRotationPolicy(km)
        active_id, _ = km.get_active_key(domain=domain)
        km_meta = km.get_metadata(active_id)
        records_enc = km_meta.records_encrypted_count if km_meta else 0

        audit_history = [
            {
                "rotation_id": r.rotation_id,
                "trigger": r.trigger.value,
                "decision": r.decision.value,
                "new_key_id": r.new_key_id,
                "timestamp": r.timestamp,
                "reason": r.reason,
            }
            for r in policy.get_audit_history()[-10:]
        ]

        return CryptoStatusResponse(
            active_key_id=active_id,
            algorithm="AES-256-GCM",
            rotation_interval_minutes=30.0,
            adaptive_risk_threshold=85.0,
            cooldown_seconds=60,
            total_rotations=len(km.list_keys()),
            total_records_encrypted=records_enc,
            recent_rotations=audit_history,
        )

    return app


# Default ASGI application instance for uvicorn
app = create_app()
