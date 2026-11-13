"""FastAPI application entrypoint for AI Network Anomaly Detection & Traceability.

Exposes RESTful endpoints for ingestion, analysis, incident tracking,
event timeline, key rotation lifecycle, and system health checks.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional, Union

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Response, status

from network_anomaly.api.db import DatabaseManager
from network_anomaly.api.errors import register_error_handlers
from network_anomaly.api.repositories import IncidentRepository
from network_anomaly.api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    HealthResponse,
    IncidentCreateRequest,
    IncidentResponse,
    IncidentUpdateRequest,
    IngestBatchRequest,
    IngestResponse,
    KeyMetadataResponse,
    KeyRotationRequest,
    KeyRotationResponse,
    PaginatedIncidentsResponse,
    PaginatedRotationAuditResponse,
    PaginatedTimelineResponse,
)
from network_anomaly.api.service import ApiService


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

    return app


# Default ASGI application instance for uvicorn
app = create_app()
