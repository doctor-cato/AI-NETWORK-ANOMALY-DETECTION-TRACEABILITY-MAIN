"""Thin client SDK for interacting with the Network Anomaly Detection FastAPI service.

Used by Streamlit (Issue #16) and integration tests to ensure that the UI
and external consumers strictly call REST endpoints without duplicating
ML inference or persistence logic.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

import httpx


class NetworkAnomalyApiClient:
    """Client for Network Anomaly Detection REST API."""

    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        timeout: float = 10.0,
        client: Optional[httpx.Client] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._client = client or httpx.Client(base_url=self.base_url, timeout=self.timeout)

    def close(self) -> None:
        """Close the underlying HTTP client session."""
        self._client.close()

    def __enter__(self) -> NetworkAnomalyApiClient:
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def get_health(self) -> Dict[str, Any]:
        """Fetch system and model readiness status."""
        resp = self._client.get("/health")
        resp.raise_for_status()
        return resp.json()

    def ingest_events(
        self,
        events: List[Dict[str, Any]],
        session_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Ingest a batch of flow telemetry events."""
        headers = {}
        if idempotency_key:
            headers["X-Idempotency-Key"] = idempotency_key
        payload: Dict[str, Any] = {"events": events}
        if session_id:
            payload["session_id"] = session_id
        if idempotency_key:
            payload["idempotency_key"] = idempotency_key

        resp = self._client.post("/api/v1/ingest", json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()

    def analyze(
        self,
        events: List[Dict[str, Any]],
        model_name: str = "random_forest",
        threshold: float = 0.5,
        create_incidents: bool = True,
    ) -> Dict[str, Any]:
        """Request anomaly detection analysis on flow events."""
        payload = {
            "events": events,
            "model_name": model_name,
            "threshold": threshold,
            "create_incidents": create_incidents,
        }
        resp = self._client.post("/api/v1/analyze", json=payload)
        resp.raise_for_status()
        return resp.json()

    def list_incidents(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Query paginated security incidents."""
        params: Dict[str, Any] = {"limit": limit, "offset": offset}
        if severity:
            params["severity"] = severity
        if status:
            params["status"] = status
        resp = self._client.get("/api/v1/incidents", params=params)
        resp.raise_for_status()
        return resp.json()

    def get_incident(self, incident_id: str) -> Dict[str, Any]:
        """Fetch incident details by ID."""
        resp = self._client.get(f"/api/v1/incidents/{incident_id}")
        resp.raise_for_status()
        return resp.json()

    def update_incident(self, incident_id: str, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update incident alert status or severity."""
        resp = self._client.patch(f"/api/v1/incidents/{incident_id}", json=updates)
        resp.raise_for_status()
        return resp.json()

    def get_timeline(self, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        """Fetch unified timeline events."""
        resp = self._client.get("/api/v1/timeline", params={"limit": limit, "offset": offset})
        resp.raise_for_status()
        return resp.json()

    def trigger_key_rotation(
        self,
        triggered_by: str = "operator",
        dry_run: bool = True,
        reason: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Trigger cryptographic key rotation."""
        headers = {}
        if idempotency_key:
            headers["X-Idempotency-Key"] = idempotency_key
        payload = {
            "triggered_by": triggered_by,
            "dry_run": dry_run,
            "reason": reason or "Policy rotation",
            "idempotency_key": idempotency_key,
        }
        resp = self._client.post("/api/v1/rotation", json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()

    def list_rotation_audits(self, limit: int = 50, offset: int = 0) -> Dict[str, Any]:
        """Fetch key rotation audit logs."""
        resp = self._client.get("/api/v1/rotation/audit", params={"limit": limit, "offset": offset})
        resp.raise_for_status()
        return resp.json()

    def list_keys(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Fetch key metadata list."""
        resp = self._client.get("/api/v1/keys", params={"limit": limit, "offset": offset})
        resp.raise_for_status()
        return resp.json()
