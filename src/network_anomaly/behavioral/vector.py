"""16-Dimensional Behavioral Vector schema and builder.

Implements Issue #102 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import hashlib
import json
import math
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np

from network_anomaly.canonical.event import CanonicalSecurityEvent, EventKind

from .sessionizer import SessionSummary


@dataclass
class BehavioralVector:
    vector_id: str
    entity_key: str
    window_start: str
    window_end: str
    dimensions: int = 16
    version: str = "2.0.0"
    features: List[float] = None
    feature_names: List[str] = None
    sha256_hash: str = ""
    missing_feature_count: int = 0
    missing_feature_names: Tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vector_id": self.vector_id,
            "entity_key": self.entity_key,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "dimensions": self.dimensions,
            "version": self.version,
            "features": self.features,
            "feature_names": self.feature_names,
            "sha256_hash": self.sha256_hash,
            "missing_feature_count": int(self.missing_feature_count),
            "missing_feature_names": list(self.missing_feature_names),
        }

    def to_numpy(self) -> np.ndarray:
        return np.array(self.features, dtype=np.float32)


class BehavioralVectorBuilder:
    """Builds a standardized, L2-normalized 16-D behavioral vector from a SessionSummary."""

    FEATURE_NAMES = [
        "log_duration",
        "log_bytes_in",
        "log_bytes_out",
        "bytes_ratio_clipped",
        "log_pkts_in",
        "log_pkts_out",
        "pkts_ratio_clipped",
        "unique_ports_norm",
        "unique_protocols_norm",
        "syn_flag_ratio",
        "rst_flag_ratio",
        "dns_intensity",
        "http_intensity",
        "auth_failure_ratio",
        "log_mean_iat",
        "log_std_iat",
    ]

    def build_vector(
        self,
        session: SessionSummary,
        events: Optional[Sequence[CanonicalSecurityEvent]] = None,
    ) -> BehavioralVector:
        dur = max(session.duration_seconds, 0.001)
        cnt = max(session.event_count, 1)

        raw = [
            math.log1p(session.duration_seconds),
            math.log1p(session.bytes_in),
            math.log1p(session.bytes_out),
            min(session.bytes_ratio, 10.0),
            math.log1p(session.pkts_in),
            math.log1p(session.pkts_out),
            min(session.pkts_ratio, 10.0),
            min(session.unique_ports / 100.0, 1.0),
            min(session.unique_protocols / 10.0, 1.0),
            session.syn_flag_count / cnt,
            session.rst_flag_count / cnt,
            min(session.dns_query_count / dur, 50.0),
            min(session.http_request_count / dur, 50.0),
            session.auth_failure_count / cnt,
            math.log1p(max(session.mean_iat_ms, 0.0)),
            math.log1p(max(session.std_iat_ms, 0.0)),
        ]

        # Verify no NaN or Inf and record missing/non-finite dimensions explicitly
        cleaned: List[float] = []
        missing_names: List[str] = []

        def _record_missing(name: str) -> None:
            if name not in missing_names:
                missing_names.append(name)

        if session.event_count <= 0:
            _record_missing("event_count")
        for idx, x in enumerate(raw):
            if x is None or math.isnan(x) or math.isinf(x):
                cleaned.append(0.0)
                if idx < len(self.FEATURE_NAMES):
                    _record_missing(self.FEATURE_NAMES[idx])
            else:
                cleaned.append(float(x))

        # Explicitly track missingness for app/auth dimensions when underlying event kinds are absent,
        # while keeping numeric 0.0 for backward compatibility.
        session_events = events if events is not None else getattr(session, "events", None)
        present_kinds_attr = getattr(session, "present_event_kinds", None)
        if session_events is not None:
            present_kinds = {ev.event_kind for ev in session_events}
            if EventKind.DNS not in present_kinds and session.dns_query_count <= 0:
                _record_missing("dns_intensity")
            if EventKind.WEB not in present_kinds and session.http_request_count <= 0:
                _record_missing("http_intensity")
            if EventKind.AUTH not in present_kinds and session.auth_failure_count <= 0:
                _record_missing("auth_failure_ratio")
        elif present_kinds_attr is not None:
            present_kinds = set(present_kinds_attr)
            if EventKind.DNS not in present_kinds and session.dns_query_count <= 0:
                _record_missing("dns_intensity")
            if EventKind.WEB not in present_kinds and session.http_request_count <= 0:
                _record_missing("http_intensity")
            if EventKind.AUTH not in present_kinds and session.auth_failure_count <= 0:
                _record_missing("auth_failure_ratio")
        elif (
            session.dns_query_count == 0
            and session.http_request_count == 0
            and session.auth_failure_count == 0
        ):
            _record_missing("dns_intensity")
            _record_missing("http_intensity")
            _record_missing("auth_failure_ratio")

        # L2-normalization for unit hypersphere projection
        arr = np.array(cleaned, dtype=np.float32)
        norm = np.linalg.norm(arr)
        if norm > 1e-7:
            arr = arr / norm
        normalized_features = [round(float(v), 6) for v in arr]

        # Deterministic SHA-256 hash of vector
        hash_payload = json.dumps(normalized_features).encode("ascii")
        sha256 = hashlib.sha256(hash_payload).hexdigest()

        vid = f"bv-{session.session_id}-{sha256[:8]}"
        return BehavioralVector(
            vector_id=vid,
            entity_key=session.entity_key,
            window_start=session.start_time.isoformat(),
            window_end=session.end_time.isoformat(),
            dimensions=16,
            version="2.0.0",
            features=normalized_features,
            feature_names=self.FEATURE_NAMES,
            sha256_hash=sha256,
            missing_feature_count=len(missing_names),
            missing_feature_names=tuple(missing_names),
        )


class EntityBaselineProfiler:
    """Sliding-window entity behavioral profiler and cosine deviation scorer."""

    def __init__(self, window_size: int = 50):
        if window_size < 1:
            raise ValueError("window_size must be >= 1")
        self.window_size = int(window_size)
        self._windows: Dict[str, deque[np.ndarray]] = {}

    def update(self, vector: BehavioralVector) -> int:
        buf = self._windows.setdefault(vector.entity_key, deque(maxlen=self.window_size))
        buf.append(np.asarray(vector.to_numpy(), dtype=np.float64))
        return len(buf)

    def baseline_centroid(self, entity_key: str) -> Optional[np.ndarray]:
        buf = self._windows.get(entity_key)
        if not buf:
            return None
        centroid = np.mean(np.stack(list(buf), axis=0), axis=0)
        norm = float(np.linalg.norm(centroid))
        return centroid / norm if norm > 1e-9 else centroid

    def score_deviation(self, vector: BehavioralVector) -> Dict[str, Any]:
        centroid = self.baseline_centroid(vector.entity_key)
        if centroid is None:
            return {
                "entity_key": vector.entity_key,
                "has_baseline": False,
                "deviation_score": 0.0,
                "cosine_similarity": 1.0,
                "sample_count": 0,
            }
        vec = np.asarray(vector.to_numpy(), dtype=np.float64)
        v_norm = float(np.linalg.norm(vec))
        c_norm = float(np.linalg.norm(centroid))
        if v_norm <= 1e-9 or c_norm <= 1e-9:
            cos_sim = 0.0
        else:
            cos_sim = float(np.clip(np.dot(vec, centroid) / (v_norm * c_norm), -1.0, 1.0))
        deviation = float(max(0.0, 1.0 - cos_sim))
        return {
            "entity_key": vector.entity_key,
            "has_baseline": True,
            "deviation_score": round(deviation, 6),
            "cosine_similarity": round(cos_sim, 6),
            "sample_count": len(self._windows[vector.entity_key]),
        }
