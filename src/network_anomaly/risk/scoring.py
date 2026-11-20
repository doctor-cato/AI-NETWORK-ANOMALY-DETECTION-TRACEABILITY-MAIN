"""Multi-criteria risk scoring methodology (0-100) and severity calibration.

Implements Issue #108 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional


class SeverityLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class RiskScoreOutput:
    score: float
    severity: SeverityLevel
    trigger_adaptive_rotation: bool
    component_breakdown: Dict[str, float]
    justification: List[str]
    is_ood: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": round(self.score, 2),
            "severity": self.severity.value,
            "trigger_adaptive_rotation": self.trigger_adaptive_rotation,
            "component_breakdown": {k: round(v, 2) for k, v in self.component_breakdown.items()},
            "justification": self.justification,
            "is_ood": self.is_ood,
        }


class RiskScorer:
    """Calculates deterministic risk scores on scale 0.0 to 100.0."""

    CRITICAL_ROTATION_THRESHOLD = 85.0
    HIGH_SEVERITY_THRESHOLD = 70.0
    MEDIUM_SEVERITY_THRESHOLD = 30.0

    # Sensitivity weights
    W_AI_CONFIDENCE = 50.0  # Up to 50 pts from multi-model AI ensemble
    W_BEHAVIORAL_DEV = 25.0  # Up to 25 pts from behavioral deviation / session anomaly
    W_PORT_PROTOCOL = 15.0  # Up to 15 pts from sensitive ports / critical services
    W_AUTH_FAILURES = 10.0  # Up to 10 pts from authentication failure bursts

    SENSITIVE_PORTS = {22, 23, 88, 389, 445, 1433, 3389, 5985, 5986}

    def compute_risk(
        self,
        ai_probability: float,
        behavioral_anomaly_score: float = 0.0,
        dest_port: Optional[int] = None,
        auth_failure_count: int = 0,
        is_ood: bool = False,
        known_attack_type: Optional[str] = None,
    ) -> RiskScoreOutput:
        """Compute composite risk score 0.0 .. 100.0."""
        reasons: List[str] = []
        breakdown: Dict[str, float] = {}
        non_finite_input = False

        # Clean inputs (fail-closed on NaN / +/-Inf)
        raw_ai = float(ai_probability)
        if not math.isfinite(raw_ai):
            non_finite_input = True
            ai_prob = 0.0
            reasons.append(
                "Non-finite AI probability detected; fail-closed to 0.0 and adaptive rotation blocked"
            )
        else:
            ai_prob = max(0.0, min(1.0, raw_ai))

        raw_beh = float(behavioral_anomaly_score)
        if not math.isfinite(raw_beh):
            non_finite_input = True
            beh_score = 0.0
            reasons.append(
                "Non-finite behavioral anomaly score detected; fail-closed to 0.0 and adaptive rotation blocked"
            )
        else:
            beh_score = max(0.0, min(1.0, raw_beh))

        auth_failure_count = max(0, int(auth_failure_count))

        # 1. AI Component (0 .. 50)
        c_ai = ai_prob * self.W_AI_CONFIDENCE
        breakdown["ai_confidence"] = c_ai
        if ai_prob >= 0.8:
            reasons.append(
                f"AI Model Ensemble indicated strong anomaly probability ({ai_prob:.2f})"
            )

        # 2. Behavioral Component (0 .. 25)
        c_beh = beh_score * self.W_BEHAVIORAL_DEV
        breakdown["behavioral_deviation"] = c_beh
        if beh_score >= 0.7:
            reasons.append(
                f"Behavioral vector showed marked deviation from baseline ({beh_score:.2f})"
            )

        # 3. Port / Protocol Sensitivity (0 .. 15)
        c_port = 0.0
        if dest_port in self.SENSITIVE_PORTS:
            c_port = self.W_PORT_PROTOCOL
            reasons.append(f"Targeting sensitive infrastructure port {dest_port}")
        elif dest_port is not None and dest_port < 1024:
            c_port = self.W_PORT_PROTOCOL * 0.4
        breakdown["port_protocol"] = c_port

        # 4. Auth Failures (0 .. 10)
        c_auth = min(auth_failure_count * 2.5, self.W_AUTH_FAILURES)
        breakdown["auth_failures"] = c_auth
        if auth_failure_count >= 3:
            reasons.append(f"Detected {auth_failure_count} consecutive authentication failures")

        # Total Raw Score
        raw_score = c_ai + c_beh + c_port + c_auth

        # Non-finite input handling: prevent corrupted telemetry from reaching CRITICAL or triggering rotation
        if non_finite_input:
            raw_score = min(raw_score, 65.0)

        # OOD handling: Out-of-distribution events should not get false CRITICAL without confirmation
        if is_ood:
            reasons.append(
                "Out-of-Distribution (OOD) sample: capped at 65.0 to prevent false-alarm key rotation"
            )
            raw_score = min(raw_score, 65.0)

        total_score = max(0.0, min(100.0, raw_score))

        # Severity Calibration
        if total_score >= self.CRITICAL_ROTATION_THRESHOLD:
            sev = SeverityLevel.CRITICAL
        elif total_score >= self.HIGH_SEVERITY_THRESHOLD:
            sev = SeverityLevel.HIGH
        elif total_score >= self.MEDIUM_SEVERITY_THRESHOLD:
            sev = SeverityLevel.MEDIUM
        else:
            sev = SeverityLevel.LOW

        trigger_rotation = sev == SeverityLevel.CRITICAL and not is_ood and not non_finite_input

        return RiskScoreOutput(
            score=total_score,
            severity=sev,
            trigger_adaptive_rotation=trigger_rotation,
            component_breakdown=breakdown,
            justification=reasons,
            is_ood=is_ood,
        )
