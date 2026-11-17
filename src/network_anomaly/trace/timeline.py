"""Multi-stage attack timeline reconstruction.

Implements Issue #112 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Set


class AttackPhase(str, Enum):
    RECONNAISSANCE = "RECONNAISSANCE"
    INITIAL_ACCESS = "INITIAL_ACCESS"
    LATERAL_MOVEMENT = "LATERAL_MOVEMENT"
    EXFILTRATION_IMPACT = "EXFILTRATION_IMPACT"


@dataclass
class AttackStage:
    stage_id: str
    phase: AttackPhase
    timestamp: str
    source_entity: str
    target_entity: str
    title: str
    description: str
    confidence: float
    is_observed: bool
    evidence_ids: List[str] = field(default_factory=list)
    indicators: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_id": self.stage_id,
            "phase": self.phase.value,
            "timestamp": self.timestamp,
            "source_entity": self.source_entity,
            "target_entity": self.target_entity,
            "title": self.title,
            "description": self.description,
            "confidence": round(self.confidence, 4),
            "is_observed": self.is_observed,
            "evidence_ids": self.evidence_ids,
            "indicators": self.indicators,
        }


@dataclass
class AttackTimeline:
    timeline_id: str
    campaign_name: str
    stages: List[AttackStage]
    overall_confidence: float
    start_time: str
    end_time: str
    entities_involved: List[str]

    @property
    def stage_count(self) -> int:
        return len(self.stages)

    def to_dict(self) -> Dict[str, Any]:

        return {
            "timeline_id": self.timeline_id,
            "campaign_name": self.campaign_name,
            "overall_confidence": round(self.overall_confidence, 4),
            "start_time": self.start_time,
            "end_time": self.end_time,
            "entities_involved": self.entities_involved,
            "stage_count": len(self.stages),
            "stages": [s.to_dict() for s in self.stages],
        }


class AttackTimelineReconstructor:
    """Reconstructs ordered multi-stage attack timelines from correlated events."""

    def reconstruct_timeline(
        self,
        campaign_name: str,
        events: List[Dict[str, Any]],
    ) -> AttackTimeline:
        """Classify events into ATT&CK phases and assemble timeline."""
        if not events:
            now = datetime.now(timezone.utc).isoformat()
            return AttackTimeline(
                timeline_id=f"tl-{campaign_name}",
                campaign_name=campaign_name,
                stages=[],
                overall_confidence=0.0,
                start_time=now,
                end_time=now,
                entities_involved=[],
            )

        sorted_events = sorted(events, key=lambda e: e.get("timestamp", ""))
        stages: List[AttackStage] = []
        entities: Set[str] = set()

        for idx, ev in enumerate(sorted_events):
            src = ev.get("source_ip", "unknown")
            dst = ev.get("dest_ip", "unknown")
            entities.add(src)
            entities.add(dst)

            attack_type = (ev.get("attack_type") or "").lower()
            dst_port = ev.get("dest_port", 0)
            bytes_out = ev.get("bytes_out", 0)

            # Explicit attack_type classification takes precedence
            if any(k in attack_type for k in ["exploit", "fuzzers", "backdoor", "injection"]):
                phase = AttackPhase.INITIAL_ACCESS
                title = f"Inbound exploitation targeting service on port {dst_port}"
            elif any(k in attack_type for k in ["reconnaissance", "scan", "probe"]):
                phase = AttackPhase.RECONNAISSANCE
                title = f"Port scanning and service reconnaissance from {src}"
            elif any(k in attack_type for k in ["lateral", "internal", "worm", "smb"]) or (
                dst_port in (445, 139, 3389, 22) and src.startswith("10.") and dst.startswith("10.")
            ):
                phase = AttackPhase.LATERAL_MOVEMENT
                title = f"Internal lateral traversal from {src} to {dst}"
            elif (
                any(k in attack_type for k in ["exfiltration", "dos", "ddos"]) or bytes_out > 500000
            ):
                phase = AttackPhase.EXFILTRATION_IMPACT
                title = f"Data exfiltration / high impact traffic from {src}"
            elif dst_port in (21, 23, 80, 443, 8080) and bytes_out < 500:
                phase = AttackPhase.RECONNAISSANCE
                title = f"Probing service port {dst_port} from {src}"
            else:
                phase = AttackPhase.INITIAL_ACCESS
                title = f"Suspicious activity detected between {src} and {dst}"

            stage = AttackStage(
                stage_id=f"stg-{idx + 1}",
                phase=phase,
                timestamp=ev.get("timestamp", datetime.now(timezone.utc).isoformat()),
                source_entity=src,
                target_entity=dst,
                title=title,
                description=ev.get("description", f"Event {ev.get('event_id', idx)}"),
                confidence=float(ev.get("confidence", 0.90)),
                is_observed=bool(ev.get("is_observed", True)),
                evidence_ids=[ev.get("event_id", str(idx))],
                indicators={"port": dst_port, "risk": ev.get("risk_score", 50.0)},
            )
            stages.append(stage)

        avg_conf = sum(s.confidence for s in stages) / len(stages)
        return AttackTimeline(
            timeline_id=f"tl-{campaign_name}",
            campaign_name=campaign_name,
            stages=stages,
            overall_confidence=round(avg_conf, 4),
            start_time=stages[0].timestamp,
            end_time=stages[-1].timestamp,
            entities_involved=sorted(list(entities)),
        )
