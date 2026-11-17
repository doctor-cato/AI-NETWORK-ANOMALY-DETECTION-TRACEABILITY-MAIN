"""Investigation report generator with evidence provenance.

Implements Issue #113 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .timeline import AttackTimeline


@dataclass
class InvestigationReport:
    report_id: str
    incident_id: str
    title: str
    generated_at: str
    severity: str
    root_cause_summary: str
    timeline: AttackTimeline
    evidence_provenance: List[Dict[str, Any]]
    recommended_actions: List[str]
    artifact_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "incident_id": self.incident_id,
            "title": self.title,
            "generated_at": self.generated_at,
            "severity": self.severity,
            "root_cause_summary": self.root_cause_summary,
            "artifact_hash": self.artifact_hash,
            "timeline": self.timeline.to_dict(),
            "evidence_provenance": self.evidence_provenance,
            "recommended_actions": self.recommended_actions,
        }

    def to_markdown(self) -> str:
        lines = [
            f"# Incident Investigation Report: {self.title}",
            "",
            f"- **Report ID:** `{self.report_id}`",
            f"- **Incident ID:** `{self.incident_id}`",
            f"- **Generated At:** {self.generated_at}",
            f"- **Severity:** **{self.severity}**",
            f"- **Integrity SHA-256:** `{self.artifact_hash}`",
            "",
            "## 1. Root Cause Summary",
            self.root_cause_summary,
            "",
            "## 2. Attack Timeline & Multi-stage Progression",
            f"- **Campaign:** {self.timeline.campaign_name}",
            f"- **Overall Confidence:** {self.timeline.overall_confidence * 100:.1f}%",
            f"- **Entities Involved:** {', '.join(self.timeline.entities_involved)}",
            "",
            "| Stage | Phase | Timestamp | Source | Target | Title | Evidence Ref |",
            "|---|---|---|---|---|---|---|",
        ]
        for s in self.timeline.stages:
            ev_ref = ", ".join(s.evidence_ids) or "N/A"
            lines.append(f"| `{s.stage_id}` | **{s.phase.value}** | {s.timestamp} | `{s.source_entity}` | `{s.target_entity}` | {s.title} | `{ev_ref}` |")

        lines.extend([
            "",
            "## 3. Evidence Provenance",
        ])
        for p in self.evidence_provenance:
            lines.append(f"- Evidence `{p.get('evidence_id')}`: source file `{p.get('source_file')}` (line {p.get('line')}), SHA-256 `{p.get('sha256')}`")

        lines.extend([
            "",
            "## 4. Recommended Incident Response Actions",
        ])
        for act in self.recommended_actions:
            lines.append(f"- [ ] {act}")

        return "\n".join(lines)


class InvestigationReportGenerator:
    """Renders comprehensive, verifiable incident investigation reports."""

    def generate_report(
        self,
        incident_id: str,
        title: str,
        severity: str,
        root_cause_summary: str,
        timeline: AttackTimeline,
        evidence_records: List[Dict[str, Any]],
        recommended_actions: Optional[List[str]] = None,
    ) -> InvestigationReport:
        now_iso = datetime.now(timezone.utc).isoformat()
        rid = f"rep-{incident_id}-{int(datetime.now(timezone.utc).timestamp())}"

        actions = recommended_actions or [
            "Trigger immediate risk-based adaptive key rotation for affected vector keystore.",
            "Isolate compromised host network interfaces via local firewall policy.",
            "Verify behavioral vector divergence for subsequent traffic from source entity.",
        ]

        report = InvestigationReport(
            report_id=rid,
            incident_id=incident_id,
            title=title,
            generated_at=now_iso,
            severity=severity,
            root_cause_summary=root_cause_summary,
            timeline=timeline,
            evidence_provenance=evidence_records,
            recommended_actions=actions,
        )

        # Compute deterministic artifact hash
        payload_for_hash = json.dumps(
            {
                "incident_id": incident_id,
                "timeline": timeline.to_dict(),
                "evidence": evidence_records,
            },
            sort_keys=True,
        ).encode("utf-8")
        report.artifact_hash = hashlib.sha256(payload_for_hash).hexdigest()

        return report
