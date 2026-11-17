"""Trace and Attack Reconstruction Engine for NetFlow Sentinel v2.0.

Provides entity relationship graph, cross-source event correlation, alert deduplication,
graph traversal, multi-stage attack timeline reconstruction, and investigation reports. (Milestone M6.4).
"""

from .engine import TraceEngine, TraceResult
from .graph import AlertDeduplicator, EntityNode, EntityRelationshipGraph, RelationEdge
from .investigation import InvestigationReport, InvestigationReportGenerator
from .timeline import AttackPhase, AttackStage, AttackTimeline

__all__ = [
    "EntityNode",
    "RelationEdge",
    "EntityRelationshipGraph",
    "AlertDeduplicator",
    "TraceEngine",
    "TraceResult",
    "AttackTimeline",
    "AttackStage",
    "AttackPhase",
    "InvestigationReportGenerator",
    "InvestigationReport",
]
