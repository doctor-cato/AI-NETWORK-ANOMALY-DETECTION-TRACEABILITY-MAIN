"""Trace and Attack Reconstruction Engine for NetFlow Sentinel v2.0.

Provides entity relationship graph, cross-source event correlation, alert deduplication,
graph traversal, multi-stage attack timeline reconstruction, and investigation reports. (Milestone M6.4).
"""

from .graph import EntityNode, RelationEdge, EntityRelationshipGraph, AlertDeduplicator
from .engine import TraceEngine, TraceResult
from .timeline import AttackTimeline, AttackStage, AttackPhase
from .investigation import InvestigationReportGenerator, InvestigationReport

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
