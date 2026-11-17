"""Entity relationship graph and alert deduplication.

Implements Issue #110 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set


class EntityKind(str, Enum):
    IP = "IP"
    PORT = "PORT"
    DOMAIN = "DOMAIN"
    USER = "USER"
    PROCESS = "PROCESS"
    ALERT = "ALERT"


class RelationType(str, Enum):
    CONNECTS_TO = "CONNECTS_TO"
    RESOLVES_TO = "RESOLVES_TO"
    AUTHENTICATES_AS = "AUTHENTICATES_AS"
    SPAWNS = "SPAWNS"
    TRIGGERED_ALERT = "TRIGGERED_ALERT"
    SIMILAR_BEHAVIOR = "SIMILAR_BEHAVIOR"


@dataclass
class EntityNode:
    node_id: str
    kind: EntityKind
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    first_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "kind": self.kind.value,
            "label": self.label,
            "properties": self.properties,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
        }


@dataclass
class RelationEdge:
    edge_id: str
    source_id: str
    target_id: str
    relation_type: RelationType
    confidence: float = 1.0
    is_observed: bool = True  # True = directly observed telemetry; False = inferred hypothesis
    evidence_id: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation_type": self.relation_type.value,
            "confidence": round(self.confidence, 4),
            "is_observed": self.is_observed,
            "evidence_id": self.evidence_id,
            "timestamp": self.timestamp,
            "attributes": self.attributes,
        }


class EntityRelationshipGraph:
    """In-memory Directed Entity Relationship Graph for threat tracing."""

    def __init__(self):
        self.nodes: Dict[str, EntityNode] = {}
        self.edges: Dict[str, RelationEdge] = {}
        self._adj: Dict[str, Set[str]] = {}       # node_id -> set of edge_ids (outgoing)
        self._rev_adj: Dict[str, Set[str]] = {}   # node_id -> set of edge_ids (incoming)

    def add_node(self, node_id: str, kind: EntityKind, label: str, properties: Optional[Dict[str, Any]] = None) -> EntityNode:
        if node_id in self.nodes:
            self.nodes[node_id].last_seen = datetime.now(timezone.utc).isoformat()
            if properties:
                self.nodes[node_id].properties.update(properties)
            return self.nodes[node_id]

        node = EntityNode(node_id=node_id, kind=kind, label=label, properties=properties or {})
        self.nodes[node_id] = node
        self._adj[node_id] = set()
        self._rev_adj[node_id] = set()
        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        relation_type: RelationType,
        confidence: float = 1.0,
        is_observed: bool = True,
        evidence_id: Optional[str] = None,
        attributes: Optional[Dict[str, Any]] = None,
    ) -> RelationEdge:
        # Ensure source and target exist
        if source_id not in self.nodes:
            self.add_node(source_id, EntityKind.IP, label=source_id)
        if target_id not in self.nodes:
            self.add_node(target_id, EntityKind.IP, label=target_id)

        edge_id = f"e:{source_id}->{relation_type.value}->{target_id}"
        edge = RelationEdge(
            edge_id=edge_id,
            source_id=source_id,
            target_id=target_id,
            relation_type=relation_type,
            confidence=confidence,
            is_observed=is_observed,
            evidence_id=evidence_id,
            attributes=attributes or {},
        )
        self.edges[edge_id] = edge
        self._adj[source_id].add(edge_id)
        self._rev_adj[target_id].add(edge_id)
        return edge

    def add_event(self, event: Any) -> None:
        """Convenience method to register entities and interaction edges from a CanonicalSecurityEvent."""
        src_ip = getattr(event, "source_ip", None)
        dst_ip = getattr(event, "dest_ip", None)
        if src_ip:
            self.add_node(f"ip:{src_ip}", EntityKind.IP, label=src_ip)
        if dst_ip:
            self.add_node(f"ip:{dst_ip}", EntityKind.IP, label=dst_ip)
        if src_ip and dst_ip:
            self.add_edge(
                source_id=f"ip:{src_ip}",
                target_id=f"ip:{dst_ip}",
                relation_type=RelationType.CONNECTS_TO,
                confidence=1.0,
                is_observed=True,
                evidence_id=getattr(event, "event_id", None),
                attributes={"protocol": getattr(event, "protocol", "TCP")},
            )
        auth_data = getattr(event, "auth_data", None)
        if auth_data and getattr(auth_data, "username", None):
            user = auth_data.username
            self.add_node(f"user:{user}", EntityKind.USER, label=user)
            if src_ip:
                self.add_edge(
                    source_id=f"ip:{src_ip}",
                    target_id=f"user:{user}",
                    relation_type=RelationType.AUTHENTICATES_AS,
                    confidence=1.0,
                    is_observed=True,
                    evidence_id=getattr(event, "event_id", None),
                )

    def get_neighbors(self, node_id: str, direction: str = "both") -> List[Tuple[EntityNode, RelationEdge]]:
        results = []
        if direction in ("out", "both"):
            for eid in self._adj.get(node_id, set()):
                edge = self.edges[eid]
                results.append((self.nodes[edge.target_id], edge))
        if direction in ("in", "both"):
            for eid in self._rev_adj.get(node_id, set()):
                edge = self.edges[eid]
                results.append((self.nodes[edge.source_id], edge))
        return results

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges.values()],
        }


class AlertDeduplicator:
    """Deduplicates repetitive alerts within a rolling time window."""

    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = window_seconds
        self._seen: Dict[str, float] = {}
        self._counts: Dict[str, int] = {}

    def should_emit(self, source_ip: str, dest_ip: str, attack_type: str, current_timestamp: Optional[float] = None) -> Tuple[bool, int]:
        """Return (should_emit, duplicate_count). If duplicate within window, suppress emission."""
        key = f"{source_ip}->{dest_ip}|{attack_type}"
        now = current_timestamp or datetime.now(timezone.utc).timestamp()

        last_time = self._seen.get(key, 0.0)
        count = self._counts.get(key, 0) + 1
        self._counts[key] = count

        if (now - last_time) > self.window_seconds:
            self._seen[key] = now
            return True, count
        else:
            return False, count
