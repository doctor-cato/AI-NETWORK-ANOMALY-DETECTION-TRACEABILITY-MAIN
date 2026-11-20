"""Trace Engine v2: graph traversal and evidence retrieval.

Implements Issue #111 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Any, Dict, List, Set

from .graph import EntityNode, EntityRelationshipGraph, RelationEdge


@dataclass
class TraceResult:
    root_node_id: str
    nodes_visited: List[EntityNode]
    edges_traversed: List[RelationEdge]
    observed_edges: List[RelationEdge]
    inferred_edges: List[RelationEdge]
    depth_reached: int
    truncated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "root_node_id": self.root_node_id,
            "depth_reached": self.depth_reached,
            "truncated": self.truncated,
            "nodes_count": len(self.nodes_visited),
            "edges_count": len(self.edges_traversed),
            "observed_count": len(self.observed_edges),
            "inferred_count": len(self.inferred_edges),
            "nodes": [n.to_dict() for n in self.nodes_visited],
            "edges": [e.to_dict() for e in self.edges_traversed],
        }


class TraceEngine:
    """Traverses the Entity Relationship Graph to trace attack origins and blast radius."""

    def __init__(self, graph: EntityRelationshipGraph, max_depth: int = 5, max_nodes: int = 200):
        self.graph = graph
        self.max_depth = max_depth
        self.max_nodes = max_nodes

    def trace(self, start_node_id: str, direction: str = "both") -> TraceResult:
        if start_node_id not in self.graph.nodes:
            raise KeyError(f"Start node '{start_node_id}' does not exist in relationship graph.")

        visited_nodes: Set[str] = {start_node_id}
        traversed_edges: Set[str] = set()

        # Queue: (node_id, current_depth)
        queue = deque([(start_node_id, 0)])
        max_d = 0
        truncated = False

        while queue:
            curr_id, depth = queue.popleft()
            max_d = max(max_d, depth)

            if depth >= self.max_depth:
                truncated = True
                continue

            if len(visited_nodes) >= self.max_nodes:
                truncated = True
                break

            neighbors = self.graph.get_neighbors(curr_id, direction=direction)
            for neighbor_node, edge in neighbors:
                if edge.edge_id not in traversed_edges:
                    traversed_edges.add(edge.edge_id)

                if neighbor_node.node_id not in visited_nodes:
                    visited_nodes.add(neighbor_node.node_id)
                    queue.append((neighbor_node.node_id, depth + 1))

        nodes_list = [self.graph.nodes[nid] for nid in visited_nodes]
        edges_list = [self.graph.edges[eid] for eid in traversed_edges]

        observed = [e for e in edges_list if e.is_observed]
        inferred = [e for e in edges_list if not e.is_observed]

        return TraceResult(
            root_node_id=start_node_id,
            nodes_visited=nodes_list,
            edges_traversed=edges_list,
            observed_edges=observed,
            inferred_edges=inferred,
            depth_reached=max_d,
            truncated=truncated,
        )
