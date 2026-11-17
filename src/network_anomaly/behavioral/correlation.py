"""IP-Independent Session Correlator (Issue #104 / RQ3).

Correlates anomalous network sessions using Behavioral Vector similarity,
enabling tracking of attackers rotating or spoofing IP addresses.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import numpy as np

from .similarity import BehavioralSimilarityCalculator
from .vector import BehavioralVector


@dataclass
class SessionCorrelationCluster:
    cluster_id: str
    member_session_ids: List[str]
    centroid_vector: List[float]
    average_similarity: float
    ip_addresses_observed: List[str]


class IPSpoofingSessionCorrelator:
    """Links sessions from the same entity/campaign even when IP addresses change."""

    def __init__(self, match_threshold: float = 0.85):
        self.match_threshold = match_threshold
        self.calc = BehavioralSimilarityCalculator()

    def correlate_sessions(
        self,
        vectors: List[BehavioralVector],
        session_ip_map: Optional[Dict[str, str]] = None,
    ) -> List[SessionCorrelationCluster]:
        if not vectors:
            return []

        clusters: List[SessionCorrelationCluster] = []
        assigned = set()

        for i, vec_i in enumerate(vectors):
            if vec_i.vector_id in assigned:
                continue

            current_members = [vec_i.vector_id]
            current_vectors = [vec_i.to_numpy()]
            observed_ips = set()
            if session_ip_map and vec_i.vector_id in session_ip_map:
                observed_ips.add(session_ip_map[vec_i.vector_id])

            assigned.add(vec_i.vector_id)

            for j, vec_j in enumerate(vectors[i + 1 :], start=i + 1):
                if vec_j.vector_id in assigned:
                    continue

                sim = self.calc.cosine_similarity(vec_i.to_numpy(), vec_j.to_numpy())
                if sim >= self.match_threshold:
                    current_members.append(vec_j.vector_id)
                    current_vectors.append(vec_j.to_numpy())
                    if session_ip_map and vec_j.vector_id in session_ip_map:
                        observed_ips.add(session_ip_map[vec_j.vector_id])
                    assigned.add(vec_j.vector_id)

            centroid = np.mean(current_vectors, axis=0)
            norm = np.linalg.norm(centroid)
            if norm > 1e-7:
                centroid = centroid / norm

            cid = f"cluster-{len(clusters) + 1}"
            clusters.append(
                SessionCorrelationCluster(
                    cluster_id=cid,
                    member_session_ids=current_members,
                    centroid_vector=[round(float(x), 4) for x in centroid],
                    average_similarity=round(
                        float(
                            np.mean(
                                [self.calc.cosine_similarity(centroid, v) for v in current_vectors]
                            )
                        ),
                        4,
                    ),
                    ip_addresses_observed=list(observed_ips),
                )
            )

        return clusters

    def evaluate_ip_independence_benchmark(
        self,
        ground_truth_entities: Dict[str, List[BehavioralVector]],
        session_ip_map: Dict[str, str],
    ) -> Dict[str, Any]:
        """Benchmark Strategy A (IP-tuple exact match) vs Strategy B (Behavioral Vector).

        Simulates an attacker changing IP for every session.
        """
        total_same_entity_pairs = 0
        strategy_a_matches = 0
        strategy_b_matches = 0

        # Evaluate all pairs belonging to same true entity
        for entity_id, vec_list in ground_truth_entities.items():
            n = len(vec_list)
            for i in range(n):
                for j in range(i + 1, n):
                    total_same_entity_pairs += 1
                    v1, v2 = vec_list[i], vec_list[j]

                    # Strategy A: IP exact match
                    ip1 = session_ip_map.get(v1.vector_id, "ip-1")
                    ip2 = session_ip_map.get(v2.vector_id, "ip-2")
                    if ip1 == ip2:
                        strategy_a_matches += 1

                    # Strategy B: Behavioral vector similarity
                    sim = self.calc.cosine_similarity(v1.to_numpy(), v2.to_numpy())
                    if sim >= self.match_threshold:
                        strategy_b_matches += 1

        recall_a = (
            (strategy_a_matches / total_same_entity_pairs) if total_same_entity_pairs > 0 else 0.0
        )
        recall_b = (
            (strategy_b_matches / total_same_entity_pairs) if total_same_entity_pairs > 0 else 0.0
        )

        return {
            "total_same_entity_pairs": total_same_entity_pairs,
            "strategy_a_ip_matching": {
                "correct_matches": strategy_a_matches,
                "correlation_recall": round(recall_a, 4),
            },
            "strategy_b_behavioral_vector": {
                "correct_matches": strategy_b_matches,
                "correlation_recall": round(recall_b, 4),
            },
            "hypothesis_confirmed": recall_b >= 0.85 and recall_b > recall_a,
        }
