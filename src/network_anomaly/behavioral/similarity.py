"""Behavioral profiling and similarity metrics.

Implements Issue #103 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

from enum import Enum
from typing import Tuple

import numpy as np

from .vector import BehavioralVector


class SimilarityMetric(str, Enum):
    COSINE = "COSINE"
    NORMALIZED_EUCLIDEAN = "NORMALIZED_EUCLIDEAN"
    MANHATTAN = "MANHATTAN"


class BehavioralSimilarityCalculator:
    """Calculates pairwise similarity between behavioral vectors using various distance metrics."""

    DEFAULT_MATCH_THRESHOLD = 0.85

    @staticmethod
    def cosine_similarity(u: np.ndarray, v: np.ndarray) -> float:
        norm_u = np.linalg.norm(u)
        norm_v = np.linalg.norm(v)
        if norm_u < 1e-7 or norm_v < 1e-7:
            return 0.0
        dot = np.dot(u, v)
        return float(np.clip(dot / (norm_u * norm_v), 0.0, 1.0))

    @staticmethod
    def normalized_euclidean_similarity(u: np.ndarray, v: np.ndarray) -> float:
        dist = float(np.linalg.norm(u - v))
        return float(1.0 / (1.0 + dist))

    @staticmethod
    def manhattan_similarity(u: np.ndarray, v: np.ndarray) -> float:
        dist = float(np.sum(np.abs(u - v)))
        return float(1.0 / (1.0 + dist))

    def compute_similarity(
        self,
        v1: BehavioralVector,
        v2: BehavioralVector,
        metric: SimilarityMetric = SimilarityMetric.COSINE,
    ) -> float:
        u = v1.to_numpy()
        v = v2.to_numpy()
        if metric == SimilarityMetric.COSINE:
            return self.cosine_similarity(u, v)
        elif metric == SimilarityMetric.NORMALIZED_EUCLIDEAN:
            return self.normalized_euclidean_similarity(u, v)
        elif metric == SimilarityMetric.MANHATTAN:
            return self.manhattan_similarity(u, v)
        else:
            raise ValueError(f"Unsupported metric: {metric}")

    def is_match(
        self,
        v1: BehavioralVector,
        v2: BehavioralVector,
        threshold: float = DEFAULT_MATCH_THRESHOLD,
        metric: SimilarityMetric = SimilarityMetric.COSINE,
    ) -> Tuple[bool, float]:
        score = self.compute_similarity(v1, v2, metric=metric)
        return score >= threshold, round(score, 4)
