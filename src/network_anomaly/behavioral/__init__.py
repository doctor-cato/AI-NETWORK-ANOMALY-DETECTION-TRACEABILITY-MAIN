"""Behavioral Vector Engine for NetFlow Sentinel v2.0.

Provides sessionization, 16-D behavioral vector construction, profiling,
and IP-independent session correlation. (Milestone M6.3).
"""

from .correlation import IPSpoofingSessionCorrelator
from .sessionizer import EventSessionizer, SessionSummary
from .similarity import BehavioralSimilarityCalculator, SimilarityMetric
from .vector import BehavioralVector, BehavioralVectorBuilder

__all__ = [
    "EventSessionizer",
    "SessionSummary",
    "BehavioralVector",
    "BehavioralVectorBuilder",
    "BehavioralSimilarityCalculator",
    "SimilarityMetric",
    "IPSpoofingSessionCorrelator",
]
