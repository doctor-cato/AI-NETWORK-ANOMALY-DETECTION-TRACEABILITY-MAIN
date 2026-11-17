"""Behavioral Vector Engine for NetFlow Sentinel v2.0.

Provides sessionization, 16-D behavioral vector construction, profiling,
and IP-independent session correlation. (Milestone M6.3).
"""

from .sessionizer import EventSessionizer, SessionSummary
from .vector import BehavioralVector, BehavioralVectorBuilder
from .similarity import BehavioralSimilarityCalculator, SimilarityMetric
from .correlation import IPSpoofingSessionCorrelator

__all__ = [
    "EventSessionizer",
    "SessionSummary",
    "BehavioralVector",
    "BehavioralVectorBuilder",
    "BehavioralSimilarityCalculator",
    "SimilarityMetric",
    "IPSpoofingSessionCorrelator",
]
