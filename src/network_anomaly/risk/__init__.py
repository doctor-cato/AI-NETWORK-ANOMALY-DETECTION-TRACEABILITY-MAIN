"""Risk Assessment Engine for NetFlow Sentinel v2.0.

Provides deterministic multi-criteria risk scoring (0-100), severity calibration,
and multi-model decision aggregation. (Milestone M6.4).
"""

from .aggregation import AggregationPolicy, MultiModelDecisionAggregator
from .scoring import RiskScoreOutput, RiskScorer, SeverityLevel

__all__ = [
    "RiskScorer",
    "RiskScoreOutput",
    "SeverityLevel",
    "MultiModelDecisionAggregator",
    "AggregationPolicy",
]
