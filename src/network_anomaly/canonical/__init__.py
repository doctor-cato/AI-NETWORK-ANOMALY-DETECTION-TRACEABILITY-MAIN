"""Canonical Security Event & Multi-source Feature Contract module.

Implements Issue #79 for NetFlow Sentinel v2.0.
"""

from .event import CanonicalSecurityEvent, EventKind, ValidationStatus
from .feature_contract import FeatureContract, get_flow_feature_contract_v2

__all__ = [
    "CanonicalSecurityEvent",
    "EventKind",
    "ValidationStatus",
    "FeatureContract",
    "get_flow_feature_contract_v2",
]
