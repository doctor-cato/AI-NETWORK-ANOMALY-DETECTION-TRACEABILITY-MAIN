"""Feature contract enforcement for NetFlow Sentinel v2.

Provides strict feature boundary validation, detects missing features,
and guarantees that no missing features are ever silently imputed.
"""

import math
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from pydantic import BaseModel

from network_anomaly.data.v2_schema import (
    FEATURE_CONTRACT_ID,
    FEATURE_CONTRACT_VERSION,
    ML_FEATURE_COLUMNS,
)


class FeatureContract(BaseModel):
    contract_id: str
    version: str
    feature_names: List[str]
    description: str = ""

    def validate_features(self, record: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """Validate if a dictionary contains all required features in valid finite form.

        Returns:
            (is_valid, list_of_missing_or_invalid_feature_names)
        """
        missing_or_invalid = []
        for feat in self.feature_names:
            if feat not in record or record[feat] is None:
                missing_or_invalid.append(feat)
            else:
                val = record[feat]
                try:
                    fval = float(val)
                    if math.isnan(fval) or math.isinf(fval):
                        missing_or_invalid.append(feat)
                except (ValueError, TypeError):
                    missing_or_invalid.append(feat)
        return len(missing_or_invalid) == 0, missing_or_invalid

    def extract_vector(self, record: Dict[str, Any]) -> Optional[np.ndarray]:
        """Extract a 1D numpy array of float values matching feature_names order.

        Returns:
            np.ndarray if valid and complete.
            Raises ValueError if any feature is missing (strictly NO implicit imputation).
        """
        is_valid, errors = self.validate_features(record)
        if not is_valid:
            raise ValueError(
                f"FeatureContract '{self.contract_id}' violation: missing/invalid features: {errors[:5]}"
                + (f" (and {len(errors) - 5} more)" if len(errors) > 5 else "")
                + ". Implicit imputation is strictly prohibited."
            )
        return np.array([float(record[f]) for f in self.feature_names], dtype=np.float32)


def get_flow_feature_contract_v2() -> FeatureContract:
    """Return the canonical 18-feature v2 contract aligned across AIT-NDS-v2, CTU-SME-11, and live telemetry."""
    return FeatureContract(
        contract_id=FEATURE_CONTRACT_ID,
        version=FEATURE_CONTRACT_VERSION,
        feature_names=list(ML_FEATURE_COLUMNS),
        description=(
            "Canonical 18 ML flow features derived strictly from bidirectional duration, "
            "bytes, packets, and IANA protocol across AIT-NDS-v2, CTU-SME-11, and live NetFlow/IPFIX."
        ),
    )
