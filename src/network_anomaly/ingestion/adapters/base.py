"""Abstract base adapter for normalizing heterogeneous network flow records."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from network_anomaly.data.nf_unsw_nb15_v3 import ML_FEATURE_COLUMNS
from network_anomaly.ingestion.schemas import CanonicalNetworkEvent


class BaseSourceAdapter(ABC):
    """Abstract interface for all source-specific ingestion adapters."""

    def __init__(self, source_id: str, schema_version: str = "1.0.0") -> None:
        self.source_id = source_id
        self.schema_version = schema_version

    @abstractmethod
    def adapt_record(self, raw_record: Dict[str, Any], record_idx: Optional[int] = None) -> CanonicalNetworkEvent:
        """Convert a single raw dictionary record into a CanonicalNetworkEvent."""

    def adapt_dataframe(self, df: pd.DataFrame) -> List[CanonicalNetworkEvent]:
        """Convert a batch pandas DataFrame into a list of CanonicalNetworkEvents."""
        events: List[CanonicalNetworkEvent] = []
        # Convert records to dicts for row-by-row conversion
        records = df.to_dict(orient="records")
        for idx, rec in enumerate(records):
            events.append(self.adapt_record(rec, record_idx=idx))
        return events

    @staticmethod
    def extract_ml_matrix(events: List[CanonicalNetworkEvent]) -> Tuple[pd.DataFrame, List[int]]:
        """Extract ordered 47-feature DataFrame for events eligible for ML inference.

        Strict Anti-Imputation: Rows with missing features, NaN, or infinite values are
        strictly rejected from the ML matrix to prevent synthetic median/mean imputation.

        Returns
        -------
        X_df : pd.DataFrame
            Ordered DataFrame containing only fully valid events with 47 finite numeric features.
        eligible_indices : List[int]
            Indices of the input events list that were eligible.
        """
        import math

        eligible_rows = []
        eligible_indices = []

        for idx, event in enumerate(events):
            if event.ml_features is None:
                continue

            # Ensure all 47 features are present and finite
            row = {}
            is_valid_row = True
            for col in ML_FEATURE_COLUMNS:
                if col not in event.ml_features:
                    is_valid_row = False
                    break
                val = event.ml_features[col]
                if val is None or not isinstance(val, (int, float)) or not math.isfinite(val):
                    is_valid_row = False
                    break
                row[col] = float(val)

            if is_valid_row and len(row) == len(ML_FEATURE_COLUMNS):
                eligible_rows.append(row)
                eligible_indices.append(idx)

        if not eligible_rows:
            return pd.DataFrame(columns=list(ML_FEATURE_COLUMNS)), []

        return pd.DataFrame(eligible_rows, columns=list(ML_FEATURE_COLUMNS)), eligible_indices
