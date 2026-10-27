"""Reproducible, leakage-safe exploratory data analysis for NF-UNSW-NB15-v3.

The package profiles the verified source population. It does not fit any
preprocessing, does not select features, does not change a readiness gate and
does not modify the raw dataset. Train-dependent conclusions stay
``PENDING ISSUE #7`` until a verified split exists.
"""

from .figures import render_figures
from .profiling import (
    CLASS_CONDITIONAL_FEATURES,
    EDA_SCHEMA_VERSION,
    QUANTILE_PROBABILITIES,
    DatasetProfiler,
    profile_dataset,
)
from .report import render_report

__all__ = [
    "CLASS_CONDITIONAL_FEATURES",
    "DatasetProfiler",
    "EDA_SCHEMA_VERSION",
    "QUANTILE_PROBABILITIES",
    "profile_dataset",
    "render_figures",
    "render_report",
]
