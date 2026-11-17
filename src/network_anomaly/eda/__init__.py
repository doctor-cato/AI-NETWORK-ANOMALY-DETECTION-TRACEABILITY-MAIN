"""Exploratory data analysis and multi-source profiling package for NetFlow Sentinel v2.

The retired NF-UNSW-NB15-v3 EDA modules have been moved to
``scripts/historical/nf_unsw_nb15_v3/eda_v1/``. Active v2 profiling is
executed by ``scripts/profile_multi_source.py`` on raw AIT-NDS-v2,
AIT-LDS-v2.1, AIT-ADS, and CTU-SME-11 archives.
"""

from __future__ import annotations

EDA_SCHEMA_VERSION = "v2-multi-source-profile-v1"

__all__ = ["EDA_SCHEMA_VERSION"]
