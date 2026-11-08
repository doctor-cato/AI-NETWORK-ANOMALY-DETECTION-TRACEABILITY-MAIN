"""Model definitions, baseline protocols, and constructors."""

from network_anomaly.models.isolation_forest import build_model as build_if_model
from network_anomaly.models.random_forest import (
    RandomForestBaselineConfig,
    RandomForestBaselineProtocol,
    RandomForestModel,
    build_model as build_rf_model,
    create_rf_baseline_protocol,
)
from network_anomaly.models.xgboost_model import (
    XGBoostModel,
    build_model as build_xgb_model,
)
from network_anomaly.models.xgboost_protocol import (
    XGBoostBaselineConfig,
    XGBoostBaselineProtocol,
    create_xgb_baseline_protocol,
)

__all__ = [
    "RandomForestModel",
    "XGBoostModel",
    "build_rf_model",
    "build_xgb_model",
    "build_if_model",
    "RandomForestBaselineConfig",
    "RandomForestBaselineProtocol",
    "create_rf_baseline_protocol",
    "XGBoostBaselineConfig",
    "XGBoostBaselineProtocol",
    "create_xgb_baseline_protocol",
]
