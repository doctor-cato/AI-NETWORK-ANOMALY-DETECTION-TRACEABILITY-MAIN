"""XGBoost supervised model — Issue #31 / C3.

Follows the same supervised protocol as Random Forest:
  - build_model() accepts an optional config dict and returns a fitted-ready estimator.
  - Caller is responsible for:
      1. Splitting data BEFORE any preprocessing fit (train/val/test).
      2. Fitting preprocessing ONLY on train set, then transforming val/test.
      3. Excluding metadata columns (e.g. 'id') and target columns from features.
      4. Not using test labels for feature selection, threshold tuning, or hyperparameter search.
  - Training and evaluation are BLOCKED until the UNSW-NB15 dataset is present in data/raw/
    and the split/leakage audit (C1/C2) has been verified.

Target and label mapping:
  - UNSW-NB15 'label' column: binary {0: normal, 1: attack} (confirmed from validation report).
  - 'attack_cat' column: 9 attack categories + Normal (multiclass). Use depends on task scope.
  - Default config uses binary classification (objective='binary:logistic').
  - For multiclass, override: objective='multi:softprob', num_class=<N>.
  - Do NOT assume binary or multiclass without verifying the target column in the actual dataset.

Status: IMPLEMENTED — constructor and config only.
Training/evaluation: BLOCKED (dataset not present, leakage audit not verified).
"""

import copy

from xgboost import XGBClassifier

from network_anomaly.config import XGBOOST_DEFAULTS


def build_model(config=None):
    """Return an XGBClassifier instance configured with project defaults or *config*.

    Parameters
    ----------
    config : dict or None
        Hyperparameter overrides.  If None, ``XGBOOST_DEFAULTS`` is used unchanged.
        Partial overrides are NOT merged — supply the complete config dict when overriding.

    Returns
    -------
    xgboost.XGBClassifier
        Untrained estimator.

    Notes
    -----
    - ``verbosity=0`` suppresses XGBoost's INFO-level console output during import/build.
    - ``enable_categorical=False`` is the safe default; set to True only after confirming
      XGBoost's categorical handling is compatible with the preprocessing pipeline.
    - For multiclass (attack_cat target), the caller must override ``objective`` and
      ``num_class`` before calling ``fit()``.
    """
    cfg = copy.deepcopy(config) if config is not None else copy.deepcopy(XGBOOST_DEFAULTS)
    cfg.setdefault("verbosity", 0)
    return XGBClassifier(**cfg)
