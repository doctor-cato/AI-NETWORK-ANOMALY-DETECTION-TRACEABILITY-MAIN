# Isolation Forest Evaluation Report

Run ID: 20261115T053123Z
Timestamp: 2026-11-15T05:31:24.395920+00:00
Git commit: c84f3375372df97768a9bf3b020f28025df03488
Issue: #11 — C4 Isolation Forest real-data experiment

## Status

- Training: COMPLETED
- Threshold calibration: max-F1-on-known-attacks
- Test evaluation: COMPLETED

## Training

- Model: IsolationForest (scikit-learn)
- Training population: benign-only (Label == 0) from Train partition
- n_train_benign: 1,590,608
- n_train_attack_excluded: 65,189
- Training duration: 6.84 s
- Random seed: 42

## Hyperparameters

- n_estimators: 100
- max_samples: auto
- contamination: 0.1
- max_features: 1.0
- bootstrap: False
- random_state: 42
- n_jobs: -1

## Threshold Calibration (Validation)

- Policy: max-F1-on-known-attacks
- Selection metric: f1
- Candidate thresholds evaluated: 74421
- Score direction: higher_is_more_anomalous
- Decision rule: y_pred = 1 (Attack) if (-decision_function(X)) >= threshold else 0 (Benign)
- Selected threshold: -0.033526858092757406
- Unknown attack categories (pre-registered, excluded from calibration): ['Backdoor', 'Worms']

### Validation operating-point metrics

- tp: 26920
- tn: 259711
- fp: 55160
- fn: 3399
- precision: 0.3279727095516569
- recall: 0.8878920808733797
- f1: 0.4790078203542736
- fpr: 0.1751828526602958

### Unknown attack detection on validation (observational only)

- n_samples: 181
- n_detected: 154
- detection_rate: 0.8508
- Note: Unknown attack scores observed but NOT used to select threshold.

## Test Evaluation

- TP: 27528
- TN: 264755
- FP: 50602
- FN: 3068
- Accuracy: 0.844863
- Precision: 0.352336
- Recall / Detection Rate: 0.899725
- F1: 0.506374
- FPR: 0.160459
- ROC-AUC: 0.8937301201493376
- PR-AUC: 0.28875282902932714

### Confusion matrix (rows=actual, cols=predicted, labels=[benign, attack])

```
[[264755, 50602], [3068, 27528]]
```

### Known vs Unknown Attack Evaluation (Test vs Benign)

| Subset | Attack Samples | Benign Samples | Precision | Recall | F1 | FPR | ROC-AUC | PR-AUC |
|---|---|---|---|---|---|---|---|---|
| Known Attacks | 29,300 | 315,357 | 0.342899 | 0.901229 | 0.496783 | 0.160459 | 0.893996 | 0.280723 |
| Unknown Attacks (Worms, Backdoor) | 1,296 | 315,357 | 0.021692 | 0.865741 | 0.042324 | 0.160459 | 0.887713 | 0.016738 |

## Per-Attack Detection Rates (Test)

| Category | Known/Unknown | N | Detected | Detection Rate |
|---|---|---|---|---|
| Analysis | known | 294 | 274 | 0.9320 |
| Backdoor | UNKNOWN | 1260 | 1093 | 0.8675 |
| DoS | known | 1193 | 973 | 0.8156 |
| Exploits | known | 10520 | 8715 | 0.8284 |
| Fuzzers | known | 7322 | 7025 | 0.9594 |
| Generic | known | 5111 | 4888 | 0.9564 |
| Reconnaissance | known | 4464 | 4180 | 0.9364 |
| Shellcode | known | 396 | 351 | 0.8864 |
| Worms | UNKNOWN | 36 | 29 | 0.8056 |

## Partition Overlap, Label Integrity & Shortcut Risk Observations

- Split audit status: `PASS` (exact_full_row_overlap=0, source_feature_overlap=0, canonical_flow_group_overlap=0, temporal_boundary_violations=0, binary_label_conflicts=0)
- `ml_feature_overlap` (train_vs_validation): 61007 fingerprints, 49.98% of target partition (`REVIEWED_AND_JUSTIFIED`)
- `ml_feature_overlap` (validation_vs_test): 24143 fingerprints, 33.13% of target partition (`REVIEWED_AND_JUSTIFIED`)
- `ml_feature_overlap` (train_vs_test): 59966 fingerprints, 53.21% of target partition (`REVIEWED_AND_JUSTIFIED`)
- `MIN_TTL` shortcut observation (Validation): benign_zero_fraction=0.0204, attack_zero_fraction=0.0017, benign_median=31.0, attack_median=254.0 — Deterministic TTL distributions (e.g., IXIA PerfectStorm testbed artifacts) can inflate supervised and unsupervised separation on benchmark splits.

## Limitations

- Isolation Forest is trained on benign-only traffic; unsupervised threshold calibration uses known attack categories only.
- Unknown attack detection rate reflects held-out attack-family generalization within the IXIA PerfectStorm testbed capture, NOT real-world zero-day detection capability.
- Non-i.i.d. feature-space repetition (`ml_feature_overlap`) and deterministic testbed fields such as `MIN_TTL` can affect anomaly scores without representing true network novelty.
- Temporal holdout tests chronological ordering within Jan–Feb 2015 capture only.
- Session grouping uses a 5-minute heuristic bucket; residual flow adjacency is possible.
- Results are valid only for the exact dataset version, split, preprocessor and random seed recorded in run_metadata.json.

## Traceability & Reproduction

Issue #11 → C4 → `src/network_anomaly/models/isolation_forest.py` → `scripts/train_isolation_forest.py` → this report

```powershell
$env:PYTHONPATH = "src"
python scripts/train_isolation_forest.py --evaluate-test
```

Status: EXPERIMENTALLY VALIDATED
