# Autoencoder Anomaly Detection Evaluation Report (Issue #29 / C4)

- Generated at: 2026-11-15 15:18:59 UTC
- Git commit: `7f51390bfe4cea76a413733ac1882d8579fc4a34`
- Model architecture: MLP Autoencoder `(32, 16, 32)`
- Training population: `benign-only (Label == 0)`
- Threshold calibration method: `benign_quantile` (Frozen: `True`)
- Calibrated threshold: `17234106.380850`
- Target FPR: `0.05` (Empirical Val FPR: `0.0500`)
- Configured unknown attack categories: `['Backdoor', 'Worms']`
- Dataset SHA-256: `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5`
- Split manifest SHA-256: `bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88`
- Train partition indices SHA-256: `a09ba1757484c65596a88fe22d5bd989a3cca60a01088364020e2f952b36c725`
- Validation partition indices SHA-256: `7d41a71a2a154a46fec4a0095fb277007b6b1574727976ee6593e6d56b9400bf`
- Preprocessor SHA-256: `12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19`

## 1. Validation Performance

| Metric | Value |
|---|---|
| Accuracy | 0.8764 |
| Precision | 0.1845 |
| Recall (Detection Rate) | 0.1168 |
| F1-Score | 0.1430 |
| Macro-F1 | 0.5382 |
| False Positive Rate (FPR) | 0.0500 |
| False Negative Rate (FNR) | 0.8832 |
| True Negative Rate (TNR) | 0.9500 |
| ROC-AUC | 0.6224 |
| PR-AUC | 0.1579 |

### Validation Confusion Matrix

- True Positives (TP): 3,561
- False Positives (FP): 15,744
- True Negatives (TN): 299,127
- False Negatives (FN): 26,939

### Validation Per-Category Breakdown

| Category | Type | Total | Detected | Rate |
|---|---|---|---|---|
| Analysis | known_attack | 285 | 1 | 0.0035 |
| Backdoor | unknown_attack | 144 | 12 | 0.0833 |
| Benign | benign | 314,871 | 15,744 | 0.0500 |
| DoS | known_attack | 1,445 | 230 | 0.1592 |
| Exploits | known_attack | 10,294 | 1,022 | 0.0993 |
| Fuzzers | known_attack | 8,495 | 942 | 0.1109 |
| Generic | known_attack | 5,137 | 1,001 | 0.1949 |
| Reconnaissance | known_attack | 4,107 | 264 | 0.0643 |
| Shellcode | known_attack | 556 | 85 | 0.1529 |
| Worms | unknown_attack | 37 | 4 | 0.1081 |

### Known vs Unknown Attacks Summary (Validation)

- **Known Attacks Detection Rate**: 0.1169 (3,545 / 30,319)
- **Unknown Attacks Detection Rate**: 0.0884 (16 / 181)

## 2. Test Performance (Held-out Test Lock Evaluated)

| Metric | Value |
|---|---|
| Accuracy | 0.8773 |
| Precision | 0.1804 |
| Recall (Detection Rate) | 0.1093 |
| F1-Score | 0.1361 |
| Macro-F1 | 0.5350 |
| False Positive Rate (FPR) | 0.0482 |
| False Negative Rate (FNR) | 0.8907 |
| True Negative Rate (TNR) | 0.9518 |
| ROC-AUC | 0.6303 |
| PR-AUC | 0.1615 |

## 3. Scientific Limitations & Assumptions

1. **No Zero-Day Claim**: Unknown-attack holdout is a controlled benchmark protocol,
   not a guarantee or proof of detecting real-world zero-day attacks.
2. **NetFlow Representation**: Features are aggregated statistics (NF-UNSW-NB15-v3);
   payload contents and sequence transitions are not observed.
3. **Class Imbalance & Repetition**: NetFlow data has recurring traffic patterns
   which may lead to localized reconstruction memorization.
4. **Threshold Dependency**: Detector performance is bounded by calibration
   on Validation. Distribution shifts to Test can affect empirical FPR.
