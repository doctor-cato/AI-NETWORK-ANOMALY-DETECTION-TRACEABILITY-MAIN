# Problem Statement — Network Traffic Anomaly Detection

## Problem

Network traffic contains both normal and abnormal connection patterns. Abnormal connections (e.g., scans, unauthorized access attempts, unusual protocol usage, abnormal packet sizes or timing) can indicate security incidents. The task is to build an AI system that uses network traffic features to detect anomalous connections, compare machine-learning models, evaluate detection effectiveness, and provide explainable results.

## Target entities (what is being detected)

- Network connections / flows characterized by protocol, service, duration, packet counts, byte counts, TCP flags, and derived statistics.
- Not device identity; not attacker fingerprinting; not zero-day claim without proof.

## Inputs

- Structured records from UNSW-NB15 dataset (CSV / parquet depending on version): features such as source/destination IP/port, protocol, service, duration, state, packet counts, byte counts, flow metrics, plus derived statistics.
- Target label (binary or multi-class) indicating normal vs. anomaly categories.

## Outputs

- Classification / anomaly score per connection.
- Metrics: Precision, Recall, F1-score, Macro-F1, confusion matrix, False Positive Rate.
- Explainable outputs: feature importance, error analysis (false positives / false negatives), documented limitations.

## Research / design questions

1. Which features from UNSW-NB15 are predictive of anomalies without causing target leakage (e.g., identity columns that encode time or session)?
2. How does Random Forest perform as a supervised baseline on this dataset?
3. Can Isolation Forest provide useful unsupervised detection, and how should evaluation differ (threshold selection, score interpretation)?
4. What is the false-positive trade-off and how do data limitations (class imbalance, missing values) affect reliability?
5. Is the preprocessing pipeline reproducible and free of data leakage?

## Context and motivation

Network anomaly detection supports security operations but must be validated with real data and transparent evaluation. This project aims to demonstrate a reproducible ML pipeline for a course assignment, not to claim production-grade security guarantees.

## Non-goals and boundaries

- No claim of zero-day detection without controlled experiments.
- No identification of specific attackers or devices from behavior vectors.
- No automatic blocking or counter-attack.
- No deployment to enterprise network monitoring.

Updated: 2026-10-16
