# Behavioral Engine Architecture (`canonical-behavioral-v2-16`)

## 1. Overview
The Behavioral Engine (`src/network_anomaly/behavioral/`) extends NetFlow Sentinel v2.0 beyond single-flow classification by aggregating network and host telemetry into entity-level behavioral profiles over sliding/tumbling time windows, detecting longitudinal drift, correlating sessions across IP changes, and persisting behavioral vectors with authenticated encryption at rest.

## 2. 16-D `BehavioralVector` Contract (`vector.py`)
The `canonical-behavioral-v2-16` schema defines 16 deterministic features per entity session window:

| Group | Count | Features |
|---|---|---|
| Flow & Volume | 8 | `flow_count`, `bytes_total`, `packets_total`, `bytes_per_flow`, `packets_per_flow`, `unique_dst_ips`, `unique_dst_ports`, `unique_protocols` |
| Graph & Temporal | 5 | `fan_out_ratio`, `port_entropy`, `inter_arrival_mean_sec`, `inter_arrival_std_sec`, `burstiness_index` |
| Application & Identity | 3 | `dns_intensity`, `http_intensity`, `auth_failure_ratio` |

### Flow-Only Telemetry Disclosure
When operating on flow-only telemetry (e.g., NetFlow/IPFIX/Zeek flow records without DNS, HTTP, or authentication logs), the 3 application/identity dimensions (`dns_intensity`, `http_intensity`, `auth_failure_ratio`) default to `0.0`. Every `BehavioralVector` explicitly records:
- `missing_feature_names`: list of unpopulated feature names (e.g., `["dns_intensity", "http_intensity", "auth_failure_ratio"]`).
- `completeness_status`: `"partial_flow_only"` when application/identity features are absent, or `"complete"` when all 16 dimensions are populated.

## 3. Session Windowing (`sessionizer.py`)
`EventSessionizer` groups incoming `CanonicalSecurityEvent` records by entity key (`src_ip` or host identifier) into **300-second** (5-minute) session windows. Closed or flushed windows are converted into `BehavioralVector` instances for baseline comparison, correlation, and encrypted persistence.

## 4. Online Per-Entity Baseline Profiling (`baseline.py`)
`EntityBaselineProfiler` maintains per-entity running statistics without storing raw historical feature matrices:
- **Welford's Online Algorithm**: Computes numerically stable running mean ($\mu$) and variance ($\sigma^2$) per feature dimension across observed windows.
- **EMA Z-Score Deviation**: Applies an Exponential Moving Average (EMA) over standardized Z-score deviations to produce a bounded behavioral drift score (`behavioral_drift_score`) that adapts gradually to legitimate workload shifts while flagging sudden anomalies.

## 5. Session Correlation Across IP Changes (`correlation.py`)
`IPSpoofingSessionCorrelator` links behavioral sessions across IP reassignments, DHCP leases, or spoofing attempts using cosine similarity over normalized `BehavioralVector` representations.
- **Empirical Evaluation (`RQ3` on `UWF-ZeekData24`)**: Cosine similarity achieved **`F1 = 0.7192`** compared to IP exact-match baseline **`F1 = 0.6919`**.

## 6. Encrypted Storage at Rest (`crypto/encrypted_storage.py`)
`EncryptedStorageVault` protects persisted behavioral vectors and telemetry metadata at rest:
- **Cipher**: `AES-256-GCM` authenticated encryption.
- **Key Wrapping**: `Windows DPAPI` wrapped data encryption keys (with POSIX fallback on non-Windows hosts).
- **Batch Persistence**: `store_behavioral_vectors_batch()` encrypts and persists batches of `BehavioralVector` records atomically to SQLite.

## 7. Session-Context Risk Fusion (`LiveAlertManager.process_event_risk()`)
`LiveAlertManager.process_event_risk()` fuses single-flow AI ensemble scores with the entity's current `BehavioralVector` drift score and session context before applying cooldown/deduplication and emitting `LiveAlert` records.
