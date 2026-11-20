# Behavioral Engine Architecture (`canonical-behavioral-v2-16`)

## 1. Overview
The Behavioral Engine (`src/network_anomaly/behavioral/`) extends NetFlow Sentinel v2.0 beyond single-flow classification by aggregating `CanonicalSecurityEvent` records into time-bounded entity sessions, projecting each session into a deterministic L2-normalized 16-dimensional `BehavioralVector`, profiling per-entity baselines via a sliding-window cosine centroid, correlating sessions across IP changes, and persisting vectors with authenticated encryption at rest.

## 2. 16-D `BehavioralVector` Contract (`src/network_anomaly/behavioral/vector.py`)
`BehavioralVectorBuilder` (`version = "2.0.0"`, `dimensions = 16`) maps each `SessionSummary` to the exact 16 features in `BehavioralVectorBuilder.FEATURE_NAMES`:

| Index | Feature Name | Definition (`SessionSummary` mapping) |
|---:|---|---|
| 0 | `log_duration` | `log1p(duration_seconds)` |
| 1 | `log_bytes_in` | `log1p(bytes_in)` |
| 2 | `log_bytes_out` | `log1p(bytes_out)` |
| 3 | `bytes_ratio_clipped` | `min(bytes_ratio, 10.0)` |
| 4 | `log_pkts_in` | `log1p(pkts_in)` |
| 5 | `log_pkts_out` | `log1p(pkts_out)` |
| 6 | `pkts_ratio_clipped` | `min(pkts_ratio, 10.0)` |
| 7 | `unique_ports_norm` | `min(unique_ports / 100.0, 1.0)` |
| 8 | `unique_protocols_norm` | `min(unique_protocols / 10.0, 1.0)` |
| 9 | `syn_flag_ratio` | `syn_flag_count / max(event_count, 1)` |
| 10 | `rst_flag_ratio` | `rst_flag_count / max(event_count, 1)` |
| 11 | `dns_intensity` | `min(dns_query_count / max(duration_seconds, 0.001), 50.0)` |
| 12 | `http_intensity` | `min(http_request_count / max(duration_seconds, 0.001), 50.0)` |
| 13 | `auth_failure_ratio` | `auth_failure_count / max(event_count, 1)` |
| 14 | `log_mean_iat` | `log1p(max(mean_iat_ms, 0.0))` |
| 15 | `log_std_iat` | `log1p(max(std_iat_ms, 0.0))` |

After replacing any `None`, `NaN`, or `Inf` values with `0.0`, the 16-D vector is L2-normalized onto the unit hypersphere (when `||x||_2 > 1e-7`), rounded to 6 decimal places, and hashed deterministically via `sha256_hash = SHA-256(json.dumps(normalized_features))`.

### Flow-Only Telemetry & Missingness Tracking
When operating on flow-only telemetry (where `EventKind.DNS`, `EventKind.WEB`, or `EventKind.AUTH` events are absent), `dns_intensity`, `http_intensity`, and `auth_failure_ratio` remain `0.0` for numeric compatibility, and every `BehavioralVector` explicitly records:
- `missing_feature_count`: integer count of missing/unpopulated dimensions (`int`).
- `missing_feature_names`: tuple/list of missing dimension names (e.g., `("dns_intensity", "http_intensity", "auth_failure_ratio")`).

## 3. Session Windowing (`src/network_anomaly/behavioral/sessionizer.py`)
`EventSessionizer` (default `session_timeout_seconds = 300.0`) sorts incoming `CanonicalSecurityEvent` records chronologically by `event_timestamp` and groups them by `entity_id` (falling back to `flow:{source_ip}:{source_port}->{dest_ip}:{dest_port}` when `entity_id` is absent). Within each entity group, consecutive events with an inactivity gap `> session_timeout_seconds` start a new `SessionSummary`.

## 4. Sliding-Window Entity Baseline Profiling (`src/network_anomaly/behavioral/vector.py`)
`EntityBaselineProfiler` maintains per-entity behavioral baselines in `src/network_anomaly/behavioral/vector.py`:
- **Sliding Window Buffer:** Stores up to `window_size` (default `50`) recent L2-normalized `BehavioralVector` arrays per `entity_key` using `collections.deque(maxlen=window_size)`.
- **L2-Normalized Centroid:** `baseline_centroid(entity_key)` computes the element-wise mean across the entity's buffered vectors and L2-normalizes the resulting centroid (when `||centroid||_2 > 1e-9`).
- **Cosine Deviation Scoring:** `score_deviation(vector)` computes `cos_sim = clip(dot(vec, centroid) / (||vec||_2 * ||centroid||_2), -1.0, 1.0)` and returns `deviation_score = max(0.0, 1.0 - cos_sim)` (plus `has_baseline`, `cosine_similarity`, and `sample_count`). When an entity has no prior baseline (`centroid is None`), it returns `has_baseline = False`, `deviation_score = 0.0`, `cosine_similarity = 1.0`, and `sample_count = 0`.

## 5. Similarity & Session Correlation Across IP Changes (`similarity.py`, `correlation.py`)
- `BehavioralSimilarityCalculator` (`src/network_anomaly/behavioral/similarity.py`) implements `SimilarityMetric.COSINE`, `SimilarityMetric.NORMALIZED_EUCLIDEAN`, and `SimilarityMetric.MANHATTAN`, with `DEFAULT_MATCH_THRESHOLD = 0.85`.
- `IPSpoofingSessionCorrelator` (`src/network_anomaly/behavioral/correlation.py`, default `match_threshold = 0.85`) greedily clusters `BehavioralVector` sessions whose cosine similarity meets `match_threshold`, producing `SessionCorrelationCluster` records with `member_session_ids`, normalized `centroid_vector`, `average_similarity`, and `ip_addresses_observed`.
- See `reports/experiments/behavioral/rq3_session_correlation_experiment.json` for simulation evaluation results (`RQ3`).

## 6. Encrypted Storage at Rest (`src/network_anomaly/crypto/encrypted_storage.py`)
`EncryptedStorageVault` protects persisted behavioral vectors and telemetry metadata at rest using `AES-256-GCM` authenticated encryption with `Windows DPAPI` key wrapping (and POSIX fallback on non-Windows hosts), and supports atomic batch persistence via `store_behavioral_vectors_batch()`.

## 7. Session-Context Risk Fusion (`LiveSystemOrchestrator` & `LiveAlertManager.process_event_risk()`)
`LiveSystemOrchestrator` (`src/network_anomaly/streaming/live_orchestrator.py`) builds the session `BehavioralVector` (`b_vec`), computes `EntityBaselineProfiler.score_deviation(b_vec)` (`baseline_deviation_score`), updates the entity's sliding window, and passes both `behavioral_vector` (extracting real `BehavioralVectorBuilder.FEATURE_NAMES` dimensions such as `unique_ports_norm`, `log_pkts_out`, `dns_intensity`, and `auth_failure_ratio`) and `baseline_deviation_score` into `LiveAlertManager.process_event_risk()`. `LiveAlertManager` (`src/network_anomaly/streaming/alert_manager.py`) fuses the multi-model AI anomaly probability with the behavioral anomaly score and session context via `RiskScorer`, applies 60s entity cooldown/deduplication with severity escalation (updating the active alert when a higher risk level such as `HIGH -> CRITICAL` arrives within the dedup window), and triggers `key_rotator.evaluate_adaptive_rotation()` when `risk_assess.trigger_adaptive_rotation` is active.
