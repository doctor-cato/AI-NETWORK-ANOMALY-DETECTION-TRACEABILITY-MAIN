# Synthetic UDP Loopback Integration Acceptance

**Issue:** `#137` · **Synthetic test:** yes · **Real exporter hardware:** no
**Run at (UTC):** `2026-11-18T14:50:27.101051+00:00`
**Verdict:** **`ACCEPTED`**

> This is an integration test over UDP loopback with a synthetic exporter. It is not a
> router/switch capture, not a benchmark of detection quality, and not evidence of
> production readiness.

## Scope

- Transport: UDP `127.0.0.1` (ephemeral port `62738`)
- Packets: one NetFlow v9 template+data datagram, one v9 data-only datagram
  (template-cache reuse), one IPFIX template+data datagram, one malformed datagram
- Model features: private lab IE convention `PEN 50000` (IPFIX) /
  IE `50000+i` (NetFlow v9), IEEE-754 float64

## Stage results

| Stage | Status | Evidence |
| :--- | :---: | :--- |
| udp_transport | **PASS** | 4 datagrams received on UDP port 62738 |
| decoder | **PASS** | 6 flows decoded (NetFlow v9 + IPFIX; 0 unresolved) |
| template_cache | **PASS** | 2 templates cached; data-only packet decoded |
| malformed_packet_handling | **PASS** | malformed_packet_count=1, datagrams_rejected=1 |
| streaming_pipeline | **PASS** | 6 processed, 0 dropped, queue=0.0% |
| feature_contract | **PASS** | 6/6 events satisfied all 18 non-imputed features |
| ai_inference | **PASS** | mode=REAL_MODELS, participating=['autoencoder', 'isolation_forest', 'random_forest', 'xgboost'], avg_latency_us=56889.65, ood_gate=FITTED |
| model_readiness | **PASS** | random_forest=VALIDATED; xgboost=VALIDATED; isolation_forest=VALIDATED; autoencoder=VALIDATED |
| risk_scoring | **PASS** | risk scores: 00d8a550=20.2, 59af6711=35.8, 9aef87ce=84.0, 25824741=19.1, 80619e52=20.7, 8d592977=18.6 |
| alerts | **PASS** | 1 alerts raised above the 70.0 risk threshold |
| behavioral_vector | **PASS** | 6/6 events produced a 16-D session vector |
| vector_encryption | **PASS** | 6/6 vectors stored as AES-256-GCM ciphertext in the vault (plaintext column NULL) |
| trace_graph | **PASS** | 8 entity nodes / 6 relations |

## Inference

- Mode: `REAL_MODELS`
- Runtime policy: `research` (`require_ood_gate=False`, `explicit_controlled_lab_research_profile_no_external_ood_sha`)
- Validated models: `4/4`
- OOD gate: `FITTED` (trust anchor: `unanchored_local_artifact`)
- Participating models in the ensemble: `autoencoder, isolation_forest, random_forest, xgboost`

## Limitations

- Loopback UDP with a synthetic Python exporter; no physical router or switch was tested.
- The 18 canonical v2 model features use a private lab IE convention (PEN 50000 / IE 50000+i, float64).
- Synthetic feature values are fixtures, not real benchmark samples from AIT-NDS-v2 or CTU-SME-11.
- Physical lab hardware acceptance for Issue #137 remains BLOCKED (AC #4-#5 unchecked; Issue #137 remains OPEN).

Artifacts: `reports/acceptance/synthetic_udp_loopback_report.json`, `reports/acceptance/live_gui_alert_synthetic_loopback.png`.
