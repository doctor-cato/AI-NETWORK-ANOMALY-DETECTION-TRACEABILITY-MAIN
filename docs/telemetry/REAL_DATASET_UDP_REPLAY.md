# Real-Dataset NetFlow v9 UDP Replay Verification (`#137` / `#142`)

- **Executed At (UTC):** `2026-11-18T18:02:06.853149+00:00`
- **Source Dataset:** `data/processed/v2/ait_test.csv.gz` (`real_hardware_switch: false`)
- **Runtime Policy:** `deployment` | **OOD Trust Anchor:** `explicit_expected_sha256` (`FITTED`)
- **AI Readiness:** `4/4` (`REAL_MODELS`)

## Replay Pipeline Metrics
- **Flows Sent / Decoded / Processed:** `65` / `65` / `65`
- **ML-Ready Events:** `65` | **Encrypted Behavioral Vectors:** `65`
- **Alerts Generated:** `3` | **Reconstructed Campaigns:** `1` (`multi_stage=1`)
- **Avg Inference Latency:** `117056.326 us` | **Elapsed:** `8.9661 s`

## Replayed Categories
- `Benign`: `12` flows
- `Credential_Attack`: `12` flows
- `Data_Exfiltration`: `12` flows
- `Post_Exploitation_Discovery`: `12` flows
- `Reconnaissance`: `12` flows
- `Exploitation_And_C2`: `5` flows

## Limitations
- Real flow features from published datasets were encoded into NetFlow v9 UDP datagrams over localhost (127.0.0.1); real_hardware_switch=false.
- Does NOT replace physical Cisco/MikroTik/softflowd router switch telemetry required for full #137 hardware lab signoff.
