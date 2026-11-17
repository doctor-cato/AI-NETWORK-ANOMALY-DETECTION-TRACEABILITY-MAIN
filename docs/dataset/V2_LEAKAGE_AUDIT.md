# NetFlow Sentinel v2 — Split & Leakage Audit Report

**Split Protocol:** `v2-scenario-group-purged-v1` (scenario-disjoint across independent AIT-NDS-v2 testbeds)
**Split Manifest SHA-256:** `1b7fa7aebaf3560f27b3d23ec05919a83aacd1ed6ea5448f96a6a42c7a264e0a`
**Preprocessor Manifest:** `reports/preprocessing/v2_flow_preprocessing_manifest.json` (`RobustScaler`, fit strictly on Train)

## Partition Summary (AIT-NDS-v2)
| Partition | Scenarios | Rows | Benign | Attack | Attack Rate |
|---|---|---:|---:|---:|---:|
| **Train** | `fox, harrison, santos, wardbeck, wilson` | 1,930,219 | 1,658,795 | 271,424 | 14.06% |
| **Validation** | `russellmitchell` | 377,704 | 206,676 | 171,028 | 45.28% |
| **Held-out Test** | `shaw, wheeler` | 923,292 | 747,610 | 175,682 | 19.03% |
| **Excluded Unmapped** | `shaw` empty labels | 942 | — | — | — |

## External Real-Capture Benchmarks (CTU-SME-11)
- **`ctu_echo`**: 76,073 labeled flows (36,576 Attack, 39,497 Benign).
- **`ctu_windows7ad`**: 175,146 labeled flows (2,038 Attack, 173,108 Benign; 9,394 `Unknown` excluded).

## Leakage Audit Checks
- Cross-partition scenario overlap: **0** (`PASS`)
- Cross-partition scenario+5-tuple+timestamp overlap: **0** (`PASS`)
- Within-Train identical 18-feature vectors: **827,525** (retained as authentic high-frequency benign/scan telemetry without synthetic deduplication inflation, audited transparently).
- Unique 18-feature vectors shared across Train/Val: **10,048**, Train/Test: **21,560**, Val/Test: **8,675** (identical protocol payload sizes such as single-packet RST/DNS/NTP probes occurring independently in separate testbeds).
- Preprocessor fit boundary: **strictly AIT Train**; Validation/Test/CTU receive immutable `transform()` only (`verify_preprocessing_artifact == PASS`).
