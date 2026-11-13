# Random Forest held-out Test: rf-heldout-ea330b9

Status: **EXPERIMENTALLY VALIDATED**. Positive class: `Attack (1)`; threshold: `0.5`.
Source commit: `ea330b9db98605ffc19a88c20bd1e9b61b92e6fb`. Feature contract: `nf-unsw-nb15-v3-baseline-47`.

## Confusion matrix and metrics

| TN | FP | FN | TP | Total |
| ---: | ---: | ---: | ---: | ---: |
| 315350 | 7 | 2 | 30594 | 345953 |

| Accuracy | Precision | Recall | F1 | Macro F1 | Weighted F1 | FPR |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0.999973985 | 0.999771249 | 0.999934632 | 0.999852934 | 0.999919332 | 0.999973986 | 0.000022197 |

## Independent Validation reference

These counts come from the validation audit of the locked model; they are separate from the held-out Test counts above.

| Train rows | Validation rows | Validation TN | Validation FP | Validation FN | Validation TP |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1655797 | 345371 | 314866 | 5 | 3 | 30497 |

## Attack-family breakdown

| Attack | Total | Detected | FN | Recall 95% Wilson CI |
| --- | ---: | ---: | ---: | ---: |
| Analysis | 294 | 294 | 0 | 0.987102–1.000000 |
| Backdoor | 1260 | 1260 | 0 | 0.996960–1.000000 |
| DoS | 1193 | 1191 | 2 | 0.993908–0.999540 |
| Exploits | 10520 | 10520 | 0 | 0.999635–1.000000 |
| Fuzzers | 7322 | 7322 | 0 | 0.999476–1.000000 |
| Generic | 5111 | 5111 | 0 | 0.999249–1.000000 |
| Reconnaissance | 4464 | 4464 | 0 | 0.999140–1.000000 |
| Shellcode | 396 | 396 | 0 | 0.990393–1.000000 |
| Worms | 36 | 36 | 0 | 0.903581–1.000000 |

## Misclassified flows

Sample IDs are run-scoped hashes; no addresses or ports are published.

| Sample | Type | Attack | P(Attack) | Margin to threshold | MIN_TTL | MAX_TTL | Protocol | Packets in/out | Bytes in/out | Retrans in | Duration ms |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: | --- | --- | ---: | ---: |
| 1f55c38c8093 | FP | Benign | 0.554347 | +0.054347 | 252.0 | 253.0 | 6.0 | 20.0/22.0 | 1666.0/7930.0 | 7.0 | 712.0 |
| 4a857dccab73 | FP | Benign | 0.589583 | +0.089583 | 252.0 | 253.0 | 6.0 | 10.0/8.0 | 844.0/1662.0 | 2.0 | 355.0 |
| a6b02c821155 | FP | Benign | 0.824153 | +0.324153 | 254.0 | 254.0 | 6.0 | 2.0/0.0 | 80.0/0.0 | 1.0 | 0.0 |
| cce41ff08f9d | FP | Benign | 0.522578 | +0.022578 | 252.0 | 253.0 | 6.0 | 10.0/8.0 | 858.0/1812.0 | 2.0 | 1697.0 |
| b7d790993cb0 | FP | Benign | 0.519933 | +0.019933 | 252.0 | 252.0 | 6.0 | 2.0/0.0 | 80.0/0.0 | 0.0 | 0.0 |
| 7b17e7a1407e | FN | DoS | 0.355040 | -0.144960 | 0.0 | 0.0 | 17.0 | 1.0/0.0 | 59.0/0.0 | 0.0 | 0.0 |
| dc970cad2ef6 | FN | DoS | 0.355040 | -0.144960 | 0.0 | 0.0 | 17.0 | 1.0/0.0 | 59.0/0.0 | 0.0 | 0.0 |
| 5a39490dbcf8 | FP | Benign | 0.513742 | +0.013742 | 252.0 | 253.0 | 6.0 | 8.0/8.0 | 448.0/400.0 | 2.0 | 336.0 |
| d9a38f2b6533 | FP | Benign | 0.695000 | +0.195000 | 252.0 | 253.0 | 6.0 | 1302.0/8552.0 | 52080.0/11335782.0 | 0.0 | 70926.0 |

## Feature distributions

Medians are computed on the same Test source rows; FP/FN medians describe very small groups and do not establish cause.

| Feature | Benign median | Attack median | FP median | FN median | Missing/nonfinite Test cells |
| --- | ---: | ---: | ---: | ---: | ---: |
| MIN_TTL | 31.000 | 254.000 | 252.000 | 0.000 | 0 |
| MAX_TTL | 32.000 | 254.000 | 253.000 | 0.000 | 0 |
| PROTOCOL | 6.000 | 6.000 | 6.000 | 17.000 | 0 |
| L7_PROTO | 36.000 | 7.000 | 7.000 | 5.000 | 0 |
| IN_BYTES | 1580.000 | 704.000 | 844.000 | 59.000 | 0 |
| OUT_BYTES | 2456.000 | 256.000 | 1662.000 | 0.000 | 0 |
| IN_PKTS | 18.000 | 10.000 | 10.000 | 1.000 | 0 |
| OUT_PKTS | 18.000 | 6.000 | 8.000 | 0.000 | 0 |
| FLOW_DURATION_MILLISECONDS | 24.000 | 560.000 | 355.000 | 0.000 | 0 |
| RETRANSMITTED_IN_PKTS | 4.000 | 2.000 | 2.000 | 0.000 | 0 |

Most frequent MIN_TTL values by source class:

| Class | MIN_TTL | Test rows |
| --- | ---: | ---: |
| benign | 31 | 307482 |
| benign | 0 | 7448 |
| benign | 1 | 170 |
| benign | 63 | 128 |
| benign | 29 | 56 |
| benign | 60 | 30 |
| benign | 252 | 24 |
| benign | 64 | 17 |
| attack | 254 | 22645 |
| attack | 62 | 7911 |
| attack | 0 | 40 |

## Observations and interpretation

- Fixed probability band 0.35–0.65 contains 14 flows, including 5 FP and 2 FN. This band was inspected after evaluation and did not change the threshold.
- Test class support: benign 315357, attack 30596; accuracy alone can hide rare errors.
- Test median MIN_TTL: 31.0. The class-conditional MIN_TTL counts are recorded in the JSON summary. TTL association is observed; a causal shortcut for these nine errors is a hypothesis, not established by feature importance.
- The two FN belong to the attack families shown in the table. Small family sizes limit precision of per-family conclusions.

## Temporal windows

| UTC hour | Flows | FP | FN |
| --- | ---: | ---: | ---: |
| 2015-02-18 09:00:00+00:00 | 84339 | 0 | 0 |
| 2015-02-18 10:00:00+00:00 | 106785 | 3 | 0 |
| 2015-02-18 11:00:00+00:00 | 100906 | 2 | 0 |
| 2015-02-18 12:00:00+00:00 | 53923 | 2 | 2 |

## Dataset limitations and future work

- Source is a laboratory NetFlow capture; deployment drift is untested.
- No session ID or payload context is available.
- Previous model predictions were verified against artifacts and labels, but model inference was not rerun.
- Dataset-wide EDA records 14815 exact duplicate rows, 1134553 behaviorally equivalent rows, and 122493 zero-duration rows with nonfinite rate values. These are whole-dataset counts, not counts of errors in this Test run.
- A TTL ablation or group-aware evaluation would require a new training and validation protocol. This held-out Test result must not select a new model or threshold.

## Provenance

All hashes below were checked against the existing run, dataset record, and historical manifests. Predictions remain outside Git.
Dataset DOI: `10.48610/6E0EDA1`.
Training commit: `6f50633544ccbf93fa4dd193355c1d8222360e37`; training packages: `{'pandas': '3.1.1', 'numpy': '2.5.4', 'scikit-learn': '1.9.1', 'joblib': '1.6.0'}`; split seed: `42`; evaluation Python: `3.14.10`.

- `confusion_matrix_csv_sha256`: `ced60c3baca4130edcdd783690b3079aea5b16c9d870c884eb712afc0a24fe2f`
- `confusion_matrix_png_sha256`: `ee88d7d2bf66a2042a75bdd9ea817d34469ddb3aabafecffdf2e20ef55e2b996`
- `dataset_manifest_sha256`: `5cff932354f78a223a24ae91d7268955a1758865a5affff46471c29241ae5d59`
- `dataset_sha256`: `4ebb97bd74412d566137d95a6fc3ffd8f374f1cf8cfe204d007848e7a668f9b5`
- `eda_summary_sha256`: `1e96517efde059d96d1d5df5cd7e4f61173c0abe6a48a074a2514a12efd6359b`
- `evaluation_metadata_sha256`: `8c7e74f5333e749718cc58d37e3c5191cb31121112351f29c894eaa3a5153f41`
- `metrics_json_sha256`: `0efc4ba25012707851c6b2c6f175f6004b3bdea3fe670d94f832a48eba13aa65`
- `model_artifact_sha256`: `801afcbb71f04de8f671790d747b45a3bfc98bd3e01fb02b8f37a1c76ec85eea`
- `model_manifest_sha256`: `2ea97a57c6917c2f39e94aa5795cbd83f98b2f7bbf09d7f5454344f19d08dcf3`
- `predictions_csv_sha256`: `3396d0f2c3d1b4970064f3ee364e40e0c9aa0747d47a37d984cf5aad70ff0c6c`
- `preprocessing_manifest_sha256`: `af07dc3b6c7cbc9e75426eeb5b96d52dbd191e8a09161699df2fad1bb5555441`
- `preprocessor_artifact_sha256`: `12d4360a05ef92573763ae1d9c1a5c36ea59081cf2f16112017bec56bbca1b19`
- `split_manifest_sha256`: `bb84c1e0595fe3c6e76c75ac7f233426f939b518a1b966b922b7fb35b634dd88`
- `test_indices_sha256`: `63e2e081300955fe06835b0cf7405e07e53985ca3d84164e768be09116269d03`
- `validation_audit_sha256`: `b84971d2f1783676be7a9b55705bc2f6148e43ec3eaf85fb0cf68ce6937db649`
