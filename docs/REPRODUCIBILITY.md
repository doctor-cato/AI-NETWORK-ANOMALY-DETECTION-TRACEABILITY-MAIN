# Reproducibility

## Environment

- Python: 3.11/3.12 in CI; local code declares `>=3.11`.
- Supported CI OS: Ubuntu and Windows.
- Raw dataset and large model artifacts are not committed.
- `pytest` prepends this checkout's `src/`, avoiding an editable install from another worktree.

```text
python scripts/check_environment.py
python -m pytest tests -q
python -m ruff check .
python -m black --check .
git diff --check
```

## Reproduce official bytes

```text
python scripts/fetch_nf_unsw_nb15_v3.py
python scripts/dataset_manifest.py verify
```

The manifest pins DOI, UQRDM UUID, package identifier, byte sizes, project-computed SHA-256,
publisher BagIt SHA-1 for payload files, schema order and verified distributions. The download API
returns a rotating signed URL, so the stable identity is the UQRDM record plus pinned content bytes,
not the temporary URL.

Fetcher safety includes bounded streaming, HTML/ZIP/member checks, safe extraction, cache
verification, destination lock, staging, transaction marker, backup, rollback and recovery. A
successful cache hit still rehashes all package members.

## Reproduce real-data audit

```text
python scripts/validate_data.py
```

Expected current status is `FAIL`, not PASS. The version-controlled report records the verified
dataset SHA-256, row/label/category counts, missing/non-finite counts and disk-backed duplicate
audit. The validator removes its temporary SQLite database after success or failure.

When the default CSV is absent, validation prints `SKIPPED` and exits `0`. That behavior permits CI
without a 577 MB raw CSV, but it is not real-data evidence. Synthetic test PASS only demonstrates
validator behavior.

## Split and experiment identity

No real v3 split or benchmark currently exists. A future accepted run must record:

- Git commit and dependency snapshot;
- dataset SHA-256 and split identifier;
- temporal boundaries, group rule, excluded-row ledger and row-index hashes;
- ordered feature list and trace-only metadata list;
- train-only fitted preprocessing artifact and its hash;
- model family, seed/config, artifact hash and environment;
- validation-selected threshold/hyperparameters;
- test metrics, confusion matrix, per-category errors and limitations.

Random seed `42` is the default where randomness is required. It does not replace recording the
actual seed or deterministic split algorithm.

## Leakage and transform rules

- Split/group/deduplicate before fitting preprocessing.
- Never put `Label`, `Attack`, IP identifiers or absolute timestamps in default `X`.
- Fit imputer, non-finite policy, encoder, scaler, selector and resampler only on train.
- Validation selects configuration and thresholds; test is not reused for tuning.
- Fail when exact fingerprint or flow-group identifiers cross partitions.
- Treat the five-minute bidirectional 5-tuple group as a documented heuristic, not a proven session.

See `docs/NF_UNSW_NB15_V3_SPLIT_PROTOCOL.md`.

## Historical snapshot boundary

UNSW-NB15 (2015) scripts, manifest and quality report are retained under `historical/`. Their old
PASS state describes different bytes/schema/split and cannot validate NF-UNSW-NB15-v3.
