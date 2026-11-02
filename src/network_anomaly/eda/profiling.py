"""Reproducible, leakage-safe exploratory profiling of NF-UNSW-NB15-v3.

The profiler is descriptive only. It profiles the verified source population in
bounded memory, never fits a transformer, never selects features and never
changes a readiness gate. Train-dependent conclusions stay ``PENDING ISSUE #7``
because no verified train/validation/test split exists yet.

Population statistics (counts, means, extremes, complete-case correlations) are
computed over every row. Quantiles, shape statistics and every figure are
derived from a seeded reservoir sample and are labelled as sample-based.
"""

from __future__ import annotations

import math
import os
import tempfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from network_anomaly.data.nf_unsw_nb15_v3 import (
    ALL_COLUMNS,
    CATEGORICAL_CODED_COLUMNS,
    IDENTIFIER_COLUMNS,
    ML_FEATURE_COLUMNS,
    QUANTITATIVE_ML_COLUMNS,
    TARGET_COLUMNS,
)

EDA_SCHEMA_VERSION = "nf-unsw-nb15-v3-eda-v1"

QUANTILE_PROBABILITIES = (0.01, 0.05, 0.25, 0.50, 0.75, 0.95, 0.99)
CLASS_CONDITIONAL_FEATURES = (
    "FLOW_DURATION_MILLISECONDS",
    "IN_BYTES",
    "OUT_BYTES",
    "IN_PKTS",
    "OUT_PKTS",
    "SRC_TO_DST_AVG_THROUGHPUT",
)
THROUGHPUT_COLUMNS = ("SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT")
RATE_COLUMNS = ("SRC_TO_DST_SECOND_BYTES", "DST_TO_SRC_SECOND_BYTES")
CATEGORICAL_COUNT_LIMIT = 64
EPOCH_DAY_MILLISECONDS = 86_400_000
ATTACK_CATEGORIES = (
    "Benign",
    "Analysis",
    "Backdoor",
    "DoS",
    "Exploits",
    "Fuzzers",
    "Generic",
    "Reconnaissance",
    "Shellcode",
    "Worms",
)
ATTACK_BITS = {attack: 1 << index for index, attack in enumerate(ATTACK_CATEGORIES)}
SAMPLE_COLUMNS = tuple(QUANTITATIVE_ML_COLUMNS) + (
    "Label",
    "Attack",
    "PROTOCOL",
    "L7_PROTO",
    "FLOW_START_MILLISECONDS",
)

TOKEN_CLASSES = (
    "blank",
    "nan_literal",
    "null_literal",
    "positive_infinity",
    "negative_infinity",
    "invalid_numeric",
    "numeric",
)
NON_FINITE_TOKEN_CLASSES = {
    "": "blank",
    "nan": "nan_literal",
    "+nan": "nan_literal",
    "-nan": "nan_literal",
    "null": "null_literal",
    "none": "null_literal",
    "n/a": "null_literal",
    "na": "null_literal",
    "inf": "positive_infinity",
    "+inf": "positive_infinity",
    "infinity": "positive_infinity",
    "+infinity": "positive_infinity",
    "-inf": "negative_infinity",
    "-infinity": "negative_infinity",
}


class TextModeRequired(RuntimeError):
    """Raised when the fast numeric parse cannot represent a published token."""


def _token_class(value: str) -> str:
    """Classify one raw CSV token without converting it to a number."""
    text = value.strip().lower()
    mapped = NON_FINITE_TOKEN_CLASSES.get(text)
    if mapped is not None:
        return mapped
    try:
        float(text)
    except ValueError:
        return "invalid_numeric"
    return "numeric"


def classify_token_series(values: pd.Series) -> dict[str, int]:
    """Return exact token counts for a raw text column."""
    counts = Counter({name: 0 for name in TOKEN_CLASSES})
    for value, count in values.astype("string").str.strip().value_counts().items():
        counts[_token_class(value)] += int(count)
    return dict(counts)


@dataclass
class NumericAccumulator:
    """Streaming accumulator for one numeric column of the source population."""

    name: str
    finite_count: int = 0
    mean: float = 0.0
    sum_of_squares: float = 0.0
    minimum: float = math.inf
    maximum: float = -math.inf
    total: float = 0.0
    zero_count: int = 0
    negative_value_count: int = 0
    missing_count: int = 0
    positive_infinity_count: int = 0
    negative_infinity_count: int = 0
    token_counts: dict[str, int] = field(default_factory=dict)

    def update(self, values: np.ndarray) -> None:
        """Fold one chunk of parsed values into the accumulator."""
        array = np.asarray(values, dtype="float64")
        missing = np.isnan(array)
        positive_infinity = np.isposinf(array)
        negative_infinity = np.isneginf(array)
        finite = ~(missing | positive_infinity | negative_infinity)
        self.missing_count += int(missing.sum())
        self.positive_infinity_count += int(positive_infinity.sum())
        self.negative_infinity_count += int(negative_infinity.sum())
        finite_values = array[finite]
        if finite_values.size == 0:
            return
        self.zero_count += int((finite_values == 0).sum())
        self.negative_value_count += int((finite_values < 0).sum())
        self.total += float(finite_values.sum())
        chunk_mean = float(finite_values.mean())
        chunk_m2 = float(((finite_values - chunk_mean) ** 2).sum())
        combined = self.finite_count + finite_values.size
        delta = chunk_mean - self.mean
        self.mean += delta * finite_values.size / combined
        self.sum_of_squares += (
            chunk_m2 + delta * delta * self.finite_count * finite_values.size / combined
        )
        self.finite_count = combined
        self.minimum = min(self.minimum, float(finite_values.min()))
        self.maximum = max(self.maximum, float(finite_values.max()))

    def report(self) -> dict:
        """Return the population statistics collected for this column."""
        variance = self.sum_of_squares / self.finite_count if self.finite_count else None
        tokens = dict(self.token_counts)
        if not tokens:
            tokens = {
                "blank": 0,
                "nan_literal": 0,
                "null_literal": 0,
                "positive_infinity": self.positive_infinity_count,
                "negative_infinity": self.negative_infinity_count,
                "invalid_numeric": 0,
                "numeric": self.finite_count,
            }
        return {
            "finite_count": self.finite_count,
            "unavailable_count": self.missing_count
            + self.positive_infinity_count
            + self.negative_infinity_count,
            "token_counts": tokens,
            "zero_count": self.zero_count,
            "negative_value_count": self.negative_value_count,
            "minimum": None if self.finite_count == 0 else self.minimum,
            "maximum": None if self.finite_count == 0 else self.maximum,
            "mean": None if self.finite_count == 0 else self.mean,
            "standard_deviation": None if variance is None else math.sqrt(variance),
            "total": self.total,
        }


class BoundedCounter:
    """Count categorical values while keeping the tracked vocabulary bounded."""

    def __init__(self, limit: int = CATEGORICAL_COUNT_LIMIT):
        self.limit = limit
        self.counts: Counter = Counter()
        self.other_occurrences = 0

    def update(self, values) -> None:
        """Add one chunk of raw categorical values."""
        for value, count in Counter(values).items():
            if value in self.counts or len(self.counts) < self.limit:
                self.counts[value] += int(count)
            else:
                self.other_occurrences += int(count)

    def report(self) -> dict:
        """Return exact counts for the tracked vocabulary plus an overflow bucket."""
        return {
            "tracked_distinct_values": len(self.counts),
            "tracked_values": dict(
                sorted(self.counts.items(), key=lambda item: (-item[1], str(item[0])))
            ),
            "other_occurrences": self.other_occurrences,
            "other_distinct_values_at_least": 1 if self.other_occurrences else 0,
        }


class ValueSink:
    """Disk-backed value buffer that yields exact population quantiles."""

    def __init__(self, directory: str | None, name: str):
        handle, path = tempfile.mkstemp(prefix=f"eda-{name}-", suffix=".f64", dir=directory)
        os.close(handle)
        self.path = Path(path)
        self._stream = self.path.open("wb")
        self.count = 0

    def add(self, values: np.ndarray) -> None:
        """Append finite values to the buffer."""
        array = np.asarray(values, dtype="float64")
        if array.size == 0:
            return
        array.tofile(self._stream)
        self.count += array.size

    def quantiles(self, probabilities=QUANTILE_PROBABILITIES) -> dict[str, float]:
        """Return exact quantiles over every buffered value."""
        self._stream.flush()
        self._stream.close()
        self._stream = None
        if self.count == 0:
            return {}
        values = np.fromfile(self.path, dtype="float64")
        computed = np.quantile(values, list(probabilities))
        return {
            f"p{int(round(probability * 100)):02d}": float(value)
            for probability, value in zip(probabilities, computed, strict=True)
        }

    def close(self) -> None:
        """Remove the temporary buffer."""
        if self._stream is not None:
            self._stream.close()
            self._stream = None
        self.path.unlink(missing_ok=True)


@dataclass
class _Reservoir:
    """Seeded reservoir sample used for quantiles, shape statistics and figures."""

    size: int
    values: dict[str, np.ndarray]
    filled: int = 0
    seen: int = 0


class DatasetProfiler:
    """Profile the verified NF-UNSW-NB15-v3 CSV in bounded memory."""

    def __init__(
        self,
        columns=ALL_COLUMNS,
        expected_rows: int | None = None,
        chunk_size: int = 100_000,
        sample_size: int = 200_000,
        seed: int = 42,
        max_rows: int | None = None,
        temp_directory: str | None = None,
    ):
        if chunk_size <= 0:
            raise ValueError("chunk_size must be positive")
        if sample_size <= 0:
            raise ValueError("sample_size must be positive")
        self.columns = tuple(columns)
        self.expected_rows = expected_rows
        self.chunk_size = chunk_size
        self.sample_size = sample_size
        self.seed = seed
        self.max_rows = max_rows
        self.temp_directory = temp_directory
        self.sample: dict[str, np.ndarray] = {}
        self.rng = np.random.default_rng(seed)

    # ------------------------------------------------------------------ reading
    def _numeric_dtypes(self) -> dict:
        dtypes = {}
        for column in self.columns:
            if column in IDENTIFIER_COLUMNS or column in TARGET_COLUMNS:
                dtypes[column] = object
            else:
                dtypes[column] = "float64"
        return dtypes

    def _iter_chunks(self, path: Path, text_mode: bool):
        if text_mode:
            reader = pd.read_csv(
                path,
                dtype={column: object for column in self.columns},
                keep_default_na=False,
                chunksize=self.chunk_size,
            )
        else:
            reader = pd.read_csv(
                path,
                dtype=self._numeric_dtypes(),
                chunksize=self.chunk_size,
            )
        for chunk in reader:
            yield chunk

    def _normalize_chunk(self, chunk: pd.DataFrame, text_mode: bool) -> dict[str, np.ndarray]:
        """Return one array per column, with non-numeric tokens as NaN."""
        normalized = {}
        for column in self.columns:
            values = chunk[column]
            if column in IDENTIFIER_COLUMNS or column in TARGET_COLUMNS:
                normalized[column] = values.to_numpy(dtype=object)
                continue
            if text_mode:
                converted = pd.to_numeric(values.astype("string").str.strip(), errors="coerce")
                normalized[column] = converted.to_numpy(dtype="float64")
            else:
                normalized[column] = values.to_numpy(dtype="float64")
        return normalized

    # --------------------------------------------------------------- statistics
    def profile(self, path: Path) -> dict:
        """Return the EDA summary for the dataset at ``path``."""
        path = Path(path)
        try:
            return self._profile(path, text_mode=False)
        except TextModeRequired:
            self.rng = np.random.default_rng(self.seed)
            return self._profile(path, text_mode=True)

    def _profile(self, path: Path, text_mode: bool) -> dict:
        numeric_columns = [
            column
            for column in self.columns
            if column not in IDENTIFIER_COLUMNS and column not in TARGET_COLUMNS
        ]
        quantitative = [column for column in numeric_columns if column in QUANTITATIVE_ML_COLUMNS]
        accumulators = {column: NumericAccumulator(column) for column in numeric_columns}
        class_accumulators = {
            group: {column: NumericAccumulator(column) for column in CLASS_CONDITIONAL_FEATURES}
            for group in ("label_0", "label_1")
        }
        categorical = {
            column: BoundedCounter()
            for column in CATEGORICAL_CODED_COLUMNS
            if column not in ("PROTOCOL", "L7_PROTO")
        }
        protocol_counts = BoundedCounter()
        l7_counts = BoundedCounter()
        label_counts: Counter = Counter()
        attack_counts: Counter = Counter()
        daily_counts: Counter = Counter()
        duration_throughput: Counter = Counter()
        duration_throughput_by_label = {"0": Counter(), "1": Counter()}
        hash_blocks: dict[str, list[np.ndarray]] = {"exact": [], "source": [], "ml": []}
        label_blocks: list[np.ndarray] = []
        attack_blocks: list[np.ndarray] = []
        gram = np.zeros((len(quantitative), len(quantitative)), dtype="float64")
        gram_n = 0
        gram_s1 = np.zeros(len(quantitative), dtype="float64")
        gram_s2 = np.zeros(len(quantitative), dtype="float64")
        reservoir = _Reservoir(
            size=self.sample_size,
            values={
                column: np.empty(self.sample_size, dtype="float64") for column in SAMPLE_COLUMNS
            },
        )
        sinks: dict[str, ValueSink] = {}
        label_sinks: dict[tuple[str, str], ValueSink] = {}
        rows = 0
        minimum_start = None
        maximum_end = None
        try:
            for chunk in self._iter_chunks(path, text_mode):
                if self.max_rows is not None and rows >= self.max_rows:
                    break
                if self.max_rows is not None and rows + len(chunk) > self.max_rows:
                    chunk = chunk.iloc[: self.max_rows - rows]
                normalized = self._normalize_chunk(chunk, text_mode)
                rows += len(chunk)
                labels = chunk["Label"].to_numpy(dtype=object)
                attacks = chunk["Attack"].to_numpy(dtype=object)
                label_counts.update(Counter(labels))
                attack_counts.update(Counter(attacks))
                for column, counter in categorical.items():
                    counter.update(chunk[column].to_numpy(dtype=object))
                protocol_counts.update(chunk["PROTOCOL"].to_numpy(dtype=object))
                l7_counts.update(chunk["L7_PROTO"].to_numpy(dtype=object))
                for column in numeric_columns:
                    accumulators[column].update(normalized[column])
                    if text_mode:
                        counts = classify_token_series(chunk[column])
                        merged = accumulators[column].token_counts or {
                            name: 0 for name in TOKEN_CLASSES
                        }
                        for name, value in counts.items():
                            merged[name] = merged.get(name, 0) + value
                        accumulators[column].token_counts = merged
                starts = normalized["FLOW_START_MILLISECONDS"]
                ends = normalized["FLOW_END_MILLISECONDS"]
                finite_starts = starts[np.isfinite(starts)]
                if finite_starts.size:
                    start_min = float(finite_starts.min())
                    minimum_start = (
                        start_min if minimum_start is None else min(minimum_start, start_min)
                    )
                    days, day_counts = np.unique(
                        (finite_starts // EPOCH_DAY_MILLISECONDS).astype("int64"),
                        return_counts=True,
                    )
                    for day, count in zip(days, day_counts, strict=True):
                        daily_counts[int(day)] += int(count)
                finite_ends = ends[np.isfinite(ends)]
                if finite_ends.size:
                    end_max = float(finite_ends.max())
                    maximum_end = end_max if maximum_end is None else max(maximum_end, end_max)
                self._accumulate_class_conditional(
                    normalized, labels, class_accumulators, label_sinks, sinks
                )
                self._accumulate_duration_throughput(
                    normalized, labels, duration_throughput, duration_throughput_by_label
                )
                gram_n_added, matrix = self._complete_case_matrix(normalized, quantitative)
                if matrix is not None:
                    gram += matrix.T @ matrix
                    gram_s1 += matrix.sum(axis=0)
                    gram_s2 += (matrix * matrix).sum(axis=0)
                    gram_n += gram_n_added
                self._accumulate_hashes(chunk, hash_blocks, label_blocks, attack_blocks)
                self._fill_reservoir(reservoir, normalized, labels, attacks, rows)
            quantiles = {column: sink.quantiles() for column, sink in sinks.items()}
            label_quantiles = {
                f"{group}|{column}": sink.quantiles()
                for (group, column), sink in label_sinks.items()
            }
        except (ValueError, TypeError) as error:
            if text_mode or "convert" not in str(error).lower():
                raise
            raise TextModeRequired(str(error)) from error
        finally:
            for sink in sinks.values():
                sink.close()
            for sink in label_sinks.values():
                sink.close()
        if rows == 0:
            raise ValueError("dataset has no data rows")
        if not text_mode:
            self._refine_token_columns(path, accumulators, numeric_columns)
        self.sample = {
            column: reservoir.values[column][: reservoir.filled] for column in SAMPLE_COLUMNS
        }
        duplicates = self._duplicate_summary(hash_blocks, label_blocks, attack_blocks, rows)
        correlations = self._correlations(gram, gram_n, gram_s1, gram_s2, quantitative)
        sample_statistics = self._sample_statistics(reservoir)
        return {
            "schema_version": EDA_SCHEMA_VERSION,
            "generated_at_utc": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
            "rows": rows,
            "expected_rows": self.expected_rows,
            "row_count_matches_manifest": (
                None if self.expected_rows is None else rows == self.expected_rows
            ),
            "parse_mode": "text" if text_mode else "numeric",
            "label_counts": {str(key): value for key, value in sorted(label_counts.items())},
            "attack_counts": {str(key): value for key, value in sorted(attack_counts.items())},
            "protocol_counts": protocol_counts.report(),
            "l7_proto_counts": l7_counts.report(),
            "categorical_counts": {
                column: counter.report() for column, counter in sorted(categorical.items())
            },
            "numeric_statistics": {
                column: accumulators[column].report() for column in numeric_columns
            },
            "quantiles": quantiles,
            "class_conditional": {
                group: {
                    column: accumulator.report() for column, accumulator in sorted(items.items())
                }
                for group, items in sorted(class_accumulators.items())
            },
            "class_conditional_quantiles": label_quantiles,
            "duration_throughput": {
                "population": {
                    (
                        f"duration_zero={key[0]},rate_non_finite={key[1]},"
                        f"throughput_non_finite={key[2]}"
                    ): value
                    for key, value in sorted(duration_throughput.items())
                },
                "by_label": {
                    label: {
                        (
                            f"duration_zero={key[0]},rate_non_finite={key[1]},"
                            f"throughput_non_finite={key[2]}"
                        ): value
                        for key, value in sorted(counts.items())
                    }
                    for label, counts in sorted(duration_throughput_by_label.items())
                },
                "rate_columns": list(RATE_COLUMNS),
                "throughput_columns": list(THROUGHPUT_COLUMNS),
                "note": (
                    "Association only. The published feature dictionary does not expose the "
                    "producer arithmetic, so no causal claim is made."
                ),
            },
            "time_coverage": {
                "minimum_start_epoch_ms": minimum_start,
                "maximum_end_epoch_ms": maximum_end,
                "minimum_start_utc": _epoch_ms_to_iso(minimum_start),
                "maximum_end_utc": _epoch_ms_to_iso(maximum_end),
                "capture_window_days": (
                    None
                    if minimum_start is None or maximum_end is None
                    else round((maximum_end - minimum_start) / EPOCH_DAY_MILLISECONDS, 4)
                ),
                "daily_flow_counts": {
                    _epoch_day_to_date(day): count for day, count in sorted(daily_counts.items())
                },
            },
            "duplicates": duplicates,
            "correlations": correlations,
            "sample": {
                "method": "reservoir sampling (Algorithm L) over the parsed population",
                "size": reservoir.filled,
                "requested_size": self.sample_size,
                "seed": self.seed,
                "columns": list(SAMPLE_COLUMNS),
                "limitations": (
                    "Sample-based estimates. Full-population counts, means, extremes and "
                    "complete-case Pearson correlations are computed over every row."
                ),
            },
            "sample_statistics": sample_statistics,
        }

    # ------------------------------------------------------------------ helpers
    def _accumulate_class_conditional(
        self,
        normalized: dict[str, np.ndarray],
        labels: np.ndarray,
        class_accumulators: dict,
        label_sinks: dict,
        sinks: dict,
    ) -> None:
        for group, target in (("label_0", "0"), ("label_1", "1")):
            mask = labels == target
            if not mask.any():
                continue
            for column in CLASS_CONDITIONAL_FEATURES:
                values = normalized[column][mask]
                class_accumulators[group][column].update(values)
                key = (group, column)
                if key not in label_sinks:
                    label_sinks[key] = ValueSink(self.temp_directory, f"{group}-{column}")
                label_sinks[key].add(values[np.isfinite(values)])
        for column in QUANTITATIVE_ML_COLUMNS:
            if column not in sinks:
                sinks[column] = ValueSink(self.temp_directory, column)
            values = normalized[column]
            sinks[column].add(values[np.isfinite(values)])

    def _accumulate_duration_throughput(
        self,
        normalized: dict[str, np.ndarray],
        labels: np.ndarray,
        duration_throughput: Counter,
        duration_throughput_by_label: dict,
    ) -> None:
        durations = normalized["FLOW_DURATION_MILLISECONDS"]
        zero_duration = durations == 0
        rate_non_finite = np.zeros(len(durations), dtype=bool)
        for column in RATE_COLUMNS:
            rate_non_finite |= ~np.isfinite(normalized[column])
        throughput_non_finite = np.zeros(len(durations), dtype=bool)
        for column in THROUGHPUT_COLUMNS:
            throughput_non_finite |= ~np.isfinite(normalized[column])
        for zero_flag, rate_flag, throughput_flag in (
            (False, False, False),
            (False, True, False),
            (False, True, True),
            (True, False, False),
            (True, True, False),
            (True, True, True),
        ):
            mask = (
                (zero_duration == zero_flag)
                & (rate_non_finite == rate_flag)
                & (throughput_non_finite == throughput_flag)
            )
            if not mask.any():
                continue
            duration_throughput[(zero_flag, rate_flag, throughput_flag)] += int(mask.sum())
            for label in ("0", "1"):
                label_mask = mask & (labels == label)
                duration_throughput_by_label[label][(zero_flag, rate_flag, throughput_flag)] += int(
                    label_mask.sum()
                )

    @staticmethod
    def _complete_case_matrix(normalized, quantitative):
        matrix = np.column_stack([normalized[column] for column in quantitative])
        complete = np.isfinite(matrix).all(axis=1)
        count = int(complete.sum())
        if count == 0:
            return 0, None
        return count, matrix[complete]

    def _accumulate_hashes(self, chunk, hash_blocks, label_blocks, attack_blocks) -> None:
        hash_blocks["exact"].append(
            pd.util.hash_pandas_object(chunk[list(self.columns)], index=False).to_numpy(
                dtype="uint64"
            )
        )
        source_columns = [column for column in self.columns if column not in TARGET_COLUMNS]
        hash_blocks["source"].append(
            pd.util.hash_pandas_object(chunk[source_columns], index=False).to_numpy(dtype="uint64")
        )
        hash_blocks["ml"].append(
            pd.util.hash_pandas_object(chunk[list(ML_FEATURE_COLUMNS)], index=False).to_numpy(
                dtype="uint64"
            )
        )
        label_blocks.append(pd.to_numeric(chunk["Label"], errors="coerce").to_numpy(dtype="int8"))
        attack_blocks.append(
            pd.Series(chunk["Attack"].to_numpy(dtype=object))
            .map({attack: index for index, attack in enumerate(ATTACK_CATEGORIES)})
            .fillna(-1)
            .to_numpy(dtype="int8")
        )

    def _fill_reservoir(self, reservoir: _Reservoir, normalized, labels, attacks, rows) -> None:
        columns = {column: normalized[column] for column in QUANTITATIVE_ML_COLUMNS}
        columns["Label"] = pd.to_numeric(pd.Series(labels), errors="coerce").to_numpy(
            dtype="float64"
        )
        columns["Attack"] = (
            pd.Series(attacks)
            .map({attack: index for index, attack in enumerate(ATTACK_CATEGORIES)})
            .fillna(-1)
            .to_numpy(dtype="float64")
        )
        columns["PROTOCOL"] = normalized["PROTOCOL"]
        columns["L7_PROTO"] = normalized["L7_PROTO"]
        columns["FLOW_START_MILLISECONDS"] = normalized["FLOW_START_MILLISECONDS"]
        size = reservoir.size
        values = len(next(iter(columns.values())))
        if values == 0:
            return
        if reservoir.filled < size:
            take = min(size - reservoir.filled, values)
            for column, array in columns.items():
                reservoir.values[column][reservoir.filled : reservoir.filled + take] = array[:take]
            reservoir.filled += take
            remaining = {column: array[take:] for column, array in columns.items()}
            start_index = rows - values + take
        else:
            remaining = columns
            start_index = rows - values
        remaining_length = len(next(iter(remaining.values())))
        if remaining_length == 0:
            reservoir.seen = rows
            return
        draws = self.rng.random(remaining_length)
        global_index = start_index + 1 + np.arange(remaining_length)
        targets = (draws * global_index).astype("int64")
        selected = targets < size
        if selected.any():
            index = targets[selected]
            for column, array in remaining.items():
                reservoir.values[column][index] = array[selected]
        reservoir.seen = rows

    def _refine_token_columns(self, path, accumulators, numeric_columns) -> None:
        """Resolve blank/NaN/infinity token classes for columns with non-finite values."""
        targets = [
            column
            for column in numeric_columns
            if accumulators[column].missing_count
            or accumulators[column].positive_infinity_count
            or accumulators[column].negative_infinity_count
        ]
        if not targets:
            return
        reader = pd.read_csv(
            path,
            usecols=targets,
            dtype={column: object for column in targets},
            keep_default_na=False,
            chunksize=self.chunk_size,
        )
        totals = {column: Counter({name: 0 for name in TOKEN_CLASSES}) for column in targets}
        processed = 0
        for chunk in reader:
            if self.max_rows is not None and processed >= self.max_rows:
                break
            if self.max_rows is not None and processed + len(chunk) > self.max_rows:
                chunk = chunk.head(self.max_rows - processed)
            processed += len(chunk)
            for column in targets:
                counts = classify_token_series(chunk[column])
                for name, value in counts.items():
                    totals[column][name] += value
        for column in targets:
            accumulators[column].token_counts = dict(totals[column])

    @staticmethod
    def _duplicate_summary(hash_blocks, label_blocks, attack_blocks, rows) -> dict:
        exact = (
            np.concatenate(hash_blocks["exact"])
            if hash_blocks["exact"]
            else np.empty(0, dtype="uint64")
        )
        source = (
            np.concatenate(hash_blocks["source"])
            if hash_blocks["source"]
            else np.empty(0, dtype="uint64")
        )
        ml = np.concatenate(hash_blocks["ml"]) if hash_blocks["ml"] else np.empty(0, dtype="uint64")
        labels = np.concatenate(label_blocks) if label_blocks else np.empty(0, dtype="int8")
        attacks = np.concatenate(attack_blocks) if attack_blocks else np.empty(0, dtype="int8")
        summary = {
            "method": (
                "Row-equivalence fingerprints over parsed values using "
                "pandas.util.hash_pandas_object (uint64)."
            ),
            "exact_full_row": {
                "duplicate_rows": rows - int(np.unique(exact).size),
                "distinct_rows": int(np.unique(exact).size),
            },
            "source_feature": {
                "duplicate_rows": rows - int(np.unique(source).size),
                "distinct_rows": int(np.unique(source).size),
            },
            "ml_feature_equivalent": {
                "duplicate_rows": rows - int(np.unique(ml).size),
                "distinct_rows": int(np.unique(ml).size),
            },
            "behavioral_v1": {
                "duplicate_rows": rows - int(np.unique(ml).size),
                "distinct_rows": int(np.unique(ml).size),
                "note": (
                    "The v3 contract defines behavioral-v1 over the same ordered 47 columns as "
                    "the ML baseline under a separate namespace, so the equivalence classes "
                    "and counts coincide with ml_feature_equivalent."
                ),
            },
            "automatic_removal_permitted": False,
        }
        summary["ml_feature_equivalent"].update(_group_conflicts(ml, labels, attacks))
        summary["exact_full_row"].update(_group_conflicts(exact, labels, attacks))
        return summary

    @staticmethod
    def _correlations(gram, gram_n, gram_s1, gram_s2, quantitative) -> dict:
        if gram_n < 2:
            return {
                "pearson_complete_cases": {
                    "columns": list(quantitative),
                    "observations": gram_n,
                    "matrix": [],
                }
            }
        denominator = np.sqrt(np.outer(gram_s2, gram_s2))
        numerator = gram_n * gram - np.outer(gram_s1, gram_s1)
        with np.errstate(divide="ignore", invalid="ignore"):
            matrix = np.where(denominator > 0, numerator / denominator, np.nan)
        np.fill_diagonal(matrix, 1.0)
        return {
            "pearson_complete_cases": {
                "columns": list(quantitative),
                "observations": gram_n,
                "matrix": [
                    [None if math.isnan(value) else float(value) for value in row] for row in matrix
                ],
            }
        }

    @staticmethod
    def _sample_statistics(reservoir: _Reservoir) -> dict:
        statistics = {}
        for column in QUANTITATIVE_ML_COLUMNS:
            values = reservoir.values[column][: reservoir.filled]
            finite = values[np.isfinite(values)]
            if finite.size < 2:
                continue
            deviation = finite - finite.mean()
            variance = float((deviation**2).mean())
            if variance <= 0:
                statistics[column] = {
                    "sample_count": int(finite.size),
                    "skewness": None,
                    "excess_kurtosis": None,
                    "constant": True,
                }
                continue
            statistics[column] = {
                "sample_count": int(finite.size),
                "skewness": float((deviation**3).mean() / variance**1.5),
                "excess_kurtosis": float((deviation**4).mean() / variance**2 - 3.0),
                "constant": False,
            }
        return statistics


def _group_conflicts(hashes: np.ndarray, labels: np.ndarray, attacks: np.ndarray) -> dict:
    """Summarize label and attack-category conflicts inside repeated groups."""
    if hashes.size == 0:
        return {
            "groups_with_duplicates": 0,
            "binary_label_conflict_groups": 0,
            "rows_in_binary_label_conflict_groups": 0,
            "multiple_attack_category_groups": 0,
            "rows_in_multiple_attack_category_groups": 0,
            "benign_attack_conflict_groups": 0,
        }
    order = np.argsort(hashes, kind="stable")
    sorted_hashes = hashes[order]
    sorted_labels = labels[order]
    sorted_attacks = attacks[order]
    starts = np.flatnonzero(np.r_[True, sorted_hashes[1:] != sorted_hashes[:-1]])
    counts = np.diff(np.r_[starts, sorted_hashes.size])
    repeated = counts > 1
    if not repeated.any():
        return {
            "groups_with_duplicates": 0,
            "binary_label_conflict_groups": 0,
            "rows_in_binary_label_conflict_groups": 0,
            "multiple_attack_category_groups": 0,
            "rows_in_multiple_attack_category_groups": 0,
            "benign_attack_conflict_groups": 0,
            "rows_in_benign_attack_conflict_groups": 0,
        }
    label_min = np.minimum.reduceat(sorted_labels, starts)
    label_max = np.maximum.reduceat(sorted_labels, starts)
    binary_conflict = ((label_min == 0) & (label_max == 1))[repeated]
    presence = np.zeros((len(ATTACK_CATEGORIES), starts.size), dtype=bool)
    for index, category in enumerate(ATTACK_CATEGORIES):
        matches = sorted_attacks == index
        presence[index] = np.maximum.reduceat(matches.astype("int8"), starts) > 0
    category_count = presence.sum(axis=0)
    multiple_categories = (category_count > 1)[repeated]
    benign_index = ATTACK_CATEGORIES.index("Benign")
    malicious = presence.copy()
    malicious[benign_index] = False
    benign_conflict = (presence[benign_index] & malicious.any(axis=0))[repeated]
    group_counts = counts[repeated]
    return {
        "groups_with_duplicates": int(group_counts.size),
        "binary_label_conflict_groups": int(binary_conflict.sum()),
        "rows_in_binary_label_conflict_groups": int(group_counts[binary_conflict].sum()),
        "multiple_attack_category_groups": int(multiple_categories.sum()),
        "rows_in_multiple_attack_category_groups": int(group_counts[multiple_categories].sum()),
        "benign_attack_conflict_groups": int(benign_conflict.sum()),
        "rows_in_benign_attack_conflict_groups": int(group_counts[benign_conflict].sum()),
    }


def _epoch_ms_to_iso(value: float | None) -> str | None:
    if value is None:
        return None
    return datetime.fromtimestamp(value / 1000, tz=timezone.utc).isoformat()


def _epoch_day_to_date(day: int) -> str:
    return datetime.fromtimestamp(day * 86400, tz=timezone.utc).date().isoformat()


def profile_dataset(
    path,
    columns=ALL_COLUMNS,
    expected_rows: int | None = None,
    chunk_size: int = 100_000,
    sample_size: int = 200_000,
    seed: int = 42,
    max_rows: int | None = None,
    temp_directory: str | None = None,
) -> dict:
    """Profile a dataset file and return the machine-readable EDA summary."""
    profiler = DatasetProfiler(
        columns=columns,
        expected_rows=expected_rows,
        chunk_size=chunk_size,
        sample_size=sample_size,
        seed=seed,
        max_rows=max_rows,
        temp_directory=temp_directory,
    )
    return profiler.profile(Path(path))
