"""Headless-safe figures for the NF-UNSW-NB15-v3 exploratory analysis.

Every figure is written as PNG with a title, axis labels including units, a
legend where a series is drawn, and a caption that states whether the plotted
values come from the full population or from the seeded sample.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib

matplotlib.use("Agg")

import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

FIGURE_DPI = 150
SAMPLE_NOTE = "sample-based"


def _save(figure, path: Path) -> str:
    figure.tight_layout()
    figure.savefig(path, dpi=FIGURE_DPI, bbox_inches="tight")
    plt.close(figure)
    return path.name


def _label_distribution(summary: dict, output: Path) -> dict:
    counts = summary["label_counts"]
    names = ["Benign (0)" if key == "0" else "Attack (1)" for key in sorted(counts)]
    values = [counts[key] for key in sorted(counts)]
    total = sum(values)
    figure, axes = plt.subplots(figsize=(7, 4))
    bars = axes.bar(names, values, color=["#4c72b0", "#c44e52"])
    for bar, value in zip(bars, values, strict=True):
        axes.annotate(
            f"{value:,}\n{value / total * 100:.3f}%",
            (bar.get_x() + bar.get_width() / 2, bar.get_height()),
            ha="center",
            va="bottom",
            fontsize=9,
        )
    axes.set_title("Binary target distribution (Label) - full population")
    axes.set_ylabel("Flows (count)")
    axes.set_xlabel("Label")
    axes.set_yscale("log")
    axes.legend(
        [bars[0], bars[1]],
        [f"{names[0]}: {values[0]:,}", f"{names[1]}: {values[1]:,}"],
        title="Full population (all rows)",
        loc="upper right",
    )
    name = _save(figure, output / "fig01_label_distribution.png")
    return {
        "file": name,
        "title": "Binary target distribution (Label)",
        "evidence": "full population",
        "caption": (
            "Counts and shares of the binary `Label` target over every row of the verified "
            "source file. The log scale keeps the minority class visible."
        ),
    }


def _attack_distribution(summary: dict, output: Path) -> dict:
    counts = summary["attack_counts"]
    names = sorted(counts, key=lambda key: -counts[key])
    values = [counts[key] for key in names]
    total = sum(values)
    figure, axes = plt.subplots(figsize=(8, 4.5))
    colors = ["#c44e52" if name != "Benign" else "#4c72b0" for name in names]
    bars = axes.barh(names[::-1], values[::-1], color=colors[::-1])
    for bar, value in zip(bars, values[::-1], strict=True):
        axes.annotate(
            f"{value:,} ({value / total * 100:.4f}%)",
            (value, bar.get_y() + bar.get_height() / 2),
            va="center",
            fontsize=8,
        )
    axes.set_xscale("log")
    axes.set_title("Attack category distribution (Attack) - full population")
    axes.set_xlabel("Flows (count, log scale)")
    axes.set_ylabel("Attack category")
    axes.legend(
        [bars[0]],
        ["Benign traffic"],
        title="Full population (all rows)",
        loc="lower right",
    )
    name = _save(figure, output / "fig02_attack_category_distribution.png")
    return {
        "file": name,
        "title": "Attack category distribution (Attack)",
        "evidence": "full population",
        "caption": (
            "All ten attack categories with counts and shares. `Worms` is the rarest class; "
            "the axis is logarithmic so that rare categories stay readable."
        ),
    }


def _protocol_distribution(summary: dict, output: Path) -> dict:
    protocol = summary["protocol_counts"]["tracked_values"]
    l7 = summary["l7_proto_counts"]["tracked_values"]
    figure, axes = plt.subplots(1, 2, figsize=(12, 4.5))
    protocol_items = sorted(protocol.items(), key=lambda item: -item[1])[:15]
    axes[0].bar(
        [str(key) for key, _ in protocol_items],
        [value for _, value in protocol_items],
        color="#55a868",
    )
    axes[0].set_title("IP protocol code distribution - full population")
    axes[0].set_xlabel("PROTOCOL code (numeric-coded category)")
    axes[0].set_ylabel("Flows (count)")
    axes[0].tick_params(axis="x", rotation=45)
    l7_items = sorted(l7.items(), key=lambda item: -item[1])[:15]
    axes[1].bar(
        [str(key) for key, _ in l7_items],
        [value for _, value in l7_items],
        color="#4c72b0",
    )
    axes[1].set_title("Application protocol code distribution - full population")
    axes[1].set_xlabel("L7_PROTO code (numeric-coded category)")
    axes[1].set_ylabel("Flows (count)")
    axes[1].tick_params(axis="x", rotation=45)
    name = _save(figure, output / "fig03_protocol_distribution.png")
    return {
        "file": name,
        "title": "Numeric-coded protocol distributions",
        "evidence": "full population",
        "caption": (
            "`PROTOCOL` and `L7_PROTO` are numeric-coded categories, not continuous "
            "variables. The 15 most frequent codes of each are shown; the full counts are in "
            "the machine-readable summary."
        ),
    }


def _capture_coverage(summary: dict, output: Path) -> dict:
    daily = summary["time_coverage"]["daily_flow_counts"]
    dates = sorted(daily)
    values = [daily[date] for date in dates]
    figure, axes = plt.subplots(figsize=(10, 4))
    axes.bar(dates, values, color="#4c72b0")
    axes.set_title("Captured flow coverage per UTC day - full population")
    axes.set_ylabel("Flows (count)")
    axes.set_xlabel("UTC date of FLOW_START_MILLISECONDS")
    axes.tick_params(axis="x", rotation=45)
    axes.legend([axes.patches[0]], ["Flows starting in the day"], loc="upper right")
    name = _save(figure, output / "fig04_capture_coverage_by_day.png")
    return {
        "file": name,
        "title": "Capture window coverage per UTC day",
        "evidence": "full population",
        "caption": (
            "Flow start timestamps grouped per UTC day. The published capture window is a few "
            "weeks in 2015; it does not represent contemporary traffic."
        ),
    }


def _duration_distribution(summary: dict, sample: dict, output: Path) -> dict:
    values = sample["FLOW_DURATION_MILLISECONDS"]
    finite = values[np.isfinite(values)]
    figure, axes = plt.subplots(figsize=(8, 4.5))
    axes.hist(np.log10(1 + finite), bins=60, color="#4c72b0")
    median = float(np.median(finite))
    axes.axvline(
        np.log10(1 + median),
        color="#c44e52",
        linestyle="--",
        label=f"median = {median:g} ms",
    )
    axes.set_title(f"Flow duration distribution ({SAMPLE_NOTE}, n={finite.size:,})")
    axes.set_xlabel("log10(1 + FLOW_DURATION_MILLISECONDS) [ms]")
    axes.set_ylabel("Sampled flows (count)")
    axes.legend(loc="upper right")
    name = _save(figure, output / "fig05_duration_distribution.png")
    return {
        "file": name,
        "title": "Flow duration distribution",
        "evidence": f"{SAMPLE_NOTE} (n={finite.size:,})",
        "caption": (
            "Log-transformed flow duration in milliseconds. The distribution is zero-heavy, so "
            "the log1p transform is used for readability; no flow is dropped."
        ),
    }


def _byte_packet_distributions(sample: dict, output: Path) -> dict:
    columns = ("IN_BYTES", "OUT_BYTES", "IN_PKTS", "OUT_PKTS")
    figure, axes = plt.subplots(2, 2, figsize=(11, 7))
    for axis, column in zip(axes.flat, columns, strict=True):
        values = sample[column]
        finite = values[np.isfinite(values) & (values >= 0)]
        axis.hist(np.log10(1 + finite), bins=60, color="#55a868")
        axis.set_title(f"{column} ({SAMPLE_NOTE})")
        unit = "bytes" if "BYTES" in column else "packets"
        axis.set_xlabel(f"log10(1 + {column}) [{unit}]")
        axis.set_ylabel("Sampled flows (count)")
    name = _save(figure, output / "fig06_byte_and_packet_distributions.png")
    return {
        "file": name,
        "title": "Byte and packet count distributions",
        "evidence": f"{SAMPLE_NOTE} (n={finite.size:,})",
        "caption": (
            "Inbound/outbound byte and packet counts. Both directions are strongly "
            "zero-heavy, which is why a log1p transform is used for the display only."
        ),
    }


def _throughput_distribution(summary: dict, sample: dict, output: Path) -> dict:
    figure, axes = plt.subplots(1, 2, figsize=(12, 4.5))
    for axis, column in zip(
        axes,
        ("SRC_TO_DST_AVG_THROUGHPUT", "DST_TO_SRC_AVG_THROUGHPUT"),
        strict=True,
    ):
        values = sample[column]
        finite = values[np.isfinite(values) & (values >= 0)]
        axis.hist(np.log10(1 + finite), bins=60, color="#8172b2")
        axis.set_title(f"{column} ({SAMPLE_NOTE})")
        axis.set_xlabel(f"log10(1 + {column}) [bytes per second]")
        axis.set_ylabel("Sampled flows (count)")
    figure.text(
        0.5,
        0.01,
        "Non-finite throughput counts are population statistics and are reported in the "
        "summary; they are excluded from the histograms above.",
        ha="center",
        fontsize=8,
    )
    name = _save(figure, output / "fig07_throughput_distribution.png")
    return {
        "file": name,
        "title": "Average throughput distributions",
        "evidence": f"{SAMPLE_NOTE} (n={finite.size:,})",
        "caption": (
            "Directional average throughput in bytes per second. Non-finite values are not "
            "silently replaced; they are counted separately in the population statistics."
        ),
    }


def _duration_versus_throughput(sample: dict, output: Path) -> dict:
    durations = sample["FLOW_DURATION_MILLISECONDS"]
    throughput = sample["SRC_TO_DST_AVG_THROUGHPUT"]
    finite = np.isfinite(durations) & np.isfinite(throughput) & (durations >= 0) & (throughput >= 0)
    figure, axes = plt.subplots(figsize=(7.5, 5.5))
    hexbin = axes.hexbin(
        np.log10(1 + durations[finite]),
        np.log10(1 + throughput[finite]),
        gridsize=60,
        bins="log",
        cmap="viridis",
    )
    axes.set_title(f"Duration versus source-to-destination throughput ({SAMPLE_NOTE})")
    axes.set_xlabel("log10(1 + FLOW_DURATION_MILLISECONDS) [ms]")
    axes.set_ylabel("log10(1 + SRC_TO_DST_AVG_THROUGHPUT) [bytes per second]")
    figure.colorbar(hexbin, ax=axes, label="Sampled flows per bin (log scale)")
    name = _save(figure, output / "fig08_duration_versus_throughput.png")
    return {
        "file": name,
        "title": "Duration versus throughput",
        "evidence": f"{SAMPLE_NOTE} (n={finite.size:,})",
        "caption": (
            "Joint view of duration and average throughput for rows with finite, "
            "non-negative values. The non-finite values of this dataset sit in the rate "
            "fields, not in the throughput fields; they are counted in the population "
            "contingency table. The association is descriptive and not causal."
        ),
    }


def _correlation_heatmap(summary: dict, output: Path) -> dict:
    payload = summary["correlations"]["pearson_complete_cases"]
    columns = payload["columns"]
    matrix = np.array(
        [[np.nan if value is None else value for value in row] for row in payload["matrix"]],
        dtype="float64",
    )
    figure, axes = plt.subplots(figsize=(13, 11))
    image = axes.imshow(matrix, cmap="RdBu_r", vmin=-1, vmax=1)
    axes.set_xticks(range(len(columns)))
    axes.set_yticks(range(len(columns)))
    axes.set_xticklabels(columns, rotation=90, fontsize=7)
    axes.set_yticklabels(columns, fontsize=7)
    axes.set_title(
        "Pearson correlation of quantitative features - full population, complete cases\n"
        f"(n={payload['observations']:,} observations, listwise deletion of non-finite rows)"
    )
    axes.set_xlabel("Quantitative feature")
    axes.set_ylabel("Quantitative feature")
    figure.colorbar(image, ax=axes, label="Pearson correlation coefficient")
    name = _save(figure, output / "fig09_correlation_heatmap.png")
    return {
        "file": name,
        "title": "Feature correlation heatmap",
        "evidence": f"full population, complete cases (n={payload['observations']:,})",
        "caption": (
            "Pearson correlations restricted to the 37 quantitative baseline features. "
            "Numeric-coded categorical fields such as `PROTOCOL` or `TCP_FLAGS` are "
            "deliberately excluded."
        ),
    }


def _class_conditional_boxplots(sample: dict, output: Path) -> dict:
    columns = (
        "FLOW_DURATION_MILLISECONDS",
        "IN_BYTES",
        "OUT_BYTES",
        "IN_PKTS",
    )
    labels = sample["Label"]
    figure, axes = plt.subplots(2, 2, figsize=(12, 7))
    for axis, column in zip(axes.flat, columns, strict=True):
        values = sample[column]
        finite = np.isfinite(values) & (values >= 0)
        data = [
            values[finite & (labels == 0)],
            values[finite & (labels == 1)],
        ]
        axis.boxplot(data, tick_labels=["Label 0 (benign)", "Label 1 (attack)"], showfliers=False)
        axis.set_yscale("log")
        axis.set_title(f"{column} by label ({SAMPLE_NOTE})")
        axis.set_ylabel(f"{column} (log scale)")
        axis.set_xlabel("Target class")
    name = _save(figure, output / "fig10_class_conditional_boxplots.png")
    return {
        "file": name,
        "title": "Class-conditional feature distributions",
        "evidence": f"{SAMPLE_NOTE} (n={int(np.isfinite(sample['Label']).sum()):,})",
        "caption": (
            "Descriptive class-conditional comparison only. These distributions are not used "
            "to select features, to tune thresholds or to fit any model."
        ),
    }


def _duration_throughput_quality(summary: dict, output: Path) -> dict:
    by_label = summary["duration_throughput"]["by_label"]
    keys = sorted(by_label["0"])
    benign = [by_label["0"][key] for key in keys]
    attack = [by_label["1"][key] for key in keys]
    positions = np.arange(len(keys))
    figure, axes = plt.subplots(figsize=(9, 4.5))
    axes.bar(positions - 0.2, benign, width=0.4, label="Label 0 (benign)", color="#4c72b0")
    axes.bar(positions + 0.2, attack, width=0.4, label="Label 1 (attack)", color="#c44e52")
    axes.set_xticks(positions)
    axes.set_xticklabels([key.replace(",", "\n") for key in keys], fontsize=8)
    axes.set_yscale("log")
    axes.set_title("Zero duration and non-finite throughput co-occurrence - full population")
    axes.set_ylabel("Flows (count, log scale)")
    axes.set_xlabel("duration_zero / throughput_non_finite")
    axes.legend(loc="upper right")
    name = _save(figure, output / "fig11_duration_throughput_quality.png")
    return {
        "file": name,
        "title": "Duration and throughput quality contingency",
        "evidence": "full population",
        "caption": (
            "Counts of flows per (zero duration, non-finite rate, non-finite throughput) "
            "combination, split by label. The association is an observed property of the "
            "published bytes and does not establish how the producer computed the values."
        ),
    }


def _shape_statistics(summary: dict, output: Path) -> dict:
    statistics = summary["sample_statistics"]
    shaped = sorted(
        (name, values) for name, values in statistics.items() if values["skewness"] is not None
    )
    names = [name for name, _ in shaped]
    skews = [values["skewness"] for _, values in shaped]
    figure, axes = plt.subplots(figsize=(11, 5))
    axes.bar(names, skews, color="#c44e52")
    axes.axhline(1.0, color="black", linestyle="--", linewidth=1, label="skewness = 1")
    axes.axhline(-1.0, color="black", linestyle=":", linewidth=1, label="skewness = -1")
    axes.set_title(f"Distribution skewness of quantitative features ({SAMPLE_NOTE})")
    axes.set_ylabel("Sample skewness")
    axes.set_xlabel("Quantitative feature")
    axes.tick_params(axis="x", rotation=90, labelsize=7)
    axes.legend(loc="upper left")
    name = _save(figure, output / "fig12_feature_skewness.png")
    return {
        "file": name,
        "title": "Feature skewness",
        "evidence": f"{SAMPLE_NOTE} (n={shaped[0][1]['sample_count']:,} per feature)",
        "caption": (
            "Sample skewness per quantitative feature. Magnitudes above 1 indicate a strongly "
            "right-skewed feature and therefore a transformation risk for linear models."
        ),
    }


def render_figures(summary: dict, sample: dict, output_directory) -> list[dict]:
    """Render every EDA figure and return their metadata."""
    output = Path(output_directory)
    output.mkdir(parents=True, exist_ok=True)
    figures = [
        _label_distribution(summary, output),
        _attack_distribution(summary, output),
        _protocol_distribution(summary, output),
        _capture_coverage(summary, output),
        _duration_distribution(summary, sample, output),
        _byte_packet_distributions(sample, output),
        _throughput_distribution(summary, sample, output),
        _duration_versus_throughput(sample, output),
        _correlation_heatmap(summary, output),
        _class_conditional_boxplots(sample, output),
        _duration_throughput_quality(summary, output),
        _shape_statistics(summary, output),
    ]
    return figures
