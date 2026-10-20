import json
from pathlib import Path

import pytest

from network_anomaly.data.nf_unsw_nb15_v3 import (
    ALL_COLUMNS,
    BEHAVIORAL_FINGERPRINT_COLUMNS,
    FINGERPRINT_SCHEMA_VERSION,
    ML_FEATURE_COLUMNS,
    SOURCE_FEATURE_COLUMNS,
    TARGET_COLUMNS,
    TRACE_METADATA_COLUMNS,
    audit_bounded_split_rows,
    behavioral_fingerprint,
    canonical_flow_group,
    full_row_fingerprint,
    ml_feature_fingerprint,
    source_feature_fingerprint,
    validate_feature_selection,
)

ROOT = Path(__file__).resolve().parents[2]


def row(**changes):
    values = {column: 0 for column in ALL_COLUMNS}
    values.update(
        {
            "FLOW_START_MILLISECONDS": 1_000,
            "FLOW_END_MILLISECONDS": 1_002,
            "IPV4_SRC_ADDR": "192.0.2.1",
            "L4_SRC_PORT": 12345,
            "IPV4_DST_ADDR": "198.51.100.2",
            "L4_DST_PORT": 443,
            "PROTOCOL": 6,
            "Label": 0,
            "Attack": "Benign",
        }
    )
    values.update(changes)
    return values


def test_code_contract_matches_manifest_column_order():
    manifest = json.loads(
        (ROOT / "data" / "NF_UNSW_NB15_V3_MANIFEST.json").read_text(encoding="utf-8")
    )

    assert tuple(manifest["schema"]["columns_in_order"]) == ALL_COLUMNS
    assert len(ML_FEATURE_COLUMNS) == 47
    assert TRACE_METADATA_COLUMNS == (
        "FLOW_START_MILLISECONDS",
        "FLOW_END_MILLISECONDS",
        "IPV4_SRC_ADDR",
        "IPV4_DST_ADDR",
        "L4_SRC_PORT",
        "L4_DST_PORT",
    )
    assert set(ML_FEATURE_COLUMNS).isdisjoint(TRACE_METADATA_COLUMNS + TARGET_COLUMNS)
    assert set(ML_FEATURE_COLUMNS + TRACE_METADATA_COLUMNS + TARGET_COLUMNS) == set(ALL_COLUMNS)
    assert SOURCE_FEATURE_COLUMNS == ALL_COLUMNS[:-2]
    assert BEHAVIORAL_FINGERPRINT_COLUMNS == ML_FEATURE_COLUMNS
    assert FINGERPRINT_SCHEMA_VERSION == "nf-unsw-nb15-v3-fingerprint-v1"


def test_feature_contract_excludes_targets_identifiers_and_absolute_timestamps():
    assert validate_feature_selection(ML_FEATURE_COLUMNS) == ML_FEATURE_COLUMNS
    assert not set(TRACE_METADATA_COLUMNS) & set(ML_FEATURE_COLUMNS)
    assert "Label" not in ML_FEATURE_COLUMNS
    assert "Attack" not in ML_FEATURE_COLUMNS


@pytest.mark.parametrize(
    "forbidden",
    [
        "Label",
        "Attack",
        "IPV4_SRC_ADDR",
        "FLOW_START_MILLISECONDS",
        "L4_SRC_PORT",
        "L4_DST_PORT",
    ],
)
def test_feature_contract_rejects_leakage_prone_columns(forbidden):
    with pytest.raises(ValueError, match="forbidden"):
        validate_feature_selection((*ML_FEATURE_COLUMNS, forbidden), require_complete=False)


def test_feature_contract_rejects_unknown_duplicate_and_wrong_order():
    with pytest.raises(ValueError, match="unknown"):
        validate_feature_selection(("NOT_A_COLUMN",), require_complete=False)
    with pytest.raises(ValueError, match="duplicate"):
        validate_feature_selection(("IN_BYTES", "IN_BYTES"), require_complete=False)
    with pytest.raises(ValueError, match="ordered"):
        validate_feature_selection(tuple(reversed(ML_FEATURE_COLUMNS)))


def test_flow_group_is_direction_independent_within_bucket():
    forward = row()
    reverse = row(
        FLOW_START_MILLISECONDS=1_500,
        IPV4_SRC_ADDR=forward["IPV4_DST_ADDR"],
        L4_SRC_PORT=forward["L4_DST_PORT"],
        IPV4_DST_ADDR=forward["IPV4_SRC_ADDR"],
        L4_DST_PORT=forward["L4_SRC_PORT"],
    )

    assert canonical_flow_group(forward, 1_000) == canonical_flow_group(reverse, 1_000)


def test_fingerprint_definitions_separate_exact_source_ml_and_behavioral_purposes():
    original = row()
    changed_target = row(Label=1, Attack="Analysis")
    changed_metadata = row(IPV4_SRC_ADDR="203.0.113.7", L4_SRC_PORT=23456)

    assert full_row_fingerprint(original) != full_row_fingerprint(changed_target)
    assert source_feature_fingerprint(original) == source_feature_fingerprint(changed_target)
    assert source_feature_fingerprint(original) != source_feature_fingerprint(changed_metadata)
    assert ml_feature_fingerprint(original) == ml_feature_fingerprint(changed_metadata)
    assert behavioral_fingerprint(original) == behavioral_fingerprint(changed_metadata)
    assert ml_feature_fingerprint(original) != behavioral_fingerprint(original)


def test_cross_split_duplicate_and_group_overlap_fail():
    training = row()
    duplicate = dict(training)
    same_group = row(IN_BYTES=99)

    result = audit_bounded_split_rows(
        {"train": [training], "validation": [same_group], "test": [duplicate]}
    )

    assert result["status"] == "FAIL"
    assert result["exact_overlaps"]
    assert result["source_feature_overlaps"]
    assert result["ml_feature_overlaps"]
    assert result["group_overlaps"]


def test_disjoint_groups_pass():
    result = audit_bounded_split_rows(
        {
            "train": [row(IN_BYTES=1)],
            "validation": [
                row(
                    FLOW_START_MILLISECONDS=400_000,
                    FLOW_END_MILLISECONDS=400_002,
                    IN_BYTES=2,
                )
            ],
            "test": [
                row(
                    FLOW_START_MILLISECONDS=800_000,
                    FLOW_END_MILLISECONDS=800_002,
                    IPV4_DST_ADDR="203.0.113.9",
                    IN_BYTES=3,
                )
            ],
        }
    )

    assert result == {
        "status": "PASS",
        "exact_overlaps": [],
        "source_feature_overlaps": [],
        "ml_feature_overlaps": [],
        "group_overlaps": [],
        "temporal_boundary_violations": [],
    }


def test_temporal_boundary_and_purge_gap_guard():
    result = audit_bounded_split_rows(
        {
            "train": [row(FLOW_START_MILLISECONDS=2_000)],
            "validation": [row(FLOW_START_MILLISECONDS=1_500, IPV4_DST_ADDR="203.0.113.9")],
            "test": [],
        }
    )
    assert result["status"] == "FAIL"
    assert result["temporal_boundary_violations"] == [
        ("train", "validation", 2_000, 1_500, -500)
    ]

    purge_result = audit_bounded_split_rows(
        {
            "train": [row(FLOW_START_MILLISECONDS=1_000)],
            "validation": [row(FLOW_START_MILLISECONDS=1_500, IPV4_DST_ADDR="203.0.113.9")],
            "test": [],
        },
        purge_gap_milliseconds=1_000,
    )
    assert purge_result["status"] == "FAIL"
    assert purge_result["temporal_boundary_violations"][0][-1] == 500
