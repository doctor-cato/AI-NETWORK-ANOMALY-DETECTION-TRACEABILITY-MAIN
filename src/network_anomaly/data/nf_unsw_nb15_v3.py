"""NF-UNSW-NB15-v3 feature and split safeguards.

These helpers define contracts only. They do not claim that a production split
or model experiment has been executed.
"""

from hashlib import blake2b

DATASET_NAME = "NF-UNSW-NB15-v3"
TIMESTAMP_COLUMNS = ("FLOW_START_MILLISECONDS", "FLOW_END_MILLISECONDS")
IDENTIFIER_COLUMNS = ("IPV4_SRC_ADDR", "IPV4_DST_ADDR")
TRACE_METADATA_COLUMNS = TIMESTAMP_COLUMNS + IDENTIFIER_COLUMNS
TARGET_COLUMNS = ("Label", "Attack")

ALL_COLUMNS = (
    "FLOW_START_MILLISECONDS",
    "FLOW_END_MILLISECONDS",
    "IPV4_SRC_ADDR",
    "L4_SRC_PORT",
    "IPV4_DST_ADDR",
    "L4_DST_PORT",
    "PROTOCOL",
    "L7_PROTO",
    "IN_BYTES",
    "IN_PKTS",
    "OUT_BYTES",
    "OUT_PKTS",
    "TCP_FLAGS",
    "CLIENT_TCP_FLAGS",
    "SERVER_TCP_FLAGS",
    "FLOW_DURATION_MILLISECONDS",
    "DURATION_IN",
    "DURATION_OUT",
    "MIN_TTL",
    "MAX_TTL",
    "LONGEST_FLOW_PKT",
    "SHORTEST_FLOW_PKT",
    "MIN_IP_PKT_LEN",
    "MAX_IP_PKT_LEN",
    "SRC_TO_DST_SECOND_BYTES",
    "DST_TO_SRC_SECOND_BYTES",
    "RETRANSMITTED_IN_BYTES",
    "RETRANSMITTED_IN_PKTS",
    "RETRANSMITTED_OUT_BYTES",
    "RETRANSMITTED_OUT_PKTS",
    "SRC_TO_DST_AVG_THROUGHPUT",
    "DST_TO_SRC_AVG_THROUGHPUT",
    "NUM_PKTS_UP_TO_128_BYTES",
    "NUM_PKTS_128_TO_256_BYTES",
    "NUM_PKTS_256_TO_512_BYTES",
    "NUM_PKTS_512_TO_1024_BYTES",
    "NUM_PKTS_1024_TO_1514_BYTES",
    "TCP_WIN_MAX_IN",
    "TCP_WIN_MAX_OUT",
    "ICMP_TYPE",
    "ICMP_IPV4_TYPE",
    "DNS_QUERY_ID",
    "DNS_QUERY_TYPE",
    "DNS_TTL_ANSWER",
    "FTP_COMMAND_RET_CODE",
    "SRC_TO_DST_IAT_MIN",
    "SRC_TO_DST_IAT_MAX",
    "SRC_TO_DST_IAT_AVG",
    "SRC_TO_DST_IAT_STDDEV",
    "DST_TO_SRC_IAT_MIN",
    "DST_TO_SRC_IAT_MAX",
    "DST_TO_SRC_IAT_AVG",
    "DST_TO_SRC_IAT_STDDEV",
    "Label",
    "Attack",
)
ML_FEATURE_COLUMNS = tuple(
    column for column in ALL_COLUMNS if column not in set(TRACE_METADATA_COLUMNS + TARGET_COLUMNS)
)


def validate_feature_selection(columns, require_complete=True):
    """Reject targets, trace-only identifiers, unknowns and duplicate features."""
    selected = tuple(columns)
    if len(selected) != len(set(selected)):
        raise ValueError("feature selection contains duplicate columns")
    forbidden = sorted(set(selected) & set(TRACE_METADATA_COLUMNS + TARGET_COLUMNS))
    if forbidden:
        raise ValueError(f"feature selection contains forbidden columns: {forbidden}")
    unknown = sorted(set(selected) - set(ML_FEATURE_COLUMNS))
    if unknown:
        raise ValueError(f"feature selection contains unknown columns: {unknown}")
    if require_complete and selected != ML_FEATURE_COLUMNS:
        raise ValueError("feature selection does not match the ordered v3 ML contract")
    return selected


def canonical_flow_group(row, bucket_milliseconds=300_000):
    """Create a direction-independent 5-tuple/time-bucket grouping key."""
    if bucket_milliseconds <= 0:
        raise ValueError("bucket_milliseconds must be positive")
    start = int(row["FLOW_START_MILLISECONDS"])
    source = (str(row["IPV4_SRC_ADDR"]), int(row["L4_SRC_PORT"]))
    destination = (str(row["IPV4_DST_ADDR"]), int(row["L4_DST_PORT"]))
    first, second = sorted((source, destination))
    return first, second, int(row["PROTOCOL"]), start // bucket_milliseconds


def split_row_fingerprint(row):
    """Fingerprint all non-target values for cross-split duplicate detection."""
    digest = blake2b(digest_size=16)
    for column in ALL_COLUMNS:
        if column in TARGET_COLUMNS:
            continue
        value = str(row[column]).encode("utf-8", errors="surrogatepass")
        digest.update(len(value).to_bytes(4, "big"))
        digest.update(value)
    return digest.digest()


def audit_bounded_split_rows(split_rows):
    """Audit small fixtures or bounded split manifests for cross-split overlap.

    Full-dataset implementations must use a disk-backed equivalent; this helper
    deliberately makes no scalability claim.
    """
    owners_by_fingerprint = {}
    owners_by_group = {}
    duplicate_overlaps = []
    group_overlaps = []
    for split, rows in split_rows.items():
        if split not in {"train", "validation", "test"}:
            raise ValueError(f"unsupported split name: {split}")
        for offset, row in enumerate(rows):
            fingerprint = split_row_fingerprint(row)
            previous = owners_by_fingerprint.setdefault(fingerprint, split)
            if previous != split:
                duplicate_overlaps.append((previous, split, offset))
            group = canonical_flow_group(row)
            previous = owners_by_group.setdefault(group, split)
            if previous != split:
                group_overlaps.append((previous, split, offset))
    return {
        "status": "PASS" if not duplicate_overlaps and not group_overlaps else "FAIL",
        "duplicate_overlaps": duplicate_overlaps,
        "group_overlaps": group_overlaps,
    }
