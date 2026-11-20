"""Out-of-Distribution (OOD) Validator and Physical Flow Invariant Checker for NetFlow Sentinel v2."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Set

import numpy as np
import pandas as pd


@dataclass
class OODReport:
    """Report distinguishing hard physical flow invariant violations from statistical drift."""

    total_rows: int
    has_ood_warning: bool
    hard_violation_count: int = 0
    shortcut_shift_count: int = 0
    zero_ttl_count: int = 0
    affected_rows_count: int = 0
    shortcut_drift_ratio: float = 0.0
    zero_ttl_ratio: float = 0.0
    ood_flags: List[str] = field(default_factory=list)
    out_of_range_details: Dict[str, int] = field(default_factory=dict)
    unseen_categories: Dict[str, List[Any]] = field(default_factory=dict)
    hard_violation_indices: List[int] = field(default_factory=list)
    zero_ttl_indices: List[int] = field(default_factory=list)
    shortcut_drift_indices: List[int] = field(default_factory=list)

    @property
    def abstention_rate(self) -> float:
        return float(self.affected_rows_count / max(1, self.total_rows))

    @property
    def prediction_coverage(self) -> float:
        return max(0.0, 1.0 - self.abstention_rate)

    def summary(self) -> Dict[str, Any]:
        return {
            "total_rows": self.total_rows,
            "has_ood_warning": self.has_ood_warning,
            "hard_violation_count": self.hard_violation_count,
            "shortcut_shift_count": self.shortcut_shift_count,
            "zero_ttl_count": self.zero_ttl_count,
            "affected_rows_count": self.affected_rows_count,
            "shortcut_drift_ratio": round(self.shortcut_drift_ratio, 4),
            "zero_ttl_ratio": round(self.zero_ttl_ratio, 4),
            "abstention_rate": round(self.abstention_rate, 4),
            "prediction_coverage": round(self.prediction_coverage, 4),
            "ood_flags": self.ood_flags,
            "out_of_range_details": self.out_of_range_details,
            "unseen_categories": self.unseen_categories,
            "hard_violation_indices_count": len(self.hard_violation_indices),
            "zero_ttl_indices_count": len(self.zero_ttl_indices),
        }


class OODValidator:
    """Validates physical flow invariants and protocol domain boundaries on canonical v2 flows."""

    KNOWN_PROTOCOLS: Set[int] = {0, 1, 2, 6, 17, 47, 50, 51, 58, 89}

    def __init__(
        self,
        check_protocol_drift: bool = True,
    ) -> None:
        self.check_protocol_drift = check_protocol_drift

    def audit_dataframe(self, df: pd.DataFrame) -> OODReport:
        """Audit a canonical v2 flow DataFrame for hard physical invariants and unseen protocols."""
        n_rows = len(df)
        if n_rows == 0:
            return OODReport(total_rows=0, has_ood_warning=False)

        flags: List[str] = []
        out_of_range: Dict[str, int] = {}
        unseen_cats: Dict[str, List[Any]] = {}
        hard_mask = np.zeros(n_rows, dtype=bool)

        # 1. Negative duration
        if "duration_ms" in df.columns:
            dur_s = pd.to_numeric(df["duration_ms"], errors="coerce")
            dur_neg = (
                dur_s.isna()
                | ~np.isfinite(dur_s.to_numpy(dtype=np.float64, na_value=np.nan))
                | (dur_s < 0)
            )
            if dur_neg.any():
                c = int(dur_neg.sum())
                out_of_range["duration_ms_negative_or_invalid"] = c
                flags.append(
                    f"Hard constraint violation: Negative/invalid duration_ms in {c} row(s)."
                )
                hard_mask |= dur_neg.to_numpy()

        # 2. Negative byte/packet counters
        for col in ("bytes_in", "bytes_out", "pkts_in", "pkts_out", "total_bytes", "total_pkts"):
            if col in df.columns:
                cnt_s = pd.to_numeric(df[col], errors="coerce")
                neg_c = (
                    cnt_s.isna()
                    | ~np.isfinite(cnt_s.to_numpy(dtype=np.float64, na_value=np.nan))
                    | (cnt_s < 0)
                )
                if neg_c.any():
                    c = int(neg_c.sum())
                    out_of_range[f"{col}_negative_or_invalid"] = c
                    flags.append(
                        f"Hard constraint violation: Negative/invalid {col} in {c} row(s)."
                    )
                    hard_mask |= neg_c.to_numpy()

        # 3. Port bounds [0, 65535]
        for col in ("source_port", "dest_port"):
            if col in df.columns:
                port_s = pd.to_numeric(df[col], errors="coerce")
                inv_port = (port_s < 0) | (port_s > 65535) | port_s.isna()
                if inv_port.any():
                    c = int(inv_port.sum())
                    out_of_range[f"{col}_out_of_range"] = c
                    flags.append(
                        f"Hard constraint violation: Port out of range in {col} ({c} rows)."
                    )
                    hard_mask |= inv_port.to_numpy()

        # 4. Protocol bounds [0, 255]
        if "protocol_num" in df.columns:
            proto_s = pd.to_numeric(df["protocol_num"], errors="coerce")
            inv_proto = (proto_s < 0) | (proto_s > 255) | proto_s.isna()
            if inv_proto.any():
                c = int(inv_proto.sum())
                out_of_range["protocol_num_out_of_range"] = c
                flags.append(f"Hard constraint violation: Protocol out of [0, 255] ({c} rows).")
                hard_mask |= inv_proto.to_numpy()

            if self.check_protocol_drift:
                proto_clean = proto_s.dropna().unique()
                unknown = [
                    int(p)
                    for p in proto_clean
                    if 0 <= int(p) <= 255 and int(p) not in self.KNOWN_PROTOCOLS
                ]
                if unknown:
                    unseen_cats["protocol_num"] = unknown
                    flags.append(f"Unseen IP protocol IDs detected: {unknown}")

        # 5. Ratio bounds [0, 1]
        for col in ("bytes_in_ratio", "pkts_in_ratio"):
            if col in df.columns:
                r_s = pd.to_numeric(df[col], errors="coerce")
                inv_r = r_s.isna() | (r_s < -1e-6) | (r_s > 1.0 + 1e-6)
                if inv_r.any():
                    c = int(inv_r.sum())
                    out_of_range[f"{col}_out_of_bounds"] = c
                    flags.append(
                        f"Hard constraint violation: Ratio {col} outside [0, 1] ({c} rows)."
                    )
                    hard_mask |= inv_r.to_numpy()

        hard_violation_count = int(hard_mask.sum())
        hard_indices = [int(i) for i in np.where(hard_mask)[0]]

        return OODReport(
            total_rows=n_rows,
            has_ood_warning=len(flags) > 0,
            hard_violation_count=hard_violation_count,
            shortcut_shift_count=0,
            zero_ttl_count=0,
            affected_rows_count=hard_violation_count,
            shortcut_drift_ratio=0.0,
            zero_ttl_ratio=0.0,
            ood_flags=flags,
            out_of_range_details=out_of_range,
            unseen_categories=unseen_cats,
            hard_violation_indices=hard_indices,
            zero_ttl_indices=[],
            shortcut_drift_indices=[],
        )
