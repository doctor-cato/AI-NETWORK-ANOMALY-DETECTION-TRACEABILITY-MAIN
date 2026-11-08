"""Out-of-Distribution (OOD) Validator and Shortcut Drift Detection (Issue #46)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

import numpy as np
import pandas as pd


@dataclass
class OODReport:
    """Detailed report distinguishing hard protocol violations from statistical domain drift."""

    total_rows: int
    has_ood_warning: bool
    hard_violation_count: int = 0
    shortcut_shift_count: int = 0
    zero_ttl_count: int = 0
    affected_rows_count: int = 0
    shortcut_drift_ratio: float = 0.0
    ood_flags: List[str] = field(default_factory=list)
    out_of_range_details: Dict[str, int] = field(default_factory=dict)
    unseen_categories: Dict[str, List[Any]] = field(default_factory=dict)

    def summary(self) -> Dict[str, Any]:
        return {
            "total_rows": self.total_rows,
            "has_ood_warning": self.has_ood_warning,
            "hard_violation_count": self.hard_violation_count,
            "shortcut_shift_count": self.shortcut_shift_count,
            "zero_ttl_count": self.zero_ttl_count,
            "affected_rows_count": self.affected_rows_count,
            "shortcut_drift_ratio": round(self.shortcut_drift_ratio, 4),
            "ood_flags": self.ood_flags,
            "out_of_range_details": self.out_of_range_details,
            "unseen_categories": self.unseen_categories,
        }


class OODValidator:
    """Validates boundary constraints and audits lab shortcut collapse."""

    # Lab shortcuts identified in audit report reports/models/rf_baseline_validation_audit.json
    CANONICAL_LAB_SHORTCUT_TTLS: Set[int] = {31, 62, 254, 255}

    KNOWN_PROTOCOLS: Set[int] = {0, 1, 2, 6, 17, 47, 50, 51, 58, 89}

    def __init__(self, check_shortcut_drift: bool = True) -> None:
        self.check_shortcut_drift = check_shortcut_drift

    def audit_dataframe(self, df: pd.DataFrame) -> OODReport:
        """Audit a feature matrix for hard boundary violations and distribution drift."""
        n_rows = len(df)
        if n_rows == 0:
            return OODReport(total_rows=0, has_ood_warning=False)

        flags: List[str] = []
        out_of_range: Dict[str, int] = {}
        unseen_cats: Dict[str, List[Any]] = {}
        hard_mask = np.zeros(n_rows, dtype=bool)

        # 1. Hard Check: Negative flow duration
        if "FLOW_DURATION_MILLISECONDS" in df.columns:
            dur_neg = df["FLOW_DURATION_MILLISECONDS"] < 0
            if dur_neg.any():
                c = int(dur_neg.sum())
                out_of_range["FLOW_DURATION_MILLISECONDS_negative"] = c
                flags.append(f"Hard constraint violation: Negative flow duration in {c} row(s).")
                hard_mask |= dur_neg.values

        # 2. Hard Check: Inverted TTL (MIN_TTL > MAX_TTL)
        if "MIN_TTL" in df.columns and "MAX_TTL" in df.columns:
            ttl_inv = df["MIN_TTL"] > df["MAX_TTL"]
            if ttl_inv.any():
                c = int(ttl_inv.sum())
                out_of_range["MIN_TTL_greater_than_MAX_TTL"] = c
                flags.append(f"Hard constraint violation: Inverted TTL (MIN_TTL > MAX_TTL) in {c} row(s).")
                hard_mask |= ttl_inv.values

        # 3. Hard Check: Inverted packet lengths
        if "LONGEST_FLOW_PKT" in df.columns and "SHORTEST_FLOW_PKT" in df.columns:
            pkt_inv = df["SHORTEST_FLOW_PKT"] > df["LONGEST_FLOW_PKT"]
            if pkt_inv.any():
                c = int(pkt_inv.sum())
                out_of_range["SHORTEST_greater_than_LONGEST"] = c
                flags.append(f"Hard constraint violation: Inverted packet lengths in {c} row(s).")
                hard_mask |= pkt_inv.values

        # 4. Hard Check: Negative byte or packet counters
        for col in ("IN_BYTES", "IN_PKTS", "OUT_BYTES", "OUT_PKTS"):
            if col in df.columns:
                neg_c = df[col] < 0
                if neg_c.any():
                    c = int(neg_c.sum())
                    out_of_range[f"{col}_negative"] = c
                    flags.append(f"Hard constraint violation: Negative counter in {col} ({c} rows).")
                    hard_mask |= neg_c.values

        # 5. Hard Check: Invalid port numbers
        for col in ("L4_SRC_PORT", "L4_DST_PORT"):
            if col in df.columns:
                inv_port = (df[col] < 0) | (df[col] > 65535)
                if inv_port.any():
                    c = int(inv_port.sum())
                    out_of_range[f"{col}_out_of_range"] = c
                    flags.append(f"Hard constraint violation: Port out of range [0, 65535] in {col} ({c} rows).")
                    hard_mask |= inv_port.values

        # 6. Statistical / Domain Drift Audit: MIN_TTL Shortcut Collapse & Zero TTL
        zero_ttl_count = 0
        drift_count = 0
        drift_ratio = 0.0

        if "MIN_TTL" in df.columns:
            min_ttl_series = df["MIN_TTL"].dropna()
            zero_mask = min_ttl_series == 0
            zero_ttl_count = int(zero_mask.sum())
            if zero_ttl_count > 0:
                flags.append(
                    f"Domain telemetry shift: {zero_ttl_count}/{n_rows} rows ({zero_ttl_count/n_rows*100:.1f}%) "
                    "have MIN_TTL=0 (indicates probe unobserved initial TTL or NetFlow export aggregation)."
                )

            if self.check_shortcut_drift:
                min_ttl_vals = min_ttl_series.astype(int)
                drift_mask = ~min_ttl_vals.isin(self.CANONICAL_LAB_SHORTCUT_TTLS)
                drift_count = int(drift_mask.sum())
                drift_ratio = float(drift_count / n_rows) if n_rows > 0 else 0.0
                if drift_count > 0:
                    flags.append(
                        f"Shortcut shift: {drift_count}/{n_rows} rows ({drift_ratio*100:.1f}%) "
                        f"have MIN_TTL outside UNSW-NB15 lab generator shortcuts (31/62/254/255)."
                    )

        # 7. Unseen IP Protocols (Informational Domain Drift)
        if "PROTOCOL" in df.columns:
            protos = df["PROTOCOL"].dropna().unique()
            unknown = [int(p) for p in protos if int(p) not in self.KNOWN_PROTOCOLS]
            if unknown:
                unseen_cats["PROTOCOL"] = unknown
                flags.append(f"Unseen IP protocol IDs detected: {unknown}")

        hard_violation_count = int(hard_mask.sum())
        total_affected = hard_violation_count

        return OODReport(
            total_rows=n_rows,
            has_ood_warning=len(flags) > 0,
            hard_violation_count=hard_violation_count,
            shortcut_shift_count=drift_count,
            zero_ttl_count=zero_ttl_count,
            affected_rows_count=total_affected,
            shortcut_drift_ratio=drift_ratio,
            ood_flags=flags,
            out_of_range_details=out_of_range,
            unseen_categories=unseen_cats,
        )
