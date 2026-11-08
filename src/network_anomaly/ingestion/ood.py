"""Out-of-Distribution (OOD) Validator and Shortcut Drift Detection (Issue #46)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

import numpy as np
import pandas as pd


@dataclass
class OODReport:
    """Detailed report on out-of-distribution values and lab shortcut collapse."""

    total_rows: int
    has_ood_warning: bool
    ood_flags: List[str] = field(default_factory=list)
    affected_rows_count: int = 0
    shortcut_shift_count: int = 0
    out_of_range_details: Dict[str, int] = field(default_factory=dict)
    unseen_categories: Dict[str, List[Any]] = field(default_factory=dict)

    def summary(self) -> Dict[str, Any]:
        return {
            "total_rows": self.total_rows,
            "has_ood_warning": self.has_ood_warning,
            "affected_rows_count": self.affected_rows_count,
            "shortcut_shift_count": self.shortcut_shift_count,
            "ood_flags": self.ood_flags,
            "out_of_range_details": self.out_of_range_details,
            "unseen_categories": self.unseen_categories,
        }


class OODValidator:
    """Validates feature value ranges and flags domain drift / lab shortcut collapse."""

    # Lab shortcuts identified in audit report reports/models/rf_baseline_validation_audit.json
    CANONICAL_LAB_SHORTCUT_TTLS: Set[int] = {31, 62, 254, 255}

    KNOWN_PROTOCOLS: Set[int] = {0, 1, 2, 6, 17, 47, 50, 51, 58, 89}

    def __init__(self, check_shortcut_drift: bool = True) -> None:
        self.check_shortcut_drift = check_shortcut_drift

    def audit_dataframe(self, df: pd.DataFrame) -> OODReport:
        """Audit a feature matrix for boundary violations and distribution drift."""
        n_rows = len(df)
        if n_rows == 0:
            return OODReport(total_rows=0, has_ood_warning=False)

        flags: List[str] = []
        out_of_range: Dict[str, int] = {}
        unseen_cats: Dict[str, List[Any]] = {}
        affected_mask = np.zeros(n_rows, dtype=bool)

        # 1. Negative duration check
        if "FLOW_DURATION_MILLISECONDS" in df.columns:
            dur_neg = df["FLOW_DURATION_MILLISECONDS"] < 0
            if dur_neg.any():
                c = int(dur_neg.sum())
                out_of_range["FLOW_DURATION_MILLISECONDS_negative"] = c
                flags.append(f"Negative flow duration detected in {c} row(s).")
                affected_mask |= dur_neg.values

        # 2. TTL boundary and shortcut drift check
        if "MIN_TTL" in df.columns and "MAX_TTL" in df.columns:
            ttl_inv = df["MIN_TTL"] > df["MAX_TTL"]
            if ttl_inv.any():
                c = int(ttl_inv.sum())
                out_of_range["MIN_TTL_greater_than_MAX_TTL"] = c
                flags.append(f"Inverted TTL (MIN_TTL > MAX_TTL) in {c} row(s).")
                affected_mask |= ttl_inv.values

            # Shortcut collapse audit
            if self.check_shortcut_drift:
                min_ttl_vals = df["MIN_TTL"].dropna().astype(int)
                drift_mask = ~min_ttl_vals.isin(self.CANONICAL_LAB_SHORTCUT_TTLS)
                drift_count = int(drift_mask.sum())
                if drift_count > 0:
                    flags.append(
                        f"Shortcut shift: {drift_count}/{n_rows} rows ({drift_count/n_rows*100:.1f}%) "
                        f"have MIN_TTL outside UNSW-NB15 lab generator shortcuts (31/62/254/255)."
                    )
            else:
                drift_count = 0
        else:
            drift_count = 0

        # 3. Packet length boundary check
        if "LONGEST_FLOW_PKT" in df.columns and "SHORTEST_FLOW_PKT" in df.columns:
            pkt_inv = df["SHORTEST_FLOW_PKT"] > df["LONGEST_FLOW_PKT"]
            if pkt_inv.any():
                c = int(pkt_inv.sum())
                out_of_range["SHORTEST_greater_than_LONGEST"] = c
                flags.append(f"Inverted packet lengths in {c} row(s).")
                affected_mask |= pkt_inv.values

        # 4. Unknown protocol check
        if "PROTOCOL" in df.columns:
            protos = df["PROTOCOL"].dropna().unique()
            unknown = [int(p) for p in protos if int(p) not in self.KNOWN_PROTOCOLS]
            if unknown:
                unseen_cats["PROTOCOL"] = unknown
                flags.append(f"Unseen IP protocol IDs detected: {unknown}")

        has_warning = len(flags) > 0

        return OODReport(
            total_rows=n_rows,
            has_ood_warning=has_warning,
            ood_flags=flags,
            affected_rows_count=int(affected_mask.sum()),
            shortcut_shift_count=drift_count,
            out_of_range_details=out_of_range,
            unseen_categories=unseen_cats,
        )
