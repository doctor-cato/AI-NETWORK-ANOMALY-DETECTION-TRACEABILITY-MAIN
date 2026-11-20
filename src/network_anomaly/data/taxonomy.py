"""Unified attack taxonomy and label harmonization for NetFlow Sentinel v2.

Built strictly from verified label sets observed in:
  - AIT NetFlow Data Set v2 (10.5281/zenodo.13168643, label_info.txt + 8 scenarios)
  - CTU-SME-11 (10.5281/zenodo.7958258, Zeek conn.log.labeled)
  - AIT Alert Data Set (10.5281/zenodo.8263181)

Rules:
  - Raw labels are always preserved verbatim.
  - Binary targets are assigned ONLY when ground truth is verified.
  - ``background``, empty strings, ``unknown``, or unrecognized labels are marked
    ``UNMAPPED`` (never silently coerced to ``Benign``).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, FrozenSet, Optional, Tuple

LABEL_TAXONOMY_VERSION = "taxonomy-v2"

CANONICAL_ATTACK_CATEGORIES: Tuple[str, ...] = (
    "Benign",
    "Reconnaissance",
    "Credential_Attack",
    "Exploitation_And_C2",
    "Post_Exploitation_Discovery",
    "Data_Exfiltration",
    "Malware_And_DoS",
    "Unmapped",
)

# Exact benign labels from AIT-NDS-v2 label_info.txt + CTU-SME-11
AIT_BENIGN_LABELS: FrozenSet[str] = frozenset(
    {
        # TCP benign
        "browsing/update",
        "benign_share",
        "broken flow - benign",
        "mail",
        "monitoring",
        "http(s) intra",
        "http(s) dmz",
        "http",
        "https",
        "dns",
        "ssh",
        "proxy",
        "update/command on unassigned port",
        # UDP benign
        "mdnsv6",
        "mdns",
        "bootp",
        "ntp",
        "systemd-resolver (local)",
        "benign dns - attacker requesting updates",
        "benign dns",
        "openvpn",
        "quic",
        "stun voip",
        "netbios",
        "googledns",
    }
)

AIT_RECON_LABELS: FrozenSet[str] = frozenset(
    {
        "service_scan",
        "service_scans",
        "network_scans",
        "host_discover_dmz",
        "host_discover_local",
        "wpscan",
        "dirb_scan",
        "dirb",
        "dns_brute_force_start",
    }
)

AIT_CREDENTIAL_LABELS: FrozenSet[str] = frozenset(
    {
        "online_cracking",
        "cracking",
    }
)

AIT_EXPLOIT_C2_LABELS: FrozenSet[str] = frozenset(
    {
        "upload_rce_shell",
        "webshell",
        "reverse_shell",
        "vpn_connect",
        "privilege_escalation",
    }
)

AIT_POST_EXPLOIT_LABELS: FrozenSet[str] = frozenset(
    {
        "check_user_id",
        "check_netstat_t",
        "read_resolv",
        "check_network_config",
        "check_ps_a",
        "check_release",
        "read_group",
        "read_passwd",
        "check_date",
        "list_web_dir",
        "check_wp_config",
        "dump_wp_users",
        "read_profile",
        "list_www",
        "check_who",
        "clear",
        "check_last",
        "check_id",
        "check_whoami",
        "check_uname_r",
        "check_meminfo",
        "check_uname_a",
        "check_df",
        "check_netstat_nat",
        "list_home",
        "check_netstat_l",
        "check_cpuinfo",
        "check_uptime",
        "check_pwd",
        "list_l",
    }
)

AIT_EXFIL_LABELS: FrozenSet[str] = frozenset(
    {
        "data exfiltration",
        "dnsteal",
    }
)

EXPLICIT_UNMAPPED_LABELS: FrozenSet[str] = frozenset(
    {
        "",
        "-",
        "(empty)",
        "background",
        "unknown",
        "unlabeled",
        "nan",
        "none",
        "null",
    }
)

RAW_LABEL_MAP: Dict[str, str] = {
    "benign": "Benign",
    "normal": "Benign",
    "0": "Benign",
    "clean": "Benign",
    "service_stop": "Exploitation_And_C2",
    "malicious": "Malware_And_DoS",
}
for _lbl in AIT_BENIGN_LABELS:
    RAW_LABEL_MAP[_lbl] = "Benign"
for _lbl in AIT_RECON_LABELS:
    RAW_LABEL_MAP[_lbl] = "Reconnaissance"
for _lbl in AIT_CREDENTIAL_LABELS:
    RAW_LABEL_MAP[_lbl] = "Credential_Attack"
for _lbl in AIT_EXPLOIT_C2_LABELS:
    RAW_LABEL_MAP[_lbl] = "Exploitation_And_C2"
for _lbl in AIT_POST_EXPLOIT_LABELS:
    RAW_LABEL_MAP[_lbl] = "Post_Exploitation_Discovery"
for _lbl in AIT_EXFIL_LABELS:
    RAW_LABEL_MAP[_lbl] = "Data_Exfiltration"


@dataclass(frozen=True)
class LabelMappingResult:
    raw_label: str
    canonical_category: str
    binary_label: Optional[int]
    label_status: str  # MAPPED_BENIGN | MAPPED_ATTACK | UNMAPPED


def classify_raw_label(
    raw_label: Optional[str],
    detailed_label: Optional[str] = None,
) -> LabelMappingResult:
    """Map a raw dataset label (plus optional CTU detailedlabel) with zero silent benign coercion."""
    raw_str = "" if raw_label is None else str(raw_label).strip()
    cleaned = raw_str.lower()

    if cleaned in EXPLICIT_UNMAPPED_LABELS:
        return LabelMappingResult(
            raw_label=raw_str,
            canonical_category="Unmapped",
            binary_label=None,
            label_status="UNMAPPED",
        )

    # CTU-SME-11 binary 'Malicious' refined by detailedlabel when available
    if cleaned == "malicious":
        det = "" if detailed_label is None else str(detailed_label).strip().lower()
        if any(k in det for k in ("discovery", "scan", "portscan", "recon")):
            cat = "Reconnaissance"
        elif any(k in det for k in ("c2", "c&c", "cc", "command", "botnet", "human_attack")):
            cat = "Exploitation_And_C2"
        elif any(k in det for k in ("exfil", "steal")):
            cat = "Data_Exfiltration"
        elif any(k in det for k in ("brute", "cred", "password")):
            cat = "Credential_Attack"
        else:
            cat = "Malware_And_DoS"
        return LabelMappingResult(
            raw_label=raw_str,
            canonical_category=cat,
            binary_label=1,
            label_status="MAPPED_ATTACK",
        )

    if cleaned in RAW_LABEL_MAP:
        cat = RAW_LABEL_MAP[cleaned]
        if cat == "Benign":
            return LabelMappingResult(
                raw_label=raw_str,
                canonical_category="Benign",
                binary_label=0,
                label_status="MAPPED_BENIGN",
            )
        return LabelMappingResult(
            raw_label=raw_str,
            canonical_category=cat,
            binary_label=1,
            label_status="MAPPED_ATTACK",
        )

    # Do NOT coerce unknown labels to Benign; report explicitly as UNMAPPED
    return LabelMappingResult(
        raw_label=raw_str,
        canonical_category="Unmapped",
        binary_label=None,
        label_status="UNMAPPED",
    )


def harmonize_attack_label(
    raw_label: Optional[str],
    detailed_label: Optional[str] = None,
) -> str:
    """Map raw label onto canonical v2 taxonomy; unmapped labels return 'Unmapped'."""
    return classify_raw_label(raw_label, detailed_label=detailed_label).canonical_category
