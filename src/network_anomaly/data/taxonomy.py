"""Unified attack taxonomy and label harmonization for multi-source ingestion.

Implements Issue #87 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

from typing import Dict, Optional


# Canonical unified attack categories across NF-UNSW-NB15-v3, AIT, Suricata, Zeek
CANONICAL_ATTACK_CATEGORIES = (
    "Benign",
    "Reconnaissance",
    "Exploits",
    "Fuzzers",
    "DoS",
    "DDoS",
    "Backdoors",
    "Worms",
    "Analysis",
    "Generic",
    "Suspicious",
)

# Raw label mapping dictionary to canonical categories
RAW_LABEL_MAP: Dict[str, str] = {
    # Benign variations
    "benign": "Benign",
    "normal": "Benign",
    "0": "Benign",
    "clean": "Benign",
    # Reconnaissance / Scans
    "reconnaissance": "Reconnaissance",
    "scan": "Reconnaissance",
    "portscan": "Reconnaissance",
    "portsweep": "Reconnaissance",
    "ipsweep": "Reconnaissance",
    "probe": "Reconnaissance",
    # Exploits
    "exploits": "Exploits",
    "exploit": "Exploits",
    "injection": "Exploits",
    "sqli": "Exploits",
    "xss": "Exploits",
    "rce": "Exploits",
    # Fuzzers
    "fuzzers": "Fuzzers",
    "fuzzer": "Fuzzers",
    # DoS / DDoS
    "dos": "DoS",
    "ddos": "DDoS",
    "synflood": "DoS",
    "udpflood": "DoS",
    "smurf": "DoS",
    # Backdoors / Trojans
    "backdoor": "Backdoors",
    "backdoors": "Backdoors",
    "trojan": "Backdoors",
    "c2": "Backdoors",
    # Worms
    "worms": "Worms",
    "worm": "Worms",
    # Analysis
    "analysis": "Analysis",
    # Generic
    "generic": "Generic",
    "shellcode": "Exploits",
}


def harmonize_attack_label(raw_label: Optional[str]) -> str:
    """Map any raw dataset/log attack label onto canonical taxonomy."""
    if raw_label is None:
        return "Benign"

    cleaned = str(raw_label).strip().lower()
    if not cleaned:
        return "Benign"

    if cleaned in RAW_LABEL_MAP:
        return RAW_LABEL_MAP[cleaned]

    # Substring heuristics
    if "recon" in cleaned or "scan" in cleaned:
        return "Reconnaissance"
    if "exploit" in cleaned or "inject" in cleaned:
        return "Exploits"
    if "dos" in cleaned or "flood" in cleaned:
        return "DoS"
    if "worm" in cleaned:
        return "Worms"
    if "backdoor" in cleaned or "c2" in cleaned:
        return "Backdoors"
    if "fuzz" in cleaned:
        return "Fuzzers"

    return "Suspicious"
