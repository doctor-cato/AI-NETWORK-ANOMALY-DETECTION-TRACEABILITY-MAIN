"""Live Log Tailer with Offset Persistence and Log Rotation Handling for Zeek & Suricata.

Implements Issue #130 for NetFlow Sentinel v2.0.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

from network_anomaly.canonical.event import CanonicalSecurityEvent
from network_anomaly.ingestion.adapters.v2_adapter import (
    ApplicationDNSAdapter,
    ApplicationWebAdapter,
    IdentityAuthAdapter,
)


@dataclass
class TailerState:
    file_path: str
    last_offset: int
    last_inode: int
    updated_at_utc: str
    lines_read: int
    error_lines: int


class LiveLogTailer:
    """Robust file follower that persists read offsets across restarts and handles log rotation."""

    def __init__(
        self,
        target_log_path: Path,
        state_file_path: Optional[Path] = None,
        poll_interval_sec: float = 0.5,
    ):
        self.target_log_path = Path(target_log_path)
        self.state_file_path = state_file_path or self.target_log_path.with_suffix(
            ".tailer_state.json"
        )
        self.poll_interval_sec = poll_interval_sec

        self.last_offset = 0
        self.last_inode = 0
        self.lines_read = 0
        self.error_lines = 0

        self.dns_adapter = ApplicationDNSAdapter()
        self.web_adapter = ApplicationWebAdapter()
        self.auth_adapter = IdentityAuthAdapter()

        self._load_state()

    def _load_state(self) -> None:
        if self.state_file_path.exists():
            try:
                data = json.loads(self.state_file_path.read_text(encoding="utf-8"))
                self.last_offset = int(data.get("last_offset", 0))
                self.last_inode = int(data.get("last_inode", 0))
                self.lines_read = int(data.get("lines_read", 0))
                self.error_lines = int(data.get("error_lines", 0))
            except Exception:
                # If state is corrupt, fall back to safe zero
                self.last_offset = 0

    def _save_state(self) -> None:
        state = TailerState(
            file_path=str(self.target_log_path),
            last_offset=self.last_offset,
            last_inode=self.last_inode,
            updated_at_utc=datetime.now(timezone.utc).isoformat(),
            lines_read=self.lines_read,
            error_lines=self.error_lines,
        )
        self.state_file_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_file_path.write_text(json.dumps(asdict(state), indent=2), encoding="utf-8")

    def tail_available_events(self) -> List[CanonicalSecurityEvent]:
        """Read newly appended lines without blocking, convert to events, and persist state."""
        if not self.target_log_path.exists():
            return []

        stat = self.target_log_path.stat()
        current_inode = getattr(stat, "st_ino", 0)
        current_size = stat.st_size

        # Check for Log Rotation: Inode changed OR file size truncated
        if current_inode != self.last_inode or current_size < self.last_offset:
            # File was rotated; start reading from beginning of new file
            self.last_offset = 0
            self.last_inode = current_inode

        events: List[CanonicalSecurityEvent] = []

        with open(self.target_log_path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(self.last_offset)

            for line in f:
                line_str = line.strip()
                if not line_str:
                    continue

                self.lines_read += 1
                ev = self._parse_log_line(line_str)
                if ev:
                    events.append(ev)
                else:
                    self.error_lines += 1

            self.last_offset = f.tell()

        self._save_state()
        return events

    def _parse_log_line(self, line: str) -> Optional[CanonicalSecurityEvent]:
        # Handle Suricata EVE JSON
        if line.startswith("{") and line.endswith("}"):
            try:
                record = json.loads(line)
                ev_type = record.get("event_type")
                if ev_type == "dns":
                    return self.dns_adapter.adapt_record(
                        {
                            "ts": record.get("timestamp"),
                            "id.orig_h": record.get("src_ip"),
                            "id.orig_p": record.get("src_port"),
                            "id.resp_h": record.get("dest_ip"),
                            "id.resp_p": record.get("dest_port"),
                            "query": record.get("dns", {}).get("rrname", "unknown"),
                            "qtype_name": record.get("dns", {}).get("rrtype", "A"),
                            "rcode": record.get("dns", {}).get("rcode", 0),
                        },
                        filename=self.target_log_path.name,
                    )
                elif ev_type == "http":
                    return self.web_adapter.adapt_record(
                        {
                            "timestamp": record.get("timestamp"),
                            "remote_addr": record.get("src_ip"),
                            "server_addr": record.get("dest_ip"),
                            "method": record.get("http", {}).get("http_method", "GET"),
                            "url": record.get("http", {}).get("url", "/"),
                            "status": record.get("http", {}).get("status", 200),
                        },
                        filename=self.target_log_path.name,
                    )
            except Exception:
                return None

        # Fallback to Apache or SSH line parser
        try:
            if "sshd" in line or "Accepted" in line or "Failed" in line:
                return self.auth_adapter.adapt_line(line, filename=self.target_log_path.name)
            elif "[" in line and '"' in line:
                return self.web_adapter.adapt_line(line, filename=self.target_log_path.name)
        except Exception:
            return None

        return None
