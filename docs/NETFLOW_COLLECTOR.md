# Rust NetFlow v9 & IPFIX UDP Collector (`telemetry/netflow-rs`)

## 1. Overview & Architecture

`telemetry/netflow-rs` is a pure-Rust (`std`-only, zero external runtime dependencies) NetFlow v9 (RFC 3954) and IPFIX (RFC 7011) binary wire decoder and UDP collector developed for Issue `#128` (Milestone `M6.3`: Live Telemetry Collectors & Producers).

It decodes stateful template-driven flow exports directly from UDP datagrams and emits newline-delimited JSON (NDJSON) records conforming to the `CanonicalSecurityEvent` v2 (`schema_version: "2.0.0"`) contract.

```text
UDP Datagram (NetFlow v9 / IPFIX)
        │
        ▼
┌─────────────────────────────────────────┐
│ UdpCollector (127.0.0.1:2055 default)   │
│  • Non-loopback bind warning            │
│  • Optional exporter IP allowlist       │
└──────────────────┬──────────────────────┘
                   │ trusted exporter datagram
                   ▼
┌─────────────────────────────────────────┐
│ NetFlowIpfixDecoder                     │
│  • NetFlow v9 (20B header, FlowSet 0)   │
│  • IPFIX v10 (16B header, Set ID 2)     │
│  • Template Cache keyed by:             │
│    (exporter_ip, domain_id, template_id)│
│  • Fail-closed missing-template drop    │
└──────────────────┬──────────────────────┘
                   │
                   ▼
┌─────────────────────────────────────────┐
│ CanonicalFlowEventV2::to_json()         │
│  • schema_version: "2.0.0"              │
│  • source_id: "source:netflow-v9-ipfix" │
│  • raw_provenance: exporter/domain/tpl  │
└─────────────────────────────────────────┘
```

## 2. Wire Protocol Support

### NetFlow v9 (Version `9`)
- **Packet Header (20 bytes):** `version` (`u16 = 9`), `count` (`u16`), `sys_uptime` (`u32`), `unix_secs` (`u32`), `package_sequence` (`u32`), `source_id` (`u32`).
- **Template FlowSet:** `flowset_id == 0`. Defines one or more template records (`template_id >= 256`, `field_count`, and `(field_type, field_length)` specifiers).
- **Data FlowSet:** `flowset_id >= 256`. Decoded using the cached template matching `(exporter_ip, source_id, flowset_id)`.

### IPFIX (RFC 7011, Version `10`)
- **Message Header (16 bytes):** `version` (`u16 = 10`), `length` (`u16`), `export_time` (`u32`), `sequence_number` (`u32`), `observation_domain_id` (`u32`).
- **Template Set:** `set_id == 2`. Supports standard IANA Information Elements as well as Enterprise-bit (`0x8000`) 4-byte PEN field specifiers.
- **Data Set:** `set_id >= 256`. Decoded using the cached template matching `(exporter_ip, observation_domain_id, set_id)`.

### Supported Field / Information Element IDs

| ID | Field Name | Canonical Target |
|---:|---|---|
| `1` | `IN_BYTES` (`octetDeltaCount`) | `flow_metrics.bytes_in` |
| `2` | `IN_PKTS` (`packetDeltaCount`) | `flow_metrics.pkts_in` |
| `4` | `PROTOCOL` (`protocolIdentifier`) | `protocol` |
| `6` | `TCP_FLAGS` (`tcpControlBits`) | `flow_metrics.tcp_flags` |
| `7` | `L4_SRC_PORT` (`sourceTransportPort`) | `source_port` |
| `8` | `IPV4_SRC_ADDR` (`sourceIPv4Address`) | `source_ip`, `entity_id` |
| `11` | `L4_DST_PORT` (`destinationTransportPort`) | `dest_port` |
| `12` | `IPV4_DST_ADDR` (`destinationIPv4Address`) | `dest_ip` |
| `21` | `LAST_SWITCHED` (`flowEndSysUpTime`) | `flow_metrics.duration_ms` (`last - first`) |
| `22` | `FIRST_SWITCHED` (`flowStartSysUpTime`) | `flow_metrics.duration_ms` (`last - first`) |
| `23` | `OUT_BYTES` (`postOctetDeltaCount`) | `flow_metrics.bytes_out` |
| `24` | `OUT_PKTS` (`postPacketDeltaCount`) | `flow_metrics.pkts_out` |
| `27` | `IPV6_SRC_ADDR` (`sourceIPv6Address`) | `source_ip`, `entity_id` |
| `28` | `IPV6_DST_ADDR` (`destinationIPv6Address`) | `dest_ip` |
| `161` | `FLOW_DURATION_MILLISECONDS` | `flow_metrics.duration_ms` |

## 3. Template Cache Isolation & Fail-Closed Handling

1. **Per-Exporter & Domain Isolation:** Templates are cached in a `HashMap<TemplateKey, TemplateRecord>` keyed by `(exporter_ip: IpAddr, domain_id: u32, template_id: u16)`. Two exporters or two observation domains reusing template ID `256` never collide.
2. **Template Updates / Overwrites:** When an exporter re-advertises an existing `(exporter_ip, domain_id, template_id)` with an updated field layout, the cache overwrites the entry in place and subsequent Data Sets decode with the new layout.
3. **Fail-Closed Missing Template Counter:** When a Data FlowSet/Set arrives before its corresponding Template Set, `NetFlowIpfixDecoder` drops the Data Set without panicking and increments `metrics.missing_template_drops`.
4. **Malformed / Truncated Datagram Guard:** Truncated headers, invalid set lengths, zero-length records, or unsupported protocol versions increment `metrics.decode_errors` and return an empty event batch without panicking.

## 4. Security Controls (`UdpCollector`)

- **Loopback Default:** The CLI binds `127.0.0.1:2055` by default. Binding to a non-loopback address logs an explicit security warning (`non_loopback_warning_logged = true`).
- **Exporter IP Allowlist:** Passing `--allow-exporter <ip>` (or configuring `allowed_exporters: Option<HashSet<IpAddr>>`) drops UDP datagrams from unlisted source IPs before decoding and increments `metrics.rejected_exporters`.

## 5. `CanonicalSecurityEvent` v2 JSON Output

Each decoded flow record serializes via `CanonicalFlowEventV2::to_json()` into the v2 canonical schema:

```json
{
  "schema_version": "2.0.0",
  "event_kind": "flow",
  "source_id": "source:netflow-v9-ipfix",
  "event_timestamp": "2026-04-19T09:20:00Z",
  "entity_id": "host:10.0.1.15",
  "source_ip": "10.0.1.15",
  "dest_ip": "192.168.1.20",
  "source_port": 51514,
  "dest_port": 443,
  "protocol": "TCP",
  "flow_metrics": {
    "duration_ms": 1250,
    "bytes_in": 12800,
    "bytes_out": 64200,
    "pkts_in": 18,
    "pkts_out": 42,
    "tcp_flags": 24
  },
  "raw_provenance": {
    "source_file": "udp://127.0.0.1",
    "adapter_name": "RustNetFlowIPFIXCollector",
    "protocol_version": 10,
    "exporter_ip": "127.0.0.1",
    "observation_domain_id": 100,
    "template_id": 256,
    "sequence_number": 7
  }
}
```

## 6. Verification & Scope Boundaries

### Commands & Test Evidence

```powershell
cargo fmt --manifest-path telemetry/netflow-rs/Cargo.toml --check
cargo clippy --manifest-path telemetry/netflow-rs/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path telemetry/netflow-rs/Cargo.toml
cargo run --manifest-path telemetry/netflow-rs/Cargo.toml -- --self-test
```

All 6 unit and localhost UDP integration tests pass:
- `test_netflow_v9_template_and_data_binary_fixture`
- `test_ipfix_template_and_data_binary_fixture`
- `test_missing_template_drops_without_panic`
- `test_template_overwrite_and_exporter_isolation`
- `test_malformed_and_truncated_datagrams_no_panic`
- `test_udp_loopback_socket_and_exporter_allowlist`

### Operational Boundary Note
These tests verify binary wire decoding, template caching, fail-closed missing-template handling, exporter allowlist filtering, and `CanonicalSecurityEvent` v2 JSON serialization over deterministic fixtures and localhost UDP sockets (`TESTED`). End-to-end physical hardware router export and external `nfdump` capture benchmarking remain scoped to external lab verification under Issue `#137`.
