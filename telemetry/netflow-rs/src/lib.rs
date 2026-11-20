//! NetFlow v9 (RFC 3954) and IPFIX (RFC 7011) binary wire decoder and UDP collector.
//!
//! Provides template caching keyed by `(exporter_ip, observation_domain_id, template_id)`,
//! fail-closed handling of missing templates and malformed datagrams, exporter IP allowlist
//! enforcement, and zero-dependency serialization to the `CanonicalSecurityEvent` v2 JSON contract.

use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// Maximum number of templates retained in the decoder cache before oldest-entry eviction.
pub const MAX_TEMPLATES: usize = 1024;

/// NetFlow v9 version number.
pub const VERSION_NETFLOW_V9: u16 = 9;
/// IPFIX (RFC 7011) version number.
pub const VERSION_IPFIX: u16 = 10;

/// NetFlow v9 Template FlowSet ID.
pub const NETFLOW_V9_TEMPLATE_FLOWSET_ID: u16 = 0;
/// IPFIX Template Set ID.
pub const IPFIX_TEMPLATE_SET_ID: u16 = 2;
/// Minimum Data FlowSet / Set ID for both NetFlow v9 and IPFIX.
pub const MIN_DATA_SET_ID: u16 = 256;

// Standard IANA Information Element / Field Type IDs.
pub const FIELD_IN_BYTES: u16 = 1;
pub const FIELD_IN_PKTS: u16 = 2;
pub const FIELD_PROTOCOL: u16 = 4;
pub const FIELD_TCP_FLAGS: u16 = 6;
pub const FIELD_L4_SRC_PORT: u16 = 7;
pub const FIELD_IPV4_SRC_ADDR: u16 = 8;
pub const FIELD_L4_DST_PORT: u16 = 11;
pub const FIELD_IPV4_DST_ADDR: u16 = 12;
pub const FIELD_LAST_SWITCHED: u16 = 21;
pub const FIELD_FIRST_SWITCHED: u16 = 22;
pub const FIELD_OUT_BYTES: u16 = 23;
pub const FIELD_OUT_PKTS: u16 = 24;
pub const FIELD_IPV6_SRC_ADDR: u16 = 27;
pub const FIELD_IPV6_DST_ADDR: u16 = 28;
pub const FIELD_FLOW_DURATION_MILLISECONDS: u16 = 161;

/// Composite key isolating templates per exporter, observation domain / source ID, and template ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TemplateKey {
    pub exporter_ip: IpAddr,
    pub domain_id: u32,
    pub template_id: u16,
}

/// Single field specifier inside a Template Record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TemplateField {
    pub field_type: u16,
    pub field_length: u16,
    pub enterprise_number: Option<u32>,
}

/// Cached Template Record defining the binary layout of corresponding Data Records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TemplateRecord {
    pub template_id: u16,
    pub fields: Vec<TemplateField>,
    pub record_byte_len: usize,
}

/// Runtime telemetry counters for the collector and wire decoder.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CollectorMetrics {
    pub datagrams_received: u64,
    pub records_decoded: u64,
    pub templates_cached: u64,
    pub missing_template_drops: u64,
    pub decode_errors: u64,
    pub rejected_exporters: u64,
}

/// Flow-level traffic counters and timing extracted from a NetFlow v9 / IPFIX Data Record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlowMetricsV2 {
    pub duration_ms: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub pkts_in: u64,
    pub pkts_out: u64,
    pub tcp_flags: u8,
}

/// Provenance metadata linking a canonical event back to its wire packet and template context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawProvenanceV2 {
    pub source_file: String,
    pub adapter_name: &'static str,
    pub protocol_version: u16,
    pub exporter_ip: String,
    pub observation_domain_id: u32,
    pub template_id: u16,
    pub sequence_number: u32,
}

/// Decoded flow event conforming to the `CanonicalSecurityEvent` v2 contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalFlowEventV2 {
    pub schema_version: &'static str,
    pub event_kind: &'static str,
    pub source_id: &'static str,
    pub event_timestamp: String,
    pub entity_id: String,
    pub source_ip: String,
    pub dest_ip: String,
    pub source_port: u16,
    pub dest_port: u16,
    pub protocol: u8,
    pub flow_metrics: FlowMetricsV2,
    pub raw_provenance: RawProvenanceV2,
}

impl CanonicalFlowEventV2 {
    /// Serializes this event into a compact JSON string matching the `CanonicalSecurityEvent` v2 schema.
    pub fn to_json(&self) -> String {
        let mut out = String::with_capacity(512);
        out.push('{');
        write_json_str_field(&mut out, "schema_version", self.schema_version, true);
        write_json_str_field(&mut out, "event_kind", self.event_kind, false);
        write_json_str_field(&mut out, "source_id", self.source_id, false);
        write_json_str_field(&mut out, "event_timestamp", &self.event_timestamp, false);
        write_json_str_field(&mut out, "entity_id", &self.entity_id, false);
        write_json_str_field(&mut out, "source_ip", &self.source_ip, false);
        write_json_str_field(&mut out, "dest_ip", &self.dest_ip, false);
        let _ = write!(
            out,
            ",\"source_port\":{},\"dest_port\":{},\"protocol\":\"{}\"",
            self.source_port,
            self.dest_port,
            protocol_name(self.protocol)
        );
        let _ = write!(
            out,
            ",\"flow_metrics\":{{\"duration_ms\":{},\"bytes_in\":{},\"bytes_out\":{},\"pkts_in\":{},\"pkts_out\":{},\"tcp_flags\":{}}}",
            self.flow_metrics.duration_ms,
            self.flow_metrics.bytes_in,
            self.flow_metrics.bytes_out,
            self.flow_metrics.pkts_in,
            self.flow_metrics.pkts_out,
            self.flow_metrics.tcp_flags
        );
        out.push_str(",\"raw_provenance\":{");
        write_json_str_field(
            &mut out,
            "source_file",
            &self.raw_provenance.source_file,
            true,
        );
        write_json_str_field(
            &mut out,
            "adapter_name",
            self.raw_provenance.adapter_name,
            false,
        );
        let _ = write!(
            out,
            ",\"protocol_version\":{}",
            self.raw_provenance.protocol_version
        );
        write_json_str_field(
            &mut out,
            "exporter_ip",
            &self.raw_provenance.exporter_ip,
            false,
        );
        let _ = write!(
            out,
            ",\"observation_domain_id\":{},\"template_id\":{},\"sequence_number\":{}}}",
            self.raw_provenance.observation_domain_id,
            self.raw_provenance.template_id,
            self.raw_provenance.sequence_number
        );
        out.push('}');
        out
    }
}

fn protocol_name(proto: u8) -> String {
    match proto {
        1 => String::from("ICMP"),
        6 => String::from("TCP"),
        17 => String::from("UDP"),
        58 => String::from("ICMPv6"),
        other => other.to_string(),
    }
}

fn escape_json_str(input: &str) -> String {
    let mut escaped = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(escaped, "\\u{:04x}", c as u32);
            }
            c => escaped.push(c),
        }
    }
    escaped
}

fn write_json_str_field(buf: &mut String, key: &str, value: &str, first: bool) {
    if !first {
        buf.push(',');
    }
    let _ = write!(buf, "\"{}\":\"{}\"", key, escape_json_str(value));
}

/// Converts a Unix epoch timestamp (seconds) into an ISO-8601 UTC string (`YYYY-MM-DDTHH:MM:SSZ`)
/// using Howard Hinnant's civil-from-days algorithm without external crate dependencies.
pub fn format_unix_timestamp_iso8601(unix_secs: u32) -> String {
    let secs = u64::from(unix_secs);
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let hour = rem / 3_600;
    let minute = (rem % 3_600) / 60;
    let second = rem % 60;

    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = (yoe as i64) + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };

    format!("{year:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Stateful NetFlow v9 and IPFIX binary wire decoder with per-exporter template cache.
#[derive(Debug, Default)]
pub struct NetFlowIpfixDecoder {
    templates: HashMap<TemplateKey, TemplateRecord>,
    template_order: VecDeque<TemplateKey>,
    pub metrics: CollectorMetrics,
}

impl NetFlowIpfixDecoder {
    /// Creates a new decoder with an empty template cache and zeroed metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of currently cached templates.
    pub fn cached_template_count(&self) -> usize {
        self.templates.len()
    }

    /// Looks up a cached template by exporter IP, observation domain ID, and template ID.
    pub fn get_template(
        &self,
        exporter_ip: IpAddr,
        domain_id: u32,
        template_id: u16,
    ) -> Option<&TemplateRecord> {
        self.templates.get(&TemplateKey {
            exporter_ip,
            domain_id,
            template_id,
        })
    }

    /// Decodes a single UDP datagram from `exporter_ip`, updating template state and returning
    /// any decoded `CanonicalFlowEventV2` records. Never panics on malformed or truncated input.
    pub fn decode_datagram(
        &mut self,
        exporter_ip: IpAddr,
        datagram: &[u8],
    ) -> Vec<CanonicalFlowEventV2> {
        self.metrics.datagrams_received += 1;
        if datagram.len() < 4 {
            self.metrics.decode_errors += 1;
            return Vec::new();
        }

        let version = read_u16_be(datagram, 0);
        match version {
            VERSION_NETFLOW_V9 => self.decode_netflow_v9(exporter_ip, datagram),
            VERSION_IPFIX => self.decode_ipfix(exporter_ip, datagram),
            _ => {
                self.metrics.decode_errors += 1;
                Vec::new()
            }
        }
    }

    fn decode_netflow_v9(
        &mut self,
        exporter_ip: IpAddr,
        datagram: &[u8],
    ) -> Vec<CanonicalFlowEventV2> {
        // NetFlow v9 header is 20 bytes:
        // [0..2] version (9), [2..4] count, [4..8] sys_uptime, [8..12] unix_secs,
        // [12..16] package_sequence, [16..20] source_id
        if datagram.len() < 20 {
            self.metrics.decode_errors += 1;
            return Vec::new();
        }
        let count = read_u16_be(datagram, 2);
        if count == 0 {
            self.metrics.decode_errors += 1;
            return Vec::new();
        }
        let unix_secs = read_u32_be(datagram, 8);
        let sequence = read_u32_be(datagram, 12);
        let source_id = read_u32_be(datagram, 16);

        self.decode_sets(
            VERSION_NETFLOW_V9,
            exporter_ip,
            source_id,
            unix_secs,
            sequence,
            &datagram[20..],
        )
    }

    fn decode_ipfix(&mut self, exporter_ip: IpAddr, datagram: &[u8]) -> Vec<CanonicalFlowEventV2> {
        // IPFIX header is 16 bytes:
        // [0..2] version (10), [2..4] length, [4..8] export_time,
        // [8..12] sequence_number, [12..16] observation_domain_id
        if datagram.len() < 16 {
            self.metrics.decode_errors += 1;
            return Vec::new();
        }
        let total_len = usize::from(read_u16_be(datagram, 2));
        if total_len < 16 || total_len > datagram.len() {
            self.metrics.decode_errors += 1;
            return Vec::new();
        }
        let export_time = read_u32_be(datagram, 4);
        let sequence = read_u32_be(datagram, 8);
        let domain_id = read_u32_be(datagram, 12);

        self.decode_sets(
            VERSION_IPFIX,
            exporter_ip,
            domain_id,
            export_time,
            sequence,
            &datagram[16..total_len],
        )
    }

    fn decode_sets(
        &mut self,
        version: u16,
        exporter_ip: IpAddr,
        domain_id: u32,
        export_unix_secs: u32,
        sequence: u32,
        payload: &[u8],
    ) -> Vec<CanonicalFlowEventV2> {
        let mut events = Vec::new();
        let mut offset = 0usize;

        while offset < payload.len() {
            if payload.len() - offset < 4 {
                self.metrics.decode_errors += 1;
                break;
            }
            let set_id = read_u16_be(payload, offset);
            let set_len = usize::from(read_u16_be(payload, offset + 2));
            if set_len < 4 || offset + set_len > payload.len() {
                self.metrics.decode_errors += 1;
                break;
            }
            let set_body = &payload[offset + 4..offset + set_len];

            let is_template_set = (version == VERSION_NETFLOW_V9
                && set_id == NETFLOW_V9_TEMPLATE_FLOWSET_ID)
                || (version == VERSION_IPFIX && set_id == IPFIX_TEMPLATE_SET_ID);

            if is_template_set {
                self.decode_template_set(version, exporter_ip, domain_id, set_body);
            } else if set_id >= MIN_DATA_SET_ID {
                self.decode_data_set(
                    version,
                    exporter_ip,
                    domain_id,
                    set_id,
                    export_unix_secs,
                    sequence,
                    set_body,
                    &mut events,
                );
            }
            // Option template sets (FlowSet ID 1 in v9, Set ID 3 in IPFIX) are safely skipped.
            offset += set_len;
        }

        events
    }

    fn decode_template_set(
        &mut self,
        version: u16,
        exporter_ip: IpAddr,
        domain_id: u32,
        body: &[u8],
    ) {
        let mut pos = 0usize;
        while pos < body.len() {
            // Remaining padding (up to 3 zero bytes at the end of a template set)
            if body.len() - pos < 4 {
                if body[pos..].iter().all(|&b| b == 0) {
                    break;
                }
                self.metrics.decode_errors += 1;
                return;
            }
            let template_id = read_u16_be(body, pos);
            let field_count = usize::from(read_u16_be(body, pos + 2));
            // 0 padding at end of 4-byte aligned Template Set
            if template_id == 0 && field_count == 0 {
                break;
            }
            if template_id < MIN_DATA_SET_ID || field_count == 0 {
                self.metrics.decode_errors += 1;
                return;
            }
            pos += 4;

            let needed = field_count.saturating_mul(4);
            if pos.saturating_add(needed) > body.len() {
                self.metrics.decode_errors += 1;
                return;
            }

            let mut fields = Vec::with_capacity(field_count);
            let mut record_byte_len = 0usize;

            for _ in 0..field_count {
                if body.len() - pos < 4 {
                    self.metrics.decode_errors += 1;
                    return;
                }
                let raw_type = read_u16_be(body, pos);
                let field_length = read_u16_be(body, pos + 2);
                pos += 4;

                if field_length == 0 || field_length == 0xFFFF {
                    // Variable-length or zero-length fields are rejected cleanly in fixed-record decoding.
                    self.metrics.decode_errors += 1;
                    return;
                }

                let (field_type, enterprise_number) =
                    if version == VERSION_IPFIX && (raw_type & 0x8000) != 0 {
                        if body.len() - pos < 4 {
                            self.metrics.decode_errors += 1;
                            return;
                        }
                        let ent = read_u32_be(body, pos);
                        pos += 4;
                        (raw_type & 0x7FFF, Some(ent))
                    } else {
                        (raw_type, None)
                    };

                record_byte_len = record_byte_len.saturating_add(usize::from(field_length));
                fields.push(TemplateField {
                    field_type,
                    field_length,
                    enterprise_number,
                });
            }

            if record_byte_len == 0 {
                self.metrics.decode_errors += 1;
                return;
            }

            let key = TemplateKey {
                exporter_ip,
                domain_id,
                template_id,
            };
            let record = TemplateRecord {
                template_id,
                fields,
                record_byte_len,
            };
            if self.templates.contains_key(&key) {
                self.templates.insert(key, record);
            } else {
                while self.templates.len() >= MAX_TEMPLATES {
                    if let Some(oldest_key) = self.template_order.pop_front() {
                        self.templates.remove(&oldest_key);
                    } else {
                        break;
                    }
                }
                self.templates.insert(key, record);
                self.template_order.push_back(key);
            }
            self.metrics.templates_cached += 1;
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn decode_data_set(
        &mut self,
        version: u16,
        exporter_ip: IpAddr,
        domain_id: u32,
        template_id: u16,
        export_unix_secs: u32,
        sequence: u32,
        body: &[u8],
        out: &mut Vec<CanonicalFlowEventV2>,
    ) {
        let key = TemplateKey {
            exporter_ip,
            domain_id,
            template_id,
        };
        let Some(template) = self.templates.get(&key) else {
            self.metrics.missing_template_drops += 1;
            return;
        };

        let rec_len = template.record_byte_len;
        if rec_len == 0 || body.len() < rec_len {
            self.metrics.decode_errors += 1;
            return;
        }

        let timestamp_iso = format_unix_timestamp_iso8601(export_unix_secs);
        let exporter_str = exporter_ip.to_string();

        let mut offset = 0usize;
        while offset + rec_len <= body.len() {
            let remaining = body.len() - offset;
            if remaining < 4 && body[offset..].iter().all(|&b| b == 0) {
                break;
            }
            let record_slice = &body[offset..offset + rec_len];
            let event = decode_single_record(
                template,
                record_slice,
                version,
                &exporter_str,
                domain_id,
                sequence,
                &timestamp_iso,
            );
            out.push(event);
            self.metrics.records_decoded += 1;
            offset += rec_len;
        }
    }
}

fn decode_single_record(
    template: &TemplateRecord,
    record: &[u8],
    version: u16,
    exporter_str: &str,
    domain_id: u32,
    sequence: u32,
    timestamp_iso: &str,
) -> CanonicalFlowEventV2 {
    let mut src_ip = String::from("0.0.0.0");
    let mut dst_ip = String::from("0.0.0.0");
    let mut src_port: u16 = 0;
    let mut dst_port: u16 = 0;
    let mut protocol: u8 = 0;
    let mut bytes_in: u64 = 0;
    let mut bytes_out: u64 = 0;
    let mut pkts_in: u64 = 0;
    let mut pkts_out: u64 = 0;
    let mut tcp_flags: u8 = 0;
    let mut first_switched: Option<u64> = None;
    let mut last_switched: Option<u64> = None;
    let mut explicit_duration_ms: Option<u64> = None;

    let mut cursor = 0usize;
    for field in &template.fields {
        let len = usize::from(field.field_length);
        let slice = &record[cursor..cursor + len];
        cursor += len;

        if field.enterprise_number.is_some() {
            continue;
        }

        match field.field_type {
            FIELD_IPV4_SRC_ADDR if len == 4 => {
                let ip = Ipv4Addr::new(slice[0], slice[1], slice[2], slice[3]);
                src_ip = ip.to_string();
            }
            FIELD_IPV4_DST_ADDR if len == 4 => {
                let ip = Ipv4Addr::new(slice[0], slice[1], slice[2], slice[3]);
                dst_ip = ip.to_string();
            }
            FIELD_IPV6_SRC_ADDR if len == 16 => {
                if let Ok(octets) = <[u8; 16]>::try_from(slice) {
                    src_ip = Ipv6Addr::from(octets).to_string();
                }
            }
            FIELD_IPV6_DST_ADDR if len == 16 => {
                if let Ok(octets) = <[u8; 16]>::try_from(slice) {
                    dst_ip = Ipv6Addr::from(octets).to_string();
                }
            }
            FIELD_L4_SRC_PORT => {
                if let Some(v) = read_uint_be(slice) {
                    src_port = u16::try_from(v).unwrap_or(u16::MAX);
                }
            }
            FIELD_L4_DST_PORT => {
                if let Some(v) = read_uint_be(slice) {
                    dst_port = u16::try_from(v).unwrap_or(u16::MAX);
                }
            }
            FIELD_PROTOCOL => {
                if let Some(v) = read_uint_be(slice) {
                    protocol = u8::try_from(v).unwrap_or(u8::MAX);
                }
            }
            FIELD_IN_BYTES => {
                if let Some(v) = read_uint_be(slice) {
                    bytes_in = v;
                }
            }
            FIELD_OUT_BYTES => {
                if let Some(v) = read_uint_be(slice) {
                    bytes_out = v;
                }
            }
            FIELD_IN_PKTS => {
                if let Some(v) = read_uint_be(slice) {
                    pkts_in = v;
                }
            }
            FIELD_OUT_PKTS => {
                if let Some(v) = read_uint_be(slice) {
                    pkts_out = v;
                }
            }
            FIELD_TCP_FLAGS => {
                if let Some(v) = read_uint_be(slice) {
                    tcp_flags = u8::try_from(v).unwrap_or(u8::MAX);
                }
            }
            FIELD_FIRST_SWITCHED => {
                first_switched = read_uint_be(slice);
            }
            FIELD_LAST_SWITCHED => {
                last_switched = read_uint_be(slice);
            }
            FIELD_FLOW_DURATION_MILLISECONDS => {
                explicit_duration_ms = read_uint_be(slice);
            }
            _ => {}
        }
    }

    let duration_ms = if let Some(dur) = explicit_duration_ms {
        dur
    } else if let (Some(first), Some(last)) = (first_switched, last_switched) {
        last.saturating_sub(first)
    } else {
        0
    };

    let entity_id = format!("host:{src_ip}");

    CanonicalFlowEventV2 {
        schema_version: "2.0.0",
        event_kind: "flow",
        source_id: "source:netflow-v9-ipfix",
        event_timestamp: timestamp_iso.to_string(),
        entity_id,
        source_ip: src_ip,
        dest_ip: dst_ip,
        source_port: src_port,
        dest_port: dst_port,
        protocol,
        flow_metrics: FlowMetricsV2 {
            duration_ms,
            bytes_in,
            bytes_out,
            pkts_in,
            pkts_out,
            tcp_flags,
        },
        raw_provenance: RawProvenanceV2 {
            source_file: format!("udp://{exporter_str}"),
            adapter_name: "RustNetFlowIPFIXCollector",
            protocol_version: version,
            exporter_ip: exporter_str.to_string(),
            observation_domain_id: domain_id,
            template_id: template.template_id,
            sequence_number: sequence,
        },
    }
}

fn read_u16_be(buf: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([buf[offset], buf[offset + 1]])
}

fn read_u32_be(buf: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

fn read_uint_be(slice: &[u8]) -> Option<u64> {
    if slice.is_empty() || slice.len() > 8 {
        return None;
    }
    let mut val = 0u64;
    for &byte in slice {
        val = (val << 8) | u64::from(byte);
    }
    Some(val)
}

/// UDP socket collector wrapping [`NetFlowIpfixDecoder`] with loopback-default security and
/// optional exporter IP allowlist filtering.
pub struct UdpCollector {
    socket: UdpSocket,
    local_addr: SocketAddr,
    allowed_exporters: Option<HashSet<IpAddr>>,
    pub decoder: NetFlowIpfixDecoder,
    pub non_loopback_warning_logged: bool,
}

impl UdpCollector {
    /// Binds a UDP collector to `bind_addr` (e.g. `127.0.0.1:2055`).
    /// Logs a warning to stderr if `bind_addr` is not a loopback address.
    pub fn bind(
        bind_addr: SocketAddr,
        allowed_exporters: Option<HashSet<IpAddr>>,
    ) -> io::Result<Self> {
        let mut non_loopback_warning_logged = false;
        if !bind_addr.ip().is_loopback() {
            eprintln!(
                "WARNING: NetFlow/IPFIX UDP collector binding to non-loopback address {bind_addr}; ensure exporter allowlist and firewall controls are active."
            );
            non_loopback_warning_logged = true;
        }
        let socket = UdpSocket::bind(bind_addr)?;
        let local_addr = socket.local_addr()?;
        Ok(Self {
            socket,
            local_addr,
            allowed_exporters,
            decoder: NetFlowIpfixDecoder::new(),
            non_loopback_warning_logged,
        })
    }

    /// Returns the local socket address the collector is bound to.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Sets the read timeout on the underlying UDP socket.
    pub fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.socket.set_read_timeout(dur)
    }

    /// Returns an immutable reference to the collector telemetry metrics.
    pub fn metrics(&self) -> &CollectorMetrics {
        &self.decoder.metrics
    }

    /// Receives and decodes a single UDP datagram.
    /// Drops datagrams from untrusted exporters when `allowed_exporters` is configured.
    pub fn recv_next(&mut self, buf: &mut [u8]) -> io::Result<Vec<CanonicalFlowEventV2>> {
        let (len, peer_addr) = self.socket.recv_from(buf)?;
        let exporter_ip = peer_addr.ip();

        if let Some(allowlist) = &self.allowed_exporters {
            if !allowlist.contains(&exporter_ip) {
                self.decoder.metrics.datagrams_received += 1;
                self.decoder.metrics.rejected_exporters += 1;
                return Ok(Vec::new());
            }
        }

        Ok(self.decoder.decode_datagram(exporter_ip, &buf[..len]))
    }
}

/// Builds a synthetic binary IPFIX datagram containing a Template Set (ID 256) and a single Data Set
/// for self-testing and CLI verification.
pub fn build_sample_ipfix_datagram() -> Vec<u8> {
    // Template 256 with 11 fields:
    // SRC_IP (4), DST_IP (4), SRC_PORT (2), DST_PORT (2), PROTO (1),
    // IN_BYTES (4), OUT_BYTES (4), IN_PKTS (4), OUT_PKTS (4), DURATION_MS (4), TCP_FLAGS (1)
    // Total record length = 34 bytes.
    let template_fields: &[(u16, u16)] = &[
        (FIELD_IPV4_SRC_ADDR, 4),
        (FIELD_IPV4_DST_ADDR, 4),
        (FIELD_L4_SRC_PORT, 2),
        (FIELD_L4_DST_PORT, 2),
        (FIELD_PROTOCOL, 1),
        (FIELD_IN_BYTES, 4),
        (FIELD_OUT_BYTES, 4),
        (FIELD_IN_PKTS, 4),
        (FIELD_OUT_PKTS, 4),
        (FIELD_FLOW_DURATION_MILLISECONDS, 4),
        (FIELD_TCP_FLAGS, 1),
    ];

    // Template Set header (4) + template record header (4) + 11 * 4 (44) = 52 bytes
    let mut template_set = Vec::with_capacity(52);
    template_set.extend_from_slice(&IPFIX_TEMPLATE_SET_ID.to_be_bytes());
    template_set.extend_from_slice(&(52u16).to_be_bytes());
    template_set.extend_from_slice(&256u16.to_be_bytes());
    template_set.extend_from_slice(&(template_fields.len() as u16).to_be_bytes());
    for &(ft, fl) in template_fields {
        template_set.extend_from_slice(&ft.to_be_bytes());
        template_set.extend_from_slice(&fl.to_be_bytes());
    }

    // Data Set header (4) + 34-byte record = 38 bytes
    let mut data_set = Vec::with_capacity(38);
    data_set.extend_from_slice(&256u16.to_be_bytes());
    data_set.extend_from_slice(&38u16.to_be_bytes());
    data_set.extend_from_slice(&[10, 0, 1, 15]); // src_ip 10.0.1.15
    data_set.extend_from_slice(&[192, 168, 1, 20]); // dst_ip 192.168.1.20
    data_set.extend_from_slice(&51514u16.to_be_bytes()); // src_port
    data_set.extend_from_slice(&443u16.to_be_bytes()); // dst_port
    data_set.push(6); // protocol TCP
    data_set.extend_from_slice(&12_800u32.to_be_bytes()); // bytes_in
    data_set.extend_from_slice(&64_200u32.to_be_bytes()); // bytes_out
    data_set.extend_from_slice(&18u32.to_be_bytes()); // pkts_in
    data_set.extend_from_slice(&42u32.to_be_bytes()); // pkts_out
    data_set.extend_from_slice(&1_250u32.to_be_bytes()); // duration_ms
    data_set.push(0x18); // TCP PSH+ACK

    // IPFIX Message Header (16 bytes) + 52 + 38 = 106 bytes
    let total_len: u16 = (16 + template_set.len() + data_set.len()) as u16;
    let mut pkt = Vec::with_capacity(usize::from(total_len));
    pkt.extend_from_slice(&VERSION_IPFIX.to_be_bytes());
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&1_776_590_400u32.to_be_bytes()); // 2026-04-19T09:20:00Z
    pkt.extend_from_slice(&7u32.to_be_bytes()); // sequence 7
    pkt.extend_from_slice(&100u32.to_be_bytes()); // domain_id 100
    pkt.extend_from_slice(&template_set);
    pkt.extend_from_slice(&data_set);
    pkt
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_netflow_v9_fixture() -> Vec<u8> {
        // Template 258 with 9 fields:
        // IPV4_SRC_ADDR(4), IPV4_DST_ADDR(4), L4_SRC_PORT(2), L4_DST_PORT(2), PROTOCOL(1),
        // IN_BYTES(4), IN_PKTS(4), FIRST_SWITCHED(4), LAST_SWITCHED(4), TCP_FLAGS(1) -> 10 fields = 30 bytes
        let fields: &[(u16, u16)] = &[
            (FIELD_IPV4_SRC_ADDR, 4),
            (FIELD_IPV4_DST_ADDR, 4),
            (FIELD_L4_SRC_PORT, 2),
            (FIELD_L4_DST_PORT, 2),
            (FIELD_PROTOCOL, 1),
            (FIELD_IN_BYTES, 4),
            (FIELD_IN_PKTS, 4),
            (FIELD_FIRST_SWITCHED, 4),
            (FIELD_LAST_SWITCHED, 4),
            (FIELD_TCP_FLAGS, 1),
        ];

        // Template FlowSet: header(4) + template_id(2) + count(2) + 10*4(40) = 48 bytes
        let mut tpl_set = Vec::new();
        tpl_set.extend_from_slice(&NETFLOW_V9_TEMPLATE_FLOWSET_ID.to_be_bytes());
        tpl_set.extend_from_slice(&48u16.to_be_bytes());
        tpl_set.extend_from_slice(&258u16.to_be_bytes());
        tpl_set.extend_from_slice(&(fields.len() as u16).to_be_bytes());
        for &(t, l) in fields {
            tpl_set.extend_from_slice(&t.to_be_bytes());
            tpl_set.extend_from_slice(&l.to_be_bytes());
        }

        // Data FlowSet: header(4) + record(30) = 34 bytes
        let mut data_set = Vec::new();
        data_set.extend_from_slice(&258u16.to_be_bytes());
        data_set.extend_from_slice(&34u16.to_be_bytes());
        data_set.extend_from_slice(&[172, 16, 10, 5]); // src_ip
        data_set.extend_from_slice(&[10, 20, 30, 40]); // dst_ip
        data_set.extend_from_slice(&49152u16.to_be_bytes()); // src_port
        data_set.extend_from_slice(&8080u16.to_be_bytes()); // dst_port
        data_set.push(6); // TCP
        data_set.extend_from_slice(&4096u32.to_be_bytes()); // bytes_in
        data_set.extend_from_slice(&12u32.to_be_bytes()); // pkts_in
        data_set.extend_from_slice(&10_000u32.to_be_bytes()); // first_switched
        data_set.extend_from_slice(&10_450u32.to_be_bytes()); // last_switched -> 450 ms
        data_set.push(0x02); // SYN

        // NetFlow v9 Header (20 bytes)
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&VERSION_NETFLOW_V9.to_be_bytes());
        pkt.extend_from_slice(&2u16.to_be_bytes()); // count = 2 FlowSets
        pkt.extend_from_slice(&50_000u32.to_be_bytes()); // sys_uptime
        pkt.extend_from_slice(&1_700_000_000u32.to_be_bytes()); // unix_secs (2023-11-14T22:13:20Z)
        pkt.extend_from_slice(&42u32.to_be_bytes()); // package_sequence
        pkt.extend_from_slice(&7u32.to_be_bytes()); // source_id
        pkt.extend_from_slice(&tpl_set);
        pkt.extend_from_slice(&data_set);
        pkt
    }

    #[test]
    fn test_netflow_v9_template_and_data_binary_fixture() {
        let mut decoder = NetFlowIpfixDecoder::new();
        let exporter: IpAddr = "127.0.0.1".parse().unwrap();
        let pkt = build_netflow_v9_fixture();

        let events = decoder.decode_datagram(exporter, &pkt);
        assert_eq!(events.len(), 1);
        assert_eq!(decoder.metrics.datagrams_received, 1);
        assert_eq!(decoder.metrics.templates_cached, 1);
        assert_eq!(decoder.metrics.records_decoded, 1);
        assert_eq!(decoder.metrics.missing_template_drops, 0);
        assert_eq!(decoder.metrics.decode_errors, 0);

        let ev = &events[0];
        assert_eq!(ev.schema_version, "2.0.0");
        assert_eq!(ev.event_kind, "flow");
        assert_eq!(ev.source_id, "source:netflow-v9-ipfix");
        assert_eq!(ev.event_timestamp, "2023-11-14T22:13:20Z");
        assert_eq!(ev.entity_id, "host:172.16.10.5");
        assert_eq!(ev.source_ip, "172.16.10.5");
        assert_eq!(ev.dest_ip, "10.20.30.40");
        assert_eq!(ev.source_port, 49152);
        assert_eq!(ev.dest_port, 8080);
        assert_eq!(ev.protocol, 6);
        assert_eq!(ev.flow_metrics.duration_ms, 450);
        assert_eq!(ev.flow_metrics.bytes_in, 4096);
        assert_eq!(ev.flow_metrics.pkts_in, 12);
        assert_eq!(ev.flow_metrics.tcp_flags, 0x02);
        assert_eq!(ev.raw_provenance.adapter_name, "RustNetFlowIPFIXCollector");
        assert_eq!(ev.raw_provenance.protocol_version, 9);
        assert_eq!(ev.raw_provenance.observation_domain_id, 7);
        assert_eq!(ev.raw_provenance.template_id, 258);
        assert_eq!(ev.raw_provenance.sequence_number, 42);

        let json = ev.to_json();
        assert!(json.starts_with('{') && json.ends_with('}'));
        assert!(json.contains("\"schema_version\":\"2.0.0\""));
        assert!(json.contains("\"event_kind\":\"flow\""));
        assert!(json.contains("\"source_id\":\"source:netflow-v9-ipfix\""));
        assert!(json.contains("\"entity_id\":\"host:172.16.10.5\""));
        assert!(json.contains("\"protocol\":\"TCP\""));
        assert!(json.contains("\"source_file\":\"udp://127.0.0.1\""));
        assert!(json.contains("\"adapter_name\":\"RustNetFlowIPFIXCollector\""));
    }

    #[test]
    fn test_ipfix_template_and_data_binary_fixture() {
        let mut decoder = NetFlowIpfixDecoder::new();
        let exporter: IpAddr = "10.10.0.1".parse().unwrap();
        let pkt = build_sample_ipfix_datagram();

        let events = decoder.decode_datagram(exporter, &pkt);
        assert_eq!(events.len(), 1);
        assert_eq!(decoder.metrics.templates_cached, 1);
        assert_eq!(decoder.metrics.records_decoded, 1);
        assert_eq!(decoder.metrics.decode_errors, 0);

        let ev = &events[0];
        assert_eq!(ev.schema_version, "2.0.0");
        assert_eq!(ev.source_ip, "10.0.1.15");
        assert_eq!(ev.dest_ip, "192.168.1.20");
        assert_eq!(ev.source_port, 51514);
        assert_eq!(ev.dest_port, 443);
        assert_eq!(ev.protocol, 6);
        assert_eq!(ev.flow_metrics.bytes_in, 12_800);
        assert_eq!(ev.flow_metrics.bytes_out, 64_200);
        assert_eq!(ev.flow_metrics.pkts_in, 18);
        assert_eq!(ev.flow_metrics.pkts_out, 42);
        assert_eq!(ev.flow_metrics.duration_ms, 1_250);
        assert_eq!(ev.flow_metrics.tcp_flags, 0x18);
        assert_eq!(ev.raw_provenance.protocol_version, 10);
        assert_eq!(ev.raw_provenance.observation_domain_id, 100);
        assert_eq!(ev.raw_provenance.template_id, 256);

        let json = ev.to_json();
        assert!(json.contains("\"bytes_in\":12800"));
        assert!(json.contains("\"bytes_out\":64200"));
        assert!(json.contains("\"duration_ms\":1250"));
    }

    #[test]
    fn test_missing_template_drops_without_panic() {
        let mut decoder = NetFlowIpfixDecoder::new();
        let exporter: IpAddr = "127.0.0.1".parse().unwrap();

        // Build an IPFIX packet with ONLY a Data Set for unknown template 300
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&VERSION_IPFIX.to_be_bytes());
        pkt.extend_from_slice(&28u16.to_be_bytes()); // 16 header + 12 data set
        pkt.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes());
        // Data Set referencing unknown template 300
        pkt.extend_from_slice(&300u16.to_be_bytes());
        pkt.extend_from_slice(&12u16.to_be_bytes());
        pkt.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let events = decoder.decode_datagram(exporter, &pkt);
        assert!(events.is_empty());
        assert_eq!(decoder.metrics.missing_template_drops, 1);
        assert_eq!(decoder.metrics.decode_errors, 0);
        assert_eq!(decoder.metrics.records_decoded, 0);
    }

    #[test]
    fn test_template_overwrite_and_exporter_isolation() {
        let mut decoder = NetFlowIpfixDecoder::new();
        let exporter_a: IpAddr = "192.0.2.1".parse().unwrap();
        let exporter_b: IpAddr = "192.0.2.2".parse().unwrap();

        // Exporter A defines template 256 in domain 100 via sample IPFIX datagram (34-byte record)
        let pkt_a = build_sample_ipfix_datagram();
        let events_a = decoder.decode_datagram(exporter_a, &pkt_a);
        assert_eq!(events_a.len(), 1);
        assert_eq!(decoder.cached_template_count(), 1);

        // Exporter B sends a Data Set for template 256 without having registered its own template
        // Must NOT use Exporter A's template!
        let mut data_only = Vec::new();
        data_only.extend_from_slice(&VERSION_IPFIX.to_be_bytes());
        data_only.extend_from_slice(&54u16.to_be_bytes()); // 16 + 38
        data_only.extend_from_slice(&1_776_590_400u32.to_be_bytes());
        data_only.extend_from_slice(&2u32.to_be_bytes());
        data_only.extend_from_slice(&100u32.to_be_bytes());
        data_only.extend_from_slice(&pkt_a[68..]); // The 38-byte Data Set from pkt_a

        let events_b = decoder.decode_datagram(exporter_b, &data_only);
        assert!(events_b.is_empty());
        assert_eq!(decoder.metrics.missing_template_drops, 1);

        // Same exporter A, different observation_domain_id (200 vs 100) is also isolated
        let mut domain_200_data = data_only.clone();
        domain_200_data[12..16].copy_from_slice(&200u32.to_be_bytes());
        let events_a_dom200 = decoder.decode_datagram(exporter_a, &domain_200_data);
        assert!(events_a_dom200.is_empty());
        assert_eq!(decoder.metrics.missing_template_drops, 2);

        // Now Exporter A overwrites template 256 (domain 100) with a smaller 9-byte template:
        // SRC_IP(4), DST_IP(4), PROTOCOL(1)
        let mut overwrite_pkt = Vec::new();
        overwrite_pkt.extend_from_slice(&VERSION_IPFIX.to_be_bytes());
        overwrite_pkt.extend_from_slice(&49u16.to_be_bytes()); // 16 header + 20 tpl + 13 data = 49
        overwrite_pkt.extend_from_slice(&1_776_590_500u32.to_be_bytes());
        overwrite_pkt.extend_from_slice(&8u32.to_be_bytes());
        overwrite_pkt.extend_from_slice(&100u32.to_be_bytes());
        // Template Set (20 bytes = 4 set header + 4 template record header + 3*4 fields)
        overwrite_pkt.extend_from_slice(&IPFIX_TEMPLATE_SET_ID.to_be_bytes());
        overwrite_pkt.extend_from_slice(&20u16.to_be_bytes());
        overwrite_pkt.extend_from_slice(&256u16.to_be_bytes());
        overwrite_pkt.extend_from_slice(&3u16.to_be_bytes());
        overwrite_pkt.extend_from_slice(&FIELD_IPV4_SRC_ADDR.to_be_bytes());
        overwrite_pkt.extend_from_slice(&4u16.to_be_bytes());
        overwrite_pkt.extend_from_slice(&FIELD_IPV4_DST_ADDR.to_be_bytes());
        overwrite_pkt.extend_from_slice(&4u16.to_be_bytes());
        overwrite_pkt.extend_from_slice(&FIELD_PROTOCOL.to_be_bytes());
        overwrite_pkt.extend_from_slice(&1u16.to_be_bytes());
        // Data Set (13 bytes = 4 header + 9 record)
        overwrite_pkt.extend_from_slice(&256u16.to_be_bytes());
        overwrite_pkt.extend_from_slice(&13u16.to_be_bytes());
        overwrite_pkt.extend_from_slice(&[10, 9, 8, 7]);
        overwrite_pkt.extend_from_slice(&[10, 9, 8, 1]);
        overwrite_pkt.push(17); // UDP

        let overwritten_events = decoder.decode_datagram(exporter_a, &overwrite_pkt);
        assert_eq!(overwritten_events.len(), 1);
        assert_eq!(overwritten_events[0].source_ip, "10.9.8.7");
        assert_eq!(overwritten_events[0].dest_ip, "10.9.8.1");
        assert_eq!(overwritten_events[0].protocol, 17);
        assert_eq!(decoder.cached_template_count(), 1);
    }

    #[test]
    fn test_malformed_and_truncated_datagrams_no_panic() {
        let mut decoder = NetFlowIpfixDecoder::new();
        let exporter: IpAddr = "127.0.0.1".parse().unwrap();

        // 1. Empty and 2-byte buffer
        assert!(decoder.decode_datagram(exporter, &[]).is_empty());
        assert!(decoder.decode_datagram(exporter, &[0x00, 0x09]).is_empty());

        // 2. Unsupported version (v5)
        assert!(decoder
            .decode_datagram(exporter, &[0x00, 0x05, 0x00, 0x01, 0, 0, 0, 0])
            .is_empty());

        // 3. Truncated NetFlow v9 header (< 20 bytes)
        assert!(decoder
            .decode_datagram(exporter, &[0x00, 0x09, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .is_empty());

        // 4. IPFIX header claiming total length > actual buffer length
        let mut bad_ipfix = vec![0u8; 16];
        bad_ipfix[0..2].copy_from_slice(&VERSION_IPFIX.to_be_bytes());
        bad_ipfix[2..4].copy_from_slice(&120u16.to_be_bytes());
        assert!(decoder.decode_datagram(exporter, &bad_ipfix).is_empty());

        // 5. IPFIX packet with truncated Set header (set_len = 2, invalid < 4)
        let mut bad_set = vec![0u8; 20];
        bad_set[0..2].copy_from_slice(&VERSION_IPFIX.to_be_bytes());
        bad_set[2..4].copy_from_slice(&20u16.to_be_bytes());
        bad_set[16..18].copy_from_slice(&IPFIX_TEMPLATE_SET_ID.to_be_bytes());
        bad_set[18..20].copy_from_slice(&2u16.to_be_bytes());
        assert!(decoder.decode_datagram(exporter, &bad_set).is_empty());

        assert_eq!(decoder.metrics.decode_errors, 6);
    }

    #[test]
    fn test_udp_loopback_socket_and_exporter_allowlist() {
        let bind_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut allowlist = HashSet::new();
        allowlist.insert("127.0.0.1".parse::<IpAddr>().unwrap());

        let mut collector = UdpCollector::bind(bind_addr, Some(allowlist)).unwrap();
        collector
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert!(!collector.non_loopback_warning_logged);

        let dest = collector.local_addr();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
        let datagram = build_sample_ipfix_datagram();
        sender.send_to(&datagram, dest).unwrap();

        let mut buf = [0u8; 2048];
        let events = collector.recv_next(&mut buf).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source_ip, "10.0.1.15");
        assert_eq!(collector.metrics().records_decoded, 1);
        assert_eq!(collector.metrics().rejected_exporters, 0);

        // Now test untrusted exporter rejection with an allowlist that excludes 127.0.0.1
        let mut strict_allowlist = HashSet::new();
        strict_allowlist.insert("192.0.2.99".parse::<IpAddr>().unwrap());
        let mut strict_collector = UdpCollector::bind(bind_addr, Some(strict_allowlist)).unwrap();
        strict_collector
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        sender
            .send_to(&datagram, strict_collector.local_addr())
            .unwrap();
        let rejected_events = strict_collector.recv_next(&mut buf).unwrap();
        assert!(rejected_events.is_empty());
        assert_eq!(strict_collector.metrics().rejected_exporters, 1);
        assert_eq!(strict_collector.metrics().records_decoded, 0);
    }

    #[test]
    fn test_protocol_string_mapping() {
        assert_eq!(protocol_name(1), "ICMP");
        assert_eq!(protocol_name(6), "TCP");
        assert_eq!(protocol_name(17), "UDP");
        assert_eq!(protocol_name(58), "ICMPv6");
        assert_eq!(protocol_name(47), "47");
    }

    #[test]
    fn test_template_cache_eviction_at_max_cap() {
        let mut decoder = NetFlowIpfixDecoder::new();
        let exporter: IpAddr = "127.0.0.1".parse().unwrap();

        let make_ipfix_template_pkt = |template_id: u16| -> Vec<u8> {
            // IPFIX header (16) + Template Set (16: 4 set hdr + 4 tpl hdr + 2*4 fields) = 32 bytes
            let mut pkt = Vec::with_capacity(32);
            pkt.extend_from_slice(&VERSION_IPFIX.to_be_bytes());
            pkt.extend_from_slice(&32u16.to_be_bytes());
            pkt.extend_from_slice(&1_700_000_000u32.to_be_bytes());
            pkt.extend_from_slice(&1u32.to_be_bytes());
            pkt.extend_from_slice(&10u32.to_be_bytes());
            pkt.extend_from_slice(&IPFIX_TEMPLATE_SET_ID.to_be_bytes());
            pkt.extend_from_slice(&16u16.to_be_bytes());
            pkt.extend_from_slice(&template_id.to_be_bytes());
            pkt.extend_from_slice(&2u16.to_be_bytes());
            pkt.extend_from_slice(&FIELD_IPV4_SRC_ADDR.to_be_bytes());
            pkt.extend_from_slice(&4u16.to_be_bytes());
            pkt.extend_from_slice(&FIELD_IPV4_DST_ADDR.to_be_bytes());
            pkt.extend_from_slice(&4u16.to_be_bytes());
            pkt
        };

        for idx in 0..MAX_TEMPLATES {
            let tid = MIN_DATA_SET_ID + idx as u16;
            let pkt = make_ipfix_template_pkt(tid);
            assert!(decoder.decode_datagram(exporter, &pkt).is_empty());
        }
        assert_eq!(decoder.cached_template_count(), MAX_TEMPLATES);
        assert!(decoder
            .get_template(exporter, 10, MIN_DATA_SET_ID)
            .is_some());

        // Overwriting an existing template at cap must not evict the oldest entry.
        let overwrite_pkt = make_ipfix_template_pkt(MIN_DATA_SET_ID + 1);
        assert!(decoder.decode_datagram(exporter, &overwrite_pkt).is_empty());
        assert_eq!(decoder.cached_template_count(), MAX_TEMPLATES);
        assert!(decoder
            .get_template(exporter, 10, MIN_DATA_SET_ID)
            .is_some());

        // Inserting a brand-new template beyond MAX_TEMPLATES evicts the oldest (MIN_DATA_SET_ID).
        let newest_tid = MIN_DATA_SET_ID + MAX_TEMPLATES as u16;
        let newest_pkt = make_ipfix_template_pkt(newest_tid);
        assert!(decoder.decode_datagram(exporter, &newest_pkt).is_empty());
        assert_eq!(decoder.cached_template_count(), MAX_TEMPLATES);
        assert!(decoder
            .get_template(exporter, 10, MIN_DATA_SET_ID)
            .is_none());
        assert!(decoder
            .get_template(exporter, 10, MIN_DATA_SET_ID + 1)
            .is_some());
        assert!(decoder.get_template(exporter, 10, newest_tid).is_some());
    }

    #[test]
    fn test_crafted_huge_field_count_rejected_without_oom() {
        let mut decoder = NetFlowIpfixDecoder::new();
        let exporter: IpAddr = "127.0.0.1".parse().unwrap();

        // IPFIX packet with template claiming field_count = 65535 in a 28-byte packet
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&VERSION_IPFIX.to_be_bytes());
        pkt.extend_from_slice(&28u16.to_be_bytes());
        pkt.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&IPFIX_TEMPLATE_SET_ID.to_be_bytes());
        pkt.extend_from_slice(&12u16.to_be_bytes());
        pkt.extend_from_slice(&256u16.to_be_bytes());
        pkt.extend_from_slice(&u16::MAX.to_be_bytes()); // field_count = 65535
        pkt.extend_from_slice(&FIELD_PROTOCOL.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());

        let events = decoder.decode_datagram(exporter, &pkt);
        assert!(events.is_empty());
        assert_eq!(decoder.cached_template_count(), 0);
        assert_eq!(decoder.metrics.decode_errors, 1);
    }

    #[test]
    fn test_data_set_four_byte_padding_guard() {
        let mut decoder = NetFlowIpfixDecoder::new();
        let exporter: IpAddr = "127.0.0.1".parse().unwrap();

        // IPFIX Template 256: PROTOCOL(1) + TCP_FLAGS(1) -> record_byte_len = 2
        // Template Set = 4 + 4 + 2*4 = 16 bytes
        // Data Set = 4 + 2 (1 record) + 2 (0x00 padding for 4-byte alignment) = 8 bytes
        // Total = 16 header + 16 tpl + 8 data = 40 bytes
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&VERSION_IPFIX.to_be_bytes());
        pkt.extend_from_slice(&40u16.to_be_bytes());
        pkt.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&5u32.to_be_bytes());
        // Template Set
        pkt.extend_from_slice(&IPFIX_TEMPLATE_SET_ID.to_be_bytes());
        pkt.extend_from_slice(&16u16.to_be_bytes());
        pkt.extend_from_slice(&256u16.to_be_bytes());
        pkt.extend_from_slice(&2u16.to_be_bytes());
        pkt.extend_from_slice(&FIELD_PROTOCOL.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&FIELD_TCP_FLAGS.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        // Data Set
        pkt.extend_from_slice(&256u16.to_be_bytes());
        pkt.extend_from_slice(&8u16.to_be_bytes());
        pkt.push(6); // TCP
        pkt.push(0x18); // PSH+ACK
        pkt.extend_from_slice(&[0x00, 0x00]); // 2-byte RFC 7011 alignment padding

        let events = decoder.decode_datagram(exporter, &pkt);
        assert_eq!(events.len(), 1);
        assert_eq!(decoder.metrics.records_decoded, 1);
        assert_eq!(decoder.metrics.decode_errors, 0);
        assert_eq!(events[0].protocol, 6);
        assert_eq!(events[0].flow_metrics.tcp_flags, 0x18);
    }

    #[test]
    fn test_read_uint_be_bounds_and_clamping() {
        assert_eq!(read_uint_be(&[]), None);
        assert_eq!(read_uint_be(&[1, 2, 3, 4, 5, 6, 7, 8, 9]), None);
        assert_eq!(read_uint_be(&[0x01, 0xBB]), Some(443));
        assert_eq!(read_uint_be(&[0, 0, 0, 0, 0, 0, 0x01, 0x00]), Some(256));

        // Verify oversized u16 port field (4 bytes = 0x0001_0001) clamps to u16::MAX instead of wrapping to 1.
        let mut decoder = NetFlowIpfixDecoder::new();
        let exporter: IpAddr = "127.0.0.1".parse().unwrap();
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&VERSION_IPFIX.to_be_bytes());
        pkt.extend_from_slice(&36u16.to_be_bytes()); // 16 + 12 + 8
        pkt.extend_from_slice(&1_700_000_000u32.to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes());
        pkt.extend_from_slice(&1u32.to_be_bytes());
        // Template Set (12 bytes)
        pkt.extend_from_slice(&IPFIX_TEMPLATE_SET_ID.to_be_bytes());
        pkt.extend_from_slice(&12u16.to_be_bytes());
        pkt.extend_from_slice(&256u16.to_be_bytes());
        pkt.extend_from_slice(&1u16.to_be_bytes());
        pkt.extend_from_slice(&FIELD_L4_SRC_PORT.to_be_bytes());
        pkt.extend_from_slice(&4u16.to_be_bytes());
        // Data Set (8 bytes)
        pkt.extend_from_slice(&256u16.to_be_bytes());
        pkt.extend_from_slice(&8u16.to_be_bytes());
        pkt.extend_from_slice(&0x0001_0001u32.to_be_bytes());

        let events = decoder.decode_datagram(exporter, &pkt);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source_port, u16::MAX);
    }
}
