use std::collections::HashSet;
use std::env;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;

use netflow_rs::{build_sample_ipfix_datagram, NetFlowIpfixDecoder, UdpCollector};

fn print_usage() {
    eprintln!(
        "Usage: netflow-rs [--bind <addr:port>] [--allow-exporter <ip>]... [--once] [--self-test]"
    );
}

fn main() -> ExitCode {
    let mut bind_addr_str = String::from("127.0.0.1:2055");
    let mut allowed_exporters: HashSet<IpAddr> = HashSet::new();
    let mut once = false;
    let mut self_test = false;

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--bind" => {
                let Some(val) = args.next() else {
                    eprintln!("ERROR: --bind requires a <host:port> argument");
                    print_usage();
                    return ExitCode::from(2);
                };
                bind_addr_str = val;
            }
            "--allow-exporter" => {
                let Some(val) = args.next() else {
                    eprintln!("ERROR: --allow-exporter requires an <ip> argument");
                    print_usage();
                    return ExitCode::from(2);
                };
                match val.parse::<IpAddr>() {
                    Ok(ip) => {
                        allowed_exporters.insert(ip);
                    }
                    Err(err) => {
                        eprintln!("ERROR: invalid exporter IP '{val}': {err}");
                        return ExitCode::from(2);
                    }
                }
            }
            "--once" => {
                once = true;
            }
            "--self-test" => {
                self_test = true;
            }
            "--help" | "-h" => {
                print_usage();
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("ERROR: unrecognized argument '{other}'");
                print_usage();
                return ExitCode::from(2);
            }
        }
    }

    if self_test {
        let mut decoder = NetFlowIpfixDecoder::new();
        let exporter: IpAddr = match "127.0.0.1".parse() {
            Ok(ip) => ip,
            Err(_) => return ExitCode::from(1),
        };
        let pkt = build_sample_ipfix_datagram();
        let events = decoder.decode_datagram(exporter, &pkt);
        for ev in &events {
            println!("{}", ev.to_json());
        }
        eprintln!(
            "self-test complete: datagrams_received={} templates_cached={} records_decoded={} missing_template_drops={} decode_errors={}",
            decoder.metrics.datagrams_received,
            decoder.metrics.templates_cached,
            decoder.metrics.records_decoded,
            decoder.metrics.missing_template_drops,
            decoder.metrics.decode_errors,
        );
        return if events.len() == 1 && decoder.metrics.decode_errors == 0 {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }

    let bind_addr: SocketAddr = match bind_addr_str.parse() {
        Ok(addr) => addr,
        Err(err) => {
            eprintln!("ERROR: invalid bind address '{bind_addr_str}': {err}");
            return ExitCode::from(2);
        }
    };

    let allow_opt = if allowed_exporters.is_empty() {
        None
    } else {
        Some(allowed_exporters)
    };

    let mut collector = match UdpCollector::bind(bind_addr, allow_opt) {
        Ok(c) => c,
        Err(err) => {
            eprintln!("ERROR: failed to bind UDP collector on {bind_addr}: {err}");
            return ExitCode::from(1);
        }
    };

    eprintln!(
        "NetFlow v9 / IPFIX collector listening on {}",
        collector.local_addr()
    );

    let mut buf = [0u8; 65_535];
    loop {
        match collector.recv_next(&mut buf) {
            Ok(events) => {
                for ev in &events {
                    println!("{}", ev.to_json());
                }
                if once {
                    let m = collector.metrics();
                    eprintln!(
                        "collector summary: datagrams_received={} templates_cached={} records_decoded={} missing_template_drops={} decode_errors={} rejected_exporters={}",
                        m.datagrams_received,
                        m.templates_cached,
                        m.records_decoded,
                        m.missing_template_drops,
                        m.decode_errors,
                        m.rejected_exporters,
                    );
                    break;
                }
            }
            Err(err) => {
                eprintln!("ERROR: UDP receive error: {err}");
                return ExitCode::from(1);
            }
        }
    }

    ExitCode::SUCCESS
}
