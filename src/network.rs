//! Network timing diagnostics. TCP connect RTT is NOT Rocket League match ping.
use serde::Serialize;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

#[derive(Debug, Serialize)]
struct Report<'a> {
    target_host: &'a str,
    target_port: u16,
    protocol: &'static str,
    requested_samples: u8,
    succeeded: usize,
    failed: usize,
    median_tcp_connect_ms: f64,
    p95_tcp_connect_ms: f64,
    mean_abs_consecutive_rtt_change_ms: f64,
    warning: &'static str,
}

fn calculate(values: &[f64]) -> Result<(f64, f64, f64), String> {
    if values.is_empty() {
        return Err("No successful TCP connections; cannot calculate RTT statistics".into());
    }
    let mut sorted = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let n = sorted.len();
    let median = if n % 2 == 0 {
        (sorted[n / 2 - 1] + sorted[n / 2]) / 2.0
    } else {
        sorted[n / 2]
    };
    let p95 = sorted[((n - 1) as f64 * 0.95).ceil() as usize];
    let variation = if n < 2 {
        0.0
    } else {
        values.windows(2).map(|pair| (pair[1] - pair[0]).abs()).sum::<f64>() / (n - 1) as f64
    };
    Ok((median, p95, variation))
}

pub fn probe(host: &str, port: u16, samples: u8, timeout_ms: u64, json: bool) -> Result<(), String> {
    if host.is_empty() || host.chars().any(char::is_whitespace)
        || host.starts_with('-') || host.contains('/') || host.contains('\\')
    {
        return Err("--host must be a hostname or IP address without whitespace or paths".into());
    }
    if port == 0 || !(1..=30).contains(&samples) || !(100..=5000).contains(&timeout_ms) {
        return Err("Use --port 1..65535, --samples 1..30 and --timeout-ms 100..5000".into());
    }

    let addresses: Vec<_> = (host, port).to_socket_addrs()
        .map_err(|e| format!("DNS resolution failed for {host}: {e}"))?.collect();
    if addresses.is_empty() {
        return Err(format!("DNS resolved no addresses for {host}"));
    }

    let timeout = Duration::from_millis(timeout_ms);
    let mut measurements = Vec::with_capacity(samples as usize);
    let mut failed = 0_usize;
    for _ in 0..samples {
        let mut connected = None;
        for address in &addresses {
            let started = Instant::now();
            if let Ok(socket) = TcpStream::connect_timeout(address, timeout) {
                connected = Some(started.elapsed().as_secs_f64() * 1000.0);
                drop(socket);
                break;
            }
        }
        match connected {
            Some(ms) => measurements.push(ms),
            None => failed += 1,
        }
    }
    let (median, p95, variation) = calculate(&measurements)?;
    let report = Report {
        target_host: host,
        target_port: port,
        protocol: "TCP connect (not game UDP)",
        requested_samples: samples,
        succeeded: measurements.len(),
        failed,
        median_tcp_connect_ms: median,
        p95_tcp_connect_ms: p95,
        mean_abs_consecutive_rtt_change_ms: variation,
        warning: "This is a TCP connection diagnostic to your chosen host, NOT Rocket League server ping or proof of lower in-game latency.",
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?);
    } else {
        println!("TCP network probe: {}:{} ({samples} samples)", host, port);
        println!("Connected: {} | Failed: {}", report.succeeded, report.failed);
        println!("Median TCP connect: {:.2} ms", report.median_tcp_connect_ms);
        println!("P95 TCP connect: {:.2} ms", report.p95_tcp_connect_ms);
        println!("Mean consecutive RTT variation: {:.2} ms", report.mean_abs_consecutive_rtt_change_ms);
        println!("Important: {}", report.warning);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn statistics_are_deterministic() {
        let (median, p95, variation) = calculate(&[10.0, 30.0, 20.0, 40.0]).unwrap();
        assert_eq!(median, 25.0);
        assert_eq!(p95, 40.0);
        assert_eq!(variation, (20.0 + 10.0 + 20.0) / 3.0);
        assert_eq!(calculate(&[42.0]).unwrap(), (42.0, 42.0, 0.0));
    }
    #[test]
    fn empty_measurement_set_is_rejected() {
        assert!(calculate(&[]).is_err());
    }
    #[test]
    fn probes_reject_invalid_configuration_without_network() {
        assert!(probe("bad host", 443, 1, 1000, false).is_err());
        assert!(probe("example.com", 0, 1, 1000, false).is_err());
        assert!(probe("example.com", 443, 0, 1000, false).is_err());
        assert!(probe("example.com", 443, 1, 10, false).is_err());
    }
}
