use clap::Parser;
use dns_lookup::lookup_host;
use std::io::{self, Write};
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Instant;
use winping::{Buffer, Error as PingError, Pinger};

/// Windows MTR - Network diagnostic tool combining ping and traceroute
#[derive(Parser, Debug)]
#[command(name = "mtr")]
#[command(version = "0.1.0")]
#[command(about = "Windows MTR - traceroute and ping combined", long_about = None)]
struct Args {
    /// Target hostname or IP address
    target: String,

    /// Number of pings per hop (0 = unlimited)
    #[arg(short = 'c', long, default_value = "0")]
    count: u32,

    /// Interval between cycles in milliseconds
    #[arg(short = 'i', long, default_value = "500")]
    interval: u64,

    /// Maximum number of hops (TTL)
    #[arg(short = 'm', long = "max-ttl", default_value = "30")]
    max_ttl: u8,

    /// Do not resolve hostnames
    #[arg(short = 'n', long = "no-dns")]
    no_dns: bool,

    /// Report mode: print final report and exit
    #[arg(short = 'r', long)]
    report: bool,

    /// Report mode cycle count
    #[arg(short = 'C', long = "report-cycles", default_value = "10")]
    report_cycles: u32,

    /// Ping timeout in milliseconds
    #[arg(short = 't', long, default_value = "500")]
    timeout: u32,
}

/// Statistics for a single hop
#[derive(Clone)]
struct HopStats {
    ttl: u8,
    ip: Option<IpAddr>,
    hostname: Option<String>,
    sent: u32,
    received: u32,
    last_rtt: Option<u32>,
    min_rtt: Option<u32>,
    max_rtt: Option<u32>,
    sum_rtt: u64,
    sum_rtt_sq: u64,
}

impl HopStats {
    fn new(ttl: u8) -> Self {
        Self {
            ttl,
            ip: None,
            hostname: None,
            sent: 0,
            received: 0,
            last_rtt: None,
            min_rtt: None,
            max_rtt: None,
            sum_rtt: 0,
            sum_rtt_sq: 0,
        }
    }

    fn record_response(&mut self, ip: IpAddr, rtt: u32) {
        self.ip = Some(ip);
        self.sent += 1;
        self.received += 1;
        self.last_rtt = Some(rtt);
        self.sum_rtt += rtt as u64;
        self.sum_rtt_sq += (rtt as u64) * (rtt as u64);
        self.min_rtt = Some(self.min_rtt.map_or(rtt, |m| m.min(rtt)));
        self.max_rtt = Some(self.max_rtt.map_or(rtt, |m| m.max(rtt)));
    }

    fn record_timeout(&mut self) {
        self.sent += 1;
    }

    fn loss_percent(&self) -> f64 {
        if self.sent == 0 { 0.0 } else { ((self.sent - self.received) as f64 / self.sent as f64) * 100.0 }
    }

    fn avg_rtt(&self) -> f64 {
        if self.received == 0 { 0.0 } else { self.sum_rtt as f64 / self.received as f64 }
    }

    fn std_dev(&self) -> f64 {
        if self.received < 2 { 0.0 } else {
            let n = self.received as f64;
            let mean = self.avg_rtt();
            let variance = (self.sum_rtt_sq as f64 / n) - (mean * mean);
            if variance > 0.0 { variance.sqrt() } else { 0.0 }
        }
    }
}

#[derive(Clone)]
enum ProbeResult {
    Reply { ip: IpAddr, rtt: u32 },
    TtlExpired { ip: IpAddr, rtt: u32 },
    Unreachable { ip: IpAddr },
    Timeout,
}

fn resolve_target(target: &str) -> Result<IpAddr, String> {
    if let Ok(ip) = target.parse::<IpAddr>() { return Ok(ip); }
    match lookup_host(target) {
        Ok(ips) => {
            for ip in &ips { if ip.is_ipv4() { return Ok(*ip); } }
            ips.into_iter().next().ok_or_else(|| format!("No IP found for {}", target))
        }
        Err(e) => Err(format!("Failed to resolve {}: {}", target, e)),
    }
}

fn reverse_lookup(ip: IpAddr) -> Option<String> {
    if let Ok(hosts) = dns_lookup::lookup_addr(&ip) {
        if !hosts.is_empty() && hosts != ip.to_string() { return Some(hosts); }
    }
    None
}

fn format_hop(hop: &HopStats, no_dns: bool) -> String {
    let host_str = match (&hop.ip, &hop.hostname) {
        (Some(ip), Some(hostname)) if !no_dns => format!("{} ({})", hostname, ip),
        (Some(ip), _) => ip.to_string(),
        (None, _) => "???".to_string(),
    };
    let last = hop.last_rtt.map_or("---".to_string(), |r| format!("{:.1}", r as f64));
    let avg = if hop.received > 0 { format!("{:.1}", hop.avg_rtt()) } else { "---".to_string() };
    let best = hop.min_rtt.map_or("---".to_string(), |r| format!("{:.1}", r as f64));
    let wrst = hop.max_rtt.map_or("---".to_string(), |r| format!("{:.1}", r as f64));
    let stdev = if hop.received > 1 { format!("{:.1}", hop.std_dev()) } else { "---".to_string() };
    format!(
        "{:>3}. {:<45} {:>5.1}% {:>5} {:>6} {:>6} {:>6} {:>6} {:>6}",
        hop.ttl, if host_str.len() > 45 { &host_str[..45] } else { &host_str },
        hop.loss_percent(), hop.sent, last, avg, best, wrst, stdev
    )
}

/// Probe a single hop - designed to run in a thread
fn probe_hop(target: IpAddr, ttl: u8, timeout: u32) -> (u8, ProbeResult) {
    let pinger = match Pinger::new() {
        Ok(mut p) => { p.set_ttl(ttl); p.set_timeout(timeout); p }
        Err(_) => return (ttl, ProbeResult::Timeout),
    };
    
    let mut buffer = Buffer::new();
    let start = Instant::now();
    
    match pinger.send(target, &mut buffer) {
        Ok(rtt) => (ttl, ProbeResult::Reply { ip: target, rtt }),
        Err(PingError::TtlExpired) => {
            let elapsed = start.elapsed().as_millis() as u32;
            if let Some(ip) = buffer.responding_ip() {
                (ttl, ProbeResult::TtlExpired { ip, rtt: elapsed })
            } else {
                (ttl, ProbeResult::Timeout)
            }
        }
        Err(PingError::Timeout) => (ttl, ProbeResult::Timeout),
        Err(PingError::HostUnreachable) | Err(PingError::NetUnreachable) => {
            if let Some(ip) = buffer.responding_ip() {
                (ttl, ProbeResult::Unreachable { ip })
            } else {
                (ttl, ProbeResult::Timeout)
            }
        }
        Err(_) => (ttl, ProbeResult::Timeout),
    }
}

fn refresh_display(target: &str, target_ip: IpAddr, hops: &[HopStats], display_count: usize, no_dns: bool, lines_to_clear: usize) {
    if lines_to_clear > 0 {
        print!("\x1B[{}A\x1B[J", lines_to_clear);
    }
    println!("mtr to {} ({})", target, target_ip);
    println!("{:>3} {:<45} {:>6} {:>5} {:>6} {:>6} {:>6} {:>6} {:>6}", "", "Host", "Loss%", "Snt", "Last", "Avg", "Best", "Wrst", "StDev");
    for i in 0..display_count { println!("{}", format_hop(&hops[i], no_dns)); }
    io::stdout().flush().unwrap();
}

fn main() {
    let args = Args::parse();

    let target_ip = match resolve_target(&args.target) {
        Ok(ip) => ip,
        Err(e) => { eprintln!("Error: {}", e); std::process::exit(1); }
    };

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || { r.store(false, Ordering::SeqCst); }).expect("Error setting Ctrl+C handler");

    let hops = Arc::new(Mutex::new((1..=args.max_ttl).map(HopStats::new).collect::<Vec<_>>()));
    let target_ttl = Arc::new(Mutex::new(None::<u8>));
    let mut last_display_count: usize = 0;
    let mut cycle = 0u32;

    while running.load(Ordering::SeqCst) {
        cycle += 1;
        
        let max_hop = target_ttl.lock().unwrap().unwrap_or(args.max_ttl);
        
        // Parallel probing: spawn threads for all hops
        let mut handles = vec![];
        for ttl in 1..=max_hop {
            let target = target_ip;
            let timeout = args.timeout;
            handles.push(thread::spawn(move || probe_hop(target, ttl, timeout)));
        }

        // Collect results
        let mut results: Vec<(u8, ProbeResult)> = vec![];
        for handle in handles {
            if let Ok(result) = handle.join() {
                results.push(result);
            }
        }
        results.sort_by_key(|(ttl, _)| *ttl);

        // Process results
        let mut found_target = false;
        {
            let mut hops = hops.lock().unwrap();
            let mut target_ttl = target_ttl.lock().unwrap();
            
            for (ttl, result) in results {
                let hop_idx = (ttl - 1) as usize;
                match result {
                    ProbeResult::Reply { ip, rtt } => {
                        hops[hop_idx].record_response(ip, rtt);
                        if target_ttl.is_none() { *target_ttl = Some(ttl); }
                        if !args.no_dns && hops[hop_idx].hostname.is_none() {
                            hops[hop_idx].hostname = reverse_lookup(ip);
                        }
                        found_target = true;
                    }
                    ProbeResult::TtlExpired { ip, rtt } => {
                        hops[hop_idx].record_response(ip, rtt);
                        if !args.no_dns && hops[hop_idx].hostname.is_none() {
                            hops[hop_idx].hostname = reverse_lookup(ip);
                        }
                    }
                    ProbeResult::Unreachable { ip } => {
                        hops[hop_idx].ip = Some(ip);
                        hops[hop_idx].record_timeout();
                        if !args.no_dns && hops[hop_idx].hostname.is_none() {
                            hops[hop_idx].hostname = reverse_lookup(ip);
                        }
                    }
                    ProbeResult::Timeout => {
                        hops[hop_idx].record_timeout();
                    }
                }
            }
        }

        // Display
        if !args.report {
            let display_count = {
                let t = target_ttl.lock().unwrap();
                t.unwrap_or(max_hop) as usize
            };
            let hops = hops.lock().unwrap();
            refresh_display(&args.target, target_ip, &hops, display_count, args.no_dns, last_display_count + 2);
            last_display_count = display_count;
        }

        if args.report && cycle >= args.report_cycles { break; }
        if args.count > 0 && cycle >= args.count { break; }

        if running.load(Ordering::SeqCst) && args.interval > 0 {
            std::thread::sleep(std::time::Duration::from_millis(args.interval));
        }
    }

    // Final report
    println!();
    let hops = hops.lock().unwrap();
    let final_hops = target_ttl.lock().unwrap().unwrap_or_else(|| {
        hops.iter().rposition(|h| h.sent > 0).map(|i| (i + 1) as u8).unwrap_or(1)
    });
    println!("mtr to {} ({})", args.target, target_ip);
    println!("{:>3} {:<45} {:>6} {:>5} {:>6} {:>6} {:>6} {:>6} {:>6}", "", "Host", "Loss%", "Snt", "Last", "Avg", "Best", "Wrst", "StDev");
    for ttl in 1..=final_hops { println!("{}", format_hop(&hops[(ttl - 1) as usize], args.no_dns)); }
    
    std::process::exit(0);
}
