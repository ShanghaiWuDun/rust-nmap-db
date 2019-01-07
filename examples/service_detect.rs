#[macro_use]
extern crate log;
extern crate ansi_term;
extern crate chrono;

extern crate pcre;
extern crate pcre2;
extern crate nmap_db;


pub use crate::nmap_db::{
    SERVICE_PROBE_EXCLUDE, MAC_PREFIXES_DB, 
    SERVICE_OPEN_FREQUENCY_DB, SERVICE_NAMES,
    SERVICE_PROBES,

    MacVendor, Protocol, ServiceOpenFrequency,
    Service, Port, PortSpecification,
    ServiceProbeMatchRule, ServiceProbe,

    service_detect,
    pcre2_is_match,
};

use std::cmp;
use std::fmt;
use std::time::{ Instant, Duration, };
use std::net::SocketAddr;
use std::net::TcpStream;
use std::net::UdpSocket;
use std::net::TcpListener;
use std::net::ToSocketAddrs;

use std::io::{ Read, Write, };


use crate::log::{ Record, Level, Metadata, SetLoggerError, LevelFilter, };
use crate::ansi_term::{ Color, Style, };
use crate::chrono::Local;


static LOGGER: SimpleLogger = SimpleLogger;


struct SimpleLogger;


impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        let module_path = record.module_path().unwrap_or("");
        
        if (module_path.starts_with("service_detect") || module_path.starts_with("nmap_db"))  && self.enabled(record.metadata()) {
            println!("[{:5} {} {}:{} {}] {}",
                        match record.level() {
                            Level::Error => Color::Red.paint("ERROR"),
                            Level::Warn  => Color::Yellow.paint("WARN "),
                            Level::Info  => Color::Green.paint("INFO "),
                            Level::Debug => Color::Blue.paint("DEBUG"),
                            Level::Trace => Color::Purple.paint("TRACE"),
                        },
                        Local::now().to_rfc3339(),
                        record.file().unwrap_or(""),
                        record.line().unwrap_or(0),
                        Style::new().dimmed().paint(module_path),
                        record.args());
        }
    }

    fn flush(&self) { }
}

pub fn init() -> Result<(), SetLoggerError> {
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(LevelFilter::Trace))
}



pub fn top_service_detect(port: u16) -> Vec<&'static ServiceOpenFrequency> {
    let mut elems = SERVICE_OPEN_FREQUENCY_DB.iter()
        .filter(|item| item.service.port == port)
        .collect::<Vec<&ServiceOpenFrequency>>();

    elems.sort();
    elems.reverse();

    elems
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
struct ProbeCache {
    pub probename: &'static str,
    pub protocol: Protocol,
}


fn run_probe(sa: &SocketAddr, probe: &ServiceProbe, cache: &mut Vec<ProbeCache>) -> Option<Service> {
    let this_probe_cache = ProbeCache { probename: probe.probename, protocol: probe.protocol };
    if cache.contains( &this_probe_cache) {
        return None;
    }

    cache.push(this_probe_cache);

    // probe.totalwaitms
    let waitms = Duration::from_millis(3000);

    let protocol = probe.protocol;
    match protocol {
        Protocol::Tcp => {
            // let mut socket = TcpStream::connect(&sa).ok()?;
            let mut socket = TcpStream::connect_timeout(&sa, waitms).ok()?;
            socket.set_nonblocking(false).ok()?;
            socket.set_read_timeout(Some(waitms)).ok()?;
            socket.set_write_timeout(Some(waitms)).ok()?;
            socket.set_nodelay(true).ok()?;
            
            let pkt: &[u8] = &probe.probestring;
            let raw_pkt_str = format!("{:?}", &probe.probestring);
            let pkt_str = std::str::from_utf8(pkt).unwrap_or(&raw_pkt_str);
            
            trace!("Probe {:?} {}: \"{}\"",
                    protocol,
                    probe.probename,
                    pkt_str,
            );

            if pkt.len() > 0 {
                match socket.write(&pkt) {
                    Ok(_) => { },
                    Err(e) => {
                        error!("{:?}", e);
                        if let Some(fallback_probe) = probe.fallback_probe() {
                            return run_probe(sa, &fallback_probe, cache);
                        } else {
                            return None;
                        }
                    }
                };
            }
            
            // std::thread::sleep(_waitms);

            let mut response_buffer = [0u8; 1024*2];
            let amt = match socket.read(&mut response_buffer) {
                Ok(amt) => amt,
                Err(e) => {
                    error!("{:?}", e);
                    if let Some(fallback_probe) = probe.fallback_probe() {
                        return run_probe(sa, &fallback_probe, cache);
                    } else {
                        return None;
                    }
                }
            };
            let response = &response_buffer[..amt];

            if response.len() < 1 {
                if let Some(fallback_probe) = probe.fallback_probe() {
                    return run_probe(sa, &fallback_probe, cache);
                } else {
                    return None;
                }
            }

            debug!("Payload: {:?}", std::str::from_utf8(response).unwrap_or(&format!("{:?}", response)));

            let mut soft_match = None;

            'loop2: for rule in probe.rules.iter() {
                // if now.elapsed() > waitms {
                //     break 'loop1;
                // }
                trace!("    {} {} \"{}\"",
                    if rule.is_soft_match { "SoftMatch" } else { "    Match" },
                    rule.service_name(),
                    rule.pattern(),
                );

                if rule.is_match(&response) {
                    let serv = Service {
                        name_index: rule.service_name_index,
                        protocol: protocol.clone(),
                        port: sa.port(),
                    };

                    if rule.is_soft_match && serv.service_name() != "unknown" {
                        trace!("soft match: {}", serv);
                        soft_match = Some(serv);
                    } else {
                        return Some(serv);
                    }
                }
            }

            if soft_match.is_some() {
                return soft_match;
            }

            return None
        },
        Protocol::Udp => {
            // unimplemented!()
            None
        },
        _ => unreachable!(),
    }
}

fn detect<A: ToSocketAddrs>(addr: A) -> Option<Service> {
    let sa = addr.to_socket_addrs().ok()?.next()?;
    
    trace!("detect service for {} ...", sa);

    let mut top_probes: Vec<&ServiceProbe> = Vec::new();

    let top_services = top_service_detect(sa.port());
    
    println!("{:?}", top_services);

    let mut probes_cache: Vec<ProbeCache> = Vec::new();

    let mut idx: usize = 0;
    for top_service in top_services {
        if idx > 5 {
            break;
        }

        if top_service.service.protocol != Protocol::Tcp
            && top_service.service.protocol != Protocol::Udp {
            continue;
        }

        'loop2: for probe in SERVICE_PROBES.iter() {
            for rule in probe.rules.iter() {
                if rule.service_name_index == top_service.service.name_index
                    && probe.protocol == top_service.service.protocol {
                    if !top_probes.contains(&probe) {
                        // println!("{:?}", top_service.service.service_name());
                        // println!("{:?}", rule);
                        // println!("检测到 probe: {:?}", probe.probename);
                        top_probes.push(probe);
                    }
                    break 'loop2;
                }
            }
        }

        idx += 1;
    }
    

    for top_probe in top_probes {
        debug!("快速探测: {:?} {:?}", top_probe.protocol, top_probe.probename);
        if let Some(service) = run_probe(&sa, top_probe, &mut probes_cache) {
            return Some(service);
        }
    }
    
    debug!("快速探测未命中服务 ...");

    for probe in SERVICE_PROBES.iter() {
        if let Some(service) = run_probe(&sa, probe, &mut probes_cache) {
            return Some(service);
        }
    }

    return None;
}


fn test_match() {
    let payload = b"-ERR wrong number of arguments for 'get' command\r\n";
    // %abc(\w+)end%i
    // abChelloend
    let p = "|^-err wrong number of arguments for 'get' Command\r\n$|i";
    println!("pcre2_is_match: {:?}", pcre2_is_match(p, payload));

    let p = "m@^-ERR wrong number of arguments for 'get' command\r\n$@";
    println!("pcre2_is_match: {:?}", pcre2_is_match(p, payload));


    let p = "m/^-ERR wrong number of arguments for 'get' command\r\n$/i";
    println!("pcre2_is_match: {:?}", pcre2_is_match(p, payload));

    let p = "^-ERR wrong number of arguments for 'get' command\r\n$";
    println!("pcre2_is_match: {:?}", pcre2_is_match(p, payload));
}

fn main() {
    init().unwrap();
    log::set_max_level(LevelFilter::Trace);

    // test_match();

    match detect("127.0.0.1:6379") {
        Some(service) => info!("{}", service),
        None => info!("Unknow"),
    }
}
