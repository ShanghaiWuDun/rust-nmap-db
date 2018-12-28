#![feature(duration_as_u128, test)]
#![allow(unused_imports, unused_variables, dead_code)]

#[macro_use]
extern crate log;
extern crate pcre;
extern crate pcre2;

#[cfg(test)]
extern crate test;

#[doc(hiden)]
pub mod db;


pub use self::db::{ MAC_PREFIXES_DB, SERVICE_OPEN_FREQUENCY_DB, SERVICE_NAMES, SERVICE_PROBES, };


use std::fmt;
use std::time::{ Instant, Duration, };
use std::net::SocketAddr;
use std::net::TcpStream;
use std::net::UdpSocket;
use std::net::TcpListener;
use std::net::ToSocketAddrs;

use std::io::{ Read, Write, };



// Syntax: Exclude <port specification>
// Exclude 53,T:9100,U:30000-40000
#[doc(hiden)]
pub static SERVICE_PROBE_EXCLUDE: PortSpecification = PortSpecification {
    both: &[
        Port::Number(53),
    ],
    tcp: &[
        Port::Number(9100),
    ],
    udp: &[
        Port::Range((30000, 40000)),
    ],
};


#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct MacVendor {
    pub prefix: [u8; 3],
    pub vendor: &'static str,
}

#[derive(Copy, Clone, Hash, PartialEq, PartialOrd, Eq, Ord)]
#[repr(u8)]
pub enum Protocol {
    Tcp = 0u8,
    Udp,
    Sctp,
}

impl Protocol {
    pub fn is_tcp(&self) -> bool {
        use self::Protocol::*;

        match *self {
            Tcp => true,
            _ => false,
        }
    }

    pub fn is_udp(&self) -> bool {
        use self::Protocol::*;

        match *self {
            Udp => true,
            _ => false,
        }
    }

    pub fn is_sctp(&self) -> bool {
        use self::Protocol::*;

        match *self {
            Sctp => true,
            _ => false,
        }
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Sctp => write!(f, "sctp"),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub struct ServiceOpenFrequency {
    pub service: Service,
    pub open_frequency: f64,
}


#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct Service {
    pub name_index: u16,
    pub protocol: Protocol,
    pub port: u16,
}

impl Service {
    pub fn new(name: &str, protocol: Protocol, port: u16) -> Result<Self, ()> {
        SERVICE_NAMES.binary_search(&name)
            .map_err(|e| ())
            .map(|pos| {
                Self {
                    name_index: pos as u16,
                    protocol: protocol,
                    port: port,
                }
            })
    }

    pub fn service_name(&self) -> &'static str {
        SERVICE_NAMES[self.name_index as usize]
    }

    pub fn service_index(&self) -> usize {
        self.name_index as usize
    }
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "tcp/80 {}", self.service_name())
    }
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, PartialOrd, Eq, Ord)]
pub enum Port {
    Range((u16, u16)),
    Number(u16),
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, PartialOrd, Eq, Ord)]
pub struct PortSpecification {
    pub both: &'static [Port],
    pub tcp: &'static [Port],
    pub udp: &'static [Port],
}


#[derive(Debug, Copy, Clone, Hash, PartialEq, PartialOrd, Eq, Ord)]
pub struct ServiceProbeMatchRule {
    pub is_soft_match: bool,
    pub service_name_index: u16,
    pub pattern: &'static [u8],
    pub versioninfo: &'static [ &'static [u8] ],
}


impl ServiceProbeMatchRule {
    pub fn service_name(&self) -> &'static str {
        SERVICE_NAMES[self.service_name_index as usize]
    }

    pub fn is_match(&self, subject: &[u8]) -> bool {
        let p = self.pattern();
        // {'m|', 'm@', 'm=', 'm%'}
        // { '|', '|$=', '|=', '|s', '|^#', '|is', '|si', '|i'}
        pcre2_is_match(&p, &subject)
    }

    pub fn pattern(&self) -> &str {
        unsafe {
            std::str::from_utf8_unchecked(self.pattern)
        }
    }

    pub fn version_info(&self) -> Vec<&str> {
        self.versioninfo.iter()
            .map(|info| std::str::from_utf8(info).unwrap())
            .collect::<Vec<&str>>()
    }
}


#[derive(Debug, Copy, Clone, Hash, PartialEq, PartialOrd, Eq, Ord)]
pub struct ServiceProbe {
    // Syntax: Exclude <port specification>
    // Exclude 53,T:9100,U:30000-40000
    // exclude: &'static str,
    pub probename: &'static str,
    pub probestring: &'static [u8],
    pub protocol: Protocol,          // TCP | UDP
    
    // Syntax: fallback <Comma separated list of probes>
    pub fallback: Option<&'static str>,
    // Syntax: ports <portlist>
    // ports 21,43,110,113,199,505,540,1248,5432,30444
    // ports 111,4045,32750-32810,38978
    pub ports: Option<&'static [Port]>,
    // Syntax: sslports <portlist>
    pub sslports: Option<&'static [Port]>,
    // Syntax: rarity <value between 1 and 9>
    pub rarity: Option<u8>,
    // Syntax: tcpwrappedms <milliseconds>
    pub tcpwrappedms: Option<u64>,
    // Syntax: totalwaitms <milliseconds>
    pub totalwaitms: Option<u64>,
    pub rules: &'static [ServiceProbeMatchRule],
}


impl ServiceProbe {
    pub fn fallback_probe(&self) -> Option<Self> {
        let fallback_probe_name = self.fallback?;

        for probe in SERVICE_PROBES.iter() {
            if probe.probename == fallback_probe_name {
                return Some(*probe)
            }
        }

        None
    }

    pub fn name(&self) -> &'static str {
        self.probename
    }

    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub fn probestring(&self) -> &str {
        std::str::from_utf8(self.probestring).unwrap()
    }
}


pub fn pcre_is_match(pattern: &str, subject: &[u8]) -> bool {
    match pcre::Pcre::compile(&pattern) {
        Ok(mut re) => {
            debug!("{:?}", re);
            match std::str::from_utf8(&subject) {
                Ok(res) => {
                    match re.exec(&res) {
                        Some(_m) => true,
                        None => false,
                    }
                },
                Err(e) => {
                    error!("{:?}", e);
                    false
                },
            }   
        },
        Err(e) => {
            error!("{:?}", e);
            false
        }
    }
}

pub fn pcre2_is_match(pattern: &str, subject: &[u8]) -> bool {
    let re = match pcre2::bytes::Regex::new(&pattern) {
        Ok(re) => re,
        Err(e) => {
            error!("{:?}", e);
            return false;
        }
    };

    let capture_names = re.capture_names();
    
    match re.captures(&subject) {
        Ok(Some(_m)) => true,
        Ok(None) => false,
        Err(e) => {
            error!("{:?}", e);
            return false;
        }
    }
}

pub fn service_detect<A: ToSocketAddrs>(addr: A, protocol: &Protocol) -> Option<Service> {
    assert_eq!(protocol.is_tcp() || protocol.is_udp(), true);
    let sa = addr.to_socket_addrs().ok()?.next()?;

    match protocol {
        &Protocol::Tcp => {
            let mut socket = TcpStream::connect_timeout(&sa, Duration::from_millis(3000)).ok()?;
            // socket.set_nonblocking(true).ok()?;
            socket.set_read_timeout(Some(Duration::from_millis(6000))).ok()?;
            socket.set_write_timeout(Some(Duration::from_millis(6000))).ok()?;
            
            let now = Instant::now();
            let mut probe_done: Vec<&str> = Vec::new();

            'loop1: for probe in SERVICE_PROBES.iter() {
                if probe_done.contains(&probe.probename) {
                    continue;
                }

                assert_eq!(probe.probestring.len() >= 3, true);

                let waitms = Duration::from_millis(probe.totalwaitms.unwrap_or(3000));
                let pkt: &[u8] = &probe.probestring[2..probe.probestring.len()-1];
                let pkt_str = std::str::from_utf8(pkt).unwrap();

                trace!("Probe {:?} {}: {:?}",
                        protocol,
                        probe.probename,
                        pkt_str,
                );

                if pkt.len() > 0 {
                    match socket.write_all(&pkt) {
                        Ok(_) => { },
                        Err(e) => {
                            error!("{:?}", e);
                            continue;
                        }
                    };
                }

                // std::thread::sleep(waitms);

                let mut response_buffer = [0u8; 10240];
                let amt = match socket.read(&mut response_buffer) {
                    Ok(amt) => amt,
                    Err(e) => {
                        error!("{:?}", e);
                        continue;
                    }
                };
                let response = &response_buffer[..amt];

                if response.len() < 1 {
                    continue;
                }

                debug!("Payload: {:?}", std::str::from_utf8(response).unwrap_or(&format!("{:?}", response)));

                'loop2: for rule in probe.rules.iter() {
                    // if now.elapsed() > waitms {
                    //     break 'loop1;
                    // }

                    trace!("    {} {} {:?}",
                        if rule.is_soft_match { "SoftMatch" } else { "    Match" },
                        rule.service_name(),
                        rule.pattern(),
                    );

                    if rule.is_match(&response) {
                        return Some(Service {
                            name_index: rule.service_name_index,
                            protocol: protocol.clone(),
                            port: sa.port(),
                        });
                    }
                }

                probe_done.push(probe.probename);
                // TODO: fallback
            }

            return None;
        },
        &Protocol::Udp => {
            unimplemented!()
        },
        _ => unreachable!(),
    }
}

#[cfg(test)]
#[test]
fn test_pcre() {
    let ret = pcre::Pcre::compile(r"m=^<html>\\n<head>\\n<title>TRENDnet \\| (TEG-\\w+) \\| Login</title>=', 'p/TRENDnet $1 switch http config/");
    assert_eq!(ret.is_ok(), true);

    let ret = pcre2_is_match("|^Invalid request string: Request string is: \"\r\"$|",
        b"HTTP/1.1 400 Bad Request\r\nServer: nginx/1.15.7\r\nDate: Thu, 27 Dec 2018 07:46:34 GMT\r\nContent-Type: text/html\r\nContent-Length: 157\r\nConnection: close\r\n\r\n<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx/1.15.7</center>\r\n</body>\r\n</html>\r\n");
    assert_eq!(ret, false);
}

