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

use std::cmp;
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

impl cmp::Ord for ServiceOpenFrequency {
    fn cmp(&self, other: &ServiceOpenFrequency) -> cmp::Ordering {
        assert_eq!(self.open_frequency.is_normal() || self.open_frequency == 0.0f64, true);
        assert_eq!(other.open_frequency.is_normal() || other.open_frequency == 0.0f64, true);

        if self.open_frequency == other.open_frequency {
            cmp::Ordering::Equal
        } else if self.open_frequency < other.open_frequency {
            cmp::Ordering::Less
        } else if self.open_frequency > other.open_frequency {
            cmp::Ordering::Greater
        } else {
            unreachable!()
        }
    }
}

impl PartialOrd for ServiceOpenFrequency {
    fn partial_cmp(&self, other: &ServiceOpenFrequency) -> Option<cmp::Ordering> {
        Some(self.cmp(&other))
    }
}

impl PartialEq for ServiceOpenFrequency {
    fn eq(&self, other: &ServiceOpenFrequency) -> bool {
        assert_eq!(self.open_frequency.is_normal() || self.open_frequency == 0.0f64, true);
        assert_eq!(other.open_frequency.is_normal() || other.open_frequency == 0.0f64, true);

        self.open_frequency == other.open_frequency
    }
}

impl Eq for ServiceOpenFrequency { }


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
        write!(f, "{:?}/{} {}", self.protocol, self.port, self.service_name())
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
        // self.probestring
    }
}


pub fn pcre_is_match(pattern: &str, subject: &[u8]) -> bool {
    match pcre::Pcre::compile(&pattern) {
        Ok(mut re) => {
            // debug!("{:?}", re);
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
    let mut pattern = pattern;

    if pattern.starts_with("m") {
        pattern = &pattern[1..];
    }

    let start_token = &pattern[0..1];
    
    let mut options: Option<&str> = None;

    match start_token {
        "|" | "/" |  "=" | "@" | "%" => {
            let tmp = &pattern[1..];
            let mut idx = tmp.len() - 1;
            let mut no_end = true;
            while idx > 0 {
                if start_token == &tmp[idx..idx+1] {
                    // siID
                    let opts = &tmp[idx+1..];
                    if opts.len() > 0 {
                        options = Some(opts);
                    }
                    
                    no_end = false;
                    pattern = &pattern[1..idx+1];

                    break;
                }

                idx -= 1;
            }

            if no_end {
                return false;
            }
        },
        _ => {

        },
    }

    trace!("pattern: {:?}  options: {:?}", pattern, options);

    let mut caseless = false;
    let mut dotall = false;
    let mut multi_line = false;
    let mut crlf = false;
    let mut ucp = false;
    let mut utf = false;

    if let Some(opt) = options {
        if opt.contains("i") {
            caseless = true;
        }

        if opt.contains("s") {
            dotall = true;
        }

        if opt.contains("m") {
            multi_line = true;
        }

        if opt.contains("m") {
            multi_line = true;
        }
    }

    let re = pcre2::bytes::RegexBuilder::new()
        .caseless(caseless)
        .dotall(dotall)
        .multi_line(multi_line)
        .crlf(crlf)
        .ucp(ucp)
        .utf(utf)
        .build(pattern);

    let re = match re {
        Ok(re) => re,
        Err(e) => {
            error!("{:?}", e);
            return false;
        }
    };

    let _capture_names = re.capture_names();
    
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
    unimplemented!()
}
