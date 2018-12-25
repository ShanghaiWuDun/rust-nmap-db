#![feature(duration_as_u128, test)]
#![allow(unused_imports, unused_variables, dead_code)]

#[macro_use]
extern crate log;
extern crate pcre;
extern crate pcre2;

#[cfg(test)]
extern crate test;


pub mod db;


#[derive(Debug, Copy, Clone, Hash, PartialEq, PartialOrd, Eq, Ord)]
pub struct MacVendor {
    pub prefix: [u8; 3],
    pub vendor: &'static str,
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, PartialOrd, Eq, Ord)]
#[repr(u8)]
pub enum Protocol {
    Tcp = 0u8,
    Udp,
    Sctp,
}

#[derive(Debug, Copy, Clone)]
pub struct ServiceOpenFrequency {
    pub service: Service,
    pub open_frequency: f64,
}


#[derive(Debug, Copy, Clone, Hash, PartialEq, PartialOrd, Eq, Ord)]
pub struct Service {
    pub name_index: u16,
    pub protocol: Protocol,
    pub port: u16,
}

pub fn get_service_name_by_index(idx: u16) -> Option<&'static str> {
    unimplemented!()
}

pub fn get_service_name_index_by_name(name: &str) -> Option<u16> {
    unimplemented!()
}


impl Service {
    pub fn new_with_id(id: u16, protocol: Protocol, port: u16) -> Result<Self, ()> {
        unimplemented!()
    }

    pub fn new_with_name(name: &str, protocol: Protocol, port: u16) -> Result<Self, ()> {
        unimplemented!()
    }

    pub fn name(&self) -> &'static str {
        unimplemented!()
    }

}



pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

pub enum Port {
    Range((u16, u16)),
    Number(u16),
}

pub struct PortSpecification {
    both: &'static [Port],
    tcp: &'static [Port],
    udp: &'static [Port],
}

pub struct ServiceProbeExclude {
    inner: PortSpecification,
}


pub struct ServiceProbeMatchRule {
    is_soft_match: bool,
    service_name_index: u16,
    pattern: &'static [u8],
    versioninfo: &'static [ &'static [u8] ],
}

pub struct ServiceProbe {
    // Syntax: Exclude <port specification>
    // Exclude 53,T:9100,U:30000-40000
    // exclude: &'static str,
    probename: &'static str,
    probestring: &'static [u8],
    protocol: Protocol,
    
    // Syntax: fallback <Comma separated list of probes>
    fallback: Option<&'static str>,
    // Syntax: ports <portlist>
    // ports 21,43,110,113,199,505,540,1248,5432,30444
    // ports 111,4045,32750-32810,38978
    ports: Option<&'static [Port]>,
    // Syntax: sslports <portlist>
    sslports: Option<&'static [Port]>,
    // Syntax: rarity <value between 1 and 9>
    rarity: Option<u8>,
    // Syntax: tcpwrappedms <milliseconds>
    tcpwrappedms: Option<u64>,
    // Syntax: totalwaitms <milliseconds>
    totalwaitms: Option<u64>,
    
    rules: &'static [ServiceProbeMatchRule],
}


#[cfg(test)]
#[test]
fn test_pcre() {
    let ret = pcre::Pcre::compile(r"m=^<html>\\n<head>\\n<title>TRENDnet \\| (TEG-\\w+) \\| Login</title>=', 'p/TRENDnet $1 switch http config/");
    assert_eq!(ret.is_ok(), true);
}

