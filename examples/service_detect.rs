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
};


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

fn test_pcre() {
    let ret = nmap_db::pcre2_is_match("m^Invalid request string: Request string is: \"\r\"",
        b"HTTP/1.1 400 Bad Request\r\nServer: nginx/1.15.7\r\nDate: Thu, 27 Dec 2018 07:46:34 GMT\r\nContent-Type: text/html\r\nContent-Length: 157\r\nConnection: close\r\n\r\n<html>\r\n<head><title>400 Bad Request</title></head>\r\n<body>\r\n<center><h1>400 Bad Request</h1></center>\r\n<hr><center>nginx/1.15.7</center>\r\n</body>\r\n</html>\r\n");
    println!("{:?}", ret);

}


fn main() {
    init().unwrap();
    log::set_max_level(LevelFilter::Trace)
    
    // test_pcre();

    match service_detect("127.0.0.1:80", &Protocol::Tcp) {
        Some(service) => info!("{}", service),
        None => info!("Unknow"),
    }
}
