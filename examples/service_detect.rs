#[macro_use]
extern crate log;
// extern crate env_logger;
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

fn main() {    
    // env_logger::init();
    init().unwrap();

    let service = service_detect("127.0.0.1:80", &Protocol::Tcp);

    info!("{:?}", service);
}
