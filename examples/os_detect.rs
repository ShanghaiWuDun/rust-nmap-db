extern crate nmap_db;

fn main() {
    println!("{:?}", nmap_db::db::MAC_PREFIXES_DB[2]);
    println!("{:?}", nmap_db::db::SERVICE_NAMES[2]);
    let r = &nmap_db::db::SERVICE_PROBES[2];

    
}