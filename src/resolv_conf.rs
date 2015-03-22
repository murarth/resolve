//! Partial Unix `resolv.conf(5)` parser

use std::default::Default;
use std::fs::File;
use std::io::{self, BufRead, BufReader};

use address::IpAddr;
use resolver::DnsConfig;

/// port for DNS communication
pub const DNS_PORT: u16 = 53;

/// Maximum number of name servers loaded from `resolv.conf`
pub const MAX_NAME_SERVERS: usize = 3;

/// Path to system `resolv.conf`
pub const RESOLV_CONF_PATH: &'static str = "/etc/resolv.conf";

/// Examines system `resolv.conf` and returns a configuration loosely based
/// on its contents. If the file cannot be read or lacks required directives,
/// an error is returned.
pub fn load() -> io::Result<DnsConfig> {
    let mut cfg = DnsConfig::default();

    let r = BufReader::new(try!(File::open(RESOLV_CONF_PATH)));

    for line in r.lines() {
        let line = try!(line);
        let words = line.words().collect::<Vec<_>>();

        match &words[..] {
            ["nameserver", name, ..] => {
                if cfg.name_servers.len() < MAX_NAME_SERVERS {
                    if let Ok(ip) = name.parse::<IpAddr>() {
                        cfg.name_servers.push(ip.to_socket_addr(DNS_PORT))
                    }
                }
            }
            _ => ()
        }
    }

    if cfg.name_servers.is_empty() {
        Err(io::Error::new(io::ErrorKind::Other,
            "no nameserver directives in resolv.conf", None))
    } else {
        Ok(cfg)
    }
}
