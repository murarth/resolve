//! Partial Unix `resolv.conf(5)` parser

use std::cmp::min;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use config::DnsConfig;
use hostname::get_hostname;

/// port for DNS communication
const DNS_PORT: u16 = 53;

/// Maximum number of name servers loaded from `resolv.conf`
pub const MAX_NAME_SERVERS: usize = 3;

/// Default value of `"options attempts:n"`
pub const DEFAULT_ATTEMPTS: u32 = 2;

/// Default value of `"options ndots:n"`
pub const DEFAULT_N_DOTS: u32 = 1;

/// Default value of `"options timeout:n"`
pub const DEFAULT_TIMEOUT: u64 = 5;

/// Maximum allowed value of `"options attempts:n"`
pub const MAX_ATTEMPTS: u32 = 5;

/// Maximum allowed value of `"options ndots:n"`
pub const MAX_N_DOTS: u32 = 15;

/// Maximum allowed value of `"options timeout:n"`
pub const MAX_TIMEOUT: u64 = 30;

/// Path to system `resolv.conf`
pub const RESOLV_CONF_PATH: &'static str = "/etc/resolv.conf";

fn default_config() -> DnsConfig {
    DnsConfig {
        name_servers: Vec::new(),
        search: Vec::new(),

        n_dots: DEFAULT_N_DOTS,
        attempts: DEFAULT_ATTEMPTS,
        timeout: Duration::from_secs(DEFAULT_TIMEOUT),
        retry_on_socket_error: false,

        rotate: false,
        use_inet6: false,
    }
}

/// Examines system `resolv.conf` and returns a configuration loosely based
/// on its contents. If the file cannot be read or lacks required directives,
/// an error is returned.
pub fn load() -> io::Result<DnsConfig> {
    parse(BufReader::new(try!(File::open(RESOLV_CONF_PATH))))
}

fn parse<R: BufRead>(r: R) -> io::Result<DnsConfig> {
    let mut cfg = default_config();

    for line in r.lines() {
        let line = try!(line);

        if line.is_empty() || line.starts_with(|c| c == '#' || c == ';') {
            continue;
        }

        let mut words = line.split_whitespace();

        let name = match words.next() {
            Some(name) => name,
            None => continue,
        };

        match name {
            "nameserver" => match words.next() {
                Some(ip) => {
                    if cfg.name_servers.len() < MAX_NAME_SERVERS {
                        if let Ok(ip) = ip.parse::<IpAddr>() {
                            cfg.name_servers.push(SocketAddr::new(ip, DNS_PORT))
                        }
                    }
                }
                None => (),
            },
            "domain" => match words.next() {
                Some(domain) => cfg.search = vec![domain.to_owned()],
                None => (),
            },
            "search" => {
                cfg.search = words.map(|s| s.to_owned()).collect();
            }
            "options" => {
                for opt in words {
                    let (opt, value) = match opt.find(':') {
                        Some(pos) => (&opt[..pos], &opt[pos + 1..]),
                        None => (opt, ""),
                    };

                    match opt {
                        "ndots" => {
                            if let Ok(n) = value.parse() {
                                cfg.n_dots = min(n, MAX_N_DOTS);
                            }
                        }
                        "timeout" => {
                            if let Ok(n) = value.parse() {
                                cfg.timeout = Duration::from_secs(min(n, MAX_TIMEOUT));
                            }
                        }
                        "attempts" => {
                            if let Ok(n) = value.parse() {
                                cfg.attempts = min(n, MAX_ATTEMPTS);
                            }
                        }
                        "rotate" => cfg.rotate = true,
                        "inet6" => cfg.use_inet6 = true,
                        _ => (),
                    }
                }
            }
            _ => (),
        }
    }

    if cfg.name_servers.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "no nameserver directives in resolv.conf",
        ));
    }

    if cfg.search.is_empty() {
        let host = try!(get_hostname());

        if let Some(pos) = host.find('.') {
            cfg.search = vec![host[pos + 1..].to_owned()];
        }
    }

    Ok(cfg)
}

#[cfg(test)]
mod test {
    use super::{parse, MAX_TIMEOUT};
    use std::io::Cursor;

    const TEST_CONFIG: &'static str = "\
        nameserver 127.0.0.1
        search foo.com bar.com
        options timeout:99 ndots:2 rotate";

    #[test]
    fn test_parse() {
        let r = Cursor::new(TEST_CONFIG.as_bytes());
        let cfg = parse(r).unwrap();

        assert_eq!(cfg.name_servers, ["127.0.0.1:53".parse().unwrap()]);
        assert_eq!(cfg.search, ["foo.com", "bar.com"]);
        assert_eq!(cfg.timeout.as_secs(), MAX_TIMEOUT);
        assert_eq!(cfg.n_dots, 2);
        assert_eq!(cfg.rotate, true);
    }
}
