//! DNS resolver configuration

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

/// Configures the behavior of DNS requests
#[derive(Clone, Debug)]
pub struct DnsConfig {
    /// List of name servers; must not be empty
    pub name_servers: Vec<SocketAddr>,
    /// List of search domains
    pub search: Vec<String>,

    /// Minimum number of dots in a name to trigger an initial absolute query
    pub n_dots: u32,
    /// Duration before retrying or failing an unanswered request
    pub timeout: Duration,
    /// Number of attempts made before returning an error
    pub attempts: u32,
    /// Retry on any socket error.
    pub retry_on_socket_error: bool,
    /// Whether to rotate through available nameservers
    pub rotate: bool,
    /// If `true`, perform `AAAA` queries first and return IPv4 addresses
    /// as IPv4-mapped IPv6 addresses.
    pub use_inet6: bool,
}

impl DnsConfig {
    /// Returns the default system configuration for DNS requests.
    pub fn load_default() -> io::Result<DnsConfig> {
        default_config_impl()
    }

    /// Returns a `DnsConfig` using the given set of name servers,
    /// setting all other fields to generally sensible default values.
    pub fn with_name_servers(name_servers: Vec<SocketAddr>) -> DnsConfig {
        DnsConfig {
            name_servers: name_servers,
            search: Vec::new(),

            n_dots: 1,
            timeout: Duration::from_secs(5),
            attempts: 5,
            retry_on_socket_error: false,
            rotate: false,
            use_inet6: false,
        }
    }
}

#[cfg(unix)]
fn default_config_impl() -> io::Result<DnsConfig> {
    use resolv_conf::load;
    load()
}

#[cfg(windows)]
fn default_config_impl() -> io::Result<DnsConfig> {
    // TODO: Get a list of nameservers from Windows API.
    // For now, return an IO error.
    Err(io::Error::new(
        io::ErrorKind::Other,
        "Nameserver list not available on Windows",
    ))
}
