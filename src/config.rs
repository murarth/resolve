//! DNS resolver configuration

use std::net::SocketAddr;
use std::time::Duration;

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

    /// Whether to rotate through available nameservers
    pub rotate: bool,
    /// If `true`, perform `AAAA` queries first and return IPv4 addresses
    /// as IPv4-mapped IPv6 addresses.
    pub use_inet6: bool,
}
