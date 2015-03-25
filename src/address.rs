//! IP address types

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;

/// Representation of an IPv4 or IPv6 address
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub enum IpAddr {
    /// An IPv4 address
    V4(Ipv4Addr),
    /// An IPv6 address
    V6(Ipv6Addr),
}

impl IpAddr {
    pub fn to_socket_addr(&self, port: u16) -> SocketAddr {
        match *self {
            IpAddr::V4(addr) => SocketAddr::V4(SocketAddrV4::new(addr, port)),
            IpAddr::V6(addr) => SocketAddr::V6(SocketAddrV6::new(addr, port, 0, 0)),
        }
    }
}

impl fmt::Display for IpAddr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            IpAddr::V4(ref addr) => fmt::Display::fmt(addr, f),
            IpAddr::V6(ref addr) => fmt::Display::fmt(addr, f),
        }
    }
}

/// Returns an IP address formatted as a domain name.
pub fn address_name(addr: &IpAddr) -> String {
    match *addr {
        IpAddr::V4(ref addr) => {
            let octets = addr.octets();
            format!("{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0])
        }
        IpAddr::V6(ref addr) => {
            let s = addr.segments();
            format!(
                "{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.\
                 {:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.\
                 {:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.\
                 {:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.ip6.arpa",
                s[7] & 0xf, (s[7] & 0x00f0) >> 4, (s[7] & 0x0f00) >> 8, (s[7] & 0xf000) >> 12,
                s[6] & 0xf, (s[6] & 0x00f0) >> 4, (s[6] & 0x0f00) >> 8, (s[6] & 0xf000) >> 12,
                s[5] & 0xf, (s[5] & 0x00f0) >> 4, (s[5] & 0x0f00) >> 8, (s[5] & 0xf000) >> 12,
                s[4] & 0xf, (s[4] & 0x00f0) >> 4, (s[4] & 0x0f00) >> 8, (s[4] & 0xf000) >> 12,
                s[3] & 0xf, (s[3] & 0x00f0) >> 4, (s[3] & 0x0f00) >> 8, (s[3] & 0xf000) >> 12,
                s[2] & 0xf, (s[2] & 0x00f0) >> 4, (s[2] & 0x0f00) >> 8, (s[2] & 0xf000) >> 12,
                s[1] & 0xf, (s[1] & 0x00f0) >> 4, (s[1] & 0x0f00) >> 8, (s[1] & 0xf000) >> 12,
                s[0] & 0xf, (s[0] & 0x00f0) >> 4, (s[0] & 0x0f00) >> 8, (s[0] & 0xf000) >> 12)
        }
    }
}

/// Signals an error in parsing an `IpAddr`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ParseError;

impl FromStr for IpAddr {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<IpAddr, ParseError> {
        s.parse::<Ipv4Addr>().map(|ip| IpAddr::V4(ip))
            .or_else(|_| s.parse::<Ipv6Addr>().map(|ip| IpAddr::V6(ip)))
            .map_err(|_| ParseError)
    }
}

#[cfg(test)]
mod test {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use super::{address_name, IpAddr};

    #[test]
    fn test_ip_addr() {
        assert_eq!("127.0.0.1".parse::<IpAddr>().unwrap(),
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
        assert_eq!("::1".parse::<IpAddr>().unwrap(),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)));

        assert_eq!("127.0.0.1", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)).to_string());
        assert_eq!("::1", IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)).to_string());
    }

    #[test]
    fn test_address_name() {
        assert_eq!(address_name(&"192.0.2.5".parse::<IpAddr>().unwrap()),
            "5.2.0.192.in-addr.arpa");
        assert_eq!(address_name(&"2001:db8::567:89ab".parse::<IpAddr>().unwrap()),
            "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa");
    }
}
