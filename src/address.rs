//! IP address utility functions

use std::net::{IpAddr, SocketAddr};

/// Compares two `IpAddr`s, checking for IPv6-compatible or IPv6-mapped addresses.
pub fn address_equal(a: &IpAddr, b: &IpAddr) -> bool {
    match (*a, *b) {
        // Simple comparisons; (V4 == V4) or (V6 == V6)
        (IpAddr::V4(ref a), IpAddr::V4(ref b)) => a == b,
        (IpAddr::V6(ref a), IpAddr::V6(ref b)) => a == b,
        // Not-so-simple comparison; V4 == maybe-V6-wrapped-V4
        (IpAddr::V6(ref a), IpAddr::V4(ref b)) => match a.to_ipv4() {
            Some(ref a4) => a4 == b,
            None => false,
        },
        (IpAddr::V4(..), IpAddr::V6(..)) => address_equal(b, a),
    }
}

/// Compares two `SocketAddr`s, checking for IPv6-compatible or IPv6-mapped addresses.
pub fn socket_address_equal(a: &SocketAddr, b: &SocketAddr) -> bool {
    a.port() == b.port() && address_equal(&a.ip(), &b.ip())
}

/// Returns an IP address formatted as a domain name.
pub fn address_name(addr: &IpAddr) -> String {
    match *addr {
        IpAddr::V4(ref addr) => {
            let octets = addr.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(ref addr) => {
            let s = addr.segments();
            format!(
                "{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.\
                 {:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.\
                 {:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.\
                 {:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.{:x}.ip6.arpa",
                s[7] & 0xf,
                (s[7] & 0x00f0) >> 4,
                (s[7] & 0x0f00) >> 8,
                (s[7] & 0xf000) >> 12,
                s[6] & 0xf,
                (s[6] & 0x00f0) >> 4,
                (s[6] & 0x0f00) >> 8,
                (s[6] & 0xf000) >> 12,
                s[5] & 0xf,
                (s[5] & 0x00f0) >> 4,
                (s[5] & 0x0f00) >> 8,
                (s[5] & 0xf000) >> 12,
                s[4] & 0xf,
                (s[4] & 0x00f0) >> 4,
                (s[4] & 0x0f00) >> 8,
                (s[4] & 0xf000) >> 12,
                s[3] & 0xf,
                (s[3] & 0x00f0) >> 4,
                (s[3] & 0x0f00) >> 8,
                (s[3] & 0xf000) >> 12,
                s[2] & 0xf,
                (s[2] & 0x00f0) >> 4,
                (s[2] & 0x0f00) >> 8,
                (s[2] & 0xf000) >> 12,
                s[1] & 0xf,
                (s[1] & 0x00f0) >> 4,
                (s[1] & 0x0f00) >> 8,
                (s[1] & 0xf000) >> 12,
                s[0] & 0xf,
                (s[0] & 0x00f0) >> 4,
                (s[0] & 0x0f00) >> 8,
                (s[0] & 0xf000) >> 12
            )
        }
    }
}

#[cfg(test)]
mod test {
    use super::{address_equal, address_name};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_address_equal() {
        let ip = Ipv4Addr::new(1, 2, 3, 4);
        let a = IpAddr::V4(ip);

        assert!(address_equal(&a, &IpAddr::V6(ip.to_ipv6_compatible())));
        assert!(address_equal(&a, &IpAddr::V6(ip.to_ipv6_mapped())));
        assert!(!address_equal(
            &a,
            &IpAddr::V6(Ipv6Addr::new(1, 0, 0, 0, 0, 0, 0x0102, 0x0304))
        ));
    }

    #[test]
    fn test_address_name() {
        assert_eq!(
            address_name(&"192.0.2.5".parse::<IpAddr>().unwrap()),
            "5.2.0.192.in-addr.arpa"
        );
        assert_eq!(
            address_name(&"2001:db8::567:89ab".parse::<IpAddr>().unwrap()),
            "b.a.9.8.7.6.5.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
        );
    }
}
