//! Implements parsing the system hosts file to produce a host table

use std::fs::File;
use std::io::{self, Read};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

/// Represents a host table, consisting of addresses mapped to names.
#[derive(Clone, Debug)]
pub struct HostTable {
    /// Contained hosts
    pub hosts: Vec<Host>,
}

impl HostTable {
    /// Returns the address for the first host matching the given name.
    ///
    /// If no match is found, `None` is returned.
    pub fn find_address(&self, name: &str) -> Option<IpAddr> {
        self.find_host_by_name(name).map(|h| h.address)
    }

    /// Returns the canonical name for the first host matching the given address.
    ///
    /// If no match is found, `None` is returned.
    pub fn find_name(&self, addr: IpAddr) -> Option<&str> {
        self.find_host_by_address(addr).map(|h| &h.name[..])
    }

    /// Returns the first host matching the given address.
    ///
    /// If no match is found, `None` is returned.
    pub fn find_host_by_address(&self, addr: IpAddr) -> Option<&Host> {
        self.hosts.iter().find(|h| h.address == addr)
    }

    /// Returns the first host matching the given address.
    ///
    /// If no match is found, `None` is returned.
    pub fn find_host_by_name(&self, name: &str) -> Option<&Host> {
        self.hosts
            .iter()
            .find(|h| h.name == name || h.aliases.iter().any(|a| a == name))
    }
}

/// Represents a single host within a host table.
#[derive(Clone, Debug)]
pub struct Host {
    /// Host address
    pub address: IpAddr,
    /// Canonical host name
    pub name: String,
    /// Host aliases
    pub aliases: Vec<String>,
}

/// Returns the absolute path to the system hosts file.
pub fn host_file() -> PathBuf {
    host_file_impl()
}

#[cfg(unix)]
fn host_file_impl() -> PathBuf {
    PathBuf::from("/etc/hosts")
}

#[cfg(windows)]
fn host_file_impl() -> PathBuf {
    use std::env::var_os;

    match var_os("SystemRoot") {
        Some(root) => PathBuf::from(root).join("System32/drivers/etc/hosts"),
        // I'm not sure if this is the "correct" thing to do,
        // but it seems like a better alternative than panicking.
        None => PathBuf::from("C:/Windows/System32/drivers/etc/hosts"),
    }
}

/// Loads a host table from the given filename.
///
/// If an error is encountered in opening the file or reading its contents
/// or if the file is malformed, the error is returned.
pub fn load_hosts(path: &Path) -> io::Result<HostTable> {
    let mut f = try!(File::open(path));
    let mut buf = String::new();

    try!(f.read_to_string(&mut buf));
    parse_host_table(&buf)
}

/// Attempts to parse a host table in the hosts file format.
pub fn parse_host_table(data: &str) -> io::Result<HostTable> {
    let mut hosts = Vec::new();

    for line in data.lines() {
        let mut line = line;

        if let Some(pos) = line.find('#') {
            line = &line[..pos];
        }

        let mut words = line.split_whitespace();

        let addr_str = match words.next() {
            Some(w) => w,
            None => continue,
        };

        let addr = match addr_str.parse() {
            Ok(addr) => addr,
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid address: {}", addr_str),
                ))
            }
        };

        let name = match words.next() {
            Some(w) => w,
            None => return Err(io::Error::new(io::ErrorKind::InvalidData, "missing names")),
        };

        hosts.push(Host {
            address: addr,
            name: name.to_owned(),
            aliases: words.map(|s| s.to_owned()).collect(),
        });
    }

    Ok(HostTable { hosts: hosts })
}

#[cfg(test)]
mod test {
    use super::parse_host_table;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn test_hosts() {
        let hosts = parse_host_table(
            "\
# Comment line
127.0.0.1       localhost
::1             ip6-localhost

192.168.10.1    foo foo.bar foo.local # Mid-line comment
",
        )
        .unwrap();

        assert_eq!(hosts.find_address("localhost"), Some(ip("127.0.0.1")));
        assert_eq!(hosts.find_address("ip6-localhost"), Some(ip("::1")));
        assert_eq!(hosts.find_name(ip("192.168.10.1")), Some("foo"));

        assert_eq!(hosts.find_address("missing"), None);
        assert_eq!(hosts.find_name(ip("0.0.0.0")), None);

        let host = hosts.find_host_by_address(ip("192.168.10.1")).unwrap();

        assert_eq!(host.address, ip("192.168.10.1"));
        assert_eq!(host.name, "foo");
        assert_eq!(host.aliases, ["foo.bar", "foo.local"]);
    }
}
