//! High-level resolver operations

use std::default::Default;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::vec::IntoIter;

use mio::{Evented, Poll, Token, Interest, PollOpt};

use address::{address_name, IpAddr};
use message::{Message, Qr, Question};
use record::{A, AAAA, Class, Ptr, RecordType};
use socket::{DnsSocket, Error};

/// Default timeout, in milliseconds.
pub const TIMEOUT_MS: usize = 5_000;

/// Performs resolution operations
pub struct DnsResolver {
    sock: DnsSocket,
    config: DnsConfig,
}

impl DnsResolver {
    /// Constructs a `DnsResolver` using the given configuration.
    pub fn new(config: DnsConfig) -> io::Result<DnsResolver> {
        Ok(DnsResolver{
            sock: try!(DnsSocket::new()),
            config: config,
        })
    }

    /// Constructs a `DnsResolver` using the given configuration and bound
    /// to the given address.
    pub fn bind<A: ?Sized>(addr: &A, config: DnsConfig) -> io::Result<DnsResolver>
            where A: ToSocketAddrs {
        Ok(DnsResolver{
            sock: try!(DnsSocket::bind(addr)),
            config: config,
        })
    }

    /// Resolves an IPv4 or IPv6 address to a hostname.
    pub fn resolve_addr(&mut self, addr: &IpAddr) -> io::Result<String> {
        convert_error("failed to resolve address", || {
            let mut out_msg = self.basic_message();

            out_msg.question.push(Question::new(
                address_name(addr), RecordType::Ptr, Class::Internet));

            let msg = try!(self.get_response(&out_msg));

            for rr in msg.into_records() {
                if rr.r_type == RecordType::Ptr {
                    let ptr = try!(rr.read_rdata::<Ptr>());
                    let mut name = ptr.name;
                    if name.ends_with('.') {
                        name.pop();
                    }
                    return Ok(name);
                }
            }

            Err(Error::IoError(io::Error::new(io::ErrorKind::Other,
                "failed to resolve address", Some("name not found".to_string()))))
        })
    }

    /// Resolves a hostname to a series of IPv4 or IPv6 addresses.
    pub fn resolve_host(&mut self, host: &str) -> io::Result<ResolveHost> {
        convert_error("failed to resolve host", || {
            let mut out_msg = self.basic_message();

            // First, an IPv4 request
            out_msg.question.push(Question::new(
                host.to_string(), RecordType::A, Class::Internet));

            let mut err = None;
            let mut res = Vec::new();

            match self.get_response(&out_msg) {
                Ok(msg) => {
                    for rr in msg.into_records() {
                        if rr.r_type == RecordType::A {
                            let a = try!(rr.read_rdata::<A>());
                            res.push(IpAddr::V4(a.address));
                        }
                    }
                }
                Err(e) => err = Some(e),
            }

            // Then, an IPv6 request
            out_msg.question[0].q_type = RecordType::AAAA;

            match self.get_response(&out_msg) {
                Ok(msg) => {
                    for rr in msg.into_records() {
                        if rr.r_type == RecordType::AAAA {
                            let aaaa = try!(rr.read_rdata::<AAAA>());
                            res.push(IpAddr::V6(aaaa.address));
                        }
                    }
                }
                Err(e) => err = Some(e),
            }

            if res.is_empty() {
                if let Some(e) = err {
                    Err(e)
                } else {
                    Err(Error::IoError(io::Error::new(io::ErrorKind::Other,
                        "failed to resolve host", Some("name not found".to_string()))))
                }
            } else {
                Ok(ResolveHost(res.into_iter()))
            }
        })
    }

    fn basic_message(&self) -> Message {
        let mut msg = Message::new();

        msg.header.recursion_desired = true;
        msg
    }

    fn get_response(&mut self, out_msg: &Message) -> Result<Message, Error> {
        let ns_addr = self.config.next_name_server();

        try!(self.sock.send_message(out_msg, &ns_addr));

        while try!(poll(&self.sock, self.config.timeout_ms)) {
            if let Some(msg) = try!(self.sock.recv_message(&ns_addr)) {
                if msg.header.id != out_msg.header.id {
                    continue;
                }
                if msg.header.qr != Qr::Response {
                    continue;
                }
                try!(msg.get_error());
                return Ok(msg);
            }
        }

        Err(Error::IoError(io::Error::new(io::ErrorKind::TimedOut,
            "request timed out", None)))
    }
}

fn convert_error<T, F>(desc: &'static str, f: F) -> io::Result<T>
        where F: FnOnce() -> Result<T, Error> {
    match f() {
        Ok(t) => Ok(t),
        Err(Error::IoError(e)) => Err(e),
        Err(e) => Err(io::Error::new(io::ErrorKind::Other,
            desc, Some(e.to_string())))
    }
}

#[cfg(unix)]
fn default_config() -> io::Result<DnsConfig> {
    use resolv_conf::load;
    load()
}

fn poll<E: Evented>(e: &E, timeout: usize) -> io::Result<bool> {
    let mut poll = try!(Poll::new());
    try!(poll.register(e, Token(0), Interest::readable(), PollOpt::level()));
    let ready = try!(poll.poll(timeout)) == 1;
    Ok(ready)
}

/// Resolves an IPv4 or IPv6 address to a hostname.
pub fn resolve_addr(addr: &IpAddr) -> io::Result<String> {
    let mut r = try!(DnsResolver::new(try!(default_config())));
    r.resolve_addr(addr)
}

/// Resolves a hostname to one or more IPv4 or IPv6 addresses.
///
/// # Example
///
/// ```no_run
/// use resolve::resolve_host;
/// # use std::io;
///
/// # fn foo() -> io::Result<()> {
/// for addr in try!(resolve_host("rust-lang.org")) {
///     println!("found address: {}", addr);
/// }
/// # Ok(())
/// # }
/// ```
pub fn resolve_host(host: &str) -> io::Result<ResolveHost> {
    let mut r = try!(DnsResolver::new(try!(default_config())));
    r.resolve_host(host)
}

/// Yields a series of `IpAddr` values from `resolve_host`.
pub struct ResolveHost(IntoIter<IpAddr>);

impl Iterator for ResolveHost {
    type Item = IpAddr;

    fn next(&mut self) -> Option<IpAddr> {
        self.0.next()
    }
}

#[derive(Clone, Debug)]
pub struct DnsConfig {
    /// List of name servers
    pub name_servers: Vec<SocketAddr>,
    /// Request timeout, in milliseconds
    pub timeout_ms: usize,
}

impl DnsConfig {
    /// Returns the address of the next name server.
    pub fn next_name_server(&self) -> &SocketAddr {
        // TODO: Implement round-robin and retry systems to make use of all
        // available name servers.
        &self.name_servers[0]
    }
}

impl Default for DnsConfig {
    fn default() -> DnsConfig {
        DnsConfig{
            name_servers: Vec::new(),
            timeout_ms: TIMEOUT_MS,
        }
    }
}
