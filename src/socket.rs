//! Low-level UDP socket operations

use std::error::FromError;
use std::fmt;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::unix::io::{AsRawFd, Fd};

use mio::Evented;

use message::{DecodeError, DnsError, EncodeError, Message, MESSAGE_LIMIT};

/// Represents a socket transmitting DNS messages.
pub struct DnsSocket {
    sock: UdpSocket,
}

impl DnsSocket {
    /// Returns a `DnsSocket`, bound to an unspecified address.
    pub fn new() -> io::Result<DnsSocket> {
        DnsSocket::bind("[::]:0")
    }

    /// Returns a `DnsSocket`, bound to the given address.
    pub fn bind<A: ToSocketAddrs + ?Sized>(addr: &A) -> io::Result<DnsSocket> {
        Ok(DnsSocket{
            sock: try!(UdpSocket::bind(addr)),
        })
    }

    /// Sends a message to the given address.
    pub fn send_message(&mut self, message: &Message, addr: &SocketAddr) -> Result<(), Error> {
        let mut buf = [0; MESSAGE_LIMIT];
        let data = try!(message.encode(&mut buf));
        try!(self.sock.send_to(data, addr));
        Ok(())
    }

    /// Receives a message, returning the address of the recipient.
    pub fn recv_from(&mut self) -> Result<(Message, SocketAddr), Error> {
        let mut buf = [0; MESSAGE_LIMIT];
        let (n, addr) = try!(self.sock.recv_from(&mut buf));
        let msg = try!(Message::decode(&buf[..n]));
        Ok((msg, addr))
    }

    /// Attempts to read a DNS message. The message will only be decoded if the
    /// remote address matches `addr`. If a packet is received from a non-matching
    /// address, the message is not decoded and `Ok(None)` is returned.
    pub fn recv_message(&mut self, addr: &SocketAddr) -> Result<Option<Message>, Error> {
        let mut buf = [0; MESSAGE_LIMIT];
        let (n, recv_addr) = try!(self.sock.recv_from(&mut buf));
        if !addresses_match(&recv_addr, addr) {
            return Ok(None);
        }
        Ok(Some(try!(Message::decode(&buf[..n]))))
    }
}

/// Represents an error in sending or receiving a DNS message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    DecodeError(DecodeError),
    EncodeError(EncodeError),
    DnsError(DnsError),
    IoError(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::DecodeError(e) => write!(f, "error decoding message: {}", e),
            Error::EncodeError(ref e) => write!(f, "error encoding message: {}", e),
            Error::DnsError(e) => write!(f, "server responded with error: {}", e),
            Error::IoError(ref e) => fmt::Display::fmt(e, f),
        }
    }
}

impl FromError<DecodeError> for Error {
    fn from_error(err: DecodeError) -> Error {
        Error::DecodeError(err)
    }
}

impl FromError<EncodeError> for Error {
    fn from_error(err: EncodeError) -> Error {
        Error::EncodeError(err)
    }
}

impl FromError<DnsError> for Error {
    fn from_error(err: DnsError) -> Error {
        Error::DnsError(err)
    }
}

impl FromError<io::Error> for Error {
    fn from_error(err: io::Error) -> Error {
        Error::IoError(err)
    }
}

/// Compares two `SocketAddr`s, checking for IPv4-in-IPv6 addresses
fn addresses_match(a: &SocketAddr, b: &SocketAddr) -> bool {
    match (*a, *b) {
        // Simple comparisons; (V4 == V4) or (V6 == V6)
        (SocketAddr::V4(ref a), SocketAddr::V4(ref b)) => a == b,
        (SocketAddr::V6(ref a), SocketAddr::V6(ref b)) => a == b,
        // Not-so-simple comparison; V4 == maybe-V6-wrapped-V4
        (SocketAddr::V6(ref a), SocketAddr::V4(ref b)) => {
            match a.ip().to_ipv4() {
                Some(ref a4) => a4 == b.ip() && a.port() == b.port(),
                None => false
            }
        }
        (SocketAddr::V4(..), SocketAddr::V6(..)) => addresses_match(b, a),
    }
}

impl AsRawFd for DnsSocket {
    fn as_raw_fd(&self) -> Fd {
        self.sock.as_raw_fd()
    }
}

// TODO: Implement non-blocking read from DnsSocket in order for this to be useful.
impl Evented for DnsSocket {}
