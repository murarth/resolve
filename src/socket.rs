//! Low-level UDP socket operations

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};

use address::socket_address_equal;
use message::{DecodeError, DnsError, EncodeError, Message, MESSAGE_LIMIT};

/// Represents a socket transmitting DNS messages.
pub struct DnsSocket {
    sock: UdpSocket,
}

impl DnsSocket {
    /// Returns a `DnsSocket`, bound to an unspecified address.
    pub fn new() -> io::Result<DnsSocket> {
        DnsSocket::bind(&SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0)), 0))
    }

    /// Returns a `DnsSocket`, bound to the given address.
    pub fn bind<A: ToSocketAddrs>(addr: A) -> io::Result<DnsSocket> {
        Ok(DnsSocket{
            sock: try!(UdpSocket::bind(addr)),
        })
    }

    /// Returns a reference to the wrapped `UdpSocket`.
    pub fn get(&self) -> &UdpSocket {
        &self.sock
    }

    /// Sends a message to the given address.
    pub fn send_message<A: ToSocketAddrs>(&mut self,
            message: &Message, addr: A) -> Result<(), Error> {
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

        if !socket_address_equal(&recv_addr, addr) {
            Ok(None)
        } else {
            let msg = try!(Message::decode(&buf[..n]));
            Ok(Some(msg))
        }
    }
}

/// Represents an error in sending or receiving a DNS message.
#[derive(Debug)]
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

impl From<DecodeError> for Error {
    fn from(err: DecodeError) -> Error {
        Error::DecodeError(err)
    }
}

impl From<EncodeError> for Error {
    fn from(err: EncodeError) -> Error {
        Error::EncodeError(err)
    }
}

impl From<DnsError> for Error {
    fn from(err: DnsError) -> Error {
        Error::DnsError(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IoError(err)
    }
}
