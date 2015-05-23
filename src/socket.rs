//! Low-level UDP socket operations

use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use bytes::{SliceBuf, MutSliceBuf, MutBuf};

use mio::udp::UdpSocket;

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
    pub fn bind(addr: &SocketAddr) -> io::Result<DnsSocket> {
        Ok(DnsSocket{
            sock: try!(UdpSocket::bound(addr)),
        })
    }

    /// Returns the wrapped `UdpSocket`.
    pub fn get_inner(&self) -> &UdpSocket {
        &self.sock
    }

    /// Sends a message to the given address.
    pub fn send_message(&mut self, message: &Message, addr: &SocketAddr) -> Result<Option<()>, Error> {
        let mut buf = [0; MESSAGE_LIMIT];
        let data = try!(message.encode(&mut buf));
        Ok(try!(self.sock.send_to(&mut SliceBuf::wrap(&data), addr)))
    }

    /// Receives a message, returning the address of the recipient.
    pub fn recv_from(&mut self) -> Result<Option<(Message, SocketAddr)>, Error> {
        let mut buf = [0; MESSAGE_LIMIT];

        let (addr, n_rem) = {
            let mut mutbuf = MutSliceBuf::wrap(&mut buf);
            match try!(self.sock.recv_from(&mut mutbuf)) {
                Some(addr) => (addr, mutbuf.remaining()),
                None => return Ok(None)
            }
        };

        let n = buf.len() - n_rem;
        let msg = try!(Message::decode(&buf[..n]));
        Ok(Some((msg, addr)))
    }

    /// Attempts to read a DNS message. The message will only be decoded if the
    /// remote address matches `addr`. If a packet is received from a non-matching
    /// address, the message is not decoded and `Ok(None)` is returned.
    pub fn recv_message(&mut self, addr: &SocketAddr) -> Result<Option<Message>, Error> {
        let mut buf = [0; MESSAGE_LIMIT];

        let (recv_addr, n_rem) = {
            let mut mutbuf = MutSliceBuf::wrap(&mut buf);
            match try!(self.sock.recv_from(&mut mutbuf)) {
                Some(addr) => (addr, mutbuf.remaining()),
                None => return Ok(None)
            }
        };

        if !socket_address_equal(&recv_addr, addr) {
            Ok(None)
        } else {
            let n = buf.len() - n_rem;
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
