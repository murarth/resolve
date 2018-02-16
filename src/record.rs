//! DNS resource record types

use std::mem::transmute;
use std::net::{Ipv4Addr, Ipv6Addr};

use message::{DecodeError, EncodeError, MsgReader, MsgWriter};

/// Represents the class of data in a message.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Class {
    /// Internet (`IN`)
    Internet,
    /// Any (`*`)
    Any,
    /// An unrecognized class
    Other(u16),
}

impl Class {
    /// Converts a `u16` to a `Class`.
    pub fn from_u16(u: u16) -> Class {
        match u {
            1 => Class::Internet,
            255 => Class::Any,
            n => Class::Other(n),
        }
    }

    /// Converts a `Class` to a `u16`.
    pub fn to_u16(&self) -> u16 {
        match *self {
            Class::Internet => 1,
            Class::Any => 255,
            Class::Other(n) => n,
        }
    }
}

/// Represents the type of data in a message.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RecordType {
    /// An IPv4 host address
    A,
    /// An IPv6 host address
    AAAA,
    /// Canonical name for an alias
    CName,
    /// Mail exchange
    Mx,
    /// Authoritative name server
    Ns,
    /// Domain name pointer
    Ptr,
    /// Start of authority
    Soa,
    /// Service record
    Srv,
    /// Text string
    Txt,
    /// Unrecognized record type
    Other(u16),
}

macro_rules! record_types {
    ( $( $name:ident => $code:expr , )+ ) => {
        impl RecordType {
            /// Converts a `u16` to a `RecordType`.
            pub fn from_u16(u: u16) -> RecordType {
                match u {
                    $( $code => RecordType::$name , )+
                    n => RecordType::Other(n),
                }
            }

            /// Converts a `RecordType` to a `u16`.
            pub fn to_u16(&self) -> u16 {
                match *self {
                    $( RecordType::$name => $code , )+
                    RecordType::Other(n) => n,
                }
            }
        }
    }
}

record_types!{
    A => 1,
    AAAA => 28,
    CName => 5,
    Mx => 15,
    Ns => 2,
    Ptr => 12,
    Soa => 6,
    Srv => 33,
    Txt => 16,
}

/// Represents resource record data.
pub trait Record: Sized {
    /// Decodes the `Record` from resource rdata.
    fn decode(data: &mut MsgReader) -> Result<Self, DecodeError>;

    /// Encodes the `Record` to resource rdata.
    fn encode(&self, data: &mut MsgWriter) -> Result<(), EncodeError>;

    /// Returns the `RecordType` of queries for this record.
    fn record_type() -> RecordType;
}

/// An IPv4 host address
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct A {
    /// The host address
    pub address: Ipv4Addr,
}

impl Record for A {
    fn decode(data: &mut MsgReader) -> Result<Self, DecodeError> {
        let mut buf = [0; 4];
        try!(data.read(&mut buf));
        Ok(A{address: Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3])})
    }

    fn encode(&self, data: &mut MsgWriter) -> Result<(), EncodeError> {
        data.write(&self.address.octets())
    }

    fn record_type() -> RecordType { RecordType::A }
}

/// An IPv6 host address
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct AAAA {
    /// The host address
    pub address: Ipv6Addr,
}

impl Record for AAAA {
    fn decode(data: &mut MsgReader) -> Result<Self, DecodeError> {
        let mut buf = [0; 16];
        try!(data.read(&mut buf));
        let segments: [u16; 8] = unsafe { transmute(buf) };
        Ok(AAAA{address: Ipv6Addr::new(
            u16::from_be(segments[0]), u16::from_be(segments[1]),
            u16::from_be(segments[2]), u16::from_be(segments[3]),
            u16::from_be(segments[4]), u16::from_be(segments[5]),
            u16::from_be(segments[6]), u16::from_be(segments[7]))})
    }

    fn encode(&self, data: &mut MsgWriter) -> Result<(), EncodeError> {
        let mut segments = self.address.segments();
        for seg in &mut segments { *seg = seg.to_be() }
        let buf: [u8; 16] = unsafe { transmute(segments) };
        data.write(&buf)
    }

    fn record_type() -> RecordType { RecordType::AAAA }
}

/// Canonical name for an alias
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct CName {
    /// Canonical host name
    pub name: String,
}

impl Record for CName {
    fn decode(data: &mut MsgReader) -> Result<Self, DecodeError> {
        Ok(CName{name: try!(data.read_name())})
    }

    fn encode(&self, data: &mut MsgWriter) -> Result<(), EncodeError> {
        data.write_name(&self.name)
    }

    fn record_type() -> RecordType { RecordType::CName }
}

/// Mail exchange data
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Mx {
    /// Represents the preference of this record among others.
    /// Lower values are preferred.
    pub preference: u16,
    /// Domain name willing to act as mail exchange for the host.
    pub exchange: String,
}

impl Record for Mx {
    fn decode(data: &mut MsgReader) -> Result<Self, DecodeError> {
        Ok(Mx{
            preference: try!(data.read_u16()),
            exchange: try!(data.read_name()),
        })
    }

    fn encode(&self, data: &mut MsgWriter) -> Result<(), EncodeError> {
        try!(data.write_u16(self.preference));
        data.write_name(&self.exchange)
    }

    fn record_type() -> RecordType { RecordType::Mx }
}

/// Authoritative name server
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ns {
    /// Host which should be authoritative for the specified class and domain
    pub name: String,
}

impl Record for Ns {
    fn decode(data: &mut MsgReader) -> Result<Self, DecodeError> {
        Ok(Ns{name: try!(data.read_name())})
    }

    fn encode(&self, data: &mut MsgWriter) -> Result<(), EncodeError> {
        data.write_name(&self.name)
    }

    fn record_type() -> RecordType { RecordType::Ns }
}

/// Domain name pointer
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Ptr {
    /// The name of the host
    pub name: String,
}

impl Record for Ptr {
    fn decode(data: &mut MsgReader) -> Result<Self, DecodeError> {
        Ok(Ptr{name: try!(data.read_name())})
    }

    fn encode(&self, data: &mut MsgWriter) -> Result<(), EncodeError> {
        data.write_name(&self.name)
    }

    fn record_type() -> RecordType { RecordType::Ptr }
}

/// Start of authority
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Soa {
    /// Domain name of the name server that was the original or primary source
    /// of data for this zone.
    pub mname: String,
    /// Domain name which specifies the mailbox of the person responsible
    /// for this zone.
    pub rname: String,
    /// Version number of the original copy of the zone. This value wraps and
    /// should be compared using sequence space arithmetic.
    pub serial: u32,
    /// Time interval before the zone should be refreshed.
    pub refresh: u32,
    /// Time interval that should elapse before a failed refresh should be retried.
    pub retry: u32,
    /// Time value that specifies the upper limit on the time interval that can
    /// elapse before the zone is no longer authoritative.
    pub expire: u32,
    /// Minimum TTL that should be exported with any resource record from this zone.
    pub minimum: u32,
}

impl Record for Soa {
    fn decode(data: &mut MsgReader) -> Result<Self, DecodeError> {
        Ok(Soa{
            mname: try!(data.read_name()),
            rname: try!(data.read_name()),
            serial: try!(data.read_u32()),
            refresh: try!(data.read_u32()),
            retry: try!(data.read_u32()),
            expire: try!(data.read_u32()),
            minimum: try!(data.read_u32()),
        })
    }

    fn encode(&self, data: &mut MsgWriter) -> Result<(), EncodeError> {
        try!(data.write_name(&self.mname));
        try!(data.write_name(&self.rname));
        try!(data.write_u32(self.serial));
        try!(data.write_u32(self.refresh));
        try!(data.write_u32(self.retry));
        try!(data.write_u32(self.expire));
        try!(data.write_u32(self.minimum));
        Ok(())
    }

    fn record_type() -> RecordType { RecordType::Soa }
}

/// Service record
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Srv {
    /// Record priority
    pub priority: u16,
    /// Record weight
    pub weight: u16,
    /// Service port
    pub port: u16,
    /// Target host name
    pub target: String,
}

impl Record for Srv {
    fn decode(data: &mut MsgReader) -> Result<Self, DecodeError> {
        Ok(Srv{
            priority: try!(data.read_u16()),
            weight: try!(data.read_u16()),
            port: try!(data.read_u16()),
            target: try!(data.read_name()),
        })
    }

    fn encode(&self, data: &mut MsgWriter) -> Result<(), EncodeError> {
        try!(data.write_u16(self.priority));
        try!(data.write_u16(self.weight));
        try!(data.write_u16(self.port));
        try!(data.write_name(&self.target));
        Ok(())
    }

    fn record_type() -> RecordType { RecordType::Srv }
}

/// Text record
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Txt {
    /// One or more character strings
    pub data: Vec<u8>,
}

impl Record for Txt {
    fn decode(data: &mut MsgReader) -> Result<Self, DecodeError> {
        Ok(Txt{data: try!(data.read_character_string())})
    }

    fn encode(&self, data: &mut MsgWriter) -> Result<(), EncodeError> {
        data.write_character_string(&self.data)
    }

    fn record_type() -> RecordType { RecordType::Txt }
}
