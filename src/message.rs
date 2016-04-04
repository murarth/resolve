//! Utilities for composing, decoding, and encoding messages.

use std::ascii::AsciiExt;
use std::cell::Cell;
use std::default::Default;
use std::fmt;
use std::io::{Cursor, Read, Write};
use std::mem::{transmute, zeroed};
use std::slice::Iter;
use std::str::from_utf8_unchecked;
use std::vec::IntoIter;

use rand::random;

use idna;
use record::{Class, Record, RecordType};

/// Maximum size of a DNS message, in bytes.
pub const MESSAGE_LIMIT: usize = 512;

/// Maximum length of a name segment (i.e. a `.`-separated identifier).
pub const LABEL_LIMIT: usize = 63;

/// Maximum total length of a name, in encoded format.
pub const NAME_LIMIT: usize = 255;

/// An error response code received in a response message.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DnsError(pub RCode);

impl fmt::Display for DnsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.0.get_error())
    }
}

/// Represents an error in decoding a DNS message.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// Extraneous data encountered at the end of message
    ExtraneousData,
    /// Message end was encountered before expected
    ShortMessage,
    /// Unable to decode invalid data
    InvalidMessage,
    /// An invalid name was encountered
    InvalidName,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match *self {
            DecodeError::ExtraneousData => "extraneous data",
            DecodeError::ShortMessage => "short message",
            DecodeError::InvalidMessage => "invalid message",
            DecodeError::InvalidName => "invalid name",
        })
    }
}

/// Represents an error in encoding a DNS message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// A name or label was too long or contained invalid characters
    InvalidName,
    /// Message exceeded given buffer or `MESSAGE_LIMIT` bytes
    TooLong,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            EncodeError::InvalidName => f.write_str("invalid name value"),
            EncodeError::TooLong => f.write_str("message too long"),
        }
    }
}

/// Reads a single DNS message from a series of bytes.
pub struct MsgReader<'a> {
    data: Cursor<&'a [u8]>,
}

impl<'a> MsgReader<'a> {
    /// Constructs a new message reader.
    pub fn new(data: &[u8]) -> MsgReader {
        MsgReader{data: Cursor::new(data)}
    }

    /// Returns the number of bytes remaining in the message.
    pub fn remaining(&self) -> usize {
        self.data.get_ref().len() - self.data.position() as usize
    }

    /// Reads a number of bytes equal to the length of the given buffer.
    /// Returns `Err(ShortMessage)` if there are not enough bytes remaining.
    pub fn read(&mut self, buf: &mut [u8]) -> Result<(), DecodeError> {
        match self.data.read(buf) {
            Ok(n) if n == buf.len() => Ok(()),
            _ => Err(DecodeError::ShortMessage),
        }
    }

    /// Reads a single byte from the message.
    pub fn read_byte(&mut self) -> Result<u8, DecodeError> {
        let mut buf = [0];
        try!(self.read(&mut buf));
        Ok(buf[0])
    }

    /// Reads all remaining bytes.
    pub fn read_to_end(&mut self) -> Result<Vec<u8>, DecodeError> {
        let mut res = Vec::with_capacity(self.remaining());
        res.resize(self.remaining(), 0);
        try!(self.read(&mut res));
        Ok(res)
    }

    /// Read a character-string.
    ///
    /// According to RFC 1035:
    ///
    /// > <character-string> is a single length octet followed
    /// > by that number of characters. <character-string> is
    /// > treated as binary information, and can be up to 256
    /// > characters in length (including the length octet).
    pub fn read_character_string(&mut self) -> Result<Vec<u8>, DecodeError> {
        let length_octet = try!(self.read_byte()) as usize;
        let mut res = Vec::with_capacity(length_octet);
        res.resize(length_octet, 0);
        try!(self.read(&mut res));
        Ok(res)
    }

    /// Reads a big-endian unsigned 16 bit integer.
    pub fn read_u16(&mut self) -> Result<u16, DecodeError> {
        let mut buf = [0; 2];
        try!(self.read(&mut buf));
        Ok(u16::from_be(unsafe { transmute(buf) }))
    }

    /// Reads a big-endian unsigned 32 bit integer.
    pub fn read_u32(&mut self) -> Result<u32, DecodeError> {
        let mut buf = [0; 4];
        try!(self.read(&mut buf));
        Ok(u32::from_be(unsafe { transmute(buf) }))
    }

    /// Reads `n` bytes, which are inserted at the end of the given buffer.
    pub fn read_into(&mut self, buf: &mut Vec<u8>, n: usize) -> Result<(), DecodeError> {
        let len = buf.len();
        buf.resize(len + n, 0);
        self.read(&mut buf[len..])
    }

    /// Reads a name from the message.
    pub fn read_name(&mut self) -> Result<String, DecodeError> {
        // Start position, used to check against pointer references
        let start_pos = self.data.position();
        // Offset to return to if we've finished parsing a pointer reference
        let mut restore = None;

        let mut res = String::new();
        let mut total_read = 0;

        loop {
            let len = try!(self.read_byte());

            if len == 0 {
                if total_read + 1 > NAME_LIMIT {
                    return Err(DecodeError::InvalidName);
                }
                break;
            }

            if len & 0b11000000 == 0b11000000 {
                // The beginning of a pointer reference
                let hi = (len & 0b00111111) as u64;
                let lo = try!(self.read_byte()) as u64;
                let offset = (hi << 8) | lo;

                // To prevent an infinite loop, we require the pointer to
                // point before the start of this name.
                if offset >= start_pos {
                    return Err(DecodeError::InvalidName);
                }

                if restore.is_none() {
                    restore = Some(self.data.position());
                }

                self.data.set_position(offset);
                continue;
            } else if len & 0b11000000 != 0 {
                return Err(DecodeError::InvalidMessage);
            }

            if total_read + 1 + len as usize > NAME_LIMIT {
                return Err(DecodeError::InvalidName);
            }
            total_read += 1 + len as usize;

            try!(self.read_segment(&mut res, len as usize));
        }

        if res.is_empty() {
            res.push('.');
        } else {
            res.shrink_to_fit();
        }

        if let Some(pos) = restore {
            self.data.set_position(pos);
        }

        Ok(res)
    }

    fn read_segment(&mut self, buf: &mut String, len: usize) -> Result<(), DecodeError> {
        let mut bytes = [0; 64];

        try!(self.read(&mut bytes[..len]));

        let seg = &bytes[..len];

        if !seg.is_ascii() {
            return Err(DecodeError::InvalidName);
        }

        // We just verified this was ASCII, so it's safe.
        let s = unsafe { from_utf8_unchecked(seg) };

        if !is_valid_segment(s) {
            return Err(DecodeError::InvalidName);
        }

        let label = match idna::to_unicode(s) {
            Ok(s) => s,
            Err(_) => return Err(DecodeError::InvalidName)
        };

        buf.push_str(&label);
        buf.push('.');
        Ok(())
    }

    /// Called at the end of message parsing. Returns `Err(ExtraneousData)`
    /// if there are any unread bytes remaining.
    fn finish(self) -> Result<(), DecodeError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(DecodeError::ExtraneousData)
        }
    }

    /// Reads a message header
    fn read_header(&mut self) -> Result<FullHeader, DecodeError> {
        let mut buf = [0; 12];

        try!(self.read(&mut buf));

        let hdr: HeaderData = unsafe { transmute(buf) };

        let id = u16::from_be(hdr.id);

        // 1 bit: query or response flag
        let qr = hdr.flags0 & 0b10000000;
        // 4 bits: opcode
        let op = hdr.flags0 & 0b01111000;
        // 1 bit: authoritative answer flag
        let aa = hdr.flags0 & 0b00000100;
        // 1 bit: truncation flag
        let tc = hdr.flags0 & 0b00000010;
        // 1 bit: recursion desired flag
        let rd = hdr.flags0 & 0b00000001;

        // 1 bit: recursion available flag
        let ra = hdr.flags1 & 0b10000000;
        // 3 bits: reserved for future use
        //     = hdr.flags1 & 0b01110000;
        // 4 bits: response code
        let rc = hdr.flags1 & 0b00001111;

        let qd_count = u16::from_be(hdr.qd_count);
        let an_count = u16::from_be(hdr.an_count);
        let ns_count = u16::from_be(hdr.ns_count);
        let ar_count = u16::from_be(hdr.ar_count);

        Ok(FullHeader{
            id: id,
            qr: if qr == 0 { Qr::Query } else { Qr::Response },
            op: OpCode::from_u8(op),
            authoritative: aa != 0,
            truncated: tc != 0,
            recursion_desired: rd != 0,
            recursion_available: ra != 0,
            rcode: RCode::from_u8(rc),
            qd_count: qd_count,
            an_count: an_count,
            ns_count: ns_count,
            ar_count: ar_count,
        })
    }

    /// Reads a question item
    fn read_question(&mut self) -> Result<Question, DecodeError> {
        let name = try!(self.read_name());

        let mut buf = [0; 4];

        try!(self.read(&mut buf));

        let msg: QuestionData = unsafe { transmute(buf) };

        let q_type = u16::from_be(msg.q_type);
        let q_class = u16::from_be(msg.q_class);

        Ok(Question{
            name: name,
            q_type: RecordType::from_u16(q_type),
            q_class: Class::from_u16(q_class),
        })
    }

    /// Reads a resource record item
    fn read_resource(&mut self) -> Result<Resource, DecodeError> {
        let name = try!(self.read_name());

        let mut buf = [0; 10];

        try!(self.read(&mut buf));

        let msg: ResourceData = unsafe { transmute(buf) };

        let r_type = u16::from_be(msg.r_type);
        let r_class = u16::from_be(msg.r_class);
        let ttl = u32::from_be(msg.ttl);
        let length = u16::from_be(msg.length);

        let mut r_data = Vec::new();
        try!(self.read_into(&mut r_data, length as usize));

        Ok(Resource{
            name: name,
            r_type: RecordType::from_u16(r_type),
            r_class: Class::from_u16(r_class),
            ttl: ttl,
            data: r_data,
        })
    }
}

/// Writes a single DNS message as a series of bytes.
pub struct MsgWriter<'a> {
    data: Cursor<&'a mut [u8]>,
}

impl<'a> MsgWriter<'a> {
    /// Constructs a new message writer that will write into the given byte slice.
    pub fn new(data: &mut [u8]) -> MsgWriter {
        MsgWriter{data: Cursor::new(data)}
    }

    /// Returns the number of bytes written so far.
    pub fn written(&self) -> usize {
        self.data.position() as usize
    }

    /// Returns a subslice of the wrapped byte slice that contains only the
    /// bytes written.
    pub fn into_bytes(self) -> &'a [u8] {
        let n = self.written();
        &self.data.into_inner()[..n]
    }

    /// Writes a series of bytes to the message. Returns `Err(TooLong)` if the
    /// whole buffer cannot be written.
    pub fn write(&mut self, data: &[u8]) -> Result<(), EncodeError> {
        if self.written() + data.len() > MESSAGE_LIMIT {
            // No matter the size of the buffer,
            // we always want to stop at the hard-coded message limit.
            Err(EncodeError::TooLong)
        } else {
            self.data.write_all(data).map_err(|_| EncodeError::TooLong)
        }
    }

    /// Writes a name to the message.
    pub fn write_name(&mut self, name: &str) -> Result<(), EncodeError> {
        if !is_valid_name(name) {
            Err(EncodeError::InvalidName)
        } else if name == "." {
            self.write_byte(0)
        } else {
            let mut total_len = 0;

            for seg in name.split('.') {
                let seg = match idna::to_ascii(seg) {
                    Ok(seg) => seg,
                    Err(_) => return Err(EncodeError::InvalidName)
                };

                if !is_valid_segment(&seg) {
                    return Err(EncodeError::InvalidName);
                }

                if seg.len() > LABEL_LIMIT {
                    return Err(EncodeError::InvalidName);
                }

                // Add the size octet and the segment length
                total_len += 1 + seg.len();

                if total_len > NAME_LIMIT {
                    return Err(EncodeError::InvalidName);
                }

                try!(self.write_byte(seg.len() as u8));
                try!(self.write(seg.as_bytes()));
            }

            if !name.ends_with('.') {
                if total_len + 1 > NAME_LIMIT {
                    return Err(EncodeError::InvalidName);
                }
                try!(self.write_byte(0));
            }

            Ok(())
        }
    }

    /// Writes a single byte to the message.
    pub fn write_byte(&mut self, data: u8) -> Result<(), EncodeError> {
        self.write(&[data])
    }

    /// Writes an unsigned 16 bit integer in big-endian format.
    pub fn write_u16(&mut self, data: u16) -> Result<(), EncodeError> {
        let data: [u8; 2] = unsafe { transmute(data.to_be()) };
        self.write(&data)
    }

    /// Writes an unsigned 32 bit integer in big-endian format.
    pub fn write_u32(&mut self, data: u32) -> Result<(), EncodeError> {
        let data: [u8; 4] = unsafe { transmute(data.to_be()) };
        self.write(&data)
    }

    /// Writes a message header
    fn write_header(&mut self, header: &FullHeader) -> Result<(), EncodeError> {
        let mut hdr: HeaderData = unsafe { zeroed() };

        // 2 bytes: message ID
        hdr.id = header.id.to_be();

        // 1 bit: query or response flag
        hdr.flags0 |= (header.qr as u8 & 1) << 7;
        // 4 bits: opcode
        hdr.flags0 |= (header.op.to_u8() & 0b1111) << 3;
        // 1 bit: authoritative answer flag
        hdr.flags0 |= (header.authoritative as u8) << 2;
        // 1 bit: truncation flag
        hdr.flags0 |= (header.truncated as u8) << 1;
        // 1 bit: recursion desired flag
        hdr.flags0 |= header.recursion_desired as u8;

        // 1 bit: recursion available flag
        hdr.flags1 |= (header.recursion_available as u8) << 7;
        // 3 bits: reserved for future use
        // .flags1 |= (0 as u8 & 0b111) << 4;
        // 4 bits: response code
        hdr.flags1 |= header.rcode.to_u8() & 0b1111;

        hdr.qd_count = header.qd_count.to_be();
        hdr.an_count = header.an_count.to_be();
        hdr.ns_count = header.ns_count.to_be();
        hdr.ar_count = header.ar_count.to_be();

        let buf: [u8; 12] = unsafe { transmute(hdr) };

        self.write(&buf)
    }

    /// Writes a question item
    fn write_question(&mut self, question: &Question) -> Result<(), EncodeError> {
        try!(self.write_name(&question.name));

        let mut qd: QuestionData = unsafe { zeroed() };

        qd.q_type = question.q_type.to_u16().to_be();
        qd.q_class = question.q_class.to_u16().to_be();

        let buf: [u8; 4] = unsafe { transmute(qd) };

        self.write(&buf)
    }

    /// Writes a resource record item
    fn write_resource(&mut self, resource: &Resource) -> Result<(), EncodeError> {
        try!(self.write_name(&resource.name));

        let mut rd: ResourceData = unsafe { zeroed() };

        rd.r_type = resource.r_type.to_u16().to_be();
        rd.r_class = resource.r_class.to_u16().to_be();
        rd.ttl = resource.ttl.to_be();
        rd.length = try!(to_u16(resource.data.len()));

        let buf: [u8; 10] = unsafe { transmute(rd) };

        try!(self.write(&buf));
        self.write(&resource.data)
    }
}

/// Returns a sequential ID value from a thread-local random starting value.
pub fn generate_id() -> u16 {
    // It's not really necessary for these to be sequential, but it avoids the
    // 1-in-65536 chance of producing the same random number twice in a row.
    thread_local!(static ID: Cell<u16> = Cell::new(random()));
    ID.with(|id| {
        let value = id.get();
        id.set(value.wrapping_add(1));
        value
    })
}

/// Returns whether the given string appears to be a valid hostname.
/// The contents of the name (i.e. characters in labels) are not checked here;
/// only the structure of the name is validated.
fn is_valid_name(name: &str) -> bool {
    let len = name.len();
    len != 0 && (len == 1 || !name.starts_with('.')) && !name.contains("..")
}

/// Returns whether the given string constitutes a valid name segment.
/// This check is not as strict as internet DNS servers will be. It only checks
/// for basic sanity of input. If an invalid name is given, a DNS server will
/// respond that it doesn't exist, anyway.
fn is_valid_segment(s: &str) -> bool {
    !(s.starts_with('-') || s.ends_with('-')) &&
        s.chars().all(|c| !(c.is_whitespace() || c.is_control()))
}

/// Represents a DNS message.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Message {
    /// Describes the content of the remainder of the message.
    pub header: Header,
    /// Carries the question of query type messages.
    pub question: Vec<Question>,
    /// Resource records that answer the query
    pub answer: Vec<Resource>,
    /// Resource records that point to an authoritative name server
    pub authority: Vec<Resource>,
    /// Resource records that relate to the query, but are not strictly
    /// answers for the question.
    pub additional: Vec<Resource>,
}

impl Message {
    /// Constructs a new `Message` with a random id value.
    pub fn new() -> Message {
        Message{
            header: Header::new(),
            ..Default::default()
        }
    }

    /// Constructs a new `Message` with the given id value.
    pub fn with_id(id: u16) -> Message {
        Message{
            header: Header::with_id(id),
            ..Default::default()
        }
    }

    /// Decodes a message from a series of bytes.
    pub fn decode(data: &[u8]) -> Result<Message, DecodeError> {
        let mut r = MsgReader::new(data);

        let header = try!(r.read_header());
        let mut msg = Message{
            header: header.to_header(),
            // TODO: Cap these values to prevent abuse?
            question:   Vec::with_capacity(header.qd_count as usize),
            answer:     Vec::with_capacity(header.an_count as usize),
            authority:  Vec::with_capacity(header.ns_count as usize),
            additional: Vec::with_capacity(header.ar_count as usize),
        };

        for _ in 0..header.qd_count {
            msg.question.push(try!(r.read_question()));
        }

        for _ in 0..header.an_count {
            msg.answer.push(try!(r.read_resource()));
        }

        for _ in 0..header.ns_count {
            msg.authority.push(try!(r.read_resource()));
        }

        for _ in 0..header.ar_count {
            msg.additional.push(try!(r.read_resource()));
        }

        try!(r.finish());
        Ok(msg)
    }

    /// Encodes a message to a series of bytes. On success, returns a subslice
    /// of the given buffer containing only the encoded message bytes.
    pub fn encode<'a>(&self, buf: &'a mut [u8]) -> Result<&'a [u8], EncodeError> {
        let mut w = MsgWriter::new(buf);
        let hdr = &self.header;

        let header = FullHeader{
            id: hdr.id,
            qr: hdr.qr,
            op: hdr.op,
            authoritative: hdr.authoritative,
            truncated: hdr.truncated,
            recursion_desired: hdr.recursion_desired,
            recursion_available: hdr.recursion_available,
            rcode: hdr.rcode,
            qd_count: try!(to_u16(self.question.len())),
            an_count: try!(to_u16(self.answer.len())),
            ns_count: try!(to_u16(self.authority.len())),
            ar_count: try!(to_u16(self.additional.len())),
        };

        try!(w.write_header(&header));

        for q in &self.question {
            try!(w.write_question(q));
        }
        for r in &self.answer {
            try!(w.write_resource(r));
        }
        for r in &self.authority {
            try!(w.write_resource(r));
        }
        for r in &self.additional {
            try!(w.write_resource(r));
        }

        Ok(w.into_bytes())
    }

    /// Returns a `DnsError` if the message response code is an error.
    pub fn get_error(&self) -> Result<(), DnsError> {
        if self.header.rcode == RCode::NoError {
            Ok(())
        } else {
            Err(DnsError(self.header.rcode))
        }
    }

    /// Returns an iterator over the records in this message.
    pub fn records(&self) -> RecordIter {
        RecordIter{
            iters: [
                self.answer.iter(),
                self.authority.iter(),
                self.additional.iter(),
            ]
        }
    }

    /// Consumes the message and returns an iterator over its records.
    pub fn into_records(self) -> RecordIntoIter {
        RecordIntoIter{
            iters: [
                self.answer.into_iter(),
                self.authority.into_iter(),
                self.additional.into_iter(),
            ]
        }
    }
}

/// Yields `&Resource` items from a Message.
pub struct RecordIter<'a> {
    iters: [Iter<'a, Resource>; 3],
}

impl<'a> Iterator for RecordIter<'a> {
    type Item = &'a Resource;

    fn next(&mut self) -> Option<&'a Resource> {
        self.iters[0].next()
            .or_else(|| self.iters[1].next())
            .or_else(|| self.iters[2].next())
    }
}

/// Yields `Resource` items from a Message.
pub struct RecordIntoIter {
    iters: [IntoIter<Resource>; 3],
}

impl Iterator for RecordIntoIter {
    type Item = Resource;

    fn next(&mut self) -> Option<Resource> {
        self.iters[0].next()
            .or_else(|| self.iters[1].next())
            .or_else(|| self.iters[2].next())
    }
}

/// Represents a message header.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Header {
    /// Transaction ID; corresponding replies will have the same ID.
    pub id: u16,
    /// Query or response
    pub qr: Qr,
    /// Kind of query
    pub op: OpCode,
    /// In a response, indicates that the responding name server is an authority
    /// for the domain name in question section.
    pub authoritative: bool,
    /// Indicates whether the message was truncated due to length greater than
    /// that permitted on the transmission channel.
    pub truncated: bool,
    /// In a query, directs the name server to pursue the query recursively.
    pub recursion_desired: bool,
    /// In a response, indicates whether recursive queries are available on the
    /// name server.
    pub recursion_available: bool,
    /// Response code
    pub rcode: RCode,
}

impl Header {
    /// Constructs a new `Header` with a random id value.
    pub fn new() -> Header {
        Header{
            id: generate_id(),
            ..Default::default()
        }
    }

    /// Constructs a new `Header` with the given id value.
    pub fn with_id(id: u16) -> Header {
        Header{
            id: id,
            ..Default::default()
        }
    }
}

impl Default for Header {
    fn default() -> Header {
        Header{
            id: 0,
            qr: Qr::Query,
            op: OpCode::Query,
            authoritative: false,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            rcode: RCode::NoError,
        }
    }
}

/// Contains all header data decoded from a message.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct FullHeader {
    pub id: u16,
    pub qr: Qr,
    pub op: OpCode,
    pub authoritative: bool,
    pub truncated: bool,
    pub recursion_desired: bool,
    pub recursion_available: bool,
    pub rcode: RCode,
    pub qd_count: u16,
    pub an_count: u16,
    pub ns_count: u16,
    pub ar_count: u16,
}

impl FullHeader {
    fn to_header(&self) -> Header {
        Header{
            id: self.id,
            qr: self.qr,
            op: self.op,
            authoritative: self.authoritative,
            truncated: self.truncated,
            recursion_desired: self.recursion_desired,
            recursion_available: self.recursion_available,
            rcode: self.rcode,
        }
    }
}

impl Default for FullHeader {
    fn default() -> FullHeader {
        FullHeader{
            id: 0,
            qr: Qr::Query,
            op: OpCode::Query,
            authoritative: false,
            truncated: false,
            recursion_desired: false,
            recursion_available: false,
            rcode: RCode::NoError,
            qd_count: 0,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        }
    }
}

/// Represents a question item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Question {
    /// Query name
    pub name: String,
    /// Query type
    pub q_type: RecordType,
    /// Query class
    pub q_class: Class,
}

impl Question {
    /// Constructs a new `Question`.
    pub fn new(name: String, q_type: RecordType, q_class: Class) -> Question {
        Question{
            name: name,
            q_type: q_type,
            q_class: q_class,
        }
    }
}

/// Represents a resource record item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resource {
    /// Resource name
    pub name: String,
    /// Resource type
    pub r_type: RecordType,
    /// Resource class
    pub r_class: Class,
    /// Time-to-live
    pub ttl: u32,
    /// Record data
    pub data: Vec<u8>,
}

impl Resource {
    /// Constructs a new `Resource`.
    pub fn new(name: String, r_type: RecordType,
            r_class: Class, ttl: u32) -> Resource {
        Resource{
            name: name,
            r_type: r_type,
            r_class: r_class,
            ttl: ttl,
            data: Vec::new(),
        }
    }

    /// Decodes resource data into the given `Record` type.
    pub fn read_rdata<R: Record>(&self) -> Result<R, DecodeError> {
        let mut r = MsgReader::new(&self.data);
        let res = try!(Record::decode(&mut r));
        try!(r.finish());
        Ok(res)
    }

    /// Encodes resource data from the given `Record` type.
    pub fn write_rdata<R: Record>(&mut self, record: &R) -> Result<(), EncodeError> {
        let mut buf = [0; MESSAGE_LIMIT];
        let mut w = MsgWriter::new(&mut buf[..]);
        try!(record.encode(&mut w));
        self.data = w.into_bytes().to_vec();
        Ok(())
    }
}

/// Indicates a message is either a query or response.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Qr {
    /// Query
    Query = 0,
    /// Response
    Response = 1,
}

/// Represents the kind of message query.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum OpCode {
    /// Query
    Query,
    /// Status
    Status,
    /// Notify
    Notify,
    /// Update
    Update,
    /// Unrecognized opcode
    Other(u8),
}

impl OpCode {
    /// Converts a `u8` to an `OpCode`.
    pub fn from_u8(u: u8) -> OpCode {
        match u {
            0 => OpCode::Query,
            2 => OpCode::Status,
            4 => OpCode::Notify,
            5 => OpCode::Update,
            n => OpCode::Other(n),
        }
    }

    /// Converts an `OpCode` to a `u8`.
    pub fn to_u8(&self) -> u8 {
        match *self {
            OpCode::Query => 0,
            OpCode::Status => 2,
            OpCode::Notify => 4,
            OpCode::Update => 5,
            OpCode::Other(n) => n,
        }
    }
}

/// Represents the response code of a message
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum RCode {
    /// No error condition.
    NoError,
    /// The server was unable to interpret the query.
    FormatError,
    /// The name server was unable to process the query due to a failure of
    /// the name server.
    ServerFailure,
    /// Name referenced in query does not exist.
    NameError,
    /// Requested query kind is not supported by name server.
    NotImplemented,
    /// The name server refuses to perform the specified operation for policy
    /// reasons.
    Refused,
    /// Unknown response code.
    Other(u8),
}

impl RCode {
    /// Returns an error string for the response code.
    pub fn get_error(&self) -> &'static str {
        match *self {
            RCode::NoError => "no error",
            RCode::FormatError => "format error",
            RCode::ServerFailure => "server failure",
            RCode::NameError => "no such name",
            RCode::NotImplemented => "not implemented",
            RCode::Refused => "refused",
            RCode::Other(_) => "unknown response code",
        }
    }

    /// Converts a `u8` to an `RCode`.
    pub fn from_u8(u: u8) -> RCode {
        match u {
            0 => RCode::NoError,
            1 => RCode::FormatError,
            2 => RCode::ServerFailure,
            3 => RCode::NameError,
            4 => RCode::NotImplemented,
            5 => RCode::Refused,
            n => RCode::Other(n),
        }
    }

    /// Converts an `RCode` to a `u8`.
    pub fn to_u8(&self) -> u8 {
        match *self {
            RCode::NoError => 0,
            RCode::FormatError => 1,
            RCode::ServerFailure => 2,
            RCode::NameError => 3,
            RCode::NotImplemented => 4,
            RCode::Refused => 5,
            RCode::Other(n) => n,
        }
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
struct HeaderData {
    id: u16,
    flags0: u8,
    flags1: u8,
    qd_count: u16,
    an_count: u16,
    ns_count: u16,
    ar_count: u16,
}

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
struct QuestionData {
    // name: String, -- dynamically sized
    q_type: u16,
    q_class: u16,
}

#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
struct ResourceData {
    // name: String, -- dynamically sized
    r_type: u16,
    r_class: u16,
    ttl: u32,
    length: u16,
}

fn to_u16(n: usize) -> Result<u16, EncodeError> {
    if n > u16::max_value() as usize {
        Err(EncodeError::TooLong)
    } else {
        Ok(n as u16)
    }
}

#[cfg(test)]
mod test {
    use super::{is_valid_name, EncodeError};
    use super::{Header, Message, Question, Qr, OpCode, RCode};
    use super::{MsgReader, MsgWriter};
    use record::{Class, RecordType};

    #[test]
    fn test_idna_name() {
        let mut buf = [0; 64];
        let mut w = MsgWriter::new(&mut buf);

        w.write_name("bücher.de.").unwrap();
        w.write_name("ουτοπία.δπθ.gr.").unwrap();

        let bytes = w.into_bytes();

        assert_eq!(bytes, &b"\
            \x0dxn--bcher-kva\x02de\x00\
            \x0exn--kxae4bafwg\x09xn--pxaix\x02gr\x00\
            "[..]);

        let mut r = MsgReader::new(&bytes);

        assert_eq!(r.read_name().as_ref().map(|s| &s[..]), Ok("bücher.de."));
        assert_eq!(r.read_name().as_ref().map(|s| &s[..]), Ok("ουτοπία.δπθ.gr."));
    }

    #[test]
    fn test_message() {
        let msg = Message{
            header: Header{
                id: 0xabcd,
                qr: Qr::Query,
                op: OpCode::Query,
                authoritative: false,
                truncated: false,
                recursion_desired: true,
                recursion_available: true,
                rcode: RCode::NoError,
            },
            question: vec![
                Question::new("foo.bar.com.".to_owned(),
                    RecordType::A, Class::Internet)
            ],
            answer: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        };

        let mut buf = [0; 64];
        let bytes = msg.encode(&mut buf).unwrap();

        assert_eq!(bytes,
            &[0xab, 0xcd,
                0b00000001, 0b10000000,
                0, 1, 0, 0, 0, 0, 0, 0,
                3, b'f', b'o', b'o',
                3, b'b', b'a', b'r',
                3, b'c', b'o', b'm', 0,
                0, 1, 0, 1][..]);

        let msg2 = Message::decode(&bytes).unwrap();

        assert_eq!(msg, msg2);
    }

    #[test]
    fn test_primitives() {
        let mut buf = [0; 64];
        let mut w = MsgWriter::new(&mut buf);

        w.write_byte(0x11).unwrap();
        w.write_u16(0x2233).unwrap();
        w.write_u32(0x44556677).unwrap();
        w.write_name("alpha.bravo.charlie").unwrap();
        w.write_name("delta.echo.foxtrot.").unwrap();
        w.write_name(".").unwrap();

        assert_eq!(w.write_name(""), Err(EncodeError::InvalidName));
        assert_eq!(w.write_name(
            "ohmyglobhowdidthisgethereiamnotgoodwithcomputerrrrrrrrrrrrrrrrrr.org"),
            Err(EncodeError::InvalidName));

        let bytes = w.into_bytes();

        assert_eq!(bytes, &b"\
            \x11\
            \x22\x33\
            \x44\x55\x66\x77\
            \x05alpha\x05bravo\x07charlie\x00\
            \x05delta\x04echo\x07foxtrot\x00\
            \x00"[..]);

        let mut r = MsgReader::new(&bytes);

        assert_eq!(r.read_byte(), Ok(0x11));
        assert_eq!(r.read_u16(), Ok(0x2233));
        assert_eq!(r.read_u32(), Ok(0x44556677));
        assert_eq!(r.read_name().as_ref().map(|s| &s[..]), Ok("alpha.bravo.charlie."));
        assert_eq!(r.read_name().as_ref().map(|s| &s[..]), Ok("delta.echo.foxtrot."));
        assert_eq!(r.read_name().as_ref().map(|s| &s[..]), Ok("."));
    }

    const LONGEST_NAME: &'static str =
        "aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaa\
         .com";
    const LONGEST_NAME_DOT: &'static str =
        "aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaa\
         .com.";
    const TOO_LONG_NAME: &'static str =
        "aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaa\
         .com";
    const TOO_LONG_NAME_DOT: &'static str =
        "aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaa\
         .com.";
    const TOO_LONG_SEGMENT: &'static str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
         aaaaaaaaaaaaaa.com";

    #[test]
    fn test_encode_name() {
        let mut buf = [0; 512];
        let mut w = MsgWriter::new(&mut buf);

        w.write_name(LONGEST_NAME).unwrap();
        w.write_name(LONGEST_NAME_DOT).unwrap();

        let bytes = w.into_bytes();
        let mut r = MsgReader::new(&bytes);

        assert_eq!(r.read_name().as_ref().map(|s| &s[..]), Ok(LONGEST_NAME_DOT));
        assert_eq!(r.read_name().as_ref().map(|s| &s[..]), Ok(LONGEST_NAME_DOT));

        let mut buf = [0; 512];
        let mut w = MsgWriter::new(&mut buf);

        assert_eq!(w.write_name(TOO_LONG_NAME), Err(EncodeError::InvalidName));
        assert_eq!(w.write_name(TOO_LONG_NAME_DOT), Err(EncodeError::InvalidName));
        assert_eq!(w.write_name(TOO_LONG_SEGMENT), Err(EncodeError::InvalidName));
    }

    #[test]
    fn test_valid_name() {
        assert!(is_valid_name("."));
        assert!(is_valid_name("foo.com."));
        assert!(is_valid_name("foo-123.com."));
        assert!(is_valid_name("FOO-BAR.COM"));

        assert!(!is_valid_name(""));
        assert!(!is_valid_name(".foo.com"));
        assert!(!is_valid_name("foo..bar.com"));
    }
}
