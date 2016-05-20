//! Domain Name System (DNS) communication protocol.

#![deny(missing_docs)]

extern crate idna as external_idna;
extern crate libc;
#[macro_use] extern crate log;
extern crate rand;

pub use address::address_name;
pub use config::{default_config, DnsConfig};
pub use idna::{to_ascii, to_unicode};
pub use message::{DecodeError, EncodeError, Message, Question, Resource,
    MESSAGE_LIMIT};
pub use record::{Class, Record, RecordType};
pub use resolver::{resolve_addr, resolve_host, DnsResolver};
pub use socket::{DnsSocket, Error};

pub mod address;
pub mod config;
pub mod hosts;
pub mod hostname;
pub mod idna;
pub mod message;
pub mod record;
#[cfg(unix)] pub mod resolv_conf;
pub mod resolver;
pub mod socket;
