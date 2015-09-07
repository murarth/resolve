//! Domain Name System (DNS) communication protocol.

#![feature(ip_addr, socket_timeout, vec_resize)]

extern crate libc;
extern crate rand;

pub use address::address_name;
pub use idna::{host_to_ascii, host_to_unicode};
pub use message::{DecodeError, EncodeError, Message, Question, Resource};
pub use record::{Class, Record, RecordType};
pub use resolver::{resolve_addr, resolve_host, DnsResolver};
pub use socket::{DnsSocket, Error};

pub mod address;
pub mod config;
pub mod hostname;
pub mod idna;
pub mod message;
pub mod record;
#[cfg(unix)] pub mod resolv_conf;
pub mod resolver;
pub mod socket;
