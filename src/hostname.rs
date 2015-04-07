//! System hostname detection

use std::ffi::CStr;
use std::io;
use std::str::from_utf8;

use libc::{c_char, c_int, size_t};

extern "system" {
    fn gethostname(name: *mut c_char, len: size_t) -> c_int;
}

/// Returns the system hostname.
pub fn get_hostname() -> io::Result<String> {
    let mut buf = [0 as c_char; 256];
    let res = unsafe { gethostname(buf.as_mut_ptr(), buf.len() as size_t) };

    match res {
        -1 => Err(io::Error::last_os_error()),
        _ => {
            let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
            match from_utf8(s.to_bytes()) {
                Ok(s) => Ok(s.to_string()),
                Err(_) => Err(io::Error::new(
                    io::ErrorKind::Other, "invalid hostname"))
            }
        }
    }
}
