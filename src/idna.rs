//! Implements RFC 3490, Internationalized Domain Names in Applications,
//! encoding for domain name labels containing Unicode.

use std::borrow::Cow::{self, Borrowed, Owned};

use external_idna;

/// Indicates an error in encoding or decoding Punycode data
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Error;

/// Converts a label or host to its ASCII format. If the string is already ASCII,
/// it will be returned unmodified. If an error is encountered in encoding,
/// `Err` will be returned.
pub fn to_ascii(s: &str) -> Result<Cow<str>, Error> {
    if s.is_ascii() {
        Ok(Borrowed(s))
    } else {
        external_idna::domain_to_ascii(s)
            .map(Owned)
            .map_err(|_| Error)
    }
}

/// Converts a label or host to its Unicode format. If the string is not an
/// internationalized domain name, it will be returned unmodified. If an error
/// is encountered in decoding, `Err` will be returned.
pub fn to_unicode(s: &str) -> Result<Cow<str>, Error> {
    let is_unicode = s.split('.').any(|s| s.starts_with("xn--"));

    if is_unicode {
        match external_idna::domain_to_unicode(s) {
            (s, Ok(_)) => Ok(Owned(s)),
            (_, Err(_)) => Err(Error),
        }
    } else {
        Ok(Borrowed(s))
    }
}

#[cfg(test)]
mod test {
    use super::{to_ascii, to_unicode};

    static SAMPLE_HOSTS: &'static [(&'static str, &'static str)] = &[
        ("bücher.de.", "xn--bcher-kva.de."),
        ("ουτοπία.δπθ.gr.", "xn--kxae4bafwg.xn--pxaix.gr."),
        // We want to preserve a lack of trailing '.', too.
        ("bücher.de", "xn--bcher-kva.de"),
        ("ουτοπία.δπθ.gr", "xn--kxae4bafwg.xn--pxaix.gr"),
    ];

    #[test]
    fn test_hosts() {
        for &(uni, ascii) in SAMPLE_HOSTS {
            assert_eq!(to_ascii(uni).unwrap(), ascii);
            assert_eq!(to_unicode(ascii).unwrap(), uni);

            // Ensure the functions are idempotent
            assert_eq!(to_ascii(ascii).unwrap(), ascii);
            assert_eq!(to_unicode(uni).unwrap(), uni);
        }
    }
}
