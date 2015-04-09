//! Implements RFC 3490, Internationalized Domain Names in Applications,
//! encoding for domain name labels containing Unicode.

use std::ascii::AsciiExt;
use std::borrow::Cow;
use std::borrow::Cow::*;
use std::char::from_u32;

/// Indicates an error in encoding or decoding Punycode data
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Error;

/// Converts a hostname to its ASCII representation.
/// Returns an error if the encoding operation failed.
pub fn host_to_ascii(s: &str) -> Result<Cow<str>, Error> {
    let segments: Vec<_> = try!(s.split('.').map(|s| to_ascii(s)).collect());

    if segments.iter().all(|s| match *s { Borrowed(_) => true, _ => false }) {
        Ok(Borrowed(s))
    } else {
        Ok(Owned(connect_segments(&segments)))
    }
}

/// Converts a hostname to its Unicode representation.
/// Returns an error if the decoding operation failed.
pub fn host_to_unicode(s: &str) -> Result<Cow<str>, Error> {
    let segments: Vec<_> = try!(s.split('.').map(|s| to_unicode(s)).collect());

    if segments.iter().all(|s| match *s { Borrowed(_) => true, _ => false }) {
        Ok(Borrowed(s))
    } else {
        Ok(Owned(connect_segments(&segments)))
    }
}

fn connect_segments(segments: &[Cow<str>]) -> String {
    let mut res = String::with_capacity(segments.iter()
        .map(|s| s.len()).sum::<usize>() + segments.len());

    let mut it = segments.iter().peekable();

    while let Some(s) = it.next() {
        res.push_str(s);
        if it.peek().is_some() {
            res.push('.');
        }
    }

    res
}

/// Converts a label to its ASCII format. If the string is already ASCII,
/// it will be returned unmodified. If an error is encountered in encoding,
/// `Err` will be returned.
pub fn to_ascii(s: &str) -> Result<Cow<str>, Error> {
    if s.is_ascii() {
        Ok(Borrowed(s))
    } else {
        encode(s).map(|s| Owned(format!("xn--{}", s)))
    }
}

/// Converts a label to its Unicode format. If the string is not an
/// internationalized domain name, it will be returned unmodified. If an error
/// is encountered in decoding, `Err` will be returned.
pub fn to_unicode(s: &str) -> Result<Cow<str>, Error> {
    if !starts_with_ascii_lowercase(s, "xn--") {
        Ok(Borrowed(s))
    } else {
        decode(&s[4..]).map(|s| Owned(s))
    }
}

const BASE: u32 = 36;
const T_MIN: u32 = 1;
const T_MAX: u32 = 26;
const SKEW: u32 = 38;
const DAMP: u32 = 700;
const INITIAL_BIAS: u32 = 72;
const INITIAL_N: u32 = 0x80;

fn adapt(delta: u32, num_points: u32, first_time: bool) -> u32 {
    let mut delta = if first_time {
        delta / DAMP
    } else {
        delta / 2
    };

    delta += delta / num_points;

    let mut k = 0;

    while delta > ((BASE - T_MIN) * T_MAX) / 2 {
        delta /= BASE - T_MIN;
        k += BASE;
    }

    k + (((BASE - T_MIN + 1) * delta) / (delta + SKEW))
}

/// Converts a single Punycode-encoded label to a unicode string.
pub fn decode(mut s: &str) -> Result<String, Error> {
    let mut output = Vec::new();

    if let Some(pos) = s.as_bytes().rposition_elem(&b'-') {
        if pos == 0 {
            return Err(Error);
        }
        for &b in &s.as_bytes()[..pos] {
            if b.is_ascii() {
                output.push(b as char);
            } else {
                return Err(Error);
            }
        }

        s = &s[pos + 1..];
    }

    let mut n = INITIAL_N;
    let mut i = 0;
    let mut bias = INITIAL_BIAS;

    let mut it = s.bytes().peekable();

    while it.peek().is_some() {
        let oldi = i;
        let mut w = 1;
        let mut k = BASE;

        loop {
            let b = match it.next() {
                Some(b) => b,
                None => return Err(Error)
            };

            let digit = match from_digit(b) {
                Some(n) => n,
                None => return Err(Error)
            };

            i = match digit.checked_mul(w).and_then(|n| n.checked_add(i)) {
                Some(i) => i,
                None => return Err(Error)
            };

            let t = match () {
                _ if k <= bias => T_MIN,
                _ if k >= bias + T_MAX => T_MAX,
                _ => k - bias
            };
            if digit < t {
                break;
            }

            w = match w.checked_mul(BASE - t) {
                Some(w) => w,
                None => return Err(Error)
            };

            k += BASE;
        }

        bias = adapt(i - oldi, output.len() as u32 + 1, oldi == 0);
        n = match n.checked_add(i / (output.len() as u32 + 1)) {
            Some(n) => n,
            None => return Err(Error)
        };
        i %= output.len() as u32 + 1;
        output.insert(i as usize, match from_u32(n) {
            Some(c) => c,
            None => return Err(Error)
        });
        i += 1;
    }

    Ok(output.into_iter().collect())
}

/// Converts a single label of unicode characters to a Punycode-encoded
/// ASCII string.
pub fn encode(s: &str) -> Result<String, Error> {
    if s.is_ascii() {
        return Err(Error);
    }

    let mut output = Vec::new();

    for b in s.bytes() {
        if b.is_ascii() {
            output.push(b);
        }
    }

    let b = output.len() as u32;
    let mut h = b;

    if !output.is_empty() {
        output.push(b'-');
    }

    let chars = s.chars().collect::<Vec<_>>();
    let input_len = chars.len() as u32;

    let mut n = INITIAL_N;
    let mut delta = 0;
    let mut bias = INITIAL_BIAS;

    while h < input_len {
        let min = match chars.iter().filter(|&&c| (c as u32) >= n).min() {
            Some(min) => *min as u32,
            None => return Err(Error)
        };

        delta = match (min - n).checked_mul(h + 1)
                .and_then(|n| n.checked_add(delta)) {
            Some(n) => n,
            None => return Err(Error)
        };

        n = min;

        for &c in &chars {
            let c = c as u32;
            if c < n {
                delta = match delta.checked_add(1) {
                    Some(delta) => delta,
                    None => return Err(Error)
                };
            } else if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = match () {
                        _ if k <= bias => T_MIN,
                        _ if k >= bias + T_MAX => T_MAX,
                        _ => k - bias
                    };

                    if q < t {
                        break;
                    }

                    output.push(to_digit(t + ((q - t) % (BASE - t))));
                    q = (q - t) / (BASE - t);

                    k += BASE;
                }

                output.push(to_digit(q));
                bias = adapt(delta, h + 1, h == b);
                delta = 0;
                h += 1;
            }
        }

        delta += 1;
        n += 1;
    }

    Ok(String::from_utf8(output).ok().unwrap())
}

fn from_digit(c: u8) -> Option<u32> {
    match c {
        b'a' ... b'z' => Some((c - b'a') as u32),
        b'A' ... b'Z' => Some((c - b'A') as u32),
        b'0' ... b'9' => Some((c - b'0' + 26) as u32),
        _ => None
    }
}

fn to_digit(n: u32) -> u8 {
    match n {
        0 ... 25 => n as u8 + b'a',
        26 ... 35 => (n - 26) as u8 + b'0',
        _ => unreachable!()
    }
}

/// Returns whether `s` begins with a given case-insensitive prefix.
/// `prefix` is assumed to be ASCII and lowercase. `s` does not need to be
/// either ASCII or lowercase.
pub fn starts_with_ascii_lowercase(s: &str, prefix: &str) -> bool {
    s.len() >= prefix.len() &&
        s.bytes().zip(prefix.bytes()).all(|(a, b)| a.to_ascii_lowercase() == b)
}

#[cfg(test)]
mod test {
    use super::{decode, encode, host_to_ascii, host_to_unicode};

    static SAMPLES: &'static [(&'static str, &'static str)] = &[
        // (A) Arabic (Egyptian)
        ("\u{0644}\u{064A}\u{0647}\u{0645}\u{0627}\u{0628}\u{062A}\u{0643}\u{0644}\
            \u{0645}\u{0648}\u{0634}\u{0639}\u{0631}\u{0628}\u{064A}\u{061F}",
            "egbpdaj6bu4bxfgehfvwxn"),
        // (B) Chinese (simplified)
        ("\u{4ED6}\u{4EEC}\u{4E3A}\u{4EC0}\u{4E48}\u{4E0D}\u{8BF4}\u{4E2D}\u{6587}",
            "ihqwcrb4cv8a8dqg056pqjye"),
        // (C) Chinese (traditional)
        ("\u{4ED6}\u{5011}\u{7232}\u{4EC0}\u{9EBD}\u{4E0D}\u{8AAA}\u{4E2D}\u{6587}",
            "ihqwctvzc91f659drss3x8bo0yb"),
        // (D) Czech: Pro<ccaron>prost<ecaron>nemluv<iacute><ccaron>esky
        ("\u{0050}\u{0072}\u{006F}\u{010D}\u{0070}\u{0072}\u{006F}\u{0073}\u{0074}\
            \u{011B}\u{006E}\u{0065}\u{006D}\u{006C}\u{0075}\u{0076}\u{00ED}\u{010D}\
            \u{0065}\u{0073}\u{006B}\u{0079}",
            "Proprostnemluvesky-uyb24dma41a"),
        // (E) Hebrew
        ("\u{05DC}\u{05DE}\u{05D4}\u{05D4}\u{05DD}\u{05E4}\u{05E9}\u{05D5}\u{05D8}\
            \u{05DC}\u{05D0}\u{05DE}\u{05D3}\u{05D1}\u{05E8}\u{05D9}\u{05DD}\u{05E2}\
            \u{05D1}\u{05E8}\u{05D9}\u{05EA}",
            "4dbcagdahymbxekheh6e0a7fei0b"),
        // (F) Hindi (Devanagari)
        ("\u{092F}\u{0939}\u{0932}\u{094B}\u{0917}\u{0939}\u{093F}\u{0928}\u{094D}\
            \u{0926}\u{0940}\u{0915}\u{094D}\u{092F}\u{094B}\u{0902}\u{0928}\u{0939}\
            \u{0940}\u{0902}\u{092C}\u{094B}\u{0932}\u{0938}\u{0915}\u{0924}\u{0947}\
            \u{0939}\u{0948}\u{0902}",
            "i1baa7eci9glrd9b2ae1bj0hfcgg6iyaf8o0a1dig0cd"),
        // (G) Japanese (kanji and hiragana)
        ("\u{306A}\u{305C}\u{307F}\u{3093}\u{306A}\u{65E5}\u{672C}\u{8A9E}\u{3092}\
            \u{8A71}\u{3057}\u{3066}\u{304F}\u{308C}\u{306A}\u{3044}\u{306E}\u{304B}",
            "n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa"),
        // (H) Korean (Hangul syllables)
        ("\u{C138}\u{ACC4}\u{C758}\u{BAA8}\u{B4E0}\u{C0AC}\u{B78C}\u{B4E4}\u{C774}\
            \u{D55C}\u{AD6D}\u{C5B4}\u{B97C}\u{C774}\u{D574}\u{D55C}\u{B2E4}\u{BA74}\
            \u{C5BC}\u{B9C8}\u{B098}\u{C88B}\u{C744}\u{AE4C}",
            "989aomsvi5e83db1d2a355cv1e0vak1dwrv93d5xbh15a0dt30a5jpsd879ccm6fea98c"),
        // (I) Russian (Cyrillic)
        ("\u{043F}\u{043E}\u{0447}\u{0435}\u{043C}\u{0443}\u{0436}\u{0435}\u{043E}\
            \u{043D}\u{0438}\u{043D}\u{0435}\u{0433}\u{043E}\u{0432}\u{043E}\u{0440}\
            \u{044F}\u{0442}\u{043F}\u{043E}\u{0440}\u{0443}\u{0441}\u{0441}\u{043A}\
            \u{0438}",
            "b1abfaaepdrnnbgefbadotcwatmq2g4l"),
        // (J) Spanish: Porqu<eacute>nopuedensimplementehablarenEspa<ntilde>ol
        ("\u{0050}\u{006F}\u{0072}\u{0071}\u{0075}\u{00E9}\u{006E}\u{006F}\u{0070}\
            \u{0075}\u{0065}\u{0064}\u{0065}\u{006E}\u{0073}\u{0069}\u{006D}\u{0070}\
            \u{006C}\u{0065}\u{006D}\u{0065}\u{006E}\u{0074}\u{0065}\u{0068}\u{0061}\
            \u{0062}\u{006C}\u{0061}\u{0072}\u{0065}\u{006E}\u{0045}\u{0073}\u{0070}\
            \u{0061}\u{00F1}\u{006F}\u{006C}",
            "PorqunopuedensimplementehablarenEspaol-fmd56a"),
        // (K) Vietnamese
        // T<adotbelow>isaoh<odotbelow>kh<ocirc>ngth<ecirchookabove>ch
        // <ihookabove>n<oacute>iti<ecircacute>ngVi<ecircdotbelow>t
        ("\u{0054}\u{1EA1}\u{0069}\u{0073}\u{0061}\u{006F}\u{0068}\u{1ECD}\u{006B}\
            \u{0068}\u{00F4}\u{006E}\u{0067}\u{0074}\u{0068}\u{1EC3}\u{0063}\u{0068}\
            \u{1EC9}\u{006E}\u{00F3}\u{0069}\u{0074}\u{0069}\u{1EBF}\u{006E}\u{0067}\
            \u{0056}\u{0069}\u{1EC7}\u{0074}",
            "TisaohkhngthchnitingVit-kjcr8268qyxafd2f1b9g"),
        // (L) 3<nen>B<gumi><kinpachi><sensei>
        ("\u{0033}\u{5E74}\u{0042}\u{7D44}\u{91D1}\u{516B}\u{5148}\u{751F}",
            "3B-ww4c5e180e575a65lsy2b"),
        // (M) <amuro><namie>-with-SUPER-MONKEYS
        ("\u{5B89}\u{5BA4}\u{5948}\u{7F8E}\u{6075}\u{002D}\u{0077}\u{0069}\u{0074}\
            \u{0068}\u{002D}\u{0053}\u{0055}\u{0050}\u{0045}\u{0052}\u{002D}\u{004D}\
            \u{004F}\u{004E}\u{004B}\u{0045}\u{0059}\u{0053}",
            "-with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n"),
        // (N) Hello-Another-Way-<sorezore><no><basho>
        ("\u{0048}\u{0065}\u{006C}\u{006C}\u{006F}\u{002D}\u{0041}\u{006E}\u{006F}\
            \u{0074}\u{0068}\u{0065}\u{0072}\u{002D}\u{0057}\u{0061}\u{0079}\u{002D}\
            \u{305D}\u{308C}\u{305E}\u{308C}\u{306E}\u{5834}\u{6240}",
            "Hello-Another-Way--fc4qua05auwb3674vfr0b"),
        // (O) <hitotsu><yane><no><shita>2
        ("\u{3072}\u{3068}\u{3064}\u{5C4B}\u{6839}\u{306E}\u{4E0B}\u{0032}",
            "2-u9tlzr9756bt3uc0v"),
        // (P) Maji<de>Koi<suru>5<byou><mae>
        ("\u{004D}\u{0061}\u{006A}\u{0069}\u{3067}\u{004B}\u{006F}\u{0069}\u{3059}\
            \u{308B}\u{0035}\u{79D2}\u{524D}",
            "MajiKoi5-783gue6qz075azm5e"),
        // (Q) <pafii>de<runba>
        ("\u{30D1}\u{30D5}\u{30A3}\u{30FC}\u{0064}\u{0065}\u{30EB}\u{30F3}\u{30D0}",
            "de-jg4avhby1noc0d"),
        // (R) <sono><supiido><de>
        ("\u{305D}\u{306E}\u{30B9}\u{30D4}\u{30FC}\u{30C9}\u{3067}",
            "d9juau41awczczp"),
    ];

    #[test]
    fn test_decode() {
        for &(text, code) in SAMPLES {
            assert_eq!(decode(code).as_ref().map(|s| &s[..]), Ok(text));
        }
    }

    #[test]
    fn test_encode() {
        for &(text, code) in SAMPLES {
            assert_eq!(encode(text).as_ref().map(|s| &s[..]), Ok(code));
        }
    }

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
            assert_eq!(host_to_ascii(uni).unwrap(), ascii);
            assert_eq!(host_to_unicode(ascii).unwrap(), uni);

            // Ensure the functions are idempotent
            assert_eq!(host_to_ascii(ascii).unwrap(), ascii);
            assert_eq!(host_to_unicode(uni).unwrap(), uni);
        }
    }
}
