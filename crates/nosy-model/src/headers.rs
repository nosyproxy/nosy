//! Compact binary encoding of header lists for storage.
//!
//! Layout per header: `u16 name_len | name | u32 value_len | value` (little endian).
//! Preserves order and duplicates, and is trivially fast to encode/decode.

use http::HeaderMap;

use crate::Header;

pub fn encode(map: &HeaderMap) -> Vec<u8> {
    let cap: usize = map
        .iter()
        .map(|(n, v)| 6 + n.as_str().len() + v.len())
        .sum();
    let mut out = Vec::with_capacity(cap);
    for (name, value) in map {
        push(&mut out, name.as_str().as_bytes(), value.as_bytes());
    }
    out
}

pub fn encode_pairs<'a>(pairs: impl IntoIterator<Item = (&'a [u8], &'a [u8])>) -> Vec<u8> {
    let mut out = Vec::new();
    for (n, v) in pairs {
        push(&mut out, n, v);
    }
    out
}

fn push(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    let nl = name.len().min(u16::MAX as usize);
    let vl = value.len().min(u32::MAX as usize);
    out.extend_from_slice(&(nl as u16).to_le_bytes());
    out.extend_from_slice(&name[..nl]);
    out.extend_from_slice(&(vl as u32).to_le_bytes());
    out.extend_from_slice(&value[..vl]);
}

/// Iterate raw `(name, value)` pairs. Stops silently on malformed input.
pub fn iter(mut buf: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
    std::iter::from_fn(move || {
        let (nl, rest) = buf.split_first_chunk::<2>()?;
        let nl = u16::from_le_bytes(*nl) as usize;
        let (name, rest) = rest.split_at_checked(nl)?;
        let (vl, rest) = rest.split_first_chunk::<4>()?;
        let vl = u32::from_le_bytes(*vl) as usize;
        let (value, rest) = rest.split_at_checked(vl)?;
        buf = rest;
        Some((name, value))
    })
}

pub fn decode(buf: &[u8]) -> Vec<Header> {
    iter(buf)
        .map(|(n, v)| Header {
            name: String::from_utf8_lossy(n).into_owned(),
            value: String::from_utf8_lossy(v).into_owned(),
        })
        .collect()
}

/// Find the first header with the given (lowercase) name.
pub fn find<'a>(buf: &'a [u8], name: &str) -> Option<&'a [u8]> {
    iter(buf)
        .find(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
        .map(|(_, v)| v)
}

/// `content-type` -> `Content-Type`, used when rendering HTTP/1.x messages whose
/// original casing was normalized by the parser.
pub fn title_case(name: &[u8], out: &mut Vec<u8>) {
    let mut upper = true;
    for &b in name {
        out.push(if upper { b.to_ascii_uppercase() } else { b });
        upper = b == b'-';
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn roundtrip_preserves_order_and_duplicates() {
        let mut map = HeaderMap::new();
        map.append("set-cookie", HeaderValue::from_static("a=1"));
        map.append("x-test", HeaderValue::from_static("v"));
        map.append("set-cookie", HeaderValue::from_static("b=2"));
        let enc = encode(&map);
        let dec = decode(&enc);
        let names: Vec<_> = dec.iter().map(|h| h.name.as_str()).collect();
        assert_eq!(dec.len(), 3);
        assert!(names.contains(&"x-test"));
        assert_eq!(find(&enc, "Set-Cookie"), Some(&b"a=1"[..]));
    }

    #[test]
    fn malformed_input_does_not_panic() {
        assert!(decode(&[5, 0, b'a']).is_empty());
        assert!(decode(&[]).is_empty());
    }

    #[test]
    fn title_case_works() {
        let mut out = Vec::new();
        title_case(b"content-type", &mut out);
        assert_eq!(out, b"Content-Type");
    }
}
