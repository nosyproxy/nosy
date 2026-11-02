//! Rendering stored messages as raw HTTP and decoding bodies for display.

use nosy_codec::{dechunk, decode_body};
use nosy_model::headers;
use nosy_store::{RequestMessage, ResponseMessage};

fn is_h1(version: &str) -> bool {
    version.starts_with("HTTP/1") || version.starts_with("HTTP/0")
}

fn push_headers(out: &mut Vec<u8>, encoded: &[u8], title_case: bool, skip: &[&str]) {
    for (name, value) in headers::iter(encoded) {
        if skip.iter().any(|s| name.eq_ignore_ascii_case(s.as_bytes())) {
            continue;
        }
        if title_case {
            headers::title_case(name, out);
        } else {
            out.extend_from_slice(name);
        }
        out.extend_from_slice(b": ");
        out.extend_from_slice(value);
        out.extend_from_slice(b"\r\n");
    }
}

/// Request line + headers + blank line.
pub fn request_head(m: &RequestMessage) -> Vec<u8> {
    let mut out = Vec::with_capacity(m.headers.len() + 128);
    out.extend_from_slice(format!("{} {} {}\r\n", m.method, m.path, m.http_version).as_bytes());
    push_headers(&mut out, &m.headers, is_h1(&m.http_version), &[]);
    out.extend_from_slice(b"\r\n");
    out
}

/// Status line + headers + blank line.
pub fn response_head(m: &ResponseMessage) -> Vec<u8> {
    let mut out = Vec::with_capacity(m.headers.len() + 128);
    let reason = http::StatusCode::from_u16(m.status)
        .ok()
        .and_then(|s| s.canonical_reason());
    let version = if m.http_version.is_empty() {
        "HTTP/1.1"
    } else {
        &m.http_version
    };
    out.extend_from_slice(format!("{version} {}", m.status).as_bytes());
    if let Some(r) = reason {
        out.push(b' ');
        out.extend_from_slice(r.as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    push_headers(&mut out, &m.headers, is_h1(version), &[]);
    out.extend_from_slice(b"\r\n");
    out
}

pub fn render_request(m: &RequestMessage, decode: bool) -> Vec<u8> {
    let mut out = request_head(m);
    push_body(&mut out, &m.body, &m.headers, decode);
    out
}

pub fn render_response(m: &ResponseMessage, decode: bool) -> Vec<u8> {
    let mut out = response_head(m);
    push_body(&mut out, &m.body, &m.headers, decode);
    out
}

/// Editor text for a new repeater tab. Always HTTP/1.1-shaped (the target's
/// `http2` flag decides the wire protocol). Bodies were de-chunked on capture,
/// so `Transfer-Encoding` is dropped and `Content-Length` will be recomputed.
pub fn repeater_text(m: &RequestMessage) -> String {
    let mut out = Vec::with_capacity(m.headers.len() + m.body.len() + 128);
    out.extend_from_slice(format!("{} {} HTTP/1.1\r\n", m.method, m.path).as_bytes());
    push_headers(
        &mut out,
        &m.headers,
        true,
        &[
            "transfer-encoding",
            "proxy-connection",
            "proxy-authorization",
        ],
    );
    if !m.body.is_empty() && headers::find(&m.headers, "content-length").is_none() {
        out.extend_from_slice(format!("Content-Length: {}\r\n", m.body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(&m.body);
    String::from_utf8_lossy(&out).into_owned()
}

fn push_body(out: &mut Vec<u8>, body: &[u8], encoded_headers: &[u8], decode: bool) {
    let encoding = headers::find(encoded_headers, "content-encoding");
    match encoding
        .filter(|_| decode)
        .and_then(|e| decode_body(body, e))
    {
        Some(decoded) => out.extend_from_slice(&decoded),
        None => out.extend_from_slice(body),
    }
}

pub fn body_only(body: &[u8], encoded_headers: &[u8], decode: bool) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len());
    push_body(&mut out, body, encoded_headers, decode);
    out
}

/// Decode a complete raw HTTP/1.x or serialized HTTP/2 message (as captured by
/// the repeater): de-chunk and decompress the body, leave the head untouched.
pub fn decode_raw_message(raw: &[u8]) -> Vec<u8> {
    let Some(head_end) = raw.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4) else {
        return raw.to_vec();
    };
    let (head, body) = raw.split_at(head_end);
    let mut chunked = false;
    let mut encoding: Option<&[u8]> = None;
    for line in head.split(|&b| b == b'\n').skip(1) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(i) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let (name, value) = (&line[..i], line[i + 1..].trim_ascii());
        if name.eq_ignore_ascii_case(b"transfer-encoding") && value.eq_ignore_ascii_case(b"chunked")
        {
            chunked = true;
        } else if name.eq_ignore_ascii_case(b"content-encoding") {
            encoding = Some(value);
        }
    }
    let dechunked = if chunked { dechunk(body) } else { None };
    let body = dechunked.as_deref().unwrap_or(body);
    let decoded = encoding.and_then(|e| decode_body(body, e));
    let mut out = head.to_vec();
    out.extend_from_slice(decoded.as_deref().unwrap_or(body));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(data).unwrap();
        e.finish().unwrap()
    }

    #[test]
    fn raw_message_dechunk_and_decompress() {
        let z = gzip(b"payload");
        let mut raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n"
                .to_vec();
        raw.extend_from_slice(format!("{:x}\r\n", z.len()).as_bytes());
        raw.extend_from_slice(&z);
        raw.extend_from_slice(b"\r\n0\r\n\r\n");
        let out = decode_raw_message(&raw);
        assert!(out.ends_with(b"\r\n\r\npayload"));
    }

    #[test]
    fn renders_request_title_cased_for_h1() {
        let m = RequestMessage {
            scheme: "https".into(),
            host: "a".into(),
            port: 443,
            method: "POST".into(),
            path: "/x".into(),
            http_version: "HTTP/1.1".into(),
            headers: headers::encode_pairs([
                (&b"content-type"[..], &b"a/b"[..]),
                (&b"transfer-encoding"[..], &b"chunked"[..]),
            ]),
            body: b"hi".to_vec(),
        };
        let raw = String::from_utf8(render_request(&m, false)).unwrap();
        assert!(raw.starts_with("POST /x HTTP/1.1\r\nContent-Type: a/b\r\n"));
        let rep = repeater_text(&m);
        assert!(!rep.contains("Transfer-Encoding"));
        assert!(rep.ends_with("Content-Length: 2\r\n\r\nhi"));
    }
}
