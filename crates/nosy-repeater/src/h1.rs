//! Byte-exact HTTP/1.x exchange: write the request verbatim, read one response.

use std::{io, time::Instant};

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::raw::find;

pub struct H1Response {
    pub raw: Vec<u8>,
    pub status: Option<u16>,
    pub version: Option<&'static str>,
    pub first_byte: Option<Instant>,
}

enum Framing {
    None,
    Length(usize),
    Chunked,
    Close,
}

pub async fn read_response<S: AsyncRead + Unpin>(
    s: &mut S,
    head_request: bool,
    limit: usize,
) -> io::Result<H1Response> {
    let mut out = H1Response {
        raw: Vec::with_capacity(16 * 1024),
        status: None,
        version: None,
        first_byte: None,
    };
    let buf = &mut out.raw;
    let mut start = 0;

    loop {
        // Parse a response head starting at `start`.
        let (status, version, head_len, framing) = loop {
            let mut headers = [httparse::EMPTY_HEADER; 256];
            let mut resp = httparse::Response::new(&mut headers);
            match resp.parse(&buf[start..]) {
                Ok(httparse::Status::Complete(n)) => {
                    let code = resp.code.unwrap_or(0);
                    let framing = framing(code, head_request, resp.headers);
                    let version = if resp.version == Some(0) {
                        "HTTP/1.0"
                    } else {
                        "HTTP/1.1"
                    };
                    break (code, version, n, framing);
                }
                Ok(httparse::Status::Partial) => {
                    if read_more(s, buf, limit, &mut out.first_byte).await? == 0 {
                        return Ok(out); // EOF mid-head: return what we have
                    }
                }
                Err(_) => {
                    // Not HTTP: return whatever the server sends until it closes.
                    while read_more(s, buf, limit, &mut out.first_byte).await? > 0 {}
                    return Ok(out);
                }
            }
        };
        out.status = Some(status);
        out.version = Some(version);
        let body_start = start + head_len;

        if (100..200).contains(&status) && status != 101 {
            start = body_start; // interim response (e.g. 100 Continue); keep reading
            continue;
        }

        match framing {
            Framing::None => {}
            Framing::Length(n) => {
                let end = body_start.saturating_add(n);
                while buf.len() < end {
                    if read_more(s, buf, limit, &mut out.first_byte).await? == 0 {
                        break;
                    }
                }
                buf.truncate(end.min(buf.len()));
            }
            Framing::Chunked => {
                let mut cursor = body_start;
                loop {
                    match scan_chunked(buf, &mut cursor) {
                        Some(end) => {
                            buf.truncate(end);
                            break;
                        }
                        None => {
                            if read_more(s, buf, limit, &mut out.first_byte).await? == 0 {
                                break;
                            }
                        }
                    }
                }
            }
            Framing::Close => while read_more(s, buf, limit, &mut out.first_byte).await? > 0 {},
        }
        return Ok(out);
    }
}

fn framing(code: u16, head_request: bool, headers: &[httparse::Header<'_>]) -> Framing {
    if head_request || code == 204 || code == 304 || code == 101 || (100..200).contains(&code) {
        return Framing::None;
    }
    let mut len = None;
    for h in headers {
        if h.name.eq_ignore_ascii_case("transfer-encoding")
            && std::str::from_utf8(h.value)
                .is_ok_and(|v| v.to_ascii_lowercase().contains("chunked"))
        {
            return Framing::Chunked;
        }
        if h.name.eq_ignore_ascii_case("content-length") {
            len = std::str::from_utf8(h.value)
                .ok()
                .and_then(|v| v.trim().parse().ok());
        }
    }
    len.map_or(Framing::Close, Framing::Length)
}

/// Advance `cursor` over complete chunks. Returns the end offset of the message
/// once the terminating chunk (and trailers) are fully buffered.
fn scan_chunked(buf: &[u8], cursor: &mut usize) -> Option<usize> {
    loop {
        let line_end = *cursor + find(&buf[*cursor..], b"\r\n")?;
        let line = &buf[*cursor..line_end];
        let size_str = std::str::from_utf8(line).ok()?.split(';').next()?.trim();
        let size = usize::from_str_radix(size_str, 16).ok()?;
        let data_start = line_end + 2;
        if size == 0 {
            // Trailers: either an immediate CRLF or header lines ending in CRLFCRLF.
            if buf.len() >= data_start + 2 && &buf[data_start..data_start + 2] == b"\r\n" {
                return Some(data_start + 2);
            }
            return find(&buf[data_start..], b"\r\n\r\n").map(|i| data_start + i + 4);
        }
        let next = data_start.checked_add(size)?.checked_add(2)?;
        if buf.len() < next {
            return None;
        }
        *cursor = next;
    }
}

async fn read_more<S: AsyncRead + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
    limit: usize,
    first_byte: &mut Option<Instant>,
) -> io::Result<usize> {
    if buf.len() >= limit {
        return Err(io::Error::other(format!("response exceeds {limit} bytes")));
    }
    buf.reserve(16 * 1024);
    let n = s.read_buf(buf).await?;
    if n > 0 && first_byte.is_none() {
        *first_byte = Some(Instant::now());
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse(input: &[u8], head: bool) -> H1Response {
        let mut s = input;
        read_response(&mut s, head, 1 << 20).await.unwrap()
    }

    #[tokio::test]
    async fn content_length() {
        let r = parse(
            b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcEXTRA",
            false,
        )
        .await;
        assert_eq!(r.raw, b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc");
        assert_eq!(r.status, Some(200));
    }

    #[tokio::test]
    async fn chunked_with_trailers() {
        let msg =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-T: 1\r\n\r\n";
        let mut input = msg.to_vec();
        input.extend_from_slice(b"garbage");
        assert_eq!(parse(&input, false).await.raw, msg);
        let simple =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;ext=1\r\na\r\n0\r\n\r\n";
        assert_eq!(parse(simple, false).await.raw, simple);
    }

    #[tokio::test]
    async fn interim_and_head() {
        let msg =
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let r = parse(msg, false).await;
        assert_eq!((r.status, r.raw.len()), (Some(404), msg.len()));
        let r = parse(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n", true).await;
        assert_eq!(r.status, Some(200));
    }

    #[tokio::test]
    async fn read_until_close_and_garbage() {
        let r = parse(b"HTTP/1.0 200 OK\r\n\r\nbody until close", false).await;
        assert!(r.raw.ends_with(b"until close"));
        assert_eq!(r.version, Some("HTTP/1.0"));
        let r = parse(b"SSH-2.0-OpenSSH\r\n", false).await;
        assert_eq!(r.status, None);
        assert_eq!(r.raw, b"SSH-2.0-OpenSSH\r\n");
    }
}
