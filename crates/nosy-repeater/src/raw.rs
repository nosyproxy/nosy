//! Parsing and normalization of raw HTTP/1.x request text from the editor.

/// Split at the first blank line (`\r\n\r\n` or `\n\n`). Returns `(head, body)`;
/// `head` excludes the terminator.
pub fn split_message(raw: &[u8]) -> (&[u8], &[u8]) {
    let crlf = find(raw, b"\r\n\r\n").map(|i| (i, i + 4));
    let lf = find(raw, b"\n\n").map(|i| (i, i + 2));
    let sep = match (crlf, lf) {
        (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
        (a, b) => a.or(b),
    };
    match sep {
        Some((end, body)) => (&raw[..end], &raw[body..]),
        None => (
            raw.strip_suffix(b"\r\n")
                .or(raw.strip_suffix(b"\n"))
                .unwrap_or(raw),
            &[],
        ),
    }
}

pub(crate) fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Turn editor text into wire bytes: CRLF line endings in the head, body kept
/// verbatim, and (optionally) a correct `Content-Length`.
pub fn normalize(raw: &str, update_content_length: bool) -> Vec<u8> {
    let (head, body) = split_message(raw.as_bytes());
    let mut lines: Vec<&[u8]> = head
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l))
        .collect();
    // Drop leading empty lines (common copy/paste artefact).
    while lines.first().is_some_and(|l| l.is_empty()) {
        lines.remove(0);
    }

    let mut out = Vec::with_capacity(raw.len() + 32);
    let mut has_cl = false;
    let mut chunked = false;
    let mut multipart = false;
    for l in &lines {
        if let Some((name, value)) = split_header(l) {
            if name.eq_ignore_ascii_case(b"transfer-encoding") && contains_ci(value, b"chunked") {
                chunked = true;
            }
            if name.eq_ignore_ascii_case(b"content-length") {
                has_cl = true;
            }
            if name.eq_ignore_ascii_case(b"content-type") && contains_ci(value, b"multipart/") {
                multipart = true;
            }
        }
    }
    // Editors normalize line breaks to LF, but multipart framing requires CRLF.
    let crlf_body;
    let body = if multipart {
        crlf_body = to_crlf(body);
        &crlf_body[..]
    } else {
        body
    };
    let set_cl = update_content_length && !chunked && (has_cl || !body.is_empty());
    let mut wrote_cl = false;
    for (i, l) in lines.iter().enumerate() {
        if i > 0
            && set_cl
            && let Some((name, _)) = split_header(l)
            && name.eq_ignore_ascii_case(b"content-length")
        {
            if !wrote_cl {
                out.extend_from_slice(name);
                out.extend_from_slice(format!(": {}\r\n", body.len()).as_bytes());
                wrote_cl = true;
            }
            continue;
        }
        out.extend_from_slice(l);
        out.extend_from_slice(b"\r\n");
    }
    if set_cl && !wrote_cl {
        out.extend_from_slice(format!("Content-Length: {}\r\n", body.len()).as_bytes());
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    out
}

fn to_crlf(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(body.len() + body.len() / 32);
    let mut prev = 0u8;
    for &b in body {
        if b == b'\n' && prev != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        prev = b;
    }
    out
}

pub fn split_header(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let i = line.iter().position(|&b| b == b':')?;
    let name = &line[..i];
    if name.is_empty() || name.iter().any(|b| b.is_ascii_whitespace()) {
        return None;
    }
    Some((name, line[i + 1..].trim_ascii()))
}

fn contains_ci(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// First token of the request line.
pub fn method(raw: &[u8]) -> &[u8] {
    raw.split(|&b| b == b' ').next().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crlf_and_content_length() {
        let out = normalize(
            "POST /x HTTP/1.1\nHost: a\nContent-Length: 1\n\nhello\nworld",
            true,
        );
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 11\r\n\r\nhello\nworld"
        );
    }

    #[test]
    fn adds_content_length_for_body() {
        let out = normalize("POST / HTTP/1.1\r\nHost: a\r\n\r\nab", true);
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("Content-Length: 2\r\n\r\nab")
        );
    }

    #[test]
    fn get_without_body_untouched() {
        let out = normalize("GET / HTTP/1.1\nHost: a\n", true);
        assert_eq!(out, b"GET / HTTP/1.1\r\nHost: a\r\n\r\n");
    }

    #[test]
    fn respects_disabled_update_and_chunked() {
        let out = normalize("POST / HTTP/1.1\nContent-Length: 99\n\nab", false);
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("Content-Length: 99")
        );
        let out = normalize(
            "POST / HTTP/1.1\nTransfer-Encoding: chunked\n\n2\r\nab\r\n0\r\n\r\n",
            true,
        );
        assert!(!String::from_utf8(out).unwrap().contains("Content-Length"));
    }

    #[test]
    fn multipart_body_gets_crlf() {
        let raw = "POST / HTTP/1.1\nContent-Type: multipart/form-data; boundary=x\n\n--x\nContent-Disposition: form-data; name=\"a\"\n\n1\r\n--x--\n";
        let out = String::from_utf8(normalize(raw, true)).unwrap();
        let body = "--x\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\n1\r\n--x--\r\n";
        assert!(
            out.ends_with(&format!("Content-Length: {}\r\n\r\n{body}", body.len())),
            "{out:?}"
        );
    }

    #[test]
    fn duplicate_content_length_collapsed() {
        let out = normalize(
            "POST / HTTP/1.1\nContent-Length: 1\nContent-Length: 2\n\nabc",
            true,
        );
        let s = String::from_utf8(out).unwrap();
        assert_eq!(s.matches("Content-Length").count(), 1);
        assert!(s.contains("Content-Length: 3"));
    }
}
