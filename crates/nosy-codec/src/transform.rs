//! The Decoder's transformations, mirroring `web/src/lib/transform.ts` (same op
//! ids) so the UI and the MCP bridge speak the same language.

use std::{fmt, str::FromStr};

use base64::{
    Engine, alphabet,
    engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig, general_purpose},
};
use sha1::Digest;

use crate::compression;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TransformError(pub String);

fn err<T>(msg: impl Into<String>) -> Result<T, TransformError> {
    Err(TransformError(msg.into()))
}

macro_rules! ops {
    ($($variant:ident = $id:literal / $group:literal: $desc:literal $(| $alias:literal)*;)*) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        pub enum Op { $($variant),* }

        impl Op {
            pub const ALL: &[Op] = &[$(Op::$variant),*];
            pub fn id(self) -> &'static str { match self { $(Op::$variant => $id),* } }
            pub fn group(self) -> &'static str { match self { $(Op::$variant => $group),* } }
            pub fn description(self) -> &'static str { match self { $(Op::$variant => $desc),* } }
        }

        impl FromStr for Op {
            type Err = TransformError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let s = s.trim().to_ascii_lowercase().replace('_', "-");
                match s.as_str() {
                    $($id $(| $alias)* => Ok(Op::$variant),)*
                    _ => err(format!("unknown operation `{s}`; valid: {}", Op::ALL.iter().map(|o| o.id()).collect::<Vec<_>>().join(", "))),
                }
            }
        }
    };
}

ops! {
    B64Dec = "b64-dec" / "decode": "Base64 / Base64URL decode (padding optional)" | "base64" | "base64-decode" | "b64";
    UrlDec = "url-dec" / "decode": "URL / percent decode (+ becomes space)" | "url" | "url-decode";
    HtmlDec = "html-dec" / "decode": "HTML entity decode" | "html" | "html-decode";
    HexDec = "hex-dec" / "decode": "Hex decode (accepts 0x, \\x, %, spaces)" | "hex" | "hex-decode";
    UniDec = "uni-dec" / "decode": "Unicode / JS escapes decode (\\uXXXX, \\u{..}, \\xHH, \\n)" | "unicode" | "unescape";
    Jwt = "jwt" / "decode": "Decode a JWT: header, payload, iat/nbf/exp dates" | "jwt-decode";
    B64Enc = "b64-enc" / "encode": "Base64 encode" | "base64-encode";
    B64UrlEnc = "b64url-enc" / "encode": "Base64URL encode (no padding)" | "base64url-encode";
    UrlEnc = "url-enc" / "encode": "URL encode everything except unreserved chars" | "url-encode";
    UrlEncAll = "url-enc-all" / "encode": "URL encode every byte" | "url-encode-all";
    HtmlEnc = "html-enc" / "encode": "HTML entity encode (& < > \" ')" | "html-encode";
    HexEnc = "hex-enc" / "encode": "Hex encode" | "hex-encode";
    UniEnc = "uni-enc" / "encode": "Escape non-ASCII as \\uXXXX" | "unicode-encode";
    Gunzip = "gunzip" / "compress": "gzip decompress" | "gzip-decode";
    Inflate = "inflate" / "compress": "deflate decompress (zlib or raw)" | "deflate";
    Unbrotli = "brotli" / "compress": "Brotli decompress" | "br" | "unbrotli";
    Unzstd = "zstd" / "compress": "zstd decompress" | "unzstd";
    Gzip = "gzip" / "compress": "gzip compress" | "gzip-encode";
    Md5 = "md5" / "hash": "MD5 (hex)";
    Sha1 = "sha1" / "hash": "SHA-1 (hex)" | "sha-1";
    Sha256 = "sha256" / "hash": "SHA-256 (hex)" | "sha-256";
    Sha384 = "sha384" / "hash": "SHA-384 (hex)" | "sha-384";
    Sha512 = "sha512" / "hash": "SHA-512 (hex)" | "sha-512";
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.id())
    }
}

const B64_LENIENT: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

pub fn apply(op: Op, input: &[u8]) -> Result<Vec<u8>, TransformError> {
    Ok(match op {
        Op::B64Dec => base64_decode(input)?,
        Op::B64Enc => general_purpose::STANDARD.encode(input).into_bytes(),
        Op::B64UrlEnc => general_purpose::URL_SAFE_NO_PAD.encode(input).into_bytes(),
        Op::UrlDec => url_decode(input),
        Op::UrlEnc => url_encode(input, false),
        Op::UrlEncAll => url_encode(input, true),
        Op::HtmlDec => html_decode(&String::from_utf8_lossy(input)).into_bytes(),
        Op::HtmlEnc => html_encode(&String::from_utf8_lossy(input)).into_bytes(),
        Op::HexDec => hex_decode(input)?,
        Op::HexEnc => hex(input).into_bytes(),
        Op::UniDec => unicode_decode(&String::from_utf8_lossy(input)).into_bytes(),
        Op::UniEnc => unicode_encode(&String::from_utf8_lossy(input)).into_bytes(),
        Op::Jwt => jwt_decode(&String::from_utf8_lossy(input))?.into_bytes(),
        Op::Gunzip => compression::gunzip(input).map_or_else(|| err("not valid gzip data"), Ok)?,
        Op::Inflate => {
            compression::inflate(input).map_or_else(|| err("not valid deflate data"), Ok)?
        }
        Op::Unbrotli => {
            compression::unbrotli(input).map_or_else(|| err("not valid brotli data"), Ok)?
        }
        Op::Unzstd => compression::unzstd(input).map_or_else(|| err("not valid zstd data"), Ok)?,
        Op::Gzip => compression::gzip(input),
        Op::Md5 => hex(&md5::Md5::digest(input)).into_bytes(),
        Op::Sha1 => hex(&sha1::Sha1::digest(input)).into_bytes(),
        Op::Sha256 => hex(&sha2::Sha256::digest(input)).into_bytes(),
        Op::Sha384 => hex(&sha2::Sha384::digest(input)).into_bytes(),
        Op::Sha512 => hex(&sha2::Sha512::digest(input)).into_bytes(),
    })
}

// ------------------------------------------------------------------ primitives

fn base64_decode(input: &[u8]) -> Result<Vec<u8>, TransformError> {
    let cleaned: Vec<u8> = input
        .iter()
        .filter(|b| !b.is_ascii_whitespace())
        .map(|&b| match b {
            b'-' => b'+',
            b'_' => b'/',
            b => b,
        })
        .collect();
    B64_LENIENT
        .decode(&cleaned)
        .or_else(|_| err("invalid Base64"))
}

fn url_decode(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'%' if i + 2 < input.len() => match (hex_val(input[i + 1]), hex_val(input[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push(h << 4 | l);
                    i += 3;
                    continue;
                }
                _ => out.push(b'%'),
            },
            b'+' => out.push(b' '),
            b => out.push(b),
        }
        i += 1;
    }
    out
}

fn hex_val(c: u8) -> Option<u8> {
    (c as char).to_digit(16).map(|d| d as u8)
}

fn url_encode(input: &[u8], all: bool) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = Vec::with_capacity(input.len() * 3);
    for &b in input {
        if !all && (b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~')) {
            out.push(b);
        } else {
            out.extend_from_slice(&[b'%', HEX[(b >> 4) as usize], HEX[(b & 15) as usize]]);
        }
    }
    out
}

const NAMED: &[(&str, &str)] = &[
    ("amp", "&"),
    ("lt", "<"),
    ("gt", ">"),
    ("quot", "\""),
    ("apos", "'"),
    ("nbsp", "\u{a0}"),
    ("copy", "©"),
    ("reg", "®"),
    ("trade", "™"),
    ("hellip", "…"),
    ("mdash", "—"),
    ("ndash", "–"),
    ("laquo", "«"),
    ("raquo", "»"),
    ("lsquo", "‘"),
    ("rsquo", "’"),
    ("ldquo", "“"),
    ("rdquo", "”"),
    ("bull", "•"),
    ("middot", "·"),
    ("deg", "°"),
    ("euro", "€"),
    ("times", "×"),
    ("sol", "/"),
    ("colon", ":"),
    ("lpar", "("),
    ("rpar", ")"),
    ("equals", "="),
    ("num", "#"),
    ("quest", "?"),
];

fn html_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        rest = &rest[i..];
        let end = rest[1..]
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '#'))
            .map(|e| e + 1);
        let (entity, consumed) = match end {
            Some(e) => (
                &rest[1..e],
                if rest[e..].starts_with(';') { e + 1 } else { e },
            ),
            None => (&rest[1..], rest.len()),
        };
        let decoded = if let Some(num) = entity.strip_prefix('#') {
            let cp = match num.strip_prefix(['x', 'X']) {
                Some(h) => u32::from_str_radix(h, 16).ok(),
                None => num.parse().ok(),
            };
            cp.and_then(char::from_u32).map(String::from)
        } else {
            NAMED
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(entity))
                .map(|(_, v)| v.to_string())
        };
        match decoded {
            Some(d) if !entity.is_empty() => {
                out.push_str(&d);
                rest = &rest[consumed..];
            }
            _ => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn html_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            c => out.push(c),
        }
    }
    out
}

pub fn hex(b: &[u8]) -> String {
    use std::fmt::Write;
    b.iter()
        .fold(String::with_capacity(b.len() * 2), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
}

fn hex_decode(input: &[u8]) -> Result<Vec<u8>, TransformError> {
    let s = String::from_utf8_lossy(input)
        .to_ascii_lowercase()
        .replace("0x", "")
        .replace("\\x", "");
    let digits: Vec<u8> = s
        .bytes()
        .filter(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b':' | b',' | b'-' | b'%'))
        .collect();
    if !digits.len().is_multiple_of(2) || !digits.iter().all(u8::is_ascii_hexdigit) {
        return err("invalid hex");
    }
    Ok(digits
        .chunks(2)
        .map(|p| hex_val(p[0]).unwrap() << 4 | hex_val(p[1]).unwrap())
        .collect())
}

fn unicode_decode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    let mut pending_high: Option<u32> = None;
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(&n) = chars.peek() else {
            out.push('\\');
            break;
        };
        let take =
            |chars: &mut std::iter::Peekable<std::str::Chars<'_>>, k: usize| -> Option<u32> {
                let s: String = chars.clone().take(k).collect();
                if s.len() == k && s.chars().all(|c| c.is_ascii_hexdigit()) {
                    for _ in 0..k {
                        chars.next();
                    }
                    u32::from_str_radix(&s, 16).ok()
                } else {
                    None
                }
            };
        match n {
            'u' | 'U' => {
                chars.next();
                let cp = if chars.peek() == Some(&'{') {
                    let body: String = chars.clone().skip(1).take_while(|&c| c != '}').collect();
                    match u32::from_str_radix(&body, 16) {
                        Ok(v) => {
                            for _ in 0..body.len() + 2 {
                                chars.next();
                            }
                            Some(v)
                        }
                        Err(_) => None,
                    }
                } else {
                    take(&mut chars, 4)
                };
                match cp {
                    Some(hi @ 0xD800..=0xDBFF) => pending_high = Some(hi),
                    Some(lo @ 0xDC00..=0xDFFF) if pending_high.is_some() => {
                        let hi = pending_high.take().unwrap();
                        out.extend(char::from_u32(
                            0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00),
                        ));
                    }
                    Some(v) => out.push(char::from_u32(v).unwrap_or('\u{fffd}')),
                    None => out.push_str("\\u"),
                }
                continue;
            }
            'x' | 'X' => {
                chars.next();
                match take(&mut chars, 2) {
                    Some(v) => out.push(char::from_u32(v).unwrap_or('\u{fffd}')),
                    None => out.push_str("\\x"),
                }
            }
            'n' | 'r' | 't' | 'b' | 'f' | 'v' | '0' | '\'' | '"' | '\\' | '/' => {
                chars.next();
                out.push(match n {
                    'n' => '\n',
                    'r' => '\r',
                    't' => '\t',
                    'b' => '\u{8}',
                    'f' => '\u{c}',
                    'v' => '\u{b}',
                    '0' => '\0',
                    c => c,
                });
            }
            _ => out.push('\\'),
        }
        if let Some(hi) = pending_high.take() {
            out.push(char::from_u32(hi).unwrap_or('\u{fffd}'));
        }
    }
    out
}

fn unicode_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let cp = c as u32;
        if (0x20..0x7f).contains(&cp) {
            out.push(c);
        } else if cp > 0xffff {
            out.push_str(&format!("\\u{{{cp:x}}}"));
        } else {
            out.push_str(&format!("\\u{cp:04x}"));
        }
    }
    out
}

fn jwt_segment(seg: &str) -> Result<serde_json::Value, TransformError> {
    let raw = base64_decode(seg.as_bytes())?;
    serde_json::from_slice(&raw).or_else(|_| err("not a JWT (segments are not Base64URL JSON)"))
}

pub fn jwt_decode(token: &str) -> Result<String, TransformError> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    if !(2..=3).contains(&parts.len()) {
        return err("not a JWT (expected header.payload.signature)");
    }
    let header = jwt_segment(parts[0])?;
    let payload = jwt_segment(parts[1])?;
    let pretty = |v: &serde_json::Value| serde_json::to_string_pretty(v).unwrap_or_default();
    let mut out = format!(
        "// header\n{}\n\n// payload\n{}\n",
        pretty(&header),
        pretty(&payload)
    );
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let mut times = String::new();
    for k in ["iat", "nbf", "exp"] {
        if let Some(ts) = payload.get(k).and_then(serde_json::Value::as_i64)
            && let Ok(d) = time::OffsetDateTime::from_unix_timestamp(ts)
        {
            let iso = d
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default();
            let expired = if k == "exp" && ts < now {
                "  (expired)"
            } else {
                ""
            };
            times.push_str(&format!("// {k}: {iso}{expired}\n"));
        }
    }
    if !times.is_empty() {
        out.push('\n');
        out.push_str(&times);
    }
    let alg = header.get("alg").and_then(|a| a.as_str()).unwrap_or("?");
    out.push_str(&format!(
        "\n// signature ({alg})\n{}\n",
        parts.get(2).filter(|s| !s.is_empty()).unwrap_or(&"(none)")
    ));
    Ok(out)
}

// ------------------------------------------------------------------ detection

/// Mostly printable text (valid UTF-8, few control characters)?
pub fn is_printable(b: &[u8]) -> bool {
    let Ok(s) = std::str::from_utf8(b) else {
        return false;
    };
    let bad = s
        .chars()
        .filter(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        .count();
    bad * 50 <= s.chars().count()
}

fn is_jwt_shape(s: &str) -> bool {
    let parts: Vec<&str> = s.split('.').collect();
    parts.len() == 3
        && parts[..2].iter().all(|p| p.len() >= 2)
        && parts.iter().all(|p| {
            p.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

/// Guess the next decoding step, mirroring the UI's "smart decode".
pub fn detect(b: &[u8]) -> Option<Op> {
    if b.starts_with(&[0x1f, 0x8b]) {
        return Some(Op::Gunzip);
    }
    if b.len() >= 2 && b[0] == 0x78 && matches!(b[1], 0x01 | 0x5e | 0x9c | 0xda) {
        return Some(Op::Inflate);
    }
    if b.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) {
        return Some(Op::Unzstd);
    }
    if !is_printable(b) || b.len() > 4 * 1024 * 1024 {
        return None;
    }
    let s = std::str::from_utf8(b).ok()?.trim();
    if s.len() < 4 {
        return None;
    }
    if is_jwt_shape(s) && jwt_decode(s).is_ok() {
        return Some(Op::Jwt);
    }
    let lower = s.to_ascii_lowercase();
    let has_pct = lower
        .as_bytes()
        .windows(3)
        .any(|w| w[0] == b'%' && w[1].is_ascii_hexdigit() && w[2].is_ascii_hexdigit());
    if has_pct {
        return Some(Op::UrlDec);
    }
    if lower.contains("&amp;")
        || lower.contains("&lt;")
        || lower.contains("&quot;")
        || lower.contains("&#")
    {
        return Some(Op::HtmlDec);
    }
    if lower.contains("\\u") || lower.contains("\\x") {
        return Some(Op::UniDec);
    }
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let compact_hex = compact.strip_prefix("0x").unwrap_or(&compact);
    if compact_hex.len() >= 8
        && compact_hex.len().is_multiple_of(2)
        && compact_hex.bytes().all(|b| b.is_ascii_hexdigit())
        && let Ok(out) = hex_decode(compact_hex.as_bytes())
        && (is_printable(&out) || detect(&out) == Some(Op::Gunzip))
    {
        return Some(Op::HexDec);
    }
    let b64ish = compact.len() >= 8
        && compact
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'));
    if b64ish
        && let Ok(out) = base64_decode(compact.as_bytes())
        && !out.is_empty()
        && (is_printable(&out)
            || matches!(detect(&out), Some(Op::Gunzip | Op::Inflate | Op::Unzstd)))
    {
        return Some(Op::B64Dec);
    }
    None
}

/// Repeatedly apply [`detect`] (at most `limit` steps). Returns each step and its output.
pub fn smart_chain(input: &[u8], limit: usize) -> Vec<(Op, Vec<u8>)> {
    let mut chain: Vec<(Op, Vec<u8>)> = Vec::new();
    for _ in 0..limit {
        let cur = chain.last().map_or(input, |(_, o)| o.as_slice());
        let Some(op) = detect(cur) else { break };
        match apply(op, cur) {
            Ok(next) if next != cur => {
                let done = op == Op::Jwt;
                chain.push((op, next));
                if done {
                    break;
                }
            }
            _ => break,
        }
    }
    chain
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(op: &str, input: &str) -> String {
        String::from_utf8(apply(op.parse().unwrap(), input.as_bytes()).unwrap()).unwrap()
    }

    #[test]
    fn base64_and_url() {
        assert_eq!(
            run("b64-enc", "Привет, мир"),
            "0J/RgNC40LLQtdGCLCDQvNC40YA="
        );
        assert_eq!(run("base64", "0J_RgNC40LLQtdGCLCDQvNC40YA"), "Привет, мир");
        assert_eq!(run("b64url-enc", "\u{fb}"), "w7s");
        assert!(apply(Op::B64Dec, b"a$b").is_err());
        assert_eq!(run("url-dec", "a%20b+c%2Fd%zz%E2%9C%93%"), "a b c/d%zz✓%");
        assert_eq!(run("url-enc", "a b/✓"), "a%20b%2F%E2%9C%93");
        assert_eq!(run("url-enc-all", "ab"), "%61%62");
    }

    #[test]
    fn html_hex_unicode() {
        assert_eq!(
            run(
                "html-dec",
                "&lt;a&gt; &amp;amp; &#39;&#x41; &laquo;&unknown; & x"
            ),
            "<a> &amp; 'A «&unknown; & x"
        );
        assert_eq!(run("html-enc", "<\"'&>"), "&lt;&quot;&#x27;&amp;&gt;");
        assert_eq!(run("hex-enc", "AZ"), "415a");
        assert_eq!(run("hex-dec", "0x41 5a"), "AZ");
        assert_eq!(run("hex-dec", "\\x41\\x5a"), "AZ");
        assert!(apply(Op::HexDec, b"abc").is_err());
        assert_eq!(
            run("uni-dec", "\\u041f\\u0440\\x21\\n\\u{1F600}\\ud83d\\ude00"),
            "Пр!\n😀😀"
        );
        assert_eq!(run("uni-enc", "aП😀"), "a\\u041f\\u{1f600}");
    }

    #[test]
    fn hashes_match_reference_vectors() {
        assert_eq!(run("md5", ""), "d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(
            run("md5", "The quick brown fox jumps over the lazy dog"),
            "9e107d9d372bb6826bd81d3542a419d6"
        );
        assert_eq!(
            run("sha1", "abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            run("sha256", "abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn jwt() {
        let tok = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let out = jwt_decode(tok).unwrap();
        assert!(out.contains("\"alg\": \"HS256\""));
        assert!(out.contains("\"name\": \"John Doe\""));
        assert!(out.contains("// iat: 2018-01-18T01:30:22Z"), "{out}");
        assert!(out.ends_with("SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c\n"));
    }

    #[test]
    fn smart_chain_peels_layers() {
        let inner = br#"{"user":"admin"}"#;
        let layered = apply(
            Op::UrlEnc,
            &apply(Op::B64Enc, &compression::gzip(inner)).unwrap(),
        )
        .unwrap();
        let chain = smart_chain(&layered, 8);
        assert_eq!(chain.last().unwrap().1, inner);
        let ops: Vec<_> = chain.iter().map(|(o, _)| *o).collect();
        assert!(ops.ends_with(&[Op::B64Dec, Op::Gunzip]), "{ops:?}");
        assert_eq!(detect(b"hello world"), None);
        assert_eq!(detect(b"68656c6c6f20776f726c64"), Some(Op::HexDec));
        assert_eq!(
            smart_chain(b"YWRtaW46c2VjcmV0", 8)
                .iter()
                .map(|(o, _)| *o)
                .collect::<Vec<_>>(),
            vec![Op::B64Dec]
        );
    }

    #[test]
    fn op_ids_parse_with_aliases() {
        for op in Op::ALL {
            assert_eq!(op.id().parse::<Op>().unwrap(), *op);
        }
        assert_eq!("BASE64".parse::<Op>().unwrap(), Op::B64Dec);
        assert!("nope".parse::<Op>().is_err());
    }
}
