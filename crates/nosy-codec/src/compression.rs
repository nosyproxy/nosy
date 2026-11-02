use std::io::Read;

/// Hard cap on decompressed output (zip-bomb guard).
pub const MAX_DECODED: u64 = 128 * 1024 * 1024;

/// Decode a `Content-Encoding` chain (applied in order, so undone in reverse).
/// Returns `None` if any step fails or the encoding is unknown.
pub fn decode_body(body: &[u8], content_encoding: &[u8]) -> Option<Vec<u8>> {
    let enc = std::str::from_utf8(content_encoding).ok()?;
    let mut data = body.to_vec();
    for coding in enc.rsplit(',').map(|c| c.trim().to_ascii_lowercase()) {
        data = match coding.as_str() {
            "" | "identity" => data,
            "gzip" | "x-gzip" => gunzip(&data)?,
            "deflate" => inflate(&data)?,
            "br" => unbrotli(&data)?,
            "zstd" => unzstd(&data)?,
            _ => return None,
        };
    }
    Some(data)
}

pub fn gunzip(data: &[u8]) -> Option<Vec<u8>> {
    read_all(flate2::read::MultiGzDecoder::new(data))
}

/// zlib-wrapped deflate, falling back to raw deflate (both appear in the wild).
pub fn inflate(data: &[u8]) -> Option<Vec<u8>> {
    read_all(flate2::read::ZlibDecoder::new(data))
        .or_else(|| read_all(flate2::read::DeflateDecoder::new(data)))
}

pub fn unbrotli(data: &[u8]) -> Option<Vec<u8>> {
    read_all(brotli::Decompressor::new(data, 64 * 1024))
}

pub fn unzstd(data: &[u8]) -> Option<Vec<u8>> {
    read_all(zstd::stream::read::Decoder::new(data).ok()?)
}

pub fn gzip(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).expect("writing to a Vec cannot fail");
    e.finish().expect("writing to a Vec cannot fail")
}

fn read_all(r: impl Read) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    r.take(MAX_DECODED).read_to_end(&mut out).ok()?;
    Some(out)
}

/// Remove HTTP/1.1 chunked framing. `None` if the framing is malformed.
pub fn dechunk(mut buf: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(buf.len());
    loop {
        let line_end = buf.windows(2).position(|w| w == b"\r\n")?;
        let size_str = std::str::from_utf8(&buf[..line_end])
            .ok()?
            .split(';')
            .next()?
            .trim();
        let size = usize::from_str_radix(size_str, 16).ok()?;
        buf = &buf[line_end + 2..];
        if size == 0 {
            return Some(out);
        }
        out.extend_from_slice(buf.get(..size)?);
        buf = buf.get(size + 2..)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn decodes_chains() {
        let z = gzip(b"hello");
        assert_eq!(decode_body(&z, b"gzip").unwrap(), b"hello");
        assert_eq!(decode_body(&gzip(&z), b"gzip, gzip").unwrap(), b"hello");
        assert!(decode_body(b"x", b"compress").is_none());
        let mut br = Vec::new();
        brotli::CompressorWriter::new(&mut br, 4096, 5, 22)
            .write_all(b"brotli!")
            .unwrap();
        assert_eq!(decode_body(&br, b"br").unwrap(), b"brotli!");
        let zs = zstd::encode_all(&b"zstd!"[..], 1).unwrap();
        assert_eq!(decode_body(&zs, b"zstd").unwrap(), b"zstd!");
    }

    #[test]
    fn dechunks() {
        assert_eq!(
            dechunk(b"3\r\nabc\r\n1;x=y\r\nd\r\n0\r\n\r\n").unwrap(),
            b"abcd"
        );
        assert!(dechunk(b"zz\r\n").is_none());
    }
}
