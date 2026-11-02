//! Pages served by the proxy itself (`http://nosy/`), e.g. to download the CA.

use bytes::Bytes;
use http::{HeaderValue, Response, StatusCode, header};
use http_body_util::{Either, Full};
use nosy_ca::CertificateAuthority;

use crate::{RespBody, text};

pub const MAGIC_HOST: &str = "nosy";

const INDEX: &str = r#"<!doctype html><html><head><meta charset="utf-8"><title>Nosy</title>
<style>body{font:15px system-ui;background:#111;color:#ddd;max-width:40em;margin:4em auto}a{color:#f80}</style>
</head><body><h1>Nosy</h1><p>The proxy is running.</p>
<p><a href="/ca.crt">Download CA certificate (PEM)</a> · <a href="/ca.der">DER</a></p>
<p>Import it as a trusted authority for websites in your browser or OS to intercept HTTPS.</p>
</body></html>"#;

pub fn respond(ca: &CertificateAuthority, path: &str) -> Response<RespBody> {
    let (ct, body, name) = match path {
        "/" | "" => (
            "text/html; charset=utf-8",
            Bytes::from_static(INDEX.as_bytes()),
            None,
        ),
        "/ca.crt" | "/cert" => (
            "application/x-x509-ca-cert",
            Bytes::copy_from_slice(ca.ca_pem().as_bytes()),
            Some("nosy-ca.crt"),
        ),
        "/ca.der" => (
            "application/x-x509-ca-cert",
            Bytes::copy_from_slice(ca.ca_der()),
            Some("nosy-ca.der"),
        ),
        _ => return text(StatusCode::NOT_FOUND, "not found"),
    };
    let mut r = Response::new(Either::Right(Full::new(body)));
    r.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(ct));
    if let Some(name) = name
        && let Ok(v) = HeaderValue::from_str(&format!("attachment; filename=\"{name}\""))
    {
        r.headers_mut().insert(header::CONTENT_DISPOSITION, v);
    }
    r
}
