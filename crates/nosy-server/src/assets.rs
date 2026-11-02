//! The Vue SPA, embedded at compile time (read from disk in debug builds).

use axum::{
    http::{HeaderValue, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "$NOSY_UI_DIR"]
#[allow_missing = true]
struct Assets;

pub async fn serve(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');
    if path.starts_with("api/") {
        return StatusCode::NOT_FOUND.into_response();
    }
    if let Some(r) = file(path) {
        return r;
    }
    // SPA fallback.
    file("index.html").unwrap_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "UI not built: run `make ui` (or use the nosy-web Vite dev server)",
        )
            .into_response()
    })
}

fn file(path: &str) -> Option<Response> {
    let path = if path.is_empty() { "index.html" } else { path };
    let f = Assets::get(path)?;
    let mime = mime_guess::from_path(path).first_or_octet_stream();
    // Vite emits content-hashed names under assets/.
    let cache = if path.starts_with("assets/") {
        "public, max-age=31536000, immutable"
    } else {
        "no-cache"
    };
    let mut resp = (
        [
            (header::CONTENT_TYPE, mime.as_ref().to_owned()),
            (header::CACHE_CONTROL, cache.to_owned()),
        ],
        f.data,
    )
        .into_response();
    let h = resp.headers_mut();
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if mime.essence_str() == "text/html" {
        h.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CSP),
        );
    }
    Some(resp)
}

/// Scripts only from our own origin. Captured HTML is previewed in `sandbox=""`
/// iframes, which inherit this policy and add a stricter one of their own; the
/// wildcards for images/styles/fonts only matter when the user enables loading
/// external resources in previews. `base-uri` is deliberately not restricted so
/// previews can resolve relative URLs against the original site.
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' *; \
    img-src 'self' data: blob: *; font-src 'self' data: *; media-src 'self' data: blob: *; \
    connect-src 'self'; frame-src 'self' about: blob:; object-src 'none'; \
    form-action 'self'; frame-ancestors 'none'";
