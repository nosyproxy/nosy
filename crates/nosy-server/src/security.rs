//! Guards against other websites (loaded in a browser that uses this proxy!)
//! talking to the local API:
//! * `Host` must be one we serve (DNS rebinding).
//! * State-changing requests and WebSocket upgrades must come from our own origin (CSRF / CSWSH).

use axum::{
    extract::{Request, State},
    http::{Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};

use crate::state::AppState;

pub async fn guard(State(state): State<AppState>, req: Request, next: Next) -> Response {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or_default();
    if !state.allowed_hosts.is_empty()
        && !state
            .allowed_hosts
            .iter()
            .any(|h| h.eq_ignore_ascii_case(host))
    {
        return (StatusCode::FORBIDDEN, "forbidden host").into_response();
    }
    let is_ws = req.headers().contains_key(header::UPGRADE);
    let unsafe_method = !matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    if (is_ws || unsafe_method)
        && let Some(origin) = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|o| o.to_str().ok())
    {
        let ok = origin
            .strip_prefix("http://")
            .or_else(|| origin.strip_prefix("https://"))
            .is_some_and(|o| o.eq_ignore_ascii_case(host));
        if !ok {
            return (StatusCode::FORBIDDEN, "cross-origin request rejected").into_response();
        }
    }
    next.run(req).await
}

/// Hostnames under which the UI may be reached for a given bind address.
pub fn allowed_hosts(addr: std::net::SocketAddr) -> Vec<String> {
    let port = addr.port();
    if addr.ip().is_unspecified() {
        return Vec::new(); // explicitly exposed: cannot enumerate names
    }
    let mut v = vec![format!("{addr}")];
    if addr.ip().is_loopback() {
        for h in ["localhost", "127.0.0.1", "[::1]"] {
            v.push(format!("{h}:{port}"));
        }
    }
    v
}
