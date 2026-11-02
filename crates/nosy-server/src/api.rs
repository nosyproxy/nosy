use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use nosy_model::{
    AppInfo, FlowDetail, FlowFilter, FlowId, FlowPatch, FlowSummary, HostCount, NewRepeaterTab,
    RepeaterEntry, RepeaterTab, RepeaterTabPatch, ReplayTemplate, SearchResult, SendRequest,
    Target,
};
use nosy_store::{NewEntry, Store};
use serde::Deserialize;

use crate::{
    codec,
    error::{ApiError, ApiResult},
    state::AppState,
};

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/info", get(info))
        .route("/ca.crt", get(ca_pem))
        .route("/ca.der", get(ca_der))
        .route("/flows", get(list_flows).delete(clear_flows))
        .route("/flows/delete", post(delete_flows))
        .route("/flows/{id}", get(flow_detail).patch(patch_flow))
        .route("/flows/{id}/request", get(flow_request))
        .route("/flows/{id}/response", get(flow_response))
        .route("/flows/{id}/repeater", post(flow_to_repeater))
        .route("/flows/{id}/replay", get(flow_replay))
        .route("/hosts", get(hosts))
        .route("/search", get(search))
        .route("/repeater/tabs", get(list_tabs).post(create_tab))
        .route(
            "/repeater/tabs/{id}",
            axum::routing::patch(patch_tab).delete(delete_tab),
        )
        .route("/repeater/tabs/{id}/send", post(send))
        .route("/repeater/tabs/{id}/history", get(history))
        .route("/repeater/history/{id}/request", get(history_request))
        .route("/repeater/history/{id}/response", get(history_response))
        .route("/ws", get(crate::ws::handler))
}

/// Run a blocking store operation off the async runtime.
async fn db<T: Send + 'static>(
    state: &AppState,
    f: impl FnOnce(&Store) -> nosy_store::Result<T> + Send + 'static,
) -> ApiResult<T> {
    let store = state.store.clone();
    Ok(tokio::task::spawn_blocking(move || f(&store)).await??)
}

fn octets(data: Vec<u8>) -> Response {
    (
        [
            (
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/octet-stream"),
            ),
            (header::CACHE_CONTROL, HeaderValue::from_static("no-store")),
        ],
        data,
    )
        .into_response()
}

#[derive(Deserialize)]
struct DecodeQuery {
    #[serde(default)]
    decode: bool,
    /// Only the body, without the head.
    #[serde(default)]
    body: bool,
}

async fn info(State(s): State<AppState>) -> Json<AppInfo> {
    Json((*s.info).clone())
}

async fn ca_pem(State(s): State<AppState>) -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/x-x509-ca-cert"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"nosy-ca.crt\"",
            ),
        ],
        s.ca.ca_pem().to_owned(),
    )
        .into_response()
}

async fn ca_der(State(s): State<AppState>) -> Response {
    (
        [
            (header::CONTENT_TYPE, "application/x-x509-ca-cert"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"nosy-ca.der\"",
            ),
        ],
        s.ca.ca_der().to_vec(),
    )
        .into_response()
}

// ---------------------------------------------------------------- flows

async fn list_flows(
    State(s): State<AppState>,
    Query(f): Query<FlowFilter>,
) -> ApiResult<Json<Vec<FlowSummary>>> {
    Ok(Json(db(&s, move |st| st.list_flows(&f)).await?))
}

async fn clear_flows(State(s): State<AppState>) -> ApiResult<StatusCode> {
    db(&s, |st| st.clear_flows()).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
struct DeleteBody {
    ids: Vec<FlowId>,
}

async fn delete_flows(
    State(s): State<AppState>,
    Json(b): Json<DeleteBody>,
) -> ApiResult<StatusCode> {
    db(&s, move |st| st.delete_flows(&b.ids)).await?;
    Ok(StatusCode::NO_CONTENT)
}

async fn flow_detail(
    State(s): State<AppState>,
    Path(id): Path<FlowId>,
) -> ApiResult<Json<FlowDetail>> {
    Ok(Json(db(&s, move |st| st.flow_detail(id)).await?))
}

async fn patch_flow(
    State(s): State<AppState>,
    Path(id): Path<FlowId>,
    Json(p): Json<FlowPatch>,
) -> ApiResult<Json<FlowSummary>> {
    Ok(Json(db(&s, move |st| st.patch_flow(id, &p)).await?))
}

async fn flow_request(
    State(s): State<AppState>,
    Path(id): Path<FlowId>,
    Query(q): Query<DecodeQuery>,
) -> ApiResult<Response> {
    let m = db(&s, move |st| st.request_message(id)).await?;
    let data = tokio::task::spawn_blocking(move || {
        if q.body {
            codec::body_only(&m.body, &m.headers, q.decode)
        } else {
            codec::render_request(&m, q.decode)
        }
    })
    .await?;
    Ok(octets(data))
}

async fn flow_response(
    State(s): State<AppState>,
    Path(id): Path<FlowId>,
    Query(q): Query<DecodeQuery>,
) -> ApiResult<Response> {
    let m = db(&s, move |st| st.response_message(id)).await?;
    let data = tokio::task::spawn_blocking(move || {
        if q.body {
            codec::body_only(&m.body, &m.headers, q.decode)
        } else {
            codec::render_response(&m, q.decode)
        }
    })
    .await?;
    Ok(octets(data))
}

fn replay_template(st: &Store, id: FlowId) -> nosy_store::Result<ReplayTemplate> {
    let m = st.request_message(id)?;
    let summary = st.flow(id)?;
    Ok(ReplayTemplate {
        target: Target {
            host: m.host.clone(),
            port: m.port,
            tls: m.scheme == "https",
            http2: summary.http_version == "HTTP/2",
        },
        raw_request: codec::repeater_text(&m),
    })
}

async fn flow_to_repeater(
    State(s): State<AppState>,
    Path(id): Path<FlowId>,
) -> ApiResult<Json<RepeaterTab>> {
    let tab = db(&s, move |st| {
        let t = replay_template(st, id)?;
        st.create_tab(&NewRepeaterTab {
            name: None,
            target: t.target,
            raw_request: t.raw_request,
        })
    })
    .await?;
    Ok(Json(tab))
}

/// Editor-ready request text and target for a captured flow, without creating a tab.
async fn flow_replay(
    State(s): State<AppState>,
    Path(id): Path<FlowId>,
) -> ApiResult<Json<ReplayTemplate>> {
    Ok(Json(db(&s, move |st| replay_template(st, id)).await?))
}

async fn hosts(State(s): State<AppState>) -> ApiResult<Json<Vec<HostCount>>> {
    Ok(Json(db(&s, |st| st.hosts()).await?))
}

async fn search(
    State(s): State<AppState>,
    Query(p): Query<crate::search::SearchParams>,
) -> ApiResult<Json<SearchResult>> {
    Ok(Json(db(&s, move |st| crate::search::search(st, &p)).await?))
}

// ---------------------------------------------------------------- repeater

async fn list_tabs(State(s): State<AppState>) -> ApiResult<Json<Vec<RepeaterTab>>> {
    Ok(Json(db(&s, |st| st.list_tabs()).await?))
}

async fn create_tab(
    State(s): State<AppState>,
    Json(t): Json<NewRepeaterTab>,
) -> ApiResult<Json<RepeaterTab>> {
    validate_target(&t.target)?;
    Ok(Json(db(&s, move |st| st.create_tab(&t)).await?))
}

async fn patch_tab(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    Json(p): Json<RepeaterTabPatch>,
) -> ApiResult<Json<RepeaterTab>> {
    if let Some(t) = &p.target {
        validate_target(t)?;
    }
    Ok(Json(db(&s, move |st| st.patch_tab(id, &p)).await?))
}

async fn delete_tab(State(s): State<AppState>, Path(id): Path<i64>) -> ApiResult<StatusCode> {
    db(&s, move |st| st.delete_tab(id)).await?;
    Ok(StatusCode::NO_CONTENT)
}

fn validate_target(t: &Target) -> ApiResult<()> {
    if t.host.trim().is_empty() {
        return Err(ApiError::bad_request("target host is empty"));
    }
    if t.port == 0 {
        return Err(ApiError::bad_request("target port is 0"));
    }
    Ok(())
}

/// Send the request. If the client disconnects, this future is dropped and the
/// in-flight request is cancelled with it.
async fn send(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<SendRequest>,
) -> ApiResult<Json<RepeaterEntry>> {
    validate_target(&req.target)?;
    // Persist editor state first so a reload shows what was sent.
    let patch = RepeaterTabPatch {
        target: Some(req.target.clone()),
        raw_request: Some(req.raw_request.clone()),
        ..Default::default()
    };
    db(&s, move |st| st.patch_tab(id, &patch)).await?;

    let out = s.repeater.send(&req).await;
    let target = req.target;
    let entry = db(&s, move |st| {
        st.add_repeater_entry(
            id,
            &target,
            &out.sent,
            out.response.as_deref(),
            &NewEntry {
                status: out.status,
                http_version: out.http_version,
                ttfb_us: out.ttfb_us,
                duration_us: out.duration_us,
                error: out.error,
            },
        )
    })
    .await?;
    Ok(Json(entry))
}

async fn history(
    State(s): State<AppState>,
    Path(id): Path<i64>,
) -> ApiResult<Json<Vec<RepeaterEntry>>> {
    Ok(Json(db(&s, move |st| st.repeater_history(id)).await?))
}

async fn history_request(State(s): State<AppState>, Path(id): Path<i64>) -> ApiResult<Response> {
    Ok(octets(db(&s, move |st| st.repeater_raw(id, false)).await?))
}

async fn history_response(
    State(s): State<AppState>,
    Path(id): Path<i64>,
    Query(q): Query<DecodeQuery>,
) -> ApiResult<Response> {
    let raw = db(&s, move |st| st.repeater_raw(id, true)).await?;
    let data = if q.decode {
        tokio::task::spawn_blocking(move || codec::decode_raw_message(&raw)).await?
    } else {
        raw
    };
    Ok(octets(data))
}
