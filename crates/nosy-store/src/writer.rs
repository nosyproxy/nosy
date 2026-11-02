//! Dedicated writer thread: drains the event channel and commits batches.
//!
//! No artificial delay: after the first event arrives, everything already queued
//! is drained and committed in one transaction. Under load, batches grow
//! naturally while the previous commit is in flight.

use std::collections::{HashMap, HashSet};

use crossbeam_channel::Receiver;
use nosy_model::{
    FlowId, WsEvent,
    capture::{FlowEvent, RequestRecord, ResponseRecord},
};
use rusqlite::{Connection, params};
use tokio::sync::broadcast;

use crate::{flows::summary_by_id, util::path_ext};

pub(crate) enum Msg {
    Event(FlowEvent),
    /// Reply once everything sent before this message is committed.
    Flush(crossbeam_channel::Sender<()>),
}

const MAX_BATCH: usize = 1024;

pub(crate) fn run(mut conn: Connection, rx: Receiver<Msg>, events: broadcast::Sender<WsEvent>) {
    let mut batch: Vec<FlowEvent> = Vec::with_capacity(MAX_BATCH);
    let mut waiters = Vec::new();
    let mut touched: HashSet<FlowId> = HashSet::new();

    while let Ok(first) = rx.recv() {
        push(first, &mut batch, &mut waiters);
        while batch.len() < MAX_BATCH {
            match rx.try_recv() {
                Ok(m) => push(m, &mut batch, &mut waiters),
                Err(_) => break,
            }
        }
        if !batch.is_empty() {
            touched.clear();
            if let Err(e) = commit(&mut conn, &batch, &mut touched) {
                tracing::error!(error = %e, n = batch.len(), "failed to persist flows");
            } else if events.receiver_count() > 0 {
                let flows: Vec<_> = touched
                    .iter()
                    .filter_map(|&id| summary_by_id(&conn, id).ok().flatten())
                    .collect();
                if !flows.is_empty() {
                    let _ = events.send(WsEvent::Flows { flows });
                }
            }
            batch.clear();
        }
        for w in waiters.drain(..) {
            let _ = w.send(());
        }
    }
    tracing::debug!("store writer stopped");
}

fn push(m: Msg, batch: &mut Vec<FlowEvent>, waiters: &mut Vec<crossbeam_channel::Sender<()>>) {
    match m {
        Msg::Event(e) => batch.push(e),
        Msg::Flush(tx) => waiters.push(tx),
    }
}

fn commit(
    conn: &mut Connection,
    batch: &[FlowEvent],
    touched: &mut HashSet<FlowId>,
) -> rusqlite::Result<()> {
    // Pair up request/response events of the same flow so the common case is a
    // single INSERT per table instead of insert + upsert.
    let mut responses: HashMap<FlowId, &ResponseRecord> = HashMap::new();
    for ev in batch {
        if let FlowEvent::Response(r) = ev {
            responses.insert(r.id, r);
        }
    }
    let mut merged: HashSet<FlowId> = HashSet::new();

    let tx = conn.transaction()?;
    for ev in batch {
        match ev {
            FlowEvent::Request(r) => {
                match responses.get(&r.id) {
                    Some(resp) => {
                        insert_full(&tx, r, resp)?;
                        merged.insert(r.id);
                    }
                    None => insert_request(&tx, r)?,
                }
                touched.insert(r.id);
            }
            FlowEvent::Response(r) => {
                if !merged.contains(&r.id) {
                    insert_response(&tx, r)?;
                }
                touched.insert(r.id);
            }
            FlowEvent::Error {
                id,
                ts_end,
                duration_us,
                message,
            } => {
                tx.prepare_cached(
                    "INSERT INTO flows (id, ts_end, duration_us, error) VALUES (?1, ?2, ?3, ?4)
                     ON CONFLICT(id) DO UPDATE SET
                        ts_end = excluded.ts_end, duration_us = excluded.duration_us,
                        error = excluded.error",
                )?
                .execute(params![id, ts_end, duration_us, message])?;
                touched.insert(*id);
            }
        }
    }
    tx.commit()
}

fn insert_full(
    tx: &rusqlite::Transaction<'_>,
    q: &RequestRecord,
    r: &ResponseRecord,
) -> rusqlite::Result<()> {
    tx.prepare_cached(
        "INSERT INTO flows (id, ts_start, scheme, host, port, method, path, ext, http_version,
                            req_size, truncated, ts_end, status, resp_version, resp_size,
                            content_type, duration_us, error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)
         ON CONFLICT(id) DO UPDATE SET
            ts_start = excluded.ts_start, scheme = excluded.scheme, host = excluded.host,
            port = excluded.port, method = excluded.method, path = excluded.path,
            ext = excluded.ext, http_version = excluded.http_version, req_size = excluded.req_size,
            truncated = truncated OR excluded.truncated, ts_end = excluded.ts_end,
            status = excluded.status, resp_version = excluded.resp_version,
            resp_size = excluded.resp_size, content_type = excluded.content_type,
            duration_us = excluded.duration_us, error = COALESCE(excluded.error, error)",
    )?
    .execute(params![
        q.id,
        q.ts_start,
        q.scheme,
        q.host,
        q.port,
        q.method,
        q.path,
        path_ext(&q.path),
        q.http_version,
        q.body_size,
        q.truncated || r.truncated,
        r.ts_end,
        r.status,
        r.http_version,
        r.body_size,
        r.content_type,
        r.duration_us,
        r.error,
    ])?;
    tx.prepare_cached(
        "INSERT INTO flow_data (flow_id, req_headers, req_body, resp_headers, resp_body)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(flow_id) DO UPDATE SET
            req_headers = excluded.req_headers, req_body = excluded.req_body,
            resp_headers = excluded.resp_headers, resp_body = excluded.resp_body",
    )?
    .execute(params![
        q.id,
        q.headers,
        q.body.as_ref(),
        r.headers,
        r.body.as_ref()
    ])?;
    Ok(())
}

fn insert_request(tx: &rusqlite::Transaction<'_>, r: &RequestRecord) -> rusqlite::Result<()> {
    tx.prepare_cached(
        "INSERT INTO flows (id, ts_start, scheme, host, port, method, path, ext, http_version,
                            req_size, truncated)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
         ON CONFLICT(id) DO UPDATE SET
            ts_start = excluded.ts_start, scheme = excluded.scheme, host = excluded.host,
            port = excluded.port, method = excluded.method, path = excluded.path,
            ext = excluded.ext, http_version = excluded.http_version,
            req_size = excluded.req_size, truncated = truncated OR excluded.truncated",
    )?
    .execute(params![
        r.id,
        r.ts_start,
        r.scheme,
        r.host,
        r.port,
        r.method,
        r.path,
        path_ext(&r.path),
        r.http_version,
        r.body_size,
        r.truncated,
    ])?;
    tx.prepare_cached(
        "INSERT INTO flow_data (flow_id, req_headers, req_body) VALUES (?1, ?2, ?3)
         ON CONFLICT(flow_id) DO UPDATE SET
            req_headers = excluded.req_headers, req_body = excluded.req_body",
    )?
    .execute(params![r.id, r.headers, r.body.as_ref()])?;
    Ok(())
}

fn insert_response(tx: &rusqlite::Transaction<'_>, r: &ResponseRecord) -> rusqlite::Result<()> {
    tx.prepare_cached(
        "INSERT INTO flows (id, ts_end, status, resp_version, resp_size, content_type,
                            duration_us, truncated, error)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
         ON CONFLICT(id) DO UPDATE SET
            ts_end = excluded.ts_end, status = excluded.status,
            resp_version = excluded.resp_version, resp_size = excluded.resp_size,
            content_type = excluded.content_type, duration_us = excluded.duration_us,
            truncated = truncated OR excluded.truncated,
            error = COALESCE(excluded.error, error)",
    )?
    .execute(params![
        r.id,
        r.ts_end,
        r.status,
        r.http_version,
        r.body_size,
        r.content_type,
        r.duration_us,
        r.truncated,
        r.error,
    ])?;
    tx.prepare_cached(
        "INSERT INTO flow_data (flow_id, resp_headers, resp_body) VALUES (?1, ?2, ?3)
         ON CONFLICT(flow_id) DO UPDATE SET
            resp_headers = excluded.resp_headers, resp_body = excluded.resp_body",
    )?
    .execute(params![r.id, r.headers, r.body.as_ref()])?;
    Ok(())
}
