//! Dedicated writer thread: drains the event channel and commits batches.
//!
//! No artificial delay: after the first event arrives, everything already queued
//! is drained and committed in one transaction. Under load, batches grow
//! naturally while the previous commit is in flight.
//!
//! Deletes also run here, in order with the capture events, so a flow deleted
//! while still in flight is not resurrected by its late response.

use std::collections::{HashMap, HashSet};

use crossbeam_channel::{Receiver, Sender};
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
    Flush(Sender<()>),
    /// Delete these flows (`None`: all of them) and reply with the number of rows removed.
    Delete(Option<Vec<FlowId>>, Sender<rusqlite::Result<usize>>),
}

const MAX_BATCH: usize = 1024;

const REQUEST: u8 = 1;
const END: u8 = 2;

/// Flows whose request or end (response / error) event has not arrived yet, and
/// those of them that were deleted in the meantime.
#[derive(Default)]
struct InFlight {
    open: HashMap<FlowId, u8>,
    deleted: HashSet<FlowId>,
}

impl InFlight {
    /// Record `ev`; false if its flow was deleted and the event must be dropped.
    fn admit(&mut self, ev: &FlowEvent) -> bool {
        let (id, part) = match ev {
            FlowEvent::Request(r) => (r.id, REQUEST),
            FlowEvent::Response(r) => (r.id, END),
            FlowEvent::Error { id, .. } => (*id, END),
        };
        let seen = self.open.entry(id).or_default();
        *seen |= part;
        let done = *seen == REQUEST | END;
        if done {
            self.open.remove(&id);
        }
        if !self.deleted.contains(&id) {
            return true;
        }
        if done {
            self.deleted.remove(&id);
        }
        false
    }

    fn delete(&mut self, ids: Option<&[FlowId]>) {
        match ids {
            Some(ids) => self
                .deleted
                .extend(ids.iter().filter(|id| self.open.contains_key(id))),
            None => self.deleted.extend(self.open.keys()),
        }
    }
}

pub(crate) fn run(mut conn: Connection, rx: Receiver<Msg>, events: broadcast::Sender<WsEvent>) {
    let mut batch: Vec<FlowEvent> = Vec::with_capacity(MAX_BATCH);
    let mut waiters = Vec::new();
    let mut in_flight = InFlight::default();

    while let Ok(first) = rx.recv() {
        let mut next = Some(first);
        while let Some(m) = next.take() {
            match m {
                Msg::Event(e) => batch.push(e),
                Msg::Flush(tx) => waiters.push(tx),
                Msg::Delete(ids, reply) => {
                    persist(&mut conn, &mut batch, &mut in_flight, &events);
                    in_flight.delete(ids.as_deref());
                    let _ = reply.send(delete(&mut conn, ids.as_deref()));
                }
            }
            if batch.len() < MAX_BATCH {
                next = rx.try_recv().ok();
            }
        }
        persist(&mut conn, &mut batch, &mut in_flight, &events);
        for w in waiters.drain(..) {
            let _ = w.send(());
        }
    }
    tracing::debug!("store writer stopped");
}

/// Commit and publish `batch`, leaving it empty.
fn persist(
    conn: &mut Connection,
    batch: &mut Vec<FlowEvent>,
    in_flight: &mut InFlight,
    events: &broadcast::Sender<WsEvent>,
) {
    let admitted: Vec<&FlowEvent> = batch.iter().filter(|e| in_flight.admit(e)).collect();
    if !admitted.is_empty() {
        let mut touched = HashSet::new();
        if let Err(e) = commit(conn, &admitted, &mut touched) {
            tracing::error!(error = %e, n = admitted.len(), "failed to persist flows");
        } else if events.receiver_count() > 0 {
            let flows: Vec<_> = touched
                .iter()
                .filter_map(|&id| summary_by_id(conn, id).ok().flatten())
                .collect();
            if !flows.is_empty() {
                let _ = events.send(WsEvent::Flows { flows });
            }
        }
    }
    batch.clear();
}

fn delete(conn: &mut Connection, ids: Option<&[FlowId]>) -> rusqlite::Result<usize> {
    let tx = conn.transaction()?;
    let n = match ids {
        Some(ids) => {
            let mut stmt = tx.prepare_cached("DELETE FROM flows WHERE id = ?1")?;
            let mut n = 0;
            for id in ids {
                n += stmt.execute([id])?;
            }
            n
        }
        None => {
            tx.execute("DELETE FROM flow_data", [])?;
            tx.execute("DELETE FROM flows", [])?
        }
    };
    tx.commit()?;
    Ok(n)
}

fn commit(
    conn: &mut Connection,
    batch: &[&FlowEvent],
    touched: &mut HashSet<FlowId>,
) -> rusqlite::Result<()> {
    // Pair up request/response events of the same flow so the common case is a
    // single INSERT per table instead of insert + upsert.
    let mut responses: HashMap<FlowId, &ResponseRecord> = HashMap::new();
    for &ev in batch {
        if let FlowEvent::Response(r) = ev {
            responses.insert(r.id, r);
        }
    }
    let mut merged: HashSet<FlowId> = HashSet::new();

    let tx = conn.transaction()?;
    for &ev in batch {
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
