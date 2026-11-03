//! SQLite persistence for captured flows and repeater state.
//!
//! * Writes from the proxy go through a bounded channel to a dedicated writer
//!   thread that commits in batches (see [`writer`]); the proxy never blocks.
//! * Reads and API-originated writes use a small connection pool. All methods are
//!   synchronous — call them from `spawn_blocking` in async code.

mod flows;
mod repeater;
mod schema;
mod util;
mod writer;

use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering},
    },
};

use crossbeam_channel::{Sender, TrySendError};
use nosy_model::{
    FlowDetail, FlowFilter, FlowId, FlowPatch, FlowSummary, NewRepeaterTab, RepeaterEntry,
    RepeaterTab, RepeaterTabPatch, Target, WsEvent,
    capture::{FlowEvent, FlowSink},
};
use parking_lot::Mutex;
use rusqlite::Connection;
use tokio::sync::broadcast;

pub use flows::{RequestMessage, ResponseMessage, ScanItem};
pub use repeater::NewEntry;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("not found")]
    NotFound,
    #[error("store is closed")]
    Closed,
}

pub type Result<T, E = StoreError> = std::result::Result<T, E>;

const EVENT_QUEUE: usize = 65_536;
const POOL_SIZE: usize = 4;

pub struct Store {
    tx: Sender<writer::Msg>,
    pool: Vec<Mutex<Connection>>,
    next_conn: AtomicUsize,
    next_id: AtomicI64,
    dropped: AtomicU64,
    events: broadcast::Sender<WsEvent>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store").finish_non_exhaustive()
    }
}

impl Store {
    pub fn open(path: &Path) -> Result<Arc<Self>> {
        let mut conn = Connection::open(path)?;
        schema::configure(&conn)?;
        schema::migrate(&mut conn)?;
        let max_id: i64 =
            conn.query_row("SELECT COALESCE(max(id), 0) FROM flows", [], |r| r.get(0))?;

        let mut pool = Vec::with_capacity(POOL_SIZE);
        for _ in 0..POOL_SIZE {
            let c = Connection::open(path)?;
            schema::configure(&c)?;
            pool.push(Mutex::new(c));
        }

        let (tx, rx) = crossbeam_channel::bounded(EVENT_QUEUE);
        let (events, _) = broadcast::channel(1024);
        let ev = events.clone();
        // The writer exits (after draining) once the last sender — ours — is dropped.
        std::thread::Builder::new()
            .name("nosy-store-writer".into())
            .spawn(move || writer::run(conn, rx, ev))
            .expect("spawn writer thread");

        Ok(Arc::new(Self {
            tx,
            pool,
            next_conn: AtomicUsize::new(0),
            next_id: AtomicI64::new(max_id + 1),
            dropped: AtomicU64::new(0),
            events,
        }))
    }

    /// Subscribe to live updates (only committed data is ever published).
    pub fn subscribe(&self) -> broadcast::Receiver<WsEvent> {
        self.events.subscribe()
    }

    /// Block until every event submitted so far is committed.
    pub fn flush(&self) {
        let (tx, rx) = crossbeam_channel::bounded(1);
        if self.tx.send(writer::Msg::Flush(tx)).is_ok() {
            let _ = rx.recv();
        }
    }

    /// Number of events dropped because the writer could not keep up.
    pub fn dropped_events(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    fn with_conn<R>(&self, f: impl FnOnce(&mut Connection) -> R) -> R {
        for c in &self.pool {
            if let Some(mut g) = c.try_lock() {
                return f(&mut g);
            }
        }
        let i = self.next_conn.fetch_add(1, Ordering::Relaxed) % self.pool.len();
        f(&mut self.pool[i].lock())
    }

    // ------------------------------------------------------------ flows

    pub fn list_flows(&self, filter: &FlowFilter) -> Result<Vec<FlowSummary>> {
        Ok(self.with_conn(|c| flows::list(c, filter))?)
    }

    pub fn flow(&self, id: FlowId) -> Result<FlowSummary> {
        self.with_conn(|c| flows::summary_by_id(c, id))?
            .ok_or(StoreError::NotFound)
    }

    pub fn flow_detail(&self, id: FlowId) -> Result<FlowDetail> {
        self.with_conn(|c| flows::detail(c, id))?
            .ok_or(StoreError::NotFound)
    }

    pub fn request_message(&self, id: FlowId) -> Result<RequestMessage> {
        self.with_conn(|c| flows::request_message(c, id))?
            .ok_or(StoreError::NotFound)
    }

    pub fn response_message(&self, id: FlowId) -> Result<ResponseMessage> {
        self.with_conn(|c| flows::response_message(c, id))?
            .ok_or(StoreError::NotFound)
    }

    /// Distinct hosts with flow counts, most frequent first.
    pub fn hosts(&self) -> Result<Vec<nosy_model::HostCount>> {
        Ok(self.with_conn(|c| flows::hosts(c))?)
    }

    /// Newest-first page of full flows (both messages) older than `before_id`.
    pub fn scan_page(&self, before_id: Option<FlowId>, limit: u32) -> Result<Vec<ScanItem>> {
        Ok(self.with_conn(|c| flows::scan_page(c, before_id, limit))?)
    }

    pub fn patch_flow(&self, id: FlowId, patch: &FlowPatch) -> Result<FlowSummary> {
        let s = self
            .with_conn(|c| flows::patch(c, id, patch))?
            .ok_or(StoreError::NotFound)?;
        let _ = self.events.send(WsEvent::Flows {
            flows: vec![s.clone()],
        });
        Ok(s)
    }

    pub fn delete_flows(&self, ids: &[FlowId]) -> Result<usize> {
        let n = self.delete(Some(ids.to_vec()))?;
        let _ = self.events.send(WsEvent::Deleted { ids: ids.to_vec() });
        Ok(n)
    }

    pub fn clear_flows(&self) -> Result<()> {
        self.delete(None)?;
        let _ = self.events.send(WsEvent::Cleared);
        Ok(())
    }

    /// Runs on the writer thread, after everything submitted so far is committed.
    fn delete(&self, ids: Option<Vec<FlowId>>) -> Result<usize> {
        let (tx, rx) = crossbeam_channel::bounded(1);
        self.tx
            .send(writer::Msg::Delete(ids, tx))
            .map_err(|_| StoreError::Closed)?;
        Ok(rx.recv().map_err(|_| StoreError::Closed)??)
    }

    // ------------------------------------------------------------ repeater

    pub fn list_tabs(&self) -> Result<Vec<RepeaterTab>> {
        Ok(self.with_conn(|c| repeater::list_tabs(c))?)
    }

    pub fn tab(&self, id: i64) -> Result<RepeaterTab> {
        self.with_conn(|c| repeater::get_tab(c, id))?
            .ok_or(StoreError::NotFound)
    }

    pub fn create_tab(&self, tab: &NewRepeaterTab) -> Result<RepeaterTab> {
        Ok(self.with_conn(|c| repeater::create_tab(c, tab))?)
    }

    pub fn patch_tab(&self, id: i64, patch: &RepeaterTabPatch) -> Result<RepeaterTab> {
        self.with_conn(|c| repeater::patch_tab(c, id, patch))?
            .ok_or(StoreError::NotFound)
    }

    pub fn delete_tab(&self, id: i64) -> Result<()> {
        if self.with_conn(|c| repeater::delete_tab(c, id))? {
            Ok(())
        } else {
            Err(StoreError::NotFound)
        }
    }

    pub fn add_repeater_entry(
        &self,
        tab_id: i64,
        target: &Target,
        raw_request: &[u8],
        raw_response: Option<&[u8]>,
        entry: &NewEntry,
    ) -> Result<RepeaterEntry> {
        Ok(self.with_conn(|c| {
            repeater::add_entry(c, tab_id, target, raw_request, raw_response, entry)
        })?)
    }

    pub fn repeater_history(&self, tab_id: i64) -> Result<Vec<RepeaterEntry>> {
        Ok(self.with_conn(|c| repeater::list_entries(c, tab_id))?)
    }

    pub fn repeater_raw(&self, entry_id: i64, response: bool) -> Result<Vec<u8>> {
        self.with_conn(|c| repeater::entry_raw(c, entry_id, response))?
            .ok_or(StoreError::NotFound)
    }
}

impl FlowSink for Store {
    fn next_id(&self) -> FlowId {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn submit(&self, event: FlowEvent) {
        match self.tx.try_send(writer::Msg::Event(event)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                let n = self.dropped.fetch_add(1, Ordering::Relaxed);
                if n.is_power_of_two() {
                    tracing::warn!(
                        dropped = n + 1,
                        "store queue full, dropping captured events"
                    );
                }
            }
            Err(TrySendError::Disconnected(_)) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use nosy_model::{
        capture::{RequestRecord, ResponseRecord},
        headers,
    };

    fn req(store: &Store, host: &str, path: &str, method: &str) -> FlowId {
        let id = store.next_id();
        store.submit(FlowEvent::Request(Box::new(RequestRecord {
            id,
            ts_start: 1,
            scheme: "https",
            host: host.into(),
            port: 443,
            method: method.into(),
            path: path.into(),
            http_version: "HTTP/1.1",
            headers: headers::encode_pairs([(&b"host"[..], host.as_bytes())]),
            body: Bytes::from_static(b"req-body"),
            body_size: 8,
            truncated: false,
        })));
        id
    }

    fn resp(store: &Store, id: FlowId, status: u16) {
        store.submit(FlowEvent::Response(Box::new(ResponseRecord {
            id,
            ts_end: 2,
            duration_us: 1000,
            status,
            http_version: "HTTP/1.1",
            headers: headers::encode_pairs([(&b"content-type"[..], &b"text/html"[..])]),
            content_type: Some("text/html".into()),
            body: Bytes::from_static(b"<html>"),
            body_size: 6,
            truncated: false,
            error: None,
        })));
    }

    fn open() -> (tempfile::TempDir, Arc<Store>) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("p.db")).unwrap();
        (dir, store)
    }

    #[test]
    fn request_response_roundtrip() {
        let (_d, store) = open();
        let mut sub = store.subscribe();
        let id = req(&store, "example.com", "/a?b=1", "GET");
        resp(&store, id, 200);
        store.flush();

        let d = store.flow_detail(id).unwrap();
        assert_eq!(d.summary.status, Some(200));
        assert_eq!(d.summary.host, "example.com");
        assert_eq!(d.req_body_len, 8);
        assert_eq!(d.response_headers.unwrap()[0].value, "text/html");
        assert_eq!(store.response_message(id).unwrap().body, b"<html>");
        assert!(matches!(sub.try_recv().unwrap(), WsEvent::Flows { .. }));
    }

    #[test]
    fn response_before_request_is_merged() {
        let (_d, store) = open();
        let id = store.next_id();
        resp(&store, id, 404);
        store.flush();
        store.submit(FlowEvent::Request(Box::new(RequestRecord {
            id,
            ts_start: 1,
            scheme: "http",
            host: "h".into(),
            port: 80,
            method: "POST".into(),
            path: "/".into(),
            http_version: "HTTP/1.1",
            headers: vec![],
            body: Bytes::new(),
            body_size: 0,
            truncated: false,
        })));
        store.flush();
        let s = store.flow(id).unwrap();
        assert_eq!((s.status, s.method.as_str()), (Some(404), "POST"));
    }

    #[test]
    fn filters_and_pagination() {
        let (_d, store) = open();
        for i in 0..10 {
            let id = req(
                &store,
                if i % 2 == 0 { "a.com" } else { "b.org" },
                &format!("/{i}.js"),
                "GET",
            );
            resp(&store, id, if i < 5 { 200 } else { 500 });
        }
        req(&store, "a.com", "/api", "POST");
        store.flush();

        let all = store.list_flows(&FlowFilter::default()).unwrap();
        assert_eq!(all.len(), 11);
        assert!(all[0].id > all[1].id, "newest first");

        let page = store
            .list_flows(&FlowFilter {
                limit: Some(3),
                ..Default::default()
            })
            .unwrap();
        let next = store
            .list_flows(&FlowFilter {
                before_id: Some(page[2].id),
                limit: Some(3),
                ..Default::default()
            })
            .unwrap();
        assert!(next[0].id < page[2].id);

        let f = |f: FlowFilter| store.list_flows(&f).unwrap().len();
        assert_eq!(
            f(FlowFilter {
                host: Some("a.com".into()),
                ..Default::default()
            }),
            6
        );
        assert_eq!(
            f(FlowFilter {
                host: Some("*.org".into()),
                ..Default::default()
            }),
            5
        );
        assert_eq!(
            f(FlowFilter {
                status: Some("5".into()),
                ..Default::default()
            }),
            5
        );
        assert_eq!(
            f(FlowFilter {
                status: Some("0".into()),
                ..Default::default()
            }),
            1
        );
        assert_eq!(
            f(FlowFilter {
                methods: Some("post".into()),
                ..Default::default()
            }),
            1
        );
        assert_eq!(
            f(FlowFilter {
                hide_static: Some(true),
                ..Default::default()
            }),
            1
        );
        assert_eq!(
            f(FlowFilter {
                q: Some("A.COM/API".into()),
                ..Default::default()
            }),
            1
        );
    }

    #[test]
    fn ids_continue_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.db");
        let id = {
            let s = Store::open(&path).unwrap();
            let id = req(&s, "x", "/", "GET");
            s.flush();
            id
        };
        let s = Store::open(&path).unwrap();
        assert!(s.next_id() > id);
    }

    #[test]
    fn repeater_tabs_and_history() {
        let (_d, store) = open();
        let target = Target {
            host: "x.com".into(),
            port: 443,
            tls: true,
            http2: false,
        };
        let tab = store
            .create_tab(&NewRepeaterTab {
                name: None,
                target: target.clone(),
                raw_request: "GET / HTTP/1.1\r\n\r\n".into(),
            })
            .unwrap();
        assert_eq!(tab.name, "1");
        let tab = store
            .patch_tab(
                tab.id,
                &RepeaterTabPatch {
                    name: Some("login".into()),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(tab.name, "login");
        let e = store
            .add_repeater_entry(
                tab.id,
                &target,
                b"GET /",
                Some(b"HTTP/1.1 200 OK\r\n\r\n"),
                &NewEntry {
                    status: Some(200),
                    ..Default::default()
                },
            )
            .unwrap();
        assert_eq!(store.repeater_history(tab.id).unwrap().len(), 1);
        assert_eq!(
            store.repeater_raw(e.id, true).unwrap(),
            b"HTTP/1.1 200 OK\r\n\r\n"
        );
        store.delete_tab(tab.id).unwrap();
        assert!(store.repeater_history(tab.id).unwrap().is_empty());
    }

    #[test]
    fn hosts_and_scan() {
        let (_d, store) = open();
        let a = req(&store, "a.com", "/1", "GET");
        resp(&store, a, 200);
        req(&store, "a.com", "/2", "GET");
        let b = req(&store, "b.com", "/3", "POST");
        store.flush();
        let hosts = store.hosts().unwrap();
        assert_eq!((hosts[0].host.as_str(), hosts[0].count), ("a.com", 2));
        let page = store.scan_page(None, 2).unwrap();
        assert_eq!(page[0].id, b);
        assert!(page[0].response.is_none());
        let next = store.scan_page(Some(page[1].id), 10).unwrap();
        assert_eq!(next[0].id, a);
        assert_eq!(next[0].response.as_ref().unwrap().body, b"<html>");
        assert_eq!(next[0].request.body, b"req-body");
    }

    #[test]
    fn delete_and_clear() {
        let (_d, store) = open();
        let a = req(&store, "a", "/", "GET");
        req(&store, "b", "/", "GET");
        store.flush();
        store.delete_flows(&[a]).unwrap();
        assert_eq!(store.list_flows(&FlowFilter::default()).unwrap().len(), 1);
        store.clear_flows().unwrap();
        assert!(store.list_flows(&FlowFilter::default()).unwrap().is_empty());
    }

    #[test]
    fn in_flight_flows_stay_deleted() {
        let (_d, store) = open();
        let cleared = req(&store, "a", "/", "GET");
        let deleted = req(&store, "b", "/", "GET");
        let kept = req(&store, "c", "/", "GET");
        store.flush();
        store.delete_flows(&[deleted]).unwrap();
        resp(&store, deleted, 200);
        store.flush();
        assert_eq!(store.list_flows(&FlowFilter::default()).unwrap().len(), 2);

        store.clear_flows().unwrap();
        resp(&store, cleared, 200);
        store.submit(FlowEvent::Error {
            id: kept,
            ts_end: 3,
            duration_us: 1,
            message: "reset".into(),
        });
        store.flush();
        assert!(store.list_flows(&FlowFilter::default()).unwrap().is_empty());

        let fresh = req(&store, "d", "/", "GET");
        resp(&store, fresh, 200);
        store.flush();
        let flows = store.list_flows(&FlowFilter::default()).unwrap();
        assert_eq!(flows.len(), 1);
        assert_eq!(flows[0].host, "d");
    }
}
