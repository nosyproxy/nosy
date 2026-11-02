//! Full-text search across captured traffic (heads and decoded bodies).

use std::time::{Duration, Instant};

use nosy_model::{FlowId, SearchHit, SearchResult};
use nosy_store::{ScanItem, Store};
use serde::Deserialize;

use crate::codec;

#[derive(Debug, Deserialize)]
pub struct SearchParams {
    pub q: String,
    pub limit: Option<u32>,
    pub before_id: Option<FlowId>,
    /// `all` (default), `request` or `response`.
    pub scope: Option<String>,
    /// Max flows to examine in one call.
    pub max_scan: Option<u32>,
}

const PAGE: u32 = 200;
const BUDGET: Duration = Duration::from_secs(3);
const CONTEXT: usize = 80;

/// Case-insensitive (ASCII) substring search, newest flows first. One hit per
/// message part per flow. Stops at `limit` hits, `max_scan` flows or ~3 s.
pub fn search(store: &Store, p: &SearchParams) -> nosy_store::Result<SearchResult> {
    let needle = p.q.to_ascii_lowercase();
    let limit = p.limit.unwrap_or(20).clamp(1, 200) as usize;
    let max_scan = p.max_scan.unwrap_or(5000).clamp(1, 50_000);
    let (want_req, want_resp) = match p.scope.as_deref() {
        Some("request") => (true, false),
        Some("response") => (false, true),
        _ => (true, true),
    };
    let finder = memchr::memmem::Finder::new(needle.as_bytes());
    let started = Instant::now();

    if needle.is_empty() {
        return Ok(SearchResult {
            hits: Vec::new(),
            scanned: 0,
            next_before_id: None,
        });
    }
    let mut hits: Vec<(FlowId, &'static str, String)> = Vec::new();
    let mut scanned = 0u32;
    let mut before = p.before_id;
    let mut exhausted = false;

    'outer: while scanned < max_scan && started.elapsed() < BUDGET {
        let page = store.scan_page(before, PAGE.min(max_scan - scanned))?;
        if page.is_empty() {
            exhausted = true;
            break;
        }
        for item in &page {
            scanned += 1;
            before = Some(item.id);
            for (location, haystack) in parts(item, want_req, want_resp) {
                if let Some(snippet) = find(&finder, &haystack, needle.len()) {
                    hits.push((item.id, location, snippet));
                }
            }
            if hits.len() >= limit {
                break 'outer;
            }
        }
        if (page.len() as u32) < PAGE {
            exhausted = true;
            break;
        }
    }

    hits.truncate(limit);
    let hits = hits
        .into_iter()
        .filter_map(|(id, location, snippet)| {
            Some(SearchHit {
                flow: store.flow(id).ok()?,
                location: location.into(),
                snippet,
            })
        })
        .collect();
    Ok(SearchResult {
        hits,
        scanned,
        next_before_id: if exhausted { None } else { before },
    })
}

fn parts(item: &ScanItem, req: bool, resp: bool) -> Vec<(&'static str, Vec<u8>)> {
    let mut v = Vec::with_capacity(4);
    if req {
        v.push(("request.head", codec::request_head(&item.request)));
        v.push((
            "request.body",
            codec::body_only(&item.request.body, &item.request.headers, true),
        ));
    }
    if resp && let Some(r) = &item.response {
        v.push(("response.head", codec::response_head(r)));
        v.push(("response.body", codec::body_only(&r.body, &r.headers, true)));
    }
    v
}

fn find(finder: &memchr::memmem::Finder<'_>, haystack: &[u8], len: usize) -> Option<String> {
    let lower = haystack.to_ascii_lowercase();
    let pos = finder.find(&lower)?;
    let start = pos.saturating_sub(CONTEXT);
    let end = (pos + len + CONTEXT).min(haystack.len());
    let mut s = String::from_utf8_lossy(&haystack[start..end])
        .replace("\r\n", "⏎")
        .replace('\n', "⏎");
    if start > 0 {
        s.insert(0, '…');
    }
    if end < haystack.len() {
        s.push('…');
    }
    Some(s)
}
