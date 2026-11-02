use nosy_model::{FlowDetail, FlowFilter, FlowId, FlowSummary, headers};
use rusqlite::{Connection, OptionalExtension, Row, ToSql, params};

use crate::util::STATIC_EXTS;

pub(crate) const SUMMARY_COLS: &str = "id, ts_start, scheme, host, port, method, path, http_version, \
     status, req_size, resp_size, content_type, duration_us, error, truncated, highlight, note";

pub(crate) fn summary_from_row(r: &Row<'_>) -> rusqlite::Result<FlowSummary> {
    Ok(FlowSummary {
        id: r.get(0)?,
        ts_start: r.get(1)?,
        scheme: r.get(2)?,
        host: r.get(3)?,
        port: r.get(4)?,
        method: r.get(5)?,
        path: r.get(6)?,
        http_version: r.get(7)?,
        status: r.get(8)?,
        req_size: r.get(9)?,
        resp_size: r.get(10)?,
        content_type: r.get(11)?,
        duration_us: r.get(12)?,
        error: r.get(13)?,
        truncated: r.get(14)?,
        highlight: r.get(15)?,
        note: r.get(16)?,
    })
}

pub(crate) fn summary_by_id(
    conn: &Connection,
    id: FlowId,
) -> rusqlite::Result<Option<FlowSummary>> {
    conn.prepare_cached(&format!("SELECT {SUMMARY_COLS} FROM flows WHERE id = ?1"))?
        .query_row([id], summary_from_row)
        .optional()
}

pub(crate) const MAX_LIMIT: u32 = 5000;

pub(crate) fn list(conn: &Connection, f: &FlowFilter) -> rusqlite::Result<Vec<FlowSummary>> {
    let mut sql = format!("SELECT {SUMMARY_COLS} FROM flows WHERE 1=1");
    let mut args: Vec<Box<dyn ToSql>> = Vec::new();

    if let Some(b) = f.before_id {
        sql.push_str(" AND id < ?");
        args.push(Box::new(b));
    }
    if let Some(a) = f.after_id {
        sql.push_str(" AND id > ?");
        args.push(Box::new(a));
    }
    if let Some(q) = f.q.as_deref().filter(|q| !q.is_empty()) {
        sql.push_str(" AND instr(lower(host || path), ?) > 0");
        args.push(Box::new(q.to_lowercase()));
    }
    if let Some(h) = f.host.as_deref().filter(|h| !h.is_empty()) {
        sql.push_str(" AND host LIKE ? ESCAPE '\\'");
        args.push(Box::new(glob_to_like(h)));
    }
    if let Some(m) = f.methods.as_deref().filter(|m| !m.is_empty()) {
        let methods: Vec<String> = m
            .split(',')
            .map(|s| s.trim().to_ascii_uppercase())
            .filter(|s| !s.is_empty())
            .collect();
        if !methods.is_empty() {
            sql.push_str(" AND method IN (");
            sql.push_str(&vec!["?"; methods.len()].join(","));
            sql.push(')');
            args.extend(methods.into_iter().map(|m| Box::new(m) as Box<dyn ToSql>));
        }
    }
    if let Some(s) = f.status.as_deref().filter(|s| !s.is_empty()) {
        let classes: Vec<i64> = s.split(',').filter_map(|c| c.trim().parse().ok()).collect();
        if !classes.is_empty() {
            let mut parts = Vec::new();
            let real: Vec<_> = classes.iter().copied().filter(|&c| c > 0).collect();
            if !real.is_empty() {
                let list = real
                    .iter()
                    .map(i64::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                parts.push(format!("(status / 100) IN ({list})"));
            }
            if classes.contains(&0) {
                parts.push("status IS NULL".into());
            }
            sql.push_str(&format!(" AND ({})", parts.join(" OR ")));
        }
    }
    if f.hide_static.unwrap_or(false) {
        let list = STATIC_EXTS
            .iter()
            .map(|e| format!("'{e}'"))
            .collect::<Vec<_>>()
            .join(",");
        sql.push_str(&format!(" AND ext NOT IN ({list})"));
    }
    // Resync (after_id) returns oldest-first so the client can append; paging is newest-first.
    if f.after_id.is_some() && f.before_id.is_none() {
        sql.push_str(" ORDER BY id ASC LIMIT ?");
    } else {
        sql.push_str(" ORDER BY id DESC LIMIT ?");
    }
    args.push(Box::new(f.limit.unwrap_or(500).min(MAX_LIMIT)));

    let mut stmt = conn.prepare_cached(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(args.iter()), summary_from_row)?;
    rows.collect()
}

/// `*.example.com` -> `%.example.com` with LIKE metacharacters escaped.
fn glob_to_like(glob: &str) -> String {
    let mut out = String::with_capacity(glob.len() + 2);
    let has_wild = glob.contains('*');
    if !has_wild {
        out.push('%');
    }
    for c in glob.chars() {
        match c {
            '%' | '_' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '*' => out.push('%'),
            c => out.push(c),
        }
    }
    if !has_wild {
        out.push('%');
    }
    out
}

pub(crate) fn detail(conn: &Connection, id: FlowId) -> rusqlite::Result<Option<FlowDetail>> {
    let Some(summary) = summary_by_id(conn, id)? else {
        return Ok(None);
    };
    let row = conn
        .prepare_cached(
            "SELECT d.req_headers, d.resp_headers, length(d.req_body), length(d.resp_body),
                    f.resp_version
             FROM flows f LEFT JOIN flow_data d ON d.flow_id = f.id WHERE f.id = ?1",
        )?
        .query_row([id], |r| {
            let req_h: Option<Vec<u8>> = r.get(0)?;
            let resp_h: Option<Vec<u8>> = r.get(1)?;
            Ok((
                req_h,
                resp_h,
                r.get::<_, Option<i64>>(2)?,
                r.get::<_, Option<i64>>(3)?,
                r.get::<_, Option<String>>(4)?,
            ))
        })?;
    Ok(Some(FlowDetail {
        request_headers: row.0.as_deref().map(headers::decode).unwrap_or_default(),
        response_headers: row.1.as_deref().map(headers::decode),
        req_body_len: row.2.unwrap_or(0),
        resp_body_len: row.3.unwrap_or(0),
        response_version: row.4,
        summary,
    }))
}

#[derive(Debug, Clone)]
pub struct RequestMessage {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub path: String,
    pub http_version: String,
    pub headers: Vec<u8>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ResponseMessage {
    pub status: u16,
    pub http_version: String,
    pub headers: Vec<u8>,
    pub body: Vec<u8>,
}

pub(crate) fn request_message(
    conn: &Connection,
    id: FlowId,
) -> rusqlite::Result<Option<RequestMessage>> {
    conn.prepare_cached(
        "SELECT f.scheme, f.host, f.port, f.method, f.path, f.http_version,
                d.req_headers, d.req_body
         FROM flows f LEFT JOIN flow_data d ON d.flow_id = f.id WHERE f.id = ?1",
    )?
    .query_row([id], |r| {
        Ok(RequestMessage {
            scheme: r.get(0)?,
            host: r.get(1)?,
            port: r.get(2)?,
            method: r.get(3)?,
            path: r.get(4)?,
            http_version: r.get(5)?,
            headers: r.get::<_, Option<Vec<u8>>>(6)?.unwrap_or_default(),
            body: r.get::<_, Option<Vec<u8>>>(7)?.unwrap_or_default(),
        })
    })
    .optional()
}

pub(crate) fn response_message(
    conn: &Connection,
    id: FlowId,
) -> rusqlite::Result<Option<ResponseMessage>> {
    conn.prepare_cached(
        "SELECT f.status, f.resp_version, d.resp_headers, d.resp_body
         FROM flows f JOIN flow_data d ON d.flow_id = f.id
         WHERE f.id = ?1 AND f.status IS NOT NULL",
    )?
    .query_row([id], |r| {
        Ok(ResponseMessage {
            status: r.get(0)?,
            http_version: r.get::<_, Option<String>>(1)?.unwrap_or_default(),
            headers: r.get::<_, Option<Vec<u8>>>(2)?.unwrap_or_default(),
            body: r.get::<_, Option<Vec<u8>>>(3)?.unwrap_or_default(),
        })
    })
    .optional()
}

pub(crate) fn patch(
    conn: &Connection,
    id: FlowId,
    p: &nosy_model::FlowPatch,
) -> rusqlite::Result<Option<FlowSummary>> {
    let norm = |v: &Option<String>| {
        v.as_ref()
            .map(|s| if s.is_empty() { None } else { Some(s.clone()) })
    };
    if let Some(h) = norm(&p.highlight) {
        conn.execute(
            "UPDATE flows SET highlight = ?2 WHERE id = ?1",
            params![id, h],
        )?;
    }
    if let Some(n) = norm(&p.note) {
        conn.execute("UPDATE flows SET note = ?2 WHERE id = ?1", params![id, n])?;
    }
    summary_by_id(conn, id)
}

#[cfg(test)]
mod tests {
    use super::glob_to_like;

    #[test]
    fn glob() {
        assert_eq!(glob_to_like("*.example.com"), "%.example.com");
        assert_eq!(glob_to_like("exa_mple"), "%exa\\_mple%");
    }
}

pub(crate) fn hosts(conn: &Connection) -> rusqlite::Result<Vec<nosy_model::HostCount>> {
    let mut stmt = conn.prepare_cached(
        "SELECT host, count(*) AS n FROM flows WHERE host != '' GROUP BY host ORDER BY n DESC, host",
    )?;
    stmt.query_map([], |r| {
        Ok(nosy_model::HostCount {
            host: r.get(0)?,
            count: r.get(1)?,
        })
    })?
    .collect()
}

/// A flow with both messages, for full-text scanning.
#[derive(Debug, Clone)]
pub struct ScanItem {
    pub id: FlowId,
    pub request: RequestMessage,
    pub response: Option<ResponseMessage>,
}

/// Newest-first page of complete flows with `id < before_id`.
pub(crate) fn scan_page(
    conn: &Connection,
    before_id: Option<FlowId>,
    limit: u32,
) -> rusqlite::Result<Vec<ScanItem>> {
    let mut stmt = conn.prepare_cached(
        "SELECT f.id, f.scheme, f.host, f.port, f.method, f.path, f.http_version,
                d.req_headers, d.req_body, f.status, f.resp_version, d.resp_headers, d.resp_body
         FROM flows f LEFT JOIN flow_data d ON d.flow_id = f.id
         WHERE f.id < ?1 ORDER BY f.id DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![before_id.unwrap_or(i64::MAX), limit], |r| {
        let blob = |i: usize| -> rusqlite::Result<Vec<u8>> {
            Ok(r.get::<_, Option<Vec<u8>>>(i)?.unwrap_or_default())
        };
        let status: Option<u16> = r.get(9)?;
        Ok(ScanItem {
            id: r.get(0)?,
            request: RequestMessage {
                scheme: r.get(1)?,
                host: r.get(2)?,
                port: r.get(3)?,
                method: r.get(4)?,
                path: r.get(5)?,
                http_version: r.get(6)?,
                headers: blob(7)?,
                body: blob(8)?,
            },
            response: match status {
                Some(status) => Some(ResponseMessage {
                    status,
                    http_version: r.get::<_, Option<String>>(10)?.unwrap_or_default(),
                    headers: blob(11)?,
                    body: blob(12)?,
                }),
                None => None,
            },
        })
    })?;
    rows.collect()
}
