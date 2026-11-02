use nosy_model::{NewRepeaterTab, RepeaterEntry, RepeaterTab, RepeaterTabPatch, Target, now_ms};
use rusqlite::{Connection, OptionalExtension, Row, params};

const TAB_COLS: &str = "id, name, position, host, port, tls, http2, raw_request, created_at";

fn tab_from_row(r: &Row<'_>) -> rusqlite::Result<RepeaterTab> {
    Ok(RepeaterTab {
        id: r.get(0)?,
        name: r.get(1)?,
        position: r.get(2)?,
        target: Target {
            host: r.get(3)?,
            port: r.get(4)?,
            tls: r.get(5)?,
            http2: r.get(6)?,
        },
        raw_request: r.get(7)?,
        created_at: r.get(8)?,
    })
}

pub(crate) fn list_tabs(conn: &Connection) -> rusqlite::Result<Vec<RepeaterTab>> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {TAB_COLS} FROM repeater_tabs ORDER BY position, id"
    ))?;
    stmt.query_map([], tab_from_row)?.collect()
}

pub(crate) fn get_tab(conn: &Connection, id: i64) -> rusqlite::Result<Option<RepeaterTab>> {
    conn.prepare_cached(&format!(
        "SELECT {TAB_COLS} FROM repeater_tabs WHERE id = ?1"
    ))?
    .query_row([id], tab_from_row)
    .optional()
}

pub(crate) fn create_tab(conn: &Connection, t: &NewRepeaterTab) -> rusqlite::Result<RepeaterTab> {
    let (count, pos): (i64, i64) = conn.query_row(
        "SELECT count(*), COALESCE(max(position), -1) + 1 FROM repeater_tabs",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let name = t
        .name
        .clone()
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| (count + 1).to_string());
    conn.execute(
        "INSERT INTO repeater_tabs (name, position, host, port, tls, http2, raw_request, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            name,
            pos,
            t.target.host,
            t.target.port,
            t.target.tls,
            t.target.http2,
            t.raw_request,
            now_ms()
        ],
    )?;
    let id = conn.last_insert_rowid();
    get_tab(conn, id).map(|t| t.expect("just inserted"))
}

pub(crate) fn patch_tab(
    conn: &mut Connection,
    id: i64,
    p: &RepeaterTabPatch,
) -> rusqlite::Result<Option<RepeaterTab>> {
    let tx = conn.transaction()?;
    if let Some(n) = &p.name {
        tx.execute(
            "UPDATE repeater_tabs SET name = ?2 WHERE id = ?1",
            params![id, n],
        )?;
    }
    if let Some(pos) = p.position {
        tx.execute(
            "UPDATE repeater_tabs SET position = ?2 WHERE id = ?1",
            params![id, pos],
        )?;
    }
    if let Some(t) = &p.target {
        tx.execute(
            "UPDATE repeater_tabs SET host = ?2, port = ?3, tls = ?4, http2 = ?5 WHERE id = ?1",
            params![id, t.host, t.port, t.tls, t.http2],
        )?;
    }
    if let Some(r) = &p.raw_request {
        tx.execute(
            "UPDATE repeater_tabs SET raw_request = ?2 WHERE id = ?1",
            params![id, r],
        )?;
    }
    tx.commit()?;
    get_tab(conn, id)
}

pub(crate) fn delete_tab(conn: &Connection, id: i64) -> rusqlite::Result<bool> {
    Ok(conn.execute("DELETE FROM repeater_tabs WHERE id = ?1", [id])? > 0)
}

/// Outcome of a repeater send, as recorded in history.
#[derive(Debug, Clone, Default)]
pub struct NewEntry {
    pub status: Option<u16>,
    pub http_version: Option<String>,
    pub ttfb_us: Option<i64>,
    pub duration_us: Option<i64>,
    pub error: Option<String>,
}

const ENTRY_COLS: &str = "id, tab_id, ts, host, port, tls, http2, status, http_version, ttfb_us, duration_us, resp_size, error";

fn entry_from_row(r: &Row<'_>) -> rusqlite::Result<RepeaterEntry> {
    Ok(RepeaterEntry {
        id: r.get(0)?,
        tab_id: r.get(1)?,
        ts: r.get(2)?,
        target: Target {
            host: r.get(3)?,
            port: r.get(4)?,
            tls: r.get(5)?,
            http2: r.get(6)?,
        },
        status: r.get(7)?,
        http_version: r.get(8)?,
        ttfb_us: r.get(9)?,
        duration_us: r.get(10)?,
        resp_size: r.get(11)?,
        error: r.get(12)?,
    })
}

pub(crate) fn add_entry(
    conn: &Connection,
    tab_id: i64,
    target: &Target,
    raw_request: &[u8],
    raw_response: Option<&[u8]>,
    e: &NewEntry,
) -> rusqlite::Result<RepeaterEntry> {
    conn.execute(
        "INSERT INTO repeater_history (tab_id, ts, host, port, tls, http2, status, http_version,
             ttfb_us, duration_us, resp_size, error, raw_request, raw_response)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
        params![
            tab_id,
            now_ms(),
            target.host,
            target.port,
            target.tls,
            target.http2,
            e.status,
            e.http_version,
            e.ttfb_us,
            e.duration_us,
            raw_response.map_or(0, |r| r.len() as i64),
            e.error,
            raw_request,
            raw_response,
        ],
    )?;
    let id = conn.last_insert_rowid();
    conn.prepare_cached(&format!(
        "SELECT {ENTRY_COLS} FROM repeater_history WHERE id = ?1"
    ))?
    .query_row([id], entry_from_row)
}

pub(crate) fn list_entries(conn: &Connection, tab_id: i64) -> rusqlite::Result<Vec<RepeaterEntry>> {
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {ENTRY_COLS} FROM repeater_history WHERE tab_id = ?1 ORDER BY id"
    ))?;
    stmt.query_map([tab_id], entry_from_row)?.collect()
}

pub(crate) fn entry_raw(
    conn: &Connection,
    id: i64,
    response: bool,
) -> rusqlite::Result<Option<Vec<u8>>> {
    let col = if response {
        "raw_response"
    } else {
        "raw_request"
    };
    conn.prepare_cached(&format!("SELECT {col} FROM repeater_history WHERE id = ?1"))?
        .query_row([id], |r| r.get::<_, Option<Vec<u8>>>(0))
        .optional()
        .map(Option::flatten)
}
