use rusqlite::Connection;

/// Each entry migrates from `user_version == index` to `index + 1`.
const MIGRATIONS: &[&str] = &[r#"
CREATE TABLE flows (
    id           INTEGER PRIMARY KEY,
    ts_start     INTEGER NOT NULL DEFAULT 0,
    ts_end       INTEGER,
    scheme       TEXT    NOT NULL DEFAULT '',
    host         TEXT    NOT NULL DEFAULT '',
    port         INTEGER NOT NULL DEFAULT 0,
    method       TEXT    NOT NULL DEFAULT '',
    path         TEXT    NOT NULL DEFAULT '',
    ext          TEXT    NOT NULL DEFAULT '',
    http_version TEXT    NOT NULL DEFAULT '',
    status       INTEGER,
    resp_version TEXT,
    req_size     INTEGER NOT NULL DEFAULT 0,
    resp_size    INTEGER,
    content_type TEXT,
    duration_us  INTEGER,
    error        TEXT,
    truncated    INTEGER NOT NULL DEFAULT 0,
    highlight    TEXT,
    note         TEXT
);
CREATE INDEX flows_host ON flows(host);

CREATE TABLE flow_data (
    flow_id      INTEGER PRIMARY KEY REFERENCES flows(id) ON DELETE CASCADE,
    req_headers  BLOB,
    req_body     BLOB,
    resp_headers BLOB,
    resp_body    BLOB
);

CREATE TABLE repeater_tabs (
    id          INTEGER PRIMARY KEY,
    name        TEXT    NOT NULL,
    position    INTEGER NOT NULL,
    host        TEXT    NOT NULL,
    port        INTEGER NOT NULL,
    tls         INTEGER NOT NULL,
    http2       INTEGER NOT NULL,
    raw_request TEXT    NOT NULL,
    created_at  INTEGER NOT NULL
);

CREATE TABLE repeater_history (
    id           INTEGER PRIMARY KEY,
    tab_id       INTEGER NOT NULL REFERENCES repeater_tabs(id) ON DELETE CASCADE,
    ts           INTEGER NOT NULL,
    host         TEXT    NOT NULL,
    port         INTEGER NOT NULL,
    tls          INTEGER NOT NULL,
    http2        INTEGER NOT NULL,
    status       INTEGER,
    http_version TEXT,
    ttfb_us      INTEGER,
    duration_us  INTEGER,
    resp_size    INTEGER NOT NULL DEFAULT 0,
    error        TEXT,
    raw_request  BLOB    NOT NULL,
    raw_response BLOB
);
CREATE INDEX repeater_history_tab ON repeater_history(tab_id, id);
"#];

pub fn configure(conn: &Connection) -> rusqlite::Result<()> {
    conn.execute_batch(
        "PRAGMA journal_mode = WAL;
         PRAGMA synchronous = NORMAL;
         PRAGMA foreign_keys = ON;
         PRAGMA temp_store = MEMORY;
         PRAGMA mmap_size = 268435456;
         PRAGMA cache_size = -32768;",
    )?;
    conn.busy_timeout(std::time::Duration::from_secs(10))?;
    conn.set_prepared_statement_cache_capacity(64);
    Ok(())
}

pub fn migrate(conn: &mut Connection) -> rusqlite::Result<()> {
    let version: i64 = conn.pragma_query_value(None, "user_version", |r| r.get(0))?;
    for (i, sql) in MIGRATIONS.iter().enumerate().skip(version as usize) {
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.pragma_update(None, "user_version", (i + 1) as i64)?;
        tx.commit()?;
        tracing::info!(version = i + 1, "applied migration");
    }
    Ok(())
}
