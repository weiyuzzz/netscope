//! SQLite 连接管理与版本迁移。
//!
//! - 版本跟踪使用 `PRAGMA user_version`；
//! - 迁移只向前执行（v < N 才应用 N），旧数据天然兼容；
//! - WAL 模式：后台采集写入不阻塞 UI 读取；
//! - 默认只保存网络元数据，不保存完整数据包内容。

use std::path::Path;

use rusqlite::Connection;

use super::StorageError;

/// 当前 schema 版本（每新增迁移 +1）。
pub const SCHEMA_VERSION: i32 = 3;

/// 迁移 001：MVP 核心表（网络元数据）。
const MIGRATION_001: &str = r#"
CREATE TABLE IF NOT EXISTS app_settings (
    key       TEXT PRIMARY KEY,
    value     TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS network_interfaces (
    if_index           INTEGER PRIMARY KEY,
    name               TEXT NOT NULL,
    friendly_name      TEXT NOT NULL,
    description        TEXT NOT NULL,
    if_type            TEXT NOT NULL,
    operational_status TEXT NOT NULL,
    speed_bps          INTEGER NOT NULL DEFAULT 0,
    mtu                INTEGER NOT NULL DEFAULT 0,
    mac_address        TEXT,
    ipv4_addresses     TEXT NOT NULL DEFAULT '[]',
    ipv6_addresses     TEXT NOT NULL DEFAULT '[]',
    dns_servers        TEXT NOT NULL DEFAULT '[]',
    gateways           TEXT NOT NULL DEFAULT '[]',
    first_seen         TEXT NOT NULL,
    last_seen          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS processes (
    pid        INTEGER NOT NULL,
    name       TEXT NOT NULL,
    exe_path   TEXT,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    PRIMARY KEY (pid, name)
);

CREATE TABLE IF NOT EXISTS connections (
    id              TEXT PRIMARY KEY,
    pid             INTEGER NOT NULL,
    process_name    TEXT,
    protocol        TEXT NOT NULL,
    local_ip        TEXT NOT NULL,
    local_port      INTEGER NOT NULL,
    remote_ip       TEXT,
    remote_port     INTEGER,
    state           TEXT NOT NULL,
    interface_index INTEGER,
    first_seen      TEXT NOT NULL,
    last_seen       TEXT NOT NULL,
    bytes_sent      INTEGER NOT NULL DEFAULT 0,
    bytes_received  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_connections_last_seen ON connections(last_seen);
CREATE INDEX IF NOT EXISTS idx_connections_pid ON connections(pid);

CREATE TABLE IF NOT EXISTS dns_events (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp      TEXT NOT NULL,
    source         TEXT NOT NULL,
    event_kind     TEXT NOT NULL,
    domain         TEXT NOT NULL,
    record_type    INTEGER NOT NULL,
    confidence     TEXT,
    connection_id  TEXT,
    detail         TEXT
);
CREATE INDEX IF NOT EXISTS idx_dns_events_ts ON dns_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_dns_events_domain ON dns_events(domain);

CREATE TABLE IF NOT EXISTS network_events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source    TEXT NOT NULL,
    kind      TEXT NOT NULL,
    payload   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_network_events_ts ON network_events(timestamp);

CREATE TABLE IF NOT EXISTS topology_snapshots (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    nodes     TEXT NOT NULL,
    edges     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS diagnostics (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp  TEXT NOT NULL,
    kind       TEXT NOT NULL,
    target     TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    result     TEXT NOT NULL
);
"#;

/// 迁移 002：二轮新增表（代理/VPN/抓包/TCP 指标/路由探测/网络质量）。
const MIGRATION_002: &str = r#"
CREATE TABLE IF NOT EXISTS proxy_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT NOT NULL,
    event_kind   TEXT NOT NULL,
    mechanism    TEXT NOT NULL,
    protocol     TEXT,
    host         TEXT,
    port         INTEGER,
    process_name TEXT,
    pid          INTEGER,
    source       TEXT,
    confidence   TEXT,
    detail       TEXT
);
CREATE INDEX IF NOT EXISTS idx_proxy_events_ts ON proxy_events(timestamp);

CREATE TABLE IF NOT EXISTS vpn_interfaces (
    if_index               INTEGER PRIMARY KEY,
    kind                   TEXT NOT NULL,
    friendly_name          TEXT NOT NULL,
    description            TEXT NOT NULL,
    ipv4_addresses         TEXT NOT NULL DEFAULT '[]',
    ipv6_addresses         TEXT NOT NULL DEFAULT '[]',
    is_default_route_owner INTEGER NOT NULL DEFAULT 0,
    gateway_of_default     TEXT,
    speed_bps              INTEGER NOT NULL DEFAULT 0,
    operational_status     TEXT NOT NULL,
    first_seen             TEXT NOT NULL,
    last_seen              TEXT NOT NULL,
    active                 INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS packet_captures (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    adapter     TEXT NOT NULL,
    if_index    INTEGER,
    bpf_filter  TEXT,
    started_at  TEXT NOT NULL,
    stopped_at  TEXT,
    packets     INTEGER NOT NULL DEFAULT 0,
    bytes       INTEGER NOT NULL DEFAULT 0,
    export_path TEXT
);

CREATE TABLE IF NOT EXISTS packet_summaries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    capture_id  INTEGER NOT NULL REFERENCES packet_captures(id),
    src_ip      TEXT NOT NULL,
    src_port    INTEGER,
    dst_ip      TEXT NOT NULL,
    dst_port    INTEGER,
    protocol    TEXT NOT NULL,
    packets     INTEGER NOT NULL,
    bytes       INTEGER NOT NULL,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    tcp_syn     INTEGER NOT NULL DEFAULT 0,
    tcp_fin     INTEGER NOT NULL DEFAULT 0,
    tcp_rst     INTEGER NOT NULL DEFAULT 0,
    retransmits INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_packet_summaries_capture ON packet_summaries(capture_id);

CREATE TABLE IF NOT EXISTS tcp_metrics (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp     TEXT NOT NULL,
    source        TEXT NOT NULL,
    kind          TEXT NOT NULL,
    connection_id TEXT,
    src_ip        TEXT,
    src_port      INTEGER,
    dst_ip        TEXT,
    dst_port      INTEGER,
    detail        TEXT
);
CREATE INDEX IF NOT EXISTS idx_tcp_metrics_ts ON tcp_metrics(timestamp);

CREATE TABLE IF NOT EXISTS route_probes (
    id             TEXT PRIMARY KEY,
    target         TEXT NOT NULL,
    resolved_ip    TEXT,
    protocol       TEXT NOT NULL,
    port           INTEGER,
    max_hops       INTEGER NOT NULL,
    probes_per_hop INTEGER NOT NULL,
    started_at     TEXT NOT NULL,
    finished_at    TEXT,
    complete       INTEGER NOT NULL DEFAULT 0,
    path_changed   INTEGER
);

CREATE TABLE IF NOT EXISTS route_hops (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    probe_id    TEXT NOT NULL REFERENCES route_probes(id),
    ttl         INTEGER NOT NULL,
    state       TEXT NOT NULL,
    ip          TEXT,
    rtt_ms      TEXT NOT NULL DEFAULT '[]',
    probes_sent INTEGER NOT NULL DEFAULT 0,
    hostname    TEXT,
    asn         TEXT
);
CREATE INDEX IF NOT EXISTS idx_route_hops_probe ON route_hops(probe_id);

CREATE TABLE IF NOT EXISTS network_quality (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp            TEXT NOT NULL,
    rx_bps               REAL NOT NULL,
    tx_bps               REAL NOT NULL,
    tcp_total            INTEGER NOT NULL,
    tcp_established      INTEGER NOT NULL,
    udp_endpoints        INTEGER NOT NULL,
    retransmits_recent   INTEGER NOT NULL DEFAULT 0,
    rst_recent           INTEGER NOT NULL DEFAULT 0,
    syn_failures_recent  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_network_quality_ts ON network_quality(timestamp);
"#;


/// 迁移 003：第三轮（会话录制 / 时间线 / 拓扑历史 / 诊断 / 基准 / AI）。
const MIGRATION_003: &str = r#"
CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    scope      TEXT NOT NULL,
    started_at TEXT NOT NULL,
    stopped_at TEXT,
    status     TEXT NOT NULL,
    event_count INTEGER NOT NULL DEFAULT 0,
    test_kind  TEXT NOT NULL DEFAULT 'custom'
);
CREATE INDEX IF NOT EXISTS idx_sessions_started ON sessions(started_at);

CREATE TABLE IF NOT EXISTS session_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL REFERENCES sessions(id),
    timestamp  TEXT NOT NULL,
    source     TEXT NOT NULL,
    kind       TEXT NOT NULL,
    summary    TEXT NOT NULL,
    payload    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_session_events_session ON session_events(session_id, timestamp);

CREATE TABLE IF NOT EXISTS event_timeline (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    source    TEXT NOT NULL,
    kind      TEXT NOT NULL,
    summary   TEXT NOT NULL,
    payload   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_timeline_ts ON event_timeline(timestamp);
CREATE INDEX IF NOT EXISTS idx_timeline_kind ON event_timeline(kind);

CREATE TABLE IF NOT EXISTS topology_history (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    nodes     TEXT NOT NULL,
    edges     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_topology_history_ts ON topology_history(timestamp);

CREATE TABLE IF NOT EXISTS diagnostic_rules (
    rule_id     TEXT PRIMARY KEY,
    category    TEXT NOT NULL,
    title       TEXT NOT NULL,
    severity    TEXT NOT NULL,
    description TEXT NOT NULL,
    enabled     INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS diagnostic_results (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id       TEXT NOT NULL,
    title         TEXT NOT NULL,
    severity      TEXT NOT NULL,
    confidence    TEXT NOT NULL,
    detected_at   TEXT NOT NULL,
    impact_processes TEXT NOT NULL DEFAULT '[]',
    impact_domains   TEXT NOT NULL DEFAULT '[]',
    evidence      TEXT NOT NULL,
    possible_causes  TEXT NOT NULL DEFAULT '[]',
    verification     TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_diag_results_ts ON diagnostic_results(detected_at);

CREATE TABLE IF NOT EXISTS benchmark_results (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    target      TEXT NOT NULL,
    started_at  TEXT NOT NULL,
    finished_at TEXT,
    interface   TEXT,
    proxy_mode  TEXT,
    egress_ip   TEXT,
    dns_server  TEXT,
    metrics     TEXT NOT NULL,
    error       TEXT
);
CREATE INDEX IF NOT EXISTS idx_benchmark_ts ON benchmark_results(started_at);

CREATE TABLE IF NOT EXISTS root_cause_analysis (
    id          TEXT PRIMARY KEY,
    created_at  TEXT NOT NULL,
    subject     TEXT NOT NULL,
    window_start TEXT NOT NULL,
    window_end  TEXT NOT NULL,
    symptom     TEXT NOT NULL,
    observations TEXT NOT NULL,
    causes      TEXT NOT NULL,
    suggestions TEXT NOT NULL,
    finding_rule_ids TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS ai_conversations (
    id         TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    provider   TEXT NOT NULL,
    question   TEXT NOT NULL,
    answer     TEXT NOT NULL,
    evidence_used TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ai_conv_ts ON ai_conversations(created_at);
"#;

/// 打开数据库连接并执行迁移。
pub fn open(path: &Path) -> Result<Connection, StorageError> {
    let conn = Connection::open(path)?;
    configure(&conn)?;
    migrate(&conn)?;
    Ok(conn)
}

/// 连接参数调优（WAL + 常规同步级别）。
fn configure(conn: &Connection) -> Result<(), StorageError> {
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    Ok(())
}

/// 顺序执行未应用的迁移。
pub fn migrate(conn: &Connection) -> Result<(), StorageError> {
    let current: i32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;

    if current < 1 {
        conn.execute_batch(MIGRATION_001)?;
    }
    if current < 2 {
        conn.execute_batch(MIGRATION_002)?;
    }
    if current < 3 {
        conn.execute_batch(MIGRATION_003)?;
    }
    // 后续迁移在此追加：if current < 4 { ... }

    if current < SCHEMA_VERSION {
        conn.pragma_update(None, "user_version", SCHEMA_VERSION)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_db_migrates_to_latest() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        let v: i32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
    }

    #[test]
    fn all_tables_exist_after_migration() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        let expected = [
            "app_settings",
            "network_interfaces",
            "processes",
            "connections",
            "dns_events",
            "network_events",
            "topology_snapshots",
            "diagnostics",
            // 二轮新增
            "proxy_events",
            "vpn_interfaces",
            "packet_captures",
            "packet_summaries",
            "tcp_metrics",
            "route_probes",
            "route_hops",
            "network_quality",
        ];
        for table in expected {
            let count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    [table],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 1, "表 {table} 应存在");
        }
    }

    #[test]
    fn migration_is_idempotent() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        migrate(&conn).unwrap(); // 二次调用不应报错也不应重建
        let v: i32 = conn
            .query_row("PRAGMA user_version", [], |r| r.get(0))
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
    }

    #[test]
    fn wal_mode_enabled() {
        let dir = std::env::temp_dir().join(format!("netscope_dbtest_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.db");
        let conn = open(&path).unwrap();
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
        drop(conn);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
