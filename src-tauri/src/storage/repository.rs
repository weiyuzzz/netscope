//! 数据仓库：实体读写与批量写入。
//!
//! 按功能需要逐步暴露 API；所有写入统一使用 RFC3339 UTC 时间戳文本。
//! `PersistedEvent` 为通用事件行，被网络事件 / 代理事件 / TCP 指标复用。

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::StorageError;

/// 可持久化的通用事件行。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PersistedEvent {
    pub timestamp: String,
    pub source: String,
    pub kind: String,
    /// 序列化后的载荷。
    pub payload: String,
}

/// 批量写入 network_events（后台循环的事件流）。
pub fn insert_network_events(
    conn: &Connection,
    events: &[PersistedEvent],
) -> Result<usize, StorageError> {
    if events.is_empty() {
        return Ok(0);
    }
    let mut stmt = conn.prepare(
        "INSERT INTO network_events (timestamp, source, kind, payload) VALUES (?1, ?2, ?3, ?4)",
    )?;
    let mut n = 0;
    for e in events {
        n += stmt.execute([e.timestamp.as_str(), e.source.as_str(), e.kind.as_str(), e.payload.as_str()])?;
    }
    Ok(n)
}

/// 批量 upsert 连接（连接表快照落地）。
pub fn upsert_connections(
    conn: &Connection,
    rows: &[crate::models::connection::Connection],
) -> Result<usize, StorageError> {
    if rows.is_empty() {
        return Ok(0);
    }
    let mut stmt = conn.prepare(
        "INSERT INTO connections (id, pid, process_name, protocol, local_ip, local_port, \
         remote_ip, remote_port, state, interface_index, first_seen, last_seen, bytes_sent, bytes_received) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14) \
         ON CONFLICT(id) DO UPDATE SET \
           state=excluded.state, last_seen=excluded.last_seen, \
           interface_index=excluded.interface_index, \
           process_name=COALESCE(excluded.process_name, connections.process_name)",
    )?;
    let mut n = 0;
    for c in rows {
        n += stmt.execute(rusqlite::params![
            c.id,
            c.pid,
            c.process_name,
            serde_json::to_string(&c.protocol)?,
            c.local.ip,
            c.local.port,
            c.remote.as_ref().map(|r| r.ip.clone()),
            c.remote.as_ref().map(|r| r.port),
            serde_json::to_string(&c.state)?,
            c.interface_index,
            c.first_seen.to_rfc3339(),
            c.last_seen.to_rfc3339(),
            c.bytes_sent as i64,
            c.bytes_received as i64,
        ])?;
    }
    Ok(n)
}

/// 记录代理事件。
pub fn insert_proxy_event(
    conn: &Connection,
    timestamp: &str,
    event_kind: &str,
    mechanism: &str,
    protocol: Option<&str>,
    host: Option<&str>,
    port: Option<u16>,
    process_name: Option<&str>,
    pid: Option<u32>,
    source: Option<&str>,
    confidence: Option<&str>,
    detail: &serde_json::Value,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO proxy_events (timestamp, event_kind, mechanism, protocol, host, port, \
         process_name, pid, source, confidence, detail) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        rusqlite::params![
            timestamp,
            event_kind,
            mechanism,
            protocol,
            host,
            port,
            process_name,
            pid,
            source,
            confidence,
            serde_json::to_string(detail)?
        ],
    )?;
    Ok(())
}

/// upsert VPN/虚拟网卡接口。
pub fn upsert_vpn_interface(
    conn: &Connection,
    v: &crate::models::proxy::VpnInterface,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO vpn_interfaces (if_index, kind, friendly_name, description, ipv4_addresses, \
         ipv6_addresses, is_default_route_owner, gateway_of_default, speed_bps, operational_status, \
         first_seen, last_seen, active) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13) \
         ON CONFLICT(if_index) DO UPDATE SET \
           kind=excluded.kind, friendly_name=excluded.friendly_name, description=excluded.description, \
           ipv4_addresses=excluded.ipv4_addresses, ipv6_addresses=excluded.ipv6_addresses, \
           is_default_route_owner=excluded.is_default_route_owner, gateway_of_default=excluded.gateway_of_default, \
           speed_bps=excluded.speed_bps, operational_status=excluded.operational_status, \
           last_seen=excluded.last_seen, active=excluded.active",
        rusqlite::params![
            v.if_index,
            serde_json::to_string(&v.kind)?,
            v.friendly_name,
            v.description,
            serde_json::to_string(&v.ipv4_addresses)?,
            serde_json::to_string(&v.ipv6_addresses)?,
            v.is_default_route_owner as i64,
            v.gateway_of_default,
            v.speed_bps as i64,
            v.operational_status,
            v.first_seen.to_rfc3339(),
            v.last_seen.to_rfc3339(),
            v.active as i64,
        ],
    )?;
    Ok(())
}

/// 写入网络质量采样点。
pub fn insert_network_quality(
    conn: &Connection,
    p: &crate::models::metrics::NetworkQualityPoint,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO network_quality (timestamp, rx_bps, tx_bps, tcp_total, tcp_established, \
         udp_endpoints, retransmits_recent, rst_recent, syn_failures_recent) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        rusqlite::params![
            p.timestamp.to_rfc3339(),
            p.rx_bps,
            p.tx_bps,
            p.tcp_total,
            p.tcp_established,
            p.udp_endpoints,
            p.retransmits_recent,
            p.rst_recent,
            p.syn_failures_recent,
        ],
    )?;
    Ok(())
}

/// 批量写入 TCP 指标事件。
pub fn insert_tcp_metrics(
    conn: &Connection,
    events: &[crate::models::metrics::TcpMetricEvent],
) -> Result<usize, StorageError> {
    if events.is_empty() {
        return Ok(0);
    }
    let mut stmt = conn.prepare(
        "INSERT INTO tcp_metrics (timestamp, source, kind, connection_id, src_ip, src_port, dst_ip, dst_port, detail) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
    )?;
    let mut n = 0;
    for e in events {
        n += stmt.execute(rusqlite::params![
            e.timestamp.to_rfc3339(),
            serde_json::to_string(&e.source)?,
            serde_json::to_string(&e.kind)?,
            e.connection_id,
            e.src_ip,
            e.src_port,
            e.dst_ip,
            e.dst_port,
            serde_json::to_string(&e.detail)?,
        ])?;
    }
    Ok(n)
}

/// 写入路由探测记录 + 每跳明细。
pub fn insert_route_probe(
    conn: &Connection,
    probe: &crate::models::metrics::RouteProbe,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO route_probes (id, target, resolved_ip, protocol, port, max_hops, probes_per_hop,          started_at, finished_at, complete, path_changed)          VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)          ON CONFLICT(id) DO UPDATE SET finished_at=excluded.finished_at, complete=excluded.complete,          path_changed=excluded.path_changed",
        rusqlite::params![
            probe.id,
            probe.target,
            probe.resolved_ip,
            serde_json::to_string(&probe.protocol)?,
            probe.port,
            probe.max_hops as i64,
            probe.probes_per_hop as i64,
            probe.started_at.to_rfc3339(),
            probe.finished_at.map(|t| t.to_rfc3339()),
            probe.finished_at.is_some() as i64,
            probe.path_changed.map(|b| b as i64),
        ],
    )?;
    let mut stmt = conn.prepare(
        "INSERT INTO route_hops (probe_id, ttl, state, ip, rtt_ms, probes_sent, hostname, asn)          VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
    )?;
    for h in &probe.hops {
        stmt.execute(rusqlite::params![
            probe.id,
            h.ttl as i64,
            serde_json::to_string(&h.state)?,
            h.ip,
            serde_json::to_string(&h.rtt_ms)?,
            h.probes_sent as i64,
            h.hostname,
            h.asn,
        ])?;
    }
    Ok(())
}

/// 记录 DNS 事件（缓存新域名 / 主动查询结果）。
#[allow(clippy::too_many_arguments)]
pub fn insert_dns_event(
    conn: &Connection,
    timestamp: &str,
    source: &str,
    event_kind: &str,
    domain: &str,
    record_type: u16,
    confidence: Option<&str>,
    connection_id: Option<&str>,
    detail: &serde_json::Value,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO dns_events (timestamp, source, event_kind, domain, record_type, confidence, connection_id, detail) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        rusqlite::params![
            timestamp,
            source,
            event_kind,
            domain,
            record_type,
            confidence,
            connection_id,
            serde_json::to_string(detail)?
        ],
    )?;
    Ok(())
}

/// 读取设置。
pub fn get_setting(conn: &Connection, key: &str) -> Result<Option<String>, StorageError> {
    let mut stmt =
        conn.prepare("SELECT value FROM app_settings WHERE key = ?1")?;
    let mut rows = stmt.query([key])?;
    if let Some(row) = rows.next()? {
        Ok(Some(row.get(0)?))
    } else {
        Ok(None)
    }
}

/// 写入设置（upsert）。
pub fn set_setting(
    conn: &Connection,
    key: &str,
    value: &str,
) -> Result<(), StorageError> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO app_settings (key, value, updated_at) VALUES (?1, ?2, ?3) \
         ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
        [key, value, now.as_str()],
    )?;
    Ok(())
}

/// 数据保留策略：删除早于 `keep_days` 天的历史数据（连接表保留活跃状态）。
pub fn apply_retention(conn: &Connection, keep_days: i64) -> Result<(), StorageError> {
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(keep_days)).to_rfc3339();
    conn.execute("DELETE FROM network_events WHERE timestamp < ?1", [&cutoff])?;
    conn.execute("DELETE FROM proxy_events WHERE timestamp < ?1", [&cutoff])?;
    conn.execute("DELETE FROM tcp_metrics WHERE timestamp < ?1", [&cutoff])?;
    conn.execute("DELETE FROM network_quality WHERE timestamp < ?1", [&cutoff])?;
    conn.execute(
        "DELETE FROM connections WHERE last_seen < ?1 AND state NOT IN ('\"established\"','\"listen\"','\"endpoint\"')",
        [&cutoff],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::database::migrate;

    fn test_conn() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        conn
    }

    #[test]
    fn settings_roundtrip() {
        let conn = test_conn();
        assert!(get_setting(&conn, "foo").unwrap().is_none());
        set_setting(&conn, "foo", "bar").unwrap();
        assert_eq!(get_setting(&conn, "foo").unwrap().unwrap(), "bar");
        set_setting(&conn, "foo", "baz").unwrap();
        assert_eq!(get_setting(&conn, "foo").unwrap().unwrap(), "baz");
    }

    #[test]
    fn network_events_batch_insert() {
        let conn = test_conn();
        let events = vec![
            PersistedEvent {
                timestamp: chrono::Utc::now().to_rfc3339(),
                source: "test".into(),
                kind: "conn_opened".into(),
                payload: "{}".into(),
            },
            PersistedEvent {
                timestamp: chrono::Utc::now().to_rfc3339(),
                source: "test".into(),
                kind: "conn_closed".into(),
                payload: "{}".into(),
            },
        ];
        assert_eq!(insert_network_events(&conn, &events).unwrap(), 2);
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM network_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn connection_upsert_updates_state() {
        use crate::models::connection::*;
        use chrono::Utc;
        let conn = test_conn();
        let local = Endpoint { ip: "127.0.0.1".into(), port: 40000 };
        let remote = Endpoint { ip: "127.0.0.1".into(), port: 80 };
        let now = Utc::now();
        let mut c = Connection {
            id: derive_connection_id(Protocol::Tcp, 1, &local, Some(&remote)),
            pid: 1,
            process_name: Some("a.exe".into()),
            protocol: Protocol::Tcp,
            local,
            remote: Some(remote),
            state: ConnectionState::SynSent,
            interface_index: None,
            first_seen: now,
            last_seen: now,
            bytes_sent: 0,
            bytes_received: 0,
        };
        assert_eq!(upsert_connections(&conn, &[c.clone()]).unwrap(), 1);
        c.state = ConnectionState::Established;
        upsert_connections(&conn, &[c.clone()]).unwrap();
        let state: String = conn
            .query_row("SELECT state FROM connections WHERE id=?1", [c.id.as_str()], |r| r.get(0))
            .unwrap();
        assert_eq!(state, "\"established\"");
        // upsert 不应新增行
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM connections", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1);
    }
}
