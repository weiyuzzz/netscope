//! 第三轮历史数据仓库：会话 / 时间线 / 拓扑历史 / 诊断 / 基准 / RCA / AI。
//!
//! 与 repository.rs 分层：本模块只服务第三轮功能，避免单文件过度膨胀。

use rusqlite::Connection;

use super::StorageError;
use crate::models::proxy::Confidence;
use crate::models::metrics::RouteProbe;
use crate::models::session::{
    AiConversation, BenchmarkKind, BenchmarkResult, DiagnosticFinding, RecordingSession,
    RcaReport, SessionEvent, SessionScope, SessionStatus, Severity, TimelineEvent,
    TopologyHistorySnapshot,
};

fn parse_ts(ts: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(ts)
        .map(|d| d.with_timezone(&chrono::Utc))
        .unwrap_or_else(|_| chrono::Utc::now())
}

// ---------------------------------------------------------------------------
// 统一时间线
// ---------------------------------------------------------------------------

/// 批量写入统一时间线事件。
pub fn insert_timeline_events(conn: &Connection, events: &[TimelineEvent]) -> Result<usize, StorageError> {
    if events.is_empty() {
        return Ok(0);
    }
    let mut stmt = conn.prepare(
        "INSERT INTO event_timeline (timestamp, source, kind, summary, payload) VALUES (?1,?2,?3,?4,?5)",
    )?;
    let mut n = 0;
    for e in events {
        n += stmt.execute(rusqlite::params![
            e.timestamp.to_rfc3339(),
            e.source,
            e.kind,
            e.summary,
            serde_json::to_string(&e.payload)?,
        ])?;
    }
    Ok(n)
}

/// 按过滤条件查询时间线（全部可选，时间正序返回）。
#[allow(clippy::too_many_arguments)]
pub fn query_timeline(
    conn: &Connection,
    since: Option<&str>,
    until: Option<&str>,
    kind: Option<&str>,
    source: Option<&str>,
    limit: u32,
) -> Result<Vec<TimelineEvent>, StorageError> {
    use rusqlite::types::Value as SqlValue;

    let mut sql = String::from(
        "SELECT timestamp, source, kind, summary, payload FROM event_timeline WHERE 1=1",
    );
    let mut params: Vec<SqlValue> = Vec::new();
    if let Some(s) = since {
        params.push(SqlValue::Text(s.to_string()));
        sql.push_str(&format!(" AND timestamp >= ?{}", params.len()));
    }
    if let Some(u) = until {
        params.push(SqlValue::Text(u.to_string()));
        sql.push_str(&format!(" AND timestamp <= ?{}", params.len()));
    }
    if let Some(k) = kind {
        params.push(SqlValue::Text(k.to_string()));
        sql.push_str(&format!(" AND kind = ?{}", params.len()));
    }
    if let Some(src) = source {
        params.push(SqlValue::Text(src.to_string()));
        sql.push_str(&format!(" AND source = ?{}", params.len()));
    }
    sql.push_str(" ORDER BY timestamp DESC LIMIT ");
    sql.push_str(&limit.min(5000).to_string());

    let mut stmt = conn.prepare(&sql)?;
    let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |r| {
        Ok(TimelineEvent {
            timestamp: parse_ts(&r.get::<_, String>(0)?),
            source: r.get(1)?,
            kind: r.get(2)?,
            summary: r.get(3)?,
            payload: serde_json::from_str(&r.get::<_, String>(4)?)
                .unwrap_or(serde_json::Value::Null),
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    out.reverse();
    Ok(out)
}

// ---------------------------------------------------------------------------
// 会话录制
// ---------------------------------------------------------------------------

/// 创建录制会话。
pub fn create_session(conn: &Connection, s: &RecordingSession) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO sessions (id, name, scope, started_at, stopped_at, status, event_count, test_kind) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        rusqlite::params![
            s.id,
            s.name,
            serde_json::to_string(&s.scope)?,
            s.started_at.to_rfc3339(),
            s.stopped_at.map(|t| t.to_rfc3339()),
            serde_json::to_string(&s.status)?,
            s.event_count as i64,
            s.test_kind,
        ],
    )?;
    Ok(())
}

/// 完成会话（停止 / 取消）。
pub fn finish_session(
    conn: &Connection,
    id: &str,
    stopped_at: &str,
    status: SessionStatus,
    event_count: u64,
) -> Result<(), StorageError> {
    conn.execute(
        "UPDATE sessions SET stopped_at=?2, status=?3, event_count=?4 WHERE id=?1",
        rusqlite::params![id, stopped_at, serde_json::to_string(&status)?, event_count as i64],
    )?;
    Ok(())
}

/// 批量写入会话事件。
pub fn insert_session_events(conn: &Connection, events: &[SessionEvent]) -> Result<usize, StorageError> {
    if events.is_empty() {
        return Ok(0);
    }
    let mut stmt = conn.prepare(
        "INSERT INTO session_events (session_id, timestamp, source, kind, summary, payload) \
         VALUES (?1,?2,?3,?4,?5,?6)",
    )?;
    let mut n = 0;
    for e in events {
        n += stmt.execute(rusqlite::params![
            e.session_id,
            e.timestamp.to_rfc3339(),
            e.source,
            e.kind,
            e.summary,
            serde_json::to_string(&e.payload)?,
        ])?;
    }
    Ok(n)
}

/// 查询会话事件（时间正序）。
pub fn get_session_events(
    conn: &Connection,
    session_id: &str,
    limit: u32,
) -> Result<Vec<SessionEvent>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT timestamp, source, kind, summary, payload FROM session_events \
         WHERE session_id = ?1 ORDER BY timestamp ASC LIMIT ?2",
    )?;
    let rows = stmt.query_map(rusqlite::params![session_id, limit.min(20000)], |r| {
        Ok(SessionEvent {
            session_id: session_id.to_string(),
            timestamp: parse_ts(&r.get::<_, String>(0)?),
            source: r.get(1)?,
            kind: r.get(2)?,
            summary: r.get(3)?,
            payload: serde_json::from_str(&r.get::<_, String>(4)?)
                .unwrap_or(serde_json::Value::Null),
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// 查询会话列表（时间倒序）。
pub fn list_sessions(conn: &Connection, limit: u32) -> Result<Vec<RecordingSession>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT id, name, scope, started_at, stopped_at, status, event_count, test_kind \
         FROM sessions ORDER BY started_at DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit.min(200)], |r| {
        Ok(RecordingSession {
            id: r.get(0)?,
            name: r.get(1)?,
            scope: serde_json::from_str(&r.get::<_, String>(2)?)
                .unwrap_or(SessionScope::All),
            started_at: parse_ts(&r.get::<_, String>(3)?),
            stopped_at: r
                .get::<_, Option<String>>(4)?
                .as_deref()
                .map(parse_ts),
            status: serde_json::from_str(&r.get::<_, String>(5)?)
                .unwrap_or(SessionStatus::Completed),
            event_count: r.get::<_, i64>(6)?.max(0) as u64,
            test_kind: r.get(7)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// 拓扑历史（回放基底）
// ---------------------------------------------------------------------------

/// 保存拓扑快照。
pub fn insert_topology_snapshot(
    conn: &Connection,
    snap: &TopologyHistorySnapshot,
) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO topology_history (timestamp, nodes, edges) VALUES (?1,?2,?3)",
        rusqlite::params![
            snap.timestamp.to_rfc3339(),
            serde_json::to_string(&snap.nodes)?,
            serde_json::to_string(&snap.edges)?,
        ],
    )?;
    Ok(())
}

/// 取目标时间前最近的拓扑快照。
pub fn latest_topology_snapshot_before(
    conn: &Connection,
    at: &str,
) -> Result<Option<TopologyHistorySnapshot>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT timestamp, nodes, edges FROM topology_history WHERE timestamp <= ?1 \
         ORDER BY timestamp DESC LIMIT 1",
    )?;
    let mut rows = stmt.query_map([at], |r| {
        Ok(TopologyHistorySnapshot {
            timestamp: parse_ts(&r.get::<_, String>(0)?),
            nodes: serde_json::from_str(&r.get::<_, String>(1)?).unwrap_or_default(),
            edges: serde_json::from_str(&r.get::<_, String>(2)?).unwrap_or_default(),
        })
    })?;
    if let Some(row) = rows.next() {
        return Ok(Some(row?));
    }
    Ok(None)
}

/// 拓扑历史降采样（数据压缩）：早于 keep_days 天的快照每小时仅保留第一条。
pub fn prune_topology_history(conn: &Connection, keep_days: i64) -> Result<usize, StorageError> {
    let cutoff = (chrono::Utc::now() - chrono::Duration::days(keep_days)).to_rfc3339();
    let n = conn.execute(
        "DELETE FROM topology_history WHERE timestamp < ?1 AND id NOT IN (
            SELECT MIN(id) FROM topology_history WHERE timestamp < ?1
            GROUP BY substr(timestamp, 1, 13))",
        [&cutoff],
    )?;
    Ok(n)
}

// ---------------------------------------------------------------------------
// 诊断结果
// ---------------------------------------------------------------------------

/// 写入诊断结论。
pub fn insert_finding(conn: &Connection, f: &DiagnosticFinding) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO diagnostic_results (rule_id, title, severity, confidence, detected_at, \
         impact_processes, impact_domains, evidence, possible_causes, verification) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        rusqlite::params![
            f.rule_id,
            f.title,
            serde_json::to_string(&f.severity)?,
            serde_json::to_string(&f.confidence)?,
            f.detected_at.to_rfc3339(),
            serde_json::to_string(&f.impact_processes)?,
            serde_json::to_string(&f.impact_domains)?,
            serde_json::to_string(&f.evidence)?,
            serde_json::to_string(&f.possible_causes)?,
            serde_json::to_string(&f.verification)?,
        ],
    )?;
    Ok(())
}

/// 查询最近诊断结论（时间倒序）。
pub fn query_findings(conn: &Connection, limit: u32) -> Result<Vec<DiagnosticFinding>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT rule_id, title, severity, confidence, detected_at, impact_processes, \
         impact_domains, evidence, possible_causes, verification \
         FROM diagnostic_results ORDER BY detected_at DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit.min(500)], |r| {
        Ok(DiagnosticFinding {
            rule_id: r.get(0)?,
            title: r.get(1)?,
            severity: serde_json::from_str(&r.get::<_, String>(2)?)
                .unwrap_or(Severity::Info),
            confidence: serde_json::from_str(&r.get::<_, String>(3)?)
                .unwrap_or(Confidence::Speculative),
            detected_at: parse_ts(&r.get::<_, String>(4)?),
            impact_processes: serde_json::from_str(&r.get::<_, String>(5)?).unwrap_or_default(),
            impact_domains: serde_json::from_str(&r.get::<_, String>(6)?).unwrap_or_default(),
            evidence: serde_json::from_str(&r.get::<_, String>(7)?).unwrap_or_default(),
            possible_causes: serde_json::from_str(&r.get::<_, String>(8)?).unwrap_or_default(),
            verification: serde_json::from_str(&r.get::<_, String>(9)?).unwrap_or_default(),
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// 注册规则元数据（幂等）。
pub fn upsert_rule_meta(conn: &Connection, metas: &[crate::models::session::DiagnosticRuleMeta]) -> Result<(), StorageError> {
    let mut stmt = conn.prepare(
        "INSERT INTO diagnostic_rules (rule_id, category, title, severity, description, enabled) \
         VALUES (?1,?2,?3,?4,?5,?6) \
         ON CONFLICT(rule_id) DO UPDATE SET title=excluded.title, description=excluded.description",
    )?;
    for m in metas {
        stmt.execute(rusqlite::params![
            m.rule_id,
            m.category,
            m.title,
            serde_json::to_string(&m.severity)?,
            m.description,
            m.enabled as i64,
        ])?;
    }
    Ok(())
}

/// 查询被禁用的规则 ID 集合。
pub fn disabled_rules(conn: &Connection) -> Result<Vec<String>, StorageError> {
    let mut stmt =
        conn.prepare("SELECT rule_id FROM diagnostic_rules WHERE enabled = 0")?;
    let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// 基准测试
// ---------------------------------------------------------------------------

/// 写入基准测试结果。
pub fn insert_benchmark(conn: &Connection, b: &BenchmarkResult) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO benchmark_results (id, kind, target, started_at, finished_at, interface, \
         proxy_mode, egress_ip, dns_server, metrics, error) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
        rusqlite::params![
            b.id,
            serde_json::to_string(&b.kind)?,
            b.target,
            b.started_at.to_rfc3339(),
            b.finished_at.map(|t| t.to_rfc3339()),
            b.interface,
            b.proxy_mode,
            b.egress_ip,
            b.dns_server,
            serde_json::to_string(&b.metrics)?,
            b.error,
        ],
    )?;
    Ok(())
}

/// 查询基准测试历史。
pub fn query_benchmarks(conn: &Connection, limit: u32) -> Result<Vec<BenchmarkResult>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT id, kind, target, started_at, finished_at, interface, proxy_mode, egress_ip, \
         dns_server, metrics, error FROM benchmark_results ORDER BY started_at DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit.min(500)], |r| {
        Ok(BenchmarkResult {
            id: r.get(0)?,
            kind: serde_json::from_str(&r.get::<_, String>(1)?)
                .unwrap_or(BenchmarkKind::Ping),
            target: r.get(2)?,
            started_at: parse_ts(&r.get::<_, String>(3)?),
            finished_at: r
                .get::<_, Option<String>>(4)?
                .as_deref()
                .map(parse_ts),
            interface: r.get(5)?,
            proxy_mode: r.get(6)?,
            egress_ip: r.get(7)?,
            dns_server: r.get(8)?,
            metrics: serde_json::from_str(&r.get::<_, String>(9)?)
                .unwrap_or(serde_json::Value::Null),
            error: r.get(10)?,
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// RCA / AI
// ---------------------------------------------------------------------------

/// 写入 RCA 报告。
pub fn insert_rca(conn: &Connection, r: &RcaReport) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO root_cause_analysis (id, created_at, subject, window_start, window_end, \
         symptom, observations, causes, suggestions, finding_rule_ids) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
        rusqlite::params![
            r.id,
            r.created_at.to_rfc3339(),
            r.subject,
            r.window_start.to_rfc3339(),
            r.window_end.to_rfc3339(),
            r.symptom,
            serde_json::to_string(&r.observations)?,
            serde_json::to_string(&r.causes)?,
            serde_json::to_string(&r.suggestions)?,
            serde_json::to_string(&r.finding_rule_ids)?,
        ],
    )?;
    Ok(())
}

/// 写入 AI 会话。
pub fn insert_ai_conversation(conn: &Connection, c: &AiConversation) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO ai_conversations (id, created_at, provider, question, answer, evidence_used) \
         VALUES (?1,?2,?3,?4,?5,?6)",
        rusqlite::params![
            c.id,
            c.created_at.to_rfc3339(),
            c.provider,
            c.question,
            c.answer,
            serde_json::to_string(&c.evidence_used)?,
        ],
    )?;
    Ok(())
}

/// 查询 AI 会话历史。
pub fn query_ai_conversations(conn: &Connection, limit: u32) -> Result<Vec<AiConversation>, StorageError> {
    let mut stmt = conn.prepare(
        "SELECT id, created_at, provider, question, answer, evidence_used \
         FROM ai_conversations ORDER BY created_at DESC LIMIT ?1",
    )?;
    let rows = stmt.query_map([limit.min(200)], |r| {
        Ok(AiConversation {
            id: r.get(0)?,
            created_at: parse_ts(&r.get::<_, String>(1)?),
            provider: r.get(2)?,
            question: r.get(3)?,
            answer: r.get(4)?,
            evidence_used: serde_json::from_str(&r.get::<_, String>(5)?)
                .unwrap_or(serde_json::Value::Null),
        })
    })?;
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

/// 数据库备份（VACUUM INTO，WAL 安全）。
pub fn backup_database(conn: &Connection, target: &str) -> Result<(), StorageError> {
    conn.execute("VACUUM INTO ?1", [target])?;
    Ok(())
}

/// 路由探测记录落库（Route Explorer 已用；此处统一暴露给会话录制复用）。
pub fn insert_route_probe_record(conn: &Connection, probe: &RouteProbe) -> Result<(), StorageError> {
    conn.execute(
        "INSERT INTO route_probes (id, target, resolved_ip, protocol, port, max_hops, probes_per_hop, \
         started_at, finished_at, complete, path_changed) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) \
         ON CONFLICT(id) DO UPDATE SET finished_at=excluded.finished_at, complete=excluded.complete",
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
        "INSERT INTO route_hops (probe_id, ttl, state, ip, rtt_ms, probes_sent, hostname, asn) \
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::session::SessionScope;
    use crate::storage::database::migrate;

    fn conn() -> Connection {
        let c = Connection::open_in_memory().unwrap();
        migrate(&c).unwrap();
        c
    }

    fn session(id: &str) -> RecordingSession {
        RecordingSession {
            id: id.into(),
            name: "测试录制".into(),
            scope: SessionScope::All,
            started_at: chrono::Utc::now(),
            stopped_at: None,
            status: SessionStatus::Recording,
            event_count: 0,
            test_kind: "browser".into(),
        }
    }

    #[test]
    fn session_lifecycle_roundtrip() {
        let c = conn();
        create_session(&c, &session("s1")).unwrap();
        insert_session_events(
            &c,
            &[SessionEvent {
                session_id: "s1".into(),
                timestamp: chrono::Utc::now(),
                source: "connection".into(),
                kind: "conn_opened".into(),
                summary: "打开连接".into(),
                payload: serde_json::json!({"remote": "1.2.3.4"}),
            }],
        )
        .unwrap();
        finish_session(&c, "s1", &chrono::Utc::now().to_rfc3339(), SessionStatus::Completed, 1).unwrap();

        let list = list_sessions(&c, 10).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].status, SessionStatus::Completed);
        assert_eq!(list[0].event_count, 1);
        let events = get_session_events(&c, "s1", 100).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "conn_opened");
    }

    #[test]
    fn timeline_query_filters() {
        let c = conn();
        let now = chrono::Utc::now();
        insert_timeline_events(
            &c,
            &[
                TimelineEvent {
                    timestamp: now,
                    source: "connection".into(),
                    kind: "conn_opened".into(),
                    summary: "a".into(),
                    payload: serde_json::json!({}),
                },
                TimelineEvent {
                    timestamp: now,
                    source: "dns".into(),
                    kind: "dns_new".into(),
                    summary: "b".into(),
                    payload: serde_json::json!({}),
                },
            ],
        )
        .unwrap();

        let all = query_timeline(&c, None, None, None, None, 100).unwrap();
        assert_eq!(all.len(), 2);
        let dns_only = query_timeline(&c, None, None, Some("dns_new"), None, 100).unwrap();
        assert_eq!(dns_only.len(), 1);
        assert_eq!(dns_only[0].kind, "dns_new");
        let by_source = query_timeline(&c, None, None, None, Some("dns"), 100).unwrap();
        assert_eq!(by_source.len(), 1);
    }

    #[test]
    fn topology_snapshot_roundtrip() {
        let c = conn();
        let snap = TopologyHistorySnapshot {
            timestamp: chrono::Utc::now(),
            nodes: vec![],
            edges: vec![],
        };
        insert_topology_snapshot(&c, &snap).unwrap();
        let got = latest_topology_snapshot_before(&c, &chrono::Utc::now().to_rfc3339())
            .unwrap()
            .expect("应取到快照");
        assert_eq!(got.timestamp, snap.timestamp);
    }

    #[test]
    fn findings_roundtrip() {
        let c = conn();
        let f = DiagnosticFinding {
            rule_id: "dns.failure".into(),
            title: "DNS 解析失败".into(),
            severity: Severity::Warning,
            confidence: Confidence::Inferred,
            detected_at: chrono::Utc::now(),
            impact_processes: vec!["chrome.exe".into()],
            impact_domains: vec!["google.com".into()],
            evidence: vec![],
            possible_causes: vec!["DNS 服务器不可达".into()],
            verification: vec!["nslookup www.google.com".into()],
        };
        insert_finding(&c, &f).unwrap();
        let got = query_findings(&c, 10).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].rule_id, "dns.failure");
        assert_eq!(got[0].severity, Severity::Warning);
    }

    #[test]
    fn backup_creates_file() {
        let c = conn();
        create_session(&c, &session("s-backup")).unwrap();
        let dir = std::env::temp_dir().join(format!("ns_backup_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let target = dir.join("backup.db");
        backup_database(&c, target.to_str().unwrap()).unwrap();
        assert!(target.exists(), "VACUUM INTO 应生成备份文件");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
