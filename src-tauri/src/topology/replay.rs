//! 拓扑回放（Network Replay，第三轮）。
//!
//! 历史拓扑必须基于当时保存的数据重建：
//! 1. 取目标时间前最近的拓扑快照（topology_history）作为基底；
//! 2. 应用 (快照时间, 目标时间] 窗口内的连接/DNS 时间线事件（session/全局时间线）；
//! 3. 产出该时刻的节点与边。
//!
//! 明确禁止：用"当前连接状态"冒充历史状态。

use chrono::{DateTime, Utc};
use rusqlite::Connection as DbConnection;

use crate::models::connection::Connection;
use crate::models::session::TimelineEvent;
use crate::models::topology::{TopologyEdge, TopologyNode};
use crate::storage::history_repository;
use crate::topology::builder::TopologyBuilder;
use crate::topology::graph::{GraphDiff, TopologyGraph};

/// 拓扑相关事件类型（回放时应用）。
fn is_topology_event(kind: &str) -> bool {
    matches!(
        kind,
        "conn_opened" | "conn_updated" | "conn_closed" | "dns_new"
    )
}

/// 将时间线事件重建为连接对象（载荷即序列化的 Connection）。
fn conn_from_event(e: &TimelineEvent) -> Option<Connection> {
    serde_json::from_value::<Connection>(e.payload.clone()).ok()
}

/// 回放：重建 `at` 时刻的拓扑状态。
pub fn replay_at(
    conn: &DbConnection,
    at: DateTime<Utc>,
) -> Result<(Vec<TopologyNode>, Vec<TopologyEdge>, usize), String> {
    let at_str = at.to_rfc3339();
    let snap = history_repository::latest_topology_snapshot_before(conn, &at_str)
        .map_err(|e| e.to_string())?;

    let mut graph = TopologyGraph::new();
    let mut base_time: DateTime<Utc> = at - chrono::Duration::hours(24);

    match snap {
        Some(s) => {
            base_time = s.timestamp;
            let mut diff = GraphDiff::default();
            for n in s.nodes {
                graph.upsert_node(n, &mut diff);
            }
            for e in s.edges {
                graph.upsert_edge(e, &mut diff);
            }
        }
        None => {
            // 无快照：从 host 节点起步（回放窗口过旧的诚实降级）
            let mut diff = GraphDiff::default();
            let now = Utc::now();
            graph.upsert_node(
                TopologyNode {
                    id: "host:local".into(),
                    kind: crate::models::topology::NodeKind::LocalComputer,
                    label: "本机".into(),
                    first_seen: now,
                    last_seen: now,
                    active: true,
                    data: None,
                },
                &mut diff,
            );
        }
    }

    // 应用窗口内事件（时间正序）
    let events =
        history_repository::query_timeline(conn, Some(&base_time.to_rfc3339()), Some(&at_str), None, None, 5000)
            .map_err(|e| e.to_string())?;

    let mut builder = TopologyBuilder::new();
    let mut diff = GraphDiff::default();
    let mut applied = 0usize;

    for e in &events {
        if !is_topology_event(&e.kind) {
            continue;
        }
        applied += 1;
        match e.kind.as_str() {
            "conn_opened" | "conn_updated" => {
                if let Some(c) = conn_from_event(e) {
                    builder.replay_connection(&mut graph, &mut diff, &c, true, e.timestamp);
                }
            }
            "conn_closed" => {
                if let Some(c) = conn_from_event(e) {
                    builder.replay_connection(&mut graph, &mut diff, &c, false, e.timestamp);
                }
            }
            "dns_new" => {
                if let Some(domain) = e.payload.get("domain").and_then(|v| v.as_str()) {
                    builder.replay_dns_domain(&mut graph, &mut diff, domain, e.timestamp);
                }
            }
            _ => {}
        }
    }

    let (nodes, edges) = (graph.nodes().cloned().collect(), graph.edges().cloned().collect());
    Ok((nodes, edges, applied))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::connection::{
        derive_connection_id, Connection, ConnectionState, Endpoint, Protocol,
    };
    use crate::models::session::TopologyHistorySnapshot;
    use crate::storage::database::migrate;

    fn conn() -> Connection {
        let local = Endpoint { ip: "192.168.1.10".into(), port: 50000 };
        let remote = Endpoint { ip: "1.2.3.4".into(), port: 443 };
        Connection {
            id: derive_connection_id(Protocol::Tcp, 100, &local, Some(&remote)),
            pid: 100,
            process_name: Some("chrome.exe".into()),
            protocol: Protocol::Tcp,
            local,
            remote: Some(remote),
            state: ConnectionState::Established,
            interface_index: None,
            first_seen: Utc::now() - chrono::Duration::minutes(5),
            last_seen: Utc::now(),
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    fn test_conn() -> DbConnection {
        let c = DbConnection::open_in_memory().unwrap();
        migrate(&c).unwrap();
        c
    }

    #[test]
    fn replay_rebuilds_state_from_events() {
        let c = test_conn();
        let t0 = Utc::now() - chrono::Duration::minutes(10);

        // 基底快照（只有 host 节点）
        history_repository::insert_topology_snapshot(
            &c,
            &TopologyHistorySnapshot {
                timestamp: t0,
                nodes: vec![TopologyNode {
                    id: "host:local".into(),
                    kind: crate::models::topology::NodeKind::LocalComputer,
                    label: "本机".into(),
                    first_seen: t0,
                    last_seen: t0,
                    active: true,
                    data: None,
                }],
                edges: vec![],
            },
        )
        .unwrap();

        // 窗口内事件：连接打开
        history_repository::insert_timeline_events(
            &c,
            &[TimelineEvent {
                timestamp: t0 + chrono::Duration::minutes(1),
                source: "connection".into(),
                kind: "conn_opened".into(),
                summary: "打开".into(),
                payload: serde_json::to_value(conn()).unwrap(),
            }],
        )
        .unwrap();

        // 回放到事件之后 → 应重建出进程与 IP 节点
        let (nodes, edges, applied) =
            replay_at(&c, t0 + chrono::Duration::minutes(2)).unwrap();
        assert_eq!(applied, 1, "应应用 1 条拓扑事件");
        assert!(
            nodes.iter().any(|n| n.id.contains("process:100")),
            "应重建进程节点"
        );
        assert!(nodes.iter().any(|n| n.id == "ip:1.2.3.4"), "应重建 IP 节点");
        assert_eq!(edges.len(), 1, "应重建 proc-ip 边");
    }

    #[test]
    fn replay_before_event_has_no_future_state() {
        let c = test_conn();
        let t0 = Utc::now() - chrono::Duration::minutes(10);

        history_repository::insert_topology_snapshot(
            &c,
            &TopologyHistorySnapshot {
                timestamp: t0,
                nodes: vec![TopologyNode {
                    id: "host:local".into(),
                    kind: crate::models::topology::NodeKind::LocalComputer,
                    label: "本机".into(),
                    first_seen: t0,
                    last_seen: t0,
                    active: true,
                    data: None,
                }],
                edges: vec![],
            },
        )
        .unwrap();
        history_repository::insert_timeline_events(
            &c,
            &[TimelineEvent {
                timestamp: t0 + chrono::Duration::minutes(5),
                source: "connection".into(),
                kind: "conn_opened".into(),
                summary: "打开".into(),
                payload: serde_json::to_value(conn()).unwrap(),
            }],
        )
        .unwrap();

        // 回放到事件之前 → 不得出现"未来"的连接状态
        let (nodes, _, applied) = replay_at(&c, t0 + chrono::Duration::minutes(1)).unwrap();
        assert_eq!(applied, 0, "窗口外事件不得应用");
        assert!(
            !nodes.iter().any(|n| n.id == "ip:1.2.3.4"),
            "历史状态不得包含未来的连接（不得用当前状态冒充）"
        );
    }
}
