//! 连接生命周期：快照对比生成 Opened / Updated / Closed 事件。
//!
//! 准确性保证：
//! - 连接身份 = 派生 ID（协议+四元组+PID），不同时间、不同端点绝不合并；
//! - `first_seen` 跨快照保持不变，`last_seen` 每次观测刷新；
//! - 快照中消失的连接立即产生 Closed（last_seen = 最后一次观测时间）；
//! - 进程名字段短暂不可得（权限抖动）时沿用上一次已知值，不丢失归属。
//!
//! 本模块为纯逻辑，测试全部使用合成快照，不依赖系统状态。

use std::collections::{HashMap, HashSet};

use chrono::{DateTime, Utc};

use crate::models::connection::Connection;

/// 连接生命周期事件。
#[derive(Debug, Clone, PartialEq)]
pub enum LifecycleEvent {
    /// 新观测到的连接。
    Opened(Connection),
    /// 已知连接发生变化（状态 / 归属接口 / 进程名）。
    Updated(Connection),
    /// 连接消失（last_seen = 最后观测时间）。
    Closed(Connection),
}

#[derive(Debug, Clone)]
struct Tracked {
    conn: Connection,
}

/// 连接生命周期跟踪器。
#[derive(Debug, Default)]
pub struct ConnectionTracker {
    active: HashMap<String, Tracked>,
}

/// 事件中连接的只读访问（供运行时与命令层使用）。
pub fn event_connection(ev: &LifecycleEvent) -> &Connection {
    match ev {
        LifecycleEvent::Opened(c) | LifecycleEvent::Updated(c) | LifecycleEvent::Closed(c) => c,
    }
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// 应用一次快照，返回本次产生的生命周期事件。
    pub fn apply_snapshot(
        &mut self,
        snapshot: Vec<Connection>,
        now: DateTime<Utc>,
    ) -> Vec<LifecycleEvent> {
        let mut events = Vec::new();
        let mut seen: HashSet<String> = HashSet::with_capacity(snapshot.len());

        for raw in snapshot {
            seen.insert(raw.id.clone());
            // 权限抖动时沿用已知进程名
            let conn = match self.active.get(&raw.id) {
                Some(prev) => {
                    let mut c = raw;
                    if c.process_name.is_none() {
                        c.process_name = prev.conn.process_name.clone();
                    }
                    // first_seen 不变（打开时间）；last_seen = 本次观测
                    c.first_seen = prev.conn.first_seen;
                    c.last_seen = now;
                    c
                }
                None => {
                    let mut c = raw;
                    c.first_seen = now;
                    c.last_seen = now;
                    c
                }
            };

            match self.active.get(&conn.id) {
                None => {
                    events.push(LifecycleEvent::Opened(conn.clone()));
                    self.active.insert(conn.id.clone(), Tracked { conn });
                }
                Some(prev) => {
                    let changed = prev.conn.state != conn.state
                        || prev.conn.interface_index != conn.interface_index
                        || prev.conn.process_name != conn.process_name;
                    if changed {
                        events.push(LifecycleEvent::Updated(conn.clone()));
                    }
                    self.active.insert(conn.id.clone(), Tracked { conn });
                }
            }
        }

        // 快照中未出现的 → Closed
        let disappeared: Vec<String> = self
            .active
            .keys()
            .filter(|id| !seen.contains(*id))
            .cloned()
            .collect();
        for id in disappeared {
            if let Some(mut t) = self.active.remove(&id) {
                t.conn.last_seen = now;
                t.conn.state = crate::models::connection::ConnectionState::Closed;
                events.push(LifecycleEvent::Closed(t.conn));
            }
        }

        events
    }

    /// 当前活跃连接列表（供拓扑/存储使用）。
    pub fn active_connections(&self) -> Vec<Connection> {
        self.active.values().map(|t| t.conn.clone()).collect()
    }

    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// 重置（如采集关闭时）。
    pub fn reset(&mut self) {
        self.active.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::connection::{derive_connection_id, Connection, ConnectionState, Endpoint, Protocol};
    use chrono::Utc;

    fn tcp_conn(pid: u32, lport: u16, rip: &str, rport: u16, state: ConnectionState) -> Connection {
        let local = Endpoint { ip: "192.168.1.10".into(), port: lport };
        let remote = Endpoint { ip: rip.into(), port: rport };
        Connection {
            id: derive_connection_id(Protocol::Tcp, pid, &local, Some(&remote)),
            pid,
            process_name: Some("chrome.exe".into()),
            protocol: Protocol::Tcp,
            local,
            remote: Some(remote),
            state,
            interface_index: Some(12),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    #[test]
    fn opened_updated_closed_lifecycle() {
        let mut tracker = ConnectionTracker::new();
        let t0 = Utc::now();

        // 第一次快照：新连接
        let c1 = tcp_conn(100, 50000, "1.2.3.4", 443, ConnectionState::SynSent);
        let ev = tracker.apply_snapshot(vec![c1], t0);
        assert_eq!(ev.len(), 1);
        let LifecycleEvent::Opened(o) = &ev[0] else { unreachable!() };
        assert_eq!(o.id, "tcp:192.168.1.10:50000:1.2.3.4:443:100");
        assert_eq!(o.first_seen, t0, "打开时间 = 首次观测时间");

        // 第二次快照：状态变化 → Updated，且 first_seen 保持
        let t1 = t0 + chrono::Duration::seconds(2);
        let c2 = tcp_conn(100, 50000, "1.2.3.4", 443, ConnectionState::Established);
        let ev = tracker.apply_snapshot(vec![c2], t1);
        assert_eq!(ev.len(), 1);
        let LifecycleEvent::Updated(u) = &ev[0] else { unreachable!() };
        assert_eq!(u.first_seen, t0, "first_seen 必须保持不变");
        assert_eq!(u.last_seen, t1);
        assert_eq!(u.state, ConnectionState::Established);

        // 第三次快照：连接消失 → Closed
        let t2 = t1 + chrono::Duration::seconds(2);
        let ev = tracker.apply_snapshot(vec![], t2);
        assert_eq!(ev.len(), 1);
        let LifecycleEvent::Closed(cl) = &ev[0] else { unreachable!() };
        assert_eq!(cl.last_seen, t2);
        assert_eq!(cl.first_seen, t0, "关闭事件仍保留原始打开时间");
        assert_eq!(tracker.active_count(), 0);
    }

    #[test]
    fn different_endpoints_never_merge() {
        let mut tracker = ConnectionTracker::new();
        let t0 = Utc::now();
        let a = tcp_conn(100, 50000, "1.2.3.4", 443, ConnectionState::Established);
        let ev1 = tracker.apply_snapshot(vec![a], t0);
        assert_eq!(ev1.len(), 1);

        // 同 PID 新端口 = 新连接（旧连接同时关闭）
        let t1 = t0 + chrono::Duration::seconds(1);
        let b = tcp_conn(100, 50001, "1.2.3.4", 443, ConnectionState::Established);
        let ev2 = tracker.apply_snapshot(vec![b], t1);
        assert_eq!(ev2.len(), 2, "应产生一条 Closed + 一条 Opened");
        assert!(
            ev2.iter().any(|e| matches!(e, LifecycleEvent::Closed(_))),
            "旧端点连接应关闭"
        );
        assert!(
            ev2.iter().any(|e| matches!(e, LifecycleEvent::Opened(_))),
            "新端点连接应打开"
        );
        assert_eq!(tracker.active_count(), 1);
    }

    #[test]
    fn process_name_glitch_keeps_last_known() {
        let mut tracker = ConnectionTracker::new();
        let t0 = Utc::now();
        let mut c = tcp_conn(100, 50000, "1.2.3.4", 443, ConnectionState::Established);
        let _ = tracker.apply_snapshot(vec![c.clone()], t0);

        // 下一次快照进程名不可得（None）
        c.process_name = None;
        let t1 = t0 + chrono::Duration::seconds(1);
        let ev = tracker.apply_snapshot(vec![c], t1);
        // None → 沿用 Some("chrome.exe")，因此 process_name 不变 → 仅 state 未变 → 无 Updated
        assert!(ev.is_empty());
        let active = tracker.active_connections();
        assert_eq!(active[0].process_name.as_deref(), Some("chrome.exe"));
    }

    #[test]
    fn no_change_no_event() {
        let mut tracker = ConnectionTracker::new();
        let t0 = Utc::now();
        let c = tcp_conn(100, 50000, "1.2.3.4", 443, ConnectionState::Established);
        tracker.apply_snapshot(vec![c.clone()], t0);
        let ev = tracker.apply_snapshot(vec![c], t0 + chrono::Duration::seconds(1));
        assert!(ev.is_empty(), "无变化不应产生事件");
    }
}
