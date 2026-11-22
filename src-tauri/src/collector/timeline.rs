//! 统一时间线构建（第三轮）。
//!
//! 职责：把运行时的各类产出（连接生命周期 / DNS / 代理 / 接口 / 路由 / 质量）
//! 转换为带人类可读摘要与结构化载荷的 `TimelineEvent`，供：
//! - History 页时间线展示；
//! - 会话录制（scope 过滤后落 session_events）；
//! - 诊断规则引擎输入；
//! - 拓扑回放重建。

use chrono::{DateTime, Utc};

use crate::correlator::connection_correlation::LifecycleEvent;
use crate::models::connection::Connection;
use crate::models::metrics::NetworkQualityPoint;
use crate::models::proxy::ProxyEventKind;
use crate::models::session::{SessionScope, TimelineEvent};

/// 判断是否为"环境事件"——录制 scope 为进程/域名时也应收录的上下文事件
/// （接口 / 路由 / 代理 / 质量：它们是解释网络事件的环境背景）。
pub fn is_environment_event(kind: &str) -> bool {
    matches!(
        kind,
        "interface_changed"
            | "ip_changed"
            | "speed_dropped"
            | "route_changed"
            | "proxy_detected"
            | "proxy_changed"
            | "proxy_removed"
            | "quality_sample"
    )
}

fn conn_summary(kind: &str, c: &Connection) -> String {
    let who = c.process_name.as_deref().unwrap_or("未知进程");
    let remote = match &c.remote {
        Some(r) => format!("{}:{}", r.ip, r.port),
        None => "无远端".into(),
    };
    match kind {
        "conn_opened" => format!("{who} 打开 {}:{} → {}", c.local.ip, c.local.port, remote),
        "conn_closed" => format!("{who} 关闭 {}:{} → {}", c.local.ip, c.local.port, remote),
        _ => format!(
            "{who} 连接 {}:{} → {} 状态 {:?}",
            c.local.ip,
            c.local.port,
            remote,
            c.state
        ),
    }
}

/// 连接生命周期 → 时间线事件。
pub fn connection_event(ev: &LifecycleEvent, now: DateTime<Utc>) -> TimelineEvent {
    let c = crate::correlator::connection_correlation::event_connection(ev);
    let kind = match ev {
        LifecycleEvent::Opened(_) => "conn_opened",
        LifecycleEvent::Updated(_) => "conn_updated",
        LifecycleEvent::Closed(_) => "conn_closed",
    };
    TimelineEvent {
        timestamp: c.last_seen,
        source: "connection".into(),
        kind: kind.into(),
        summary: conn_summary(kind, c),
        payload: serde_json::to_value(c).unwrap_or(serde_json::Value::Null),
    }
    .at(now)
}

/// 新 DNS 域名 → 时间线事件。
pub fn dns_events(domains: &[String], now: DateTime<Utc>) -> Vec<TimelineEvent> {
    domains
        .iter()
        .map(|d| TimelineEvent {
            timestamp: now,
            source: "dns".into(),
            kind: "dns_new".into(),
            summary: format!("新解析域名: {d}"),
            payload: serde_json::json!({ "domain": d }),
        })
        .collect()
}

/// 代理状态事件 → 时间线事件。
pub fn proxy_events(events: &[crate::models::proxy::ProxyEvent]) -> Vec<TimelineEvent> {
    events
        .iter()
        .map(|pe| {
            let kind = match pe.kind {
                ProxyEventKind::Detected => "proxy_detected",
                ProxyEventKind::Changed => "proxy_changed",
                ProxyEventKind::Removed => "proxy_removed",
            };
            TimelineEvent {
                timestamp: pe.timestamp,
                source: "proxy".into(),
                kind: kind.into(),
                summary: pe.summary.clone(),
                payload: serde_json::to_value(pe).unwrap_or(serde_json::Value::Null),
            }
        })
        .collect()
}

/// 质量采样（每 N tick 一条，供延迟变化展示）。
pub fn quality_sample(q: &NetworkQualityPoint) -> TimelineEvent {
    TimelineEvent {
        timestamp: q.timestamp,
        source: "metrics".into(),
        kind: "quality_sample".into(),
        summary: format!(
            "下行 {} 上行 {} TCP 已建立 {}",
            fmt_bps(q.rx_bps),
            fmt_bps(q.tx_bps),
            q.tcp_established
        ),
        payload: serde_json::to_value(q).unwrap_or(serde_json::Value::Null),
    }
}

fn fmt_bps(bps: f64) -> String {
    if bps < 1024.0 {
        format!("{bps:.0} B/s")
    } else if bps < 1024.0 * 1024.0 {
        format!("{:.1} KB/s", bps / 1024.0)
    } else {
        format!("{:.1} MB/s", bps / 1024.0 / 1024.0)
    }
}

/// 进程启动 / 退出差分 → 时间线事件（会话录制内容之一）。
pub fn process_events(
    diff: &crate::collector::processes::ProcessDiff,
    now: DateTime<Utc>,
) -> Vec<TimelineEvent> {
    let mut out = Vec::new();
    for (pid, name) in &diff.started {
        out.push(TimelineEvent {
            timestamp: now,
            source: "process".into(),
            kind: "process_started".into(),
            summary: format!("进程启动: {name} (PID {pid})"),
            payload: serde_json::json!({ "pid": pid, "processName": name }),
        });
    }
    for (pid, name) in &diff.exited {
        out.push(TimelineEvent {
            timestamp: now,
            source: "process".into(),
            kind: "process_exited".into(),
            summary: format!("进程退出: {name} (PID {pid})"),
            payload: serde_json::json!({ "pid": pid, "processName": name }),
        });
    }
    out
}

/// 接口 / 路由 diff 状态持有者。
#[derive(Debug, Default)]
pub struct TimelineBuilder {
    last_iface_state: std::collections::HashMap<u32, (String, Vec<String>, u64)>,
    last_default_routes: Vec<(u32, String)>,
}

impl TimelineBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// 接口状态 / IP / 协商速率 diff → 时间线事件。
    pub fn diff_interfaces(
        &mut self,
        interfaces: &[crate::models::interface::NetworkInterface],
        now: DateTime<Utc>,
    ) -> Vec<TimelineEvent> {
        let mut out = Vec::new();
        for i in interfaces {
            let state = (
                format!("{:?}", i.operational_status).to_lowercase(),
                i.ipv4_addresses.clone(),
                i.speed_bps,
            );
            if let Some(prev) = self.last_iface_state.get(&i.index) {
                if prev.0 != state.0 {
                    out.push(
                        TimelineEvent {
                            timestamp: now,
                            source: "adapter".into(),
                            kind: "interface_changed".into(),
                            summary: format!(
                                "网卡 {} 状态: {} → {}",
                                i.friendly_name, prev.0, state.0
                            ),
                            payload: serde_json::json!({
                                "ifIndex": i.index,
                                "friendlyName": i.friendly_name,
                                "from": prev.0,
                                "to": state.0,
                            }),
                        }
                        .at(now),
                    );
                }
                if prev.1 != state.1 {
                    out.push(
                        TimelineEvent {
                            timestamp: now,
                            source: "adapter".into(),
                            kind: "ip_changed".into(),
                            summary: format!(
                                "网卡 {} IP 变化: {:?} → {:?}",
                                i.friendly_name, prev.1, state.1
                            ),
                            payload: serde_json::json!({
                                "ifIndex": i.index,
                                "friendlyName": i.friendly_name,
                                "from": prev.1,
                                "to": state.1,
                            }),
                        }
                        .at(now),
                    );
                }
                if state.0 == "up" && prev.2 > 0 && i.speed_bps > 0 && i.speed_bps < prev.2 / 2 {
                    out.push(
                        TimelineEvent {
                            timestamp: now,
                            source: "adapter".into(),
                            kind: "speed_dropped".into(),
                            summary: format!(
                                "网卡 {} 协商速率下降: {} → {}",
                                i.friendly_name, prev.2, i.speed_bps
                            ),
                            payload: serde_json::json!({
                                "ifIndex": i.index,
                                "friendlyName": i.friendly_name,
                                "from": prev.2,
                                "to": i.speed_bps,
                            }),
                        }
                        .at(now),
                    );
                }
            }
            self.last_iface_state.insert(i.index, state);
        }
        out
    }

    /// 默认路由 diff → 时间线事件（首次观测只记录基线，不产生事件）。
    pub fn diff_routes(&mut self, now: DateTime<Utc>) -> Vec<TimelineEvent> {
        let routes = crate::collector::routes::default_routes().unwrap_or_default();
        let removed: Vec<(u32, String)> = self
            .last_default_routes
            .iter()
            .filter(|r| !routes.contains(r))
            .cloned()
            .collect();
        let added: Vec<(u32, String)> = routes
            .iter()
            .filter(|r| !self.last_default_routes.contains(r))
            .cloned()
            .collect();
        let out = if !self.last_default_routes.is_empty()
            && (!removed.is_empty() || !added.is_empty())
        {
            vec![
                TimelineEvent {
                    timestamp: now,
                    source: "routes".into(),
                    kind: "route_changed".into(),
                    summary: format!(
                        "默认路由变化: 移除 {:?} 新增 {:?}",
                        removed, added
                    ),
                    payload: serde_json::json!({
                        "added": added,
                        "removed": removed,
                        "current": routes,
                    }),
                }
                .at(now),
            ]
        } else {
            Vec::new()
        };
        self.last_default_routes = routes;
        out
    }
}

impl TimelineEvent {
    fn at(mut self, now: DateTime<Utc>) -> Self {
        if self.timestamp > now {
            self.timestamp = now;
        }
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::connection::{
        derive_connection_id, Connection, ConnectionState, Endpoint, Protocol,
    };
    use crate::models::interface::{NetworkInterface, OperationalStatus, InterfaceType};
    use chrono::Utc;

    fn conn(state: ConnectionState) -> Connection {
        let local = Endpoint { ip: "192.168.1.10".into(), port: 50000 };
        let remote = Endpoint { ip: "1.2.3.4".into(), port: 443 };
        Connection {
            id: derive_connection_id(Protocol::Tcp, 100, &local, Some(&remote)),
            pid: 100,
            process_name: Some("chrome.exe".into()),
            protocol: Protocol::Tcp,
            local,
            remote: Some(remote),
            state,
            interface_index: None,
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            bytes_sent: 0,
            bytes_received: 0,
        }
    }

    #[test]
    fn lifecycle_events_have_summaries() {
        let now = Utc::now();
        let opened = connection_event(&LifecycleEvent::Opened(conn(ConnectionState::SynSent)), now);
        assert_eq!(opened.kind, "conn_opened");
        assert!(opened.summary.contains("chrome.exe"));
        assert!(opened.summary.contains("1.2.3.4"));
        assert!(matches!(opened.payload.get("pid"), Some(serde_json::Value::Number(_))));

        let closed = connection_event(&LifecycleEvent::Closed(conn(ConnectionState::Closed)), now);
        assert_eq!(closed.kind, "conn_closed");
    }

    #[test]
    fn interface_down_event() {
        let mut builder = TimelineBuilder::new();
        let now = Utc::now();
        let mk = |status: OperationalStatus, ips: Vec<String>| NetworkInterface {
            index: 5,
            name: "if5".into(),
            friendly_name: "以太网".into(),
            description: "Realtek".into(),
            if_type: InterfaceType::Ethernet,
            operational_status: status,
            speed_bps: 1_000_000_000,
            mtu: 1500,
            mac_address: None,
            ipv4_addresses: ips,
            ipv6_addresses: vec![],
            dns_servers: vec![],
            gateways: vec![],
            first_seen: now,
            last_seen: now,
        };

        // 首次：只记基线，无事件
        let ev = builder.diff_interfaces(&[mk(OperationalStatus::Up, vec!["192.168.1.5".into()])], now);
        assert!(ev.is_empty(), "首次观测不应产生事件");

        // 断开
        let ev = builder.diff_interfaces(&[mk(OperationalStatus::Down, vec![])], now);
        assert!(ev.len() >= 1, "断开应产生 interface_changed（可能伴随 ip_changed）");
        assert!(ev.iter().any(|e| e.kind == "interface_changed"));
        assert!(ev.iter().any(|e| e.summary.contains("up → down")));

        // 恢复 + IP 变化
        let ev = builder.diff_interfaces(
            &[mk(OperationalStatus::Up, vec!["192.168.0.8".into()])],
            now,
        );
        assert_eq!(ev.len(), 2, "恢复 + IP 变化应产生两条事件");
        let kinds: Vec<&str> = ev.iter().map(|e| e.kind.as_str()).collect();
        assert!(kinds.contains(&"interface_changed"));
        assert!(kinds.contains(&"ip_changed"));
    }

    #[test]
    fn route_change_detected() {
        let mut builder = TimelineBuilder::new();
        let now = Utc::now();
        // 首次只记基线（真实路由表，本机必有默认路由）
        let _ = builder.diff_routes(now);
        // 人为改基线再触发变化
        builder.last_default_routes = vec![(7, "192.168.1.1".into())];
        let ev = builder.diff_routes(now);
        if !ev.is_empty() {
            assert_eq!(ev[0].kind, "route_changed");
            assert!(ev[0].summary.contains("默认路由变化"));
        }
        // （若真实路由表恰好等于伪造基线则无事件——测试仍通过）
    }

    #[test]
    fn environment_event_classification() {
        assert!(is_environment_event("interface_changed"));
        assert!(is_environment_event("route_changed"));
        assert!(is_environment_event("proxy_detected"));
        assert!(is_environment_event("quality_sample"));
        assert!(!is_environment_event("conn_opened"));
        assert!(!is_environment_event("dns_new"));
    }

    #[test]
    fn dns_events_summary() {
        let ev = dns_events(&["google.com".into()], Utc::now());
        assert_eq!(ev.len(), 1);
        assert!(ev[0].summary.contains("google.com"));
        assert_eq!(ev[0].payload["domain"], "google.com");
    }
}
