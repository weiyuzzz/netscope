//! 后台采集运行时：单线程 tick 驱动全部关联与增量计算（纯 Rust，不依赖 Tauri）。
//!
//! 每个 tick（默认 2s）：
//! 1. 全量快照（网卡 / TCP / UDP）
//! 2. 接口计数器差分 → 速率
//! 3. 连接生命周期差分 → Opened/Updated/Closed 事件
//! 4. 代理状态机（系统代理 / WinHTTP / 本地监听推断）→ 变化事件
//! 5. VPN / 虚拟网卡分类
//! 6. DNS 缓存域名（每 N tick）
//! 7. 拓扑增量（GraphDiff）
//! 8. 网络质量采样点
//!
//! 错误处理：任一采集步骤失败记录到 `errors`，不 panic、不中断循环。

use std::collections::HashMap;
use std::time::Instant;

use chrono::Utc;

use crate::collector::dns;
use crate::collector::proxy;
use crate::collector::routes;
use crate::collector::{adapters, tcp, udp};
use crate::correlator::connection_correlation::{ConnectionTracker, LifecycleEvent};
use crate::correlator::process_correlation::ProcessRegistry;
use crate::models::connection::Connection;
use crate::models::metrics::{InterfaceRate, NetworkQualityPoint};
use crate::models::proxy::{ProxyEvent, ProxyEventKind, ProxyServer, VpnInterface};
use crate::models::proxy::ProxyMechanism;
use crate::models::session::{SessionEvent, SessionScope, SessionStatus, TimelineEvent, TopologyHistorySnapshot};
use crate::storage::repository::PersistedEvent;
use crate::topology::builder::TopologyBuilder;
use crate::topology::graph::{GraphDiff, TopologyGraph};

/// 采集运行时（由 Tauri managed state 持有，Mutex 保护）。
pub struct CollectorRuntime {
    pub enabled: bool,
    pub interval_secs: u64,
    tracker: ConnectionTracker,
    registry: ProcessRegistry,
    graph: TopologyGraph,
    builder: TopologyBuilder,
    last_counters: Option<HashMap<u32, (u64, u64)>>,
    last_counter_time: Option<Instant>,
    last_system_servers: Vec<String>, // win_inet server ids（变化检测）
    last_winhttp_id: Option<String>,
    last_local_ids: Vec<String>,
    tick_count: u64,
    dns_domains: Vec<String>,
    /// SYN_SENT 跟踪：conn_id → 首次观测时间（建连失败判定用）
    syn_watch: HashMap<String, chrono::DateTime<Utc>>,
    /// 近期建连失败计数（每个质量点重置）
    syn_fail_recent: u32,
    pub timeline_builder: crate::collector::timeline::TimelineBuilder,
    last_processes: HashMap<u32, String>,
    pub last_handshake_p95_ms: Option<f64>,
    // ---- 第三轮：时间线 / 会话录制 / 拓扑快照 ----
    last_iface_state: HashMap<u32, (String, Vec<String>, u64)>,
    last_default_routes: Vec<(u32, String)>,
    pub session_id: Option<String>,
    pub session_scope: Option<SessionScope>,
    session_event_count: u64,
    // 供命令查询的最近一次缓存
    pub last_rates: Vec<InterfaceRate>,
    pub last_proxy_servers: Vec<ProxyServer>,
    pub last_proxy_links: Vec<crate::models::proxy::ProxyLink>,
    pub last_vpn: Vec<VpnInterface>,
    pub last_quality: Option<NetworkQualityPoint>,
}

/// 一次 tick 的全部产出。
#[derive(Debug, Default)]
pub struct TickOutput {
    /// 持久化事件（network_events 表）。
    pub events: Vec<PersistedEvent>,
    /// 生命周期事件（前端推送 + 拓扑）。
    pub lifecycle: Vec<LifecycleEvent>,
    /// 当前活跃连接（供命令查询）。
    pub connections: Vec<Connection>,
    pub interface_rates: Vec<InterfaceRate>,
    pub quality: Option<NetworkQualityPoint>,
    pub graph_diff: GraphDiff,
    pub proxy_servers: Vec<ProxyServer>,
    pub proxy_links: Vec<crate::models::proxy::ProxyLink>,
    pub vpn_interfaces: Vec<VpnInterface>,
    pub proxy_events: Vec<ProxyEvent>,
    pub dns_domains: Vec<String>,
    pub active_processes: usize,
    /// 采集错误（如实上报）。
    pub errors: Vec<String>,
    /// 本 tick 序号（落库节流用）。
    pub tick_count: u64,
    /// 本 tick 新出现的 DNS 缓存域名（相对上一次）。
    pub dns_new_domains: Vec<String>,
    /// 统一时间线事件（History 页 + 诊断引擎数据源）。
    pub timeline: Vec<TimelineEvent>,
    /// 会话录制事件（录制中才产生，scope 过滤后）。
    pub session_events: Vec<SessionEvent>,
    /// 拓扑快照（周期性，回放基底）。
    pub topology_snapshot: Option<TopologyHistorySnapshot>,
}

impl CollectorRuntime {
    pub fn new() -> Self {
        Self {
            enabled: true,
            interval_secs: 2,
            tracker: ConnectionTracker::new(),
            registry: ProcessRegistry::new(),
            graph: TopologyGraph::new(),
            builder: TopologyBuilder::new(),
            last_counters: None,
            last_counter_time: None,
            last_system_servers: Vec::new(),
            last_winhttp_id: None,
            last_local_ids: Vec::new(),
            tick_count: 0,
            dns_domains: Vec::new(),
            syn_watch: HashMap::new(),
            syn_fail_recent: 0,
            timeline_builder: crate::collector::timeline::TimelineBuilder::new(),
            last_processes: HashMap::new(),
            last_handshake_p95_ms: None,
            last_iface_state: HashMap::new(),
            last_default_routes: Vec::new(),
            session_id: None,
            session_scope: None,
            session_event_count: 0,
            last_rates: Vec::new(),
            last_proxy_servers: Vec::new(),
            last_proxy_links: Vec::new(),
            last_vpn: Vec::new(),
            last_quality: None,
        }
    }

    pub fn graph_snapshot(
        &self,
    ) -> (
        Vec<crate::models::topology::TopologyNode>,
        Vec<crate::models::topology::TopologyEdge>,
    ) {
        (
            self.graph.nodes().cloned().collect(),
            self.graph.edges().cloned().collect(),
        )
    }

    /// 开始录制会话。
    pub fn start_recording(&mut self, id: String, scope: SessionScope) {
        self.session_id = Some(id);
        self.session_scope = Some(scope);
        self.session_event_count = 0;
    }

    /// 停止录制，返回累计事件数。
    pub fn stop_recording(&mut self) -> u64 {
        self.session_id = None;
        self.session_scope = None;
        let n = self.session_event_count;
        self.session_event_count = 0;
        n
    }

    pub fn recording(&self) -> bool {
        self.session_id.is_some()
    }

    /// 当前活跃连接（供命令层查询）。
    pub fn tracker_active(&self) -> Vec<Connection> {
        self.tracker.active_connections()
    }

    /// 最近一次质量点的建连失败数（诊断引擎用）。
    pub fn last_syn_failures(&self) -> u32 {
        self.last_quality.as_ref().map(|q| q.syn_failures_recent).unwrap_or(0)
    }

    /// 最近一次质量点（供命令层）。
    pub fn last_quality(&self) -> Option<NetworkQualityPoint> {
        self.last_quality.clone()
    }

    /// 最近网卡快照（诊断/报告脱敏用）。
    pub fn last_interfaces(&self) -> Vec<crate::models::interface::NetworkInterface> {
        // 从拓扑图中提取网卡节点数据（实时快照由 collect_snapshot 提供，此处轻量化）
        self.graph
            .nodes()
            .filter(|n| n.kind == crate::models::topology::NodeKind::NetworkAdapter)
            .map(|n| crate::models::interface::NetworkInterface {
                index: n.id.split(':').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0),
                name: n.id.clone(),
                friendly_name: n.label.clone(),
                description: String::new(),
                if_type: crate::models::interface::InterfaceType::Other,
                operational_status: if n.active { crate::models::interface::OperationalStatus::Up } else { crate::models::interface::OperationalStatus::Down },
                speed_bps: 0,
                mtu: 0,
                mac_address: None,
                ipv4_addresses: n.data.as_ref().and_then(|d| d.get("ipv4")).and_then(|v| v.as_array()).map(|arr| arr.iter().filter_map(|x| x.as_str().map(String::from)).collect()).unwrap_or_default(),
                ipv6_addresses: vec![],
                dns_servers: vec![],
                gateways: vec![],
                first_seen: n.first_seen,
                last_seen: n.last_seen,
            })
            .collect()
    }

    /// 最近建连耗时 P95（抓包可观察时；当前从抓包会话缓存读取由命令层负责，此处返回 None 占位）。
    pub fn last_handshake_p95(&self) -> Option<f64> {
        self.last_handshake_p95_ms
    }

    /// 将路由探测结果推入拓扑（命令层调用；返回后由调用方 emit diff）。
    pub fn apply_route_probe(
        &mut self,
        probe: &crate::models::metrics::RouteProbe,
        diff: &mut GraphDiff,
    ) {
        let now = Utc::now();
        self.builder.apply_route_probe(&mut self.graph, diff, probe, now);
    }

    /// 执行一次采集 tick。
    pub fn tick(&mut self) -> TickOutput {
        let mut out = TickOutput::default();
        self.tick_count += 1;
        let now = Utc::now();

        if !self.enabled {
            return out;
        }

        // ---- 1. 全量快照 ----
        let interfaces = match adapters::list_adapters() {
            Ok(v) => v,
            Err(e) => {
                out.errors.push(format!("adapters: {e}"));
                return out;
            }
        };
        let tcp = match tcp::snapshot_tcp() {
            Ok(v) => v,
            Err(e) => {
                out.errors.push(format!("tcp: {e}"));
                return out;
            }
        };
        let udp = match udp::snapshot_udp() {
            Ok(v) => v,
            Err(e) => {
                out.errors.push(format!("udp: {e}"));
                return out;
            }
        };
        let mut all_connections = tcp;
        all_connections.extend(udp);

        // ---- 2. 接口速率差分 ----
        out.interface_rates = self.compute_interface_rates();
        self.attach_interface_names(&mut out.interface_rates, &interfaces);
        self.last_rates = out.interface_rates.clone();

        // ---- 3. 连接生命周期 ----
        out.lifecycle = self.tracker.apply_snapshot(all_connections.clone(), now);
        for ev in &out.lifecycle {
            out.events.push(persist_lifecycle(ev));
            self.registry
                .observe(ev_connection(ev).pid, ev_connection(ev).process_name.as_deref(), now);
        }
        out.connections = self.tracker.active_connections();
        out.active_processes = self.registry.count();

        // SYN 建连失败跟踪（系统级事实：SYN_SENT 消失且从未到达 ESTABLISHED）
        for ev in &out.lifecycle {
            use crate::models::connection::ConnectionState;
            let c = crate::correlator::connection_correlation::event_connection(ev);
            match ev {
                LifecycleEvent::Opened(_) if c.state == ConnectionState::SynSent => {
                    self.syn_watch.insert(c.id.clone(), now);
                }
                LifecycleEvent::Updated(_)
                    if c.state == ConnectionState::Established
                        || c.state == ConnectionState::CloseWait =>
                {
                    self.syn_watch.remove(&c.id);
                }
                LifecycleEvent::Closed(_) => {
                    if self.syn_watch.remove(&c.id).is_some() {
                        self.syn_fail_recent += 1;
                    }
                }
                _ => {}
            }
        }

        // ---- 4. 代理状态机 ----
        let (servers, proxy_events) = self.refresh_proxy_state(&all_connections, now);
        out.proxy_servers = servers.clone();
        out.proxy_events = proxy_events;
        for pe in &out.proxy_events {
            out.events.push(PersistedEvent {
                timestamp: pe.timestamp.to_rfc3339(),
                source: "proxy".into(),
                kind: format!("proxy_{}", serde_json::to_string(&pe.kind).unwrap_or_default().trim_matches('"')),
                payload: serde_json::to_string(pe).unwrap_or_default(),
            });
        }
        let links = proxy::detect_local_proxies(&all_connections).1;
        self.last_proxy_servers = servers.clone();
        self.last_proxy_links = links.clone();
        out.proxy_links = links.clone();

        // ---- 5. VPN 分类 ----
        let default_routes = routes::default_routes().unwrap_or_default();
        let vpn = proxy::classify_vpn_interfaces(&interfaces, &default_routes);
        out.vpn_interfaces = vpn.clone();
        self.last_vpn = vpn.clone();

        // ---- 6. DNS 域名（每 5 tick ≈ 10s）----
        if self.tick_count % 5 == 0 {
            match dns::read_dns_cache() {
                Ok(entries) => {
                    let new_domains: Vec<String> = entries
                        .iter()
                        .map(|e| e.domain.clone())
                        .filter(|d| !self.dns_domains.contains(d))
                        .collect();
                    if !self.dns_domains.is_empty() {
                        out.dns_new_domains = new_domains;
                    }
                    self.dns_domains = entries.iter().map(|e| e.domain.clone()).collect();
                }
                Err(e) => out.errors.push(format!("dns: {e}")),
            }
        }
        out.dns_domains = self.dns_domains.clone();

        // ---- 7. 拓扑增量 ----
        let mut diff = GraphDiff::default();
        self.builder.apply_interfaces(&mut self.graph, &mut diff, &interfaces, &vpn, now);
        self.builder
            .apply_connection_events(&mut self.graph, &mut diff, &out.lifecycle, now);
        self.builder.apply_dns_domains(&mut self.graph, &mut diff, &self.dns_domains, now);
        self.builder.apply_proxy(&mut self.graph, &mut diff, &servers, &links, now);
        if !diff.is_empty() {
            out.graph_diff = diff;
        }

        // ---- 8. 网络质量采样（每 tick，落库节流在调用方）----
        let tcp_conns = out
            .connections
            .iter()
            .filter(|c| c.protocol == crate::models::connection::Protocol::Tcp)
            .count();
        let established = out
            .connections
            .iter()
            .filter(|c| c.state == crate::models::connection::ConnectionState::Established)
            .count();
        let (rx, tx) = out
            .interface_rates
            .iter()
            .fold((0.0, 0.0), |(a, b), r| (a + r.rx_bps, b + r.tx_bps));
        out.quality = Some(NetworkQualityPoint {
            timestamp: now,
            rx_bps: rx,
            tx_bps: tx,
            tcp_total: tcp_conns as u32,
            tcp_established: established as u32,
            udp_endpoints: (out.connections.len() - tcp_conns) as u32,
            retransmits_recent: 0,
            rst_recent: 0,
            syn_failures_recent: self.syn_fail_recent,
        });
        if self.tick_count % 5 == 0 {
            self.syn_fail_recent = 0;
        }
        self.last_quality = out.quality.clone();

        // ---- 9. 统一时间线 + 会话录制 + 拓扑快照 ----
        let mut tl = Vec::new();
        for ev in &out.lifecycle {
            tl.push(crate::collector::timeline::connection_event(ev, now));
        }
        tl.extend(crate::collector::timeline::dns_events(&out.dns_new_domains, now));
        tl.extend(crate::collector::timeline::proxy_events(&out.proxy_events));
        tl.extend(self.timeline_builder.diff_interfaces(&interfaces, now));
        tl.extend(self.timeline_builder.diff_routes(now));
        if self.tick_count % 5 == 0 {
            if let Ok(current) = crate::collector::processes::snapshot_processes() {
                let diff = crate::collector::processes::diff_processes(&self.last_processes, &current);
                tl.extend(crate::collector::timeline::process_events(&diff, now));
                self.last_processes = current;
            }
        }
        if self.tick_count % 5 == 0 {
            if let Some(q) = &out.quality {
                tl.push(crate::collector::timeline::quality_sample(q));
            }
        }
        out.timeline = tl;
        if let (Some(sid), Some(scope)) = (&self.session_id, self.session_scope.clone()) {
            self.session_event_count += out.timeline.len() as u64;
            out.session_events = out
                .timeline
                .iter()
                // 环境事件（接口/路由/代理/质量）总是收录；连接/DNS 事件按 scope 过滤
                .filter(|e| {
                    crate::collector::timeline::is_environment_event(&e.kind)
                        || matches!(scope, SessionScope::All)
                        || scope.matches(&e.payload)
                })
                .map(|t| SessionEvent {
                    session_id: sid.clone(),
                    timestamp: t.timestamp,
                    source: t.source.clone(),
                    kind: t.kind.clone(),
                    summary: t.summary.clone(),
                    payload: t.payload.clone(),
                })
                .collect();
        }
        if self.tick_count % 15 == 0 {
            let (nodes, edges) = self.graph_snapshot();
            out.topology_snapshot = Some(TopologyHistorySnapshot {
                timestamp: now,
                nodes,
                edges,
            });
        }

        out.tick_count = self.tick_count;

        out
    }

    /// 接口计数器差分 → bytes/s。
    fn compute_interface_rates(&mut self) -> Vec<InterfaceRate> {
        let counters = match proxy::read_interface_counters() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };
        let now_inst = Instant::now();
        let mut rates = Vec::new();

        if let (Some(last), Some(t0)) = (&self.last_counters, self.last_counter_time) {
            let dt = now_inst.duration_since(t0).as_secs_f64();
            if dt > 0.001 {
                // 与网卡快照对齐取名称（延迟到 apply 时填，或此处留索引）
                for (idx, (in_now, out_now, _status)) in &counters.entries {
                    if let Some((in_prev, out_prev)) = last.get(idx) {
                        let rx = in_now.saturating_sub(*in_prev) as f64 / dt;
                        let tx = out_now.saturating_sub(*out_prev) as f64 / dt;
                        rates.push(InterfaceRate {
                            if_index: *idx,
                            friendly_name: format!("接口 {idx}"),
                            rx_bps: rx,
                            tx_bps: tx,
                            rx_total: *in_now,
                            tx_total: *out_now,
                            operational_status: String::new(),
                        });
                    }
                }
            }
        }
        self.last_counters = Some(
            counters
                .entries
                .iter()
                .map(|(k, (i, o, _))| (*k, (*i, *o)))
                .collect(),
        );
        self.last_counter_time = Some(now_inst);
        rates
    }

    /// 代理状态机：检测新增 / 移除 / 变化，生成事件。
    fn refresh_proxy_state(
        &mut self,
        connections: &[Connection],
        now: chrono::DateTime<Utc>,
    ) -> (Vec<ProxyServer>, Vec<ProxyEvent>) {
        let mut events = Vec::new();

        // 系统代理（WinInet）
        let system = match proxy::read_system_proxy() {
            Ok(info) => proxy::system_proxy_servers(&info),
            Err(_) => Vec::new(),
        };
        let system_ids: Vec<String> = system.iter().map(|s| s.id.clone()).collect();

        // WinHTTP
        let winhttp = proxy::read_winhttp_proxy().ok().flatten();
        let winhttp_id = winhttp.as_ref().map(|s| s.id.clone());

        // 本地监听推断
        let (local, _links) = proxy::detect_local_proxies(connections);
        let local_ids: Vec<String> = local.iter().map(|s| s.id.clone()).collect();

        // WinInet 变化检测
        if system_ids != self.last_system_servers && !self.last_system_servers.is_empty() {
            for gone in self.last_system_servers.iter().filter(|id| !system_ids.contains(id)) {
                events.push(ProxyEvent {
                    timestamp: now,
                    kind: ProxyEventKind::Removed,
                    mechanism: ProxyMechanism::WinInet,
                    summary: format!("系统代理移除: {gone}"),
                    detail: serde_json::json!({ "id": gone }),
                });
            }
            for new in system_ids.iter().filter(|id| !self.last_system_servers.contains(id)) {
                events.push(ProxyEvent {
                    timestamp: now,
                    kind: ProxyEventKind::Detected,
                    mechanism: ProxyMechanism::WinInet,
                    summary: format!("系统代理出现: {new}"),
                    detail: serde_json::json!({ "id": new }),
                });
            }
        } else if !system_ids.is_empty() && self.last_system_servers.is_empty() {
            events.push(ProxyEvent {
                timestamp: now,
                kind: ProxyEventKind::Detected,
                mechanism: ProxyMechanism::WinInet,
                summary: format!("检测到系统代理: {}", system_ids.join(", ")),
                detail: serde_json::json!({ "ids": system_ids }),
            });
        }

        // WinHTTP 变化
        if winhttp_id != self.last_winhttp_id && self.last_winhttp_id.is_some() {
            events.push(ProxyEvent {
                timestamp: now,
                kind: if winhttp_id.is_some() { ProxyEventKind::Changed } else { ProxyEventKind::Removed },
                mechanism: ProxyMechanism::WinHttp,
                summary: format!(
                    "WinHTTP 代理: {} → {}",
                    self.last_winhttp_id.clone().unwrap_or_else(|| "无".into()),
                    winhttp_id.clone().unwrap_or_else(|| "无".into())
                ),
                detail: serde_json::json!({ "id": winhttp_id }),
            });
        }

        // 本地代理变化
        for gone in self.last_local_ids.iter().filter(|id| !local_ids.contains(id)) {
            events.push(ProxyEvent {
                timestamp: now,
                kind: ProxyEventKind::Removed,
                mechanism: ProxyMechanism::LocalListener,
                summary: format!("本地代理服务消失: {gone}"),
                detail: serde_json::json!({ "id": gone }),
            });
        }
        for new in local_ids.iter().filter(|id| !self.last_local_ids.contains(id)) {
            events.push(ProxyEvent {
                timestamp: now,
                kind: ProxyEventKind::Detected,
                mechanism: ProxyMechanism::LocalListener,
                summary: format!("发现本地代理服务: {new}"),
                detail: serde_json::json!({ "id": new }),
            });
        }

        self.last_system_servers = system_ids;
        self.last_winhttp_id = winhttp_id;
        self.last_local_ids = local_ids;

        let mut all = system;
        if let Some(w) = winhttp {
            all.push(w);
        }
        all.extend(local);
        (all, events)
    }

    /// 更新接口速率的显示名称（由调用方在拿到网卡快照后调用）。
    pub fn attach_interface_names(&self, rates: &mut [InterfaceRate], interfaces: &[crate::models::interface::NetworkInterface]) {
        for r in rates {
            if let Some(i) = interfaces.iter().find(|i| i.index == r.if_index) {
                r.friendly_name = i.friendly_name.clone();
                r.operational_status = format!("{:?}", i.operational_status).to_lowercase();
            }
        }
    }
}

fn ev_connection(ev: &LifecycleEvent) -> &Connection {
    match ev {
        LifecycleEvent::Opened(c) | LifecycleEvent::Updated(c) | LifecycleEvent::Closed(c) => c,
    }
}

/// 生命周期事件 → 持久化事件行。
fn persist_lifecycle(ev: &LifecycleEvent) -> PersistedEvent {
    let c = ev_connection(ev);
    let kind = match ev {
        LifecycleEvent::Opened(_) => "conn_opened",
        LifecycleEvent::Updated(_) => "conn_updated",
        LifecycleEvent::Closed(_) => "conn_closed",
    };
    PersistedEvent {
        timestamp: c.last_seen.to_rfc3339(),
        source: "connection_table".into(),
        kind: kind.into(),
        payload: serde_json::to_string(c).unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_runs_on_real_system() {
        let mut rt = CollectorRuntime::new();
        let out = rt.tick();
        // 真实系统上不应有错误（允许空连接但 API 必须成功）
        assert!(out.errors.is_empty(), "tick 错误: {:?}", out.errors);
        // 本机必然有网卡 → 拓扑应含 host 节点
        let (nodes, _) = rt.graph_snapshot();
        assert!(nodes.iter().any(|n| n.id == "host:local"));
    }

    #[test]
    fn second_tick_is_stable() {
        let mut rt = CollectorRuntime::new();
        let _ = rt.tick();
        let out2 = rt.tick();
        assert!(out2.errors.is_empty(), "第二次 tick 错误: {:?}", out2.errors);
        // 第二次 tick 无生命周期变化时不应崩溃
        let (nodes, edges) = rt.graph_snapshot();
        assert!(!nodes.is_empty());
        let _ = edges.len();
    }
}
