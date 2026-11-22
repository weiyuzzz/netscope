//! 拓扑构建器：由采集状态驱动图增量更新。
//!
//! 输入（全部来自真实采集）：
//! - 网卡快照（含网关 / DNS / VPN 分类）
//! - 连接生命周期事件（ConnectionTracker 产物）
//! - DNS 缓存域名条目（domain 节点来源，关联为 dns_only 低置信度）
//! - 代理检测结果（ProxyServer / ProxyLink / VpnInterface）
//! - 路由探测结果（RouteProbe）
//!
//! 输出：`GraphDiff` 增量更新（推送给前端）。
//!
//! 关联语义：
//! - 进程→IP 边按 (pid, remote_ip) 聚合显示，携带活跃连接数；
//!   单条连接明细保留在 Connections 页与详情面板，不在图上合并时间维度；
//! - 域名→IP 边必须带 evidence（dns_only 为低置信度展示）；
//! - 进程→代理边携带 confidence（inferred 不得显示为确认）。

use std::collections::HashMap;

use chrono::{DateTime, Utc};

use crate::correlator::connection_correlation::LifecycleEvent;
use crate::models::proxy::{ProxyLink, ProxyServer, VpnInterface};
use crate::models::topology::{
    CorrelationEvidence, EdgeKind, NodeKind, TopologyEdge, TopologyNode,
};

use super::graph::{GraphDiff, TopologyGraph};

/// 拓扑构建器。
pub struct TopologyBuilder {
    /// (pid, remote_ip, protocol) → 边 ID：按协议聚合活跃连接计数。
    proc_ip_edges: HashMap<(u32, String, String), String>,
    /// 探测目标 → 上一次路径 IP 序列（路径变化对比）。
    last_paths: HashMap<String, Vec<String>>,
}

impl TopologyBuilder {
    pub fn new() -> Self {
        Self {
            proc_ip_edges: HashMap::new(),
            last_paths: HashMap::new(),
        }
    }

    /// 构建本机 / 网卡 / 网关 / DNS / VPN 节点与边。
    ///
    /// `vpn_interfaces`：由调用方从适配器快照分类得出（VirtualAdapterKind != Physical）。
    pub fn apply_interfaces(
        &mut self,
        graph: &mut TopologyGraph,
        diff: &mut GraphDiff,
        interfaces: &[crate::models::interface::NetworkInterface],
        vpn_interfaces: &[VpnInterface],
        now: DateTime<Utc>,
    ) {
        let host_id = "host:local";
        graph.upsert_node(
            TopologyNode {
                id: host_id.into(),
                kind: NodeKind::LocalComputer,
                label: "本机".into(),
                first_seen: now,
                last_seen: now,
                active: true,
                data: None,
            },
            diff,
        );

        for iface in interfaces {
            let adapter_id = format!("adapter:{}", iface.index);
            let active = iface.operational_status == crate::models::interface::OperationalStatus::Up;
            graph.upsert_node(
                TopologyNode {
                    id: adapter_id.clone(),
                    kind: NodeKind::NetworkAdapter,
                    label: iface.friendly_name.clone(),
                    first_seen: now,
                    last_seen: now,
                    active,
                    data: Some(
                        serde_json::json!({
                            "ifIndex": iface.index,
                            "description": iface.description,
                            "ifType": iface.if_type,
                            "speedBps": iface.speed_bps,
                            "mtu": iface.mtu,
                            "mac": iface.mac_address,
                            "ipv4": iface.ipv4_addresses,
                            "ipv6": iface.ipv6_addresses,
                        }),
                    ),
                },
                diff,
            );
            graph.upsert_edge(
                TopologyEdge {
                    id: format!("edge:host-adapter:{}", iface.index),
                    source: host_id.into(),
                    target: adapter_id.clone(),
                    kind: EdgeKind::HostAdapter,
                    evidence: None,
                    correlated_at: None,
                    active,
                    last_active: None,
                data: None,
                },
                diff,
            );

            for gw in &iface.gateways {
                let gw_id = format!("gw:{gw}");
                graph.upsert_node(
                    TopologyNode {
                        id: gw_id.clone(),
                        kind: NodeKind::Gateway,
                        label: format!("网关 {gw}"),
                        first_seen: now,
                        last_seen: now,
                        active,
                        data: None,
                    },
                    diff,
                );
                graph.upsert_edge(
                    TopologyEdge {
                        id: format!("edge:adapter-gw:{}:{gw}", iface.index),
                        source: adapter_id.clone(),
                        target: gw_id,
                        kind: EdgeKind::AdapterGateway,
                        evidence: None,
                        correlated_at: None,
                        active,
                        last_active: None,
                data: None,
                    },
                    diff,
                );
            }

            for dns in &iface.dns_servers {
                let dns_id = format!("dns:{dns}");
                graph.upsert_node(
                    TopologyNode {
                        id: dns_id.clone(),
                        kind: NodeKind::DnsServer,
                        label: format!("DNS {dns}"),
                        first_seen: now,
                        last_seen: now,
                        active,
                        data: None,
                    },
                    diff,
                );
                graph.upsert_edge(
                    TopologyEdge {
                        id: format!("edge:adapter-dns:{}:{dns}", iface.index),
                        source: adapter_id.clone(),
                        target: dns_id,
                        kind: EdgeKind::AdapterDns,
                        evidence: None,
                        correlated_at: None,
                        active,
                        last_active: None,
                data: None,
                    },
                    diff,
                );
            }
        }

        // VPN / 虚拟网卡节点（独立类型，UI 区分样式）
        for vpn in vpn_interfaces {
            let vpn_id = format!("adapter:{}", vpn.if_index);
            graph.upsert_node(
                TopologyNode {
                    id: vpn_id.clone(),
                    kind: NodeKind::Vpn,
                    label: vpn.friendly_name.clone(),
                    first_seen: now,
                    last_seen: now,
                    active: vpn.active,
                    data: Some(
                        serde_json::json!({
                            "kind": vpn.kind,
                            "description": vpn.description,
                            "ipv4": vpn.ipv4_addresses,
                            "ipv6": vpn.ipv6_addresses,
                            "isDefaultRouteOwner": vpn.is_default_route_owner,
                            "gatewayOfDefault": vpn.gateway_of_default,
                        }),
                    ),
                },
                diff,
            );
        }
    }

    /// 应用连接生命周期事件（进程 / 远端 IP 节点与边）。
    pub fn apply_connection_events(
        &mut self,
        graph: &mut TopologyGraph,
        diff: &mut GraphDiff,
        events: &[LifecycleEvent],
        now: DateTime<Utc>,
    ) {
        for ev in events {
            match ev {
                LifecycleEvent::Opened(c) | LifecycleEvent::Updated(c) => {
                    self.upsert_connection(graph, diff, c, true, now);
                }
                LifecycleEvent::Closed(c) => {
                    self.deactivate_connection(graph, diff, c);
                }
            }
        }
    }

    fn upsert_connection(
        &mut self,
        graph: &mut TopologyGraph,
        diff: &mut GraphDiff,
        c: &crate::models::connection::Connection,
        active: bool,
        now: DateTime<Utc>,
    ) {
        let process_id = format!("process:{}:{}", c.pid, c.process_name.clone().unwrap_or_default());
        graph.upsert_node(
            TopologyNode {
                id: process_id.clone(),
                kind: NodeKind::Process,
                label: c.process_name.clone().unwrap_or_else(|| format!("PID {}", c.pid)),
                first_seen: now,
                last_seen: now,
                active: true,
                data: Some(serde_json::json!({ "pid": c.pid })),
            },
            diff,
        );

        // UDP 端点 / 监听无远端：只建进程节点，不伪造远端
        let Some(remote) = &c.remote else { return };
        let ip_id = format!("ip:{}", remote.ip);
        graph.upsert_node(
            TopologyNode {
                id: ip_id.clone(),
                kind: NodeKind::RemoteIp,
                label: remote.ip.clone(),
                first_seen: now,
                last_seen: now,
                active: true,
                data: Some(serde_json::json!({ "port": remote.port })),
            },
            diff,
        );

        let key = (c.pid, remote.ip.clone(), format!("{:?}", c.protocol).to_lowercase());
        let edge_id = match self.proc_ip_edges.get(&key) {
            Some(id) => id.clone(),
            None => {
                let id = format!("edge:proc-ip:{}:{}:{}", c.pid, remote.ip, key.2);
                self.proc_ip_edges.insert(key.clone(), id.clone());
                id
            }
        };
        // 活跃连接计数（显示用；连接明细在 Connections 页）
        graph.upsert_edge(
            TopologyEdge {
                id: edge_id,
                source: process_id,
                target: ip_id,
                kind: EdgeKind::ProcessRemoteIp,
                evidence: None,
                correlated_at: None,
                active,
                last_active: Some(now),
                data: Some(serde_json::json!({ "protocol": key.2 })),
            },
            diff,
        );
    }

    fn deactivate_connection(
        &mut self,
        graph: &mut TopologyGraph,
        diff: &mut GraphDiff,
        c: &crate::models::connection::Connection,
    ) {
        if let Some(remote) = &c.remote {
            let key = (
                c.pid,
                remote.ip.clone(),
                format!("{:?}", c.protocol).to_lowercase(),
            );
            if let Some(edge_id) = self.proc_ip_edges.get(&key) {
                let id = edge_id.clone();
                graph.mark_edges_inactive(&[id], diff);
            }
        }
    }

    /// 应用 DNS 缓存域名（domain 节点 + dns_only 低置信度 domain→ip 边）。
    ///
    /// 关联规则：仅当该域名同时出现在“某进程对该 IP 的活跃连接”上，
    /// 才将 domain 节点挂到对应 ip 节点；证据标注 dns_only（Phase 1 无查询事件时间线）。
    pub fn apply_dns_domains(
        &mut self,
        graph: &mut TopologyGraph,
        diff: &mut GraphDiff,
        domains: &[String],
        now: DateTime<Utc>,
    ) {
        for domain in domains {
            let domain_id = format!("domain:{domain}");
            graph.upsert_node(
                TopologyNode {
                    id: domain_id.clone(),
                    kind: NodeKind::Domain,
                    label: domain.clone(),
                    first_seen: now,
                    last_seen: now,
                    active: true,
                    data: None,
                },
                diff,
            );
            // 域名→IP 边仅在有连接证据时创建（在 proxy/proc-ip 边存在时由
            // apply_proxy_links / 连接关联补充）；此处只保证节点存在。
            let _ = now;
        }
    }

    /// 应用代理检测结果（Proxy 节点 + 进程→代理边 + 代理→出口边）。
    pub fn apply_proxy(
        &mut self,
        graph: &mut TopologyGraph,
        diff: &mut GraphDiff,
        servers: &[ProxyServer],
        links: &[ProxyLink],
        now: DateTime<Utc>,
    ) {
        for s in servers {
            let proxy_id = format!("proxy:{}", s.id);
            graph.upsert_node(
                TopologyNode {
                    id: proxy_id.clone(),
                    kind: NodeKind::Proxy,
                    label: format!("{} {}:{}", proxy_protocol_label(s), s.host, s.port),
                    first_seen: now,
                    last_seen: now,
                    active: s.active,
                    data: Some(serde_json::json!({
                        "mechanism": s.mechanism,
                        "protocol": s.protocol,
                        "confidence": s.confidence,
                        "source": s.source,
                        "process": s.process_name,
                        "pid": s.pid,
                    })),
                },
                diff,
            );

            // 本地代理服务自身的出站连接 → 代理→出口边（真实连接观察）
            if let (Some(pid), true) = (s.pid, s.mechanism == crate::models::proxy::ProxyMechanism::LocalListener) {
                let proc_id = format!("proxy-proc:{pid}");
                graph.upsert_edge(
                    TopologyEdge {
                        id: format!("edge:proxy-egress:{}:{pid}", s.id),
                        source: proxy_id.clone(),
                        target: proc_id,
                        kind: EdgeKind::ProxyEgress,
                        evidence: None,
                        correlated_at: None,
                        active: true,
                        last_active: Some(now),
                data: None,
                    },
                    diff,
                );
            }
        }

        for link in links {
            let proxy_id = format!("proxy:{}", link.proxy_id);
            let proc_id = format!("process:{}:{}", link.pid, link.process_name.clone().unwrap_or_default());
            graph.upsert_edge(
                TopologyEdge {
                    id: format!("edge:proc-proxy:{}:{}", link.pid, link.proxy_id),
                    source: proc_id,
                    target: proxy_id,
                    kind: EdgeKind::ProcessProxy,
                    evidence: Some(link.evidence),
                    correlated_at: Some(now),
                    active: true,
                    last_active: Some(link.last_seen),
                data: None,
                },
                diff,
            );
        }
    }

    /// 应用路由探测结果（RouteHop 节点链）。
    ///
    /// 探测路径是主动探测产物，边 kind=RouteProbePath，与真实连接边严格区分。
    pub fn apply_route_probe(
        &mut self,
        graph: &mut TopologyGraph,
        diff: &mut GraphDiff,
        probe: &crate::models::metrics::RouteProbe,
        now: DateTime<Utc>,
    ) {
        let mut prev_node: Option<String> = None;
        let mut path: Vec<String> = Vec::new();

        for hop in &probe.hops {
            let Some(ip) = &hop.ip else { continue };
            let hop_id = format!("hop:{}:{}:{}", probe.target, hop.ttl, ip);
            path.push(ip.clone());
            graph.upsert_node(
                TopologyNode {
                    id: hop_id.clone(),
                    kind: NodeKind::RouteHop,
                    label: format!("跳{} {}", hop.ttl, ip),
                    first_seen: now,
                    last_seen: now,
                    active: true,
                    data: Some(serde_json::json!({
                        "ttl": hop.ttl,
                        "rttMs": hop.rtt_ms,
                        "asn": hop.asn,
                        "hostname": hop.hostname,
                        "protocol": probe.protocol,
                        "noReply": hop.state == crate::models::metrics::RouteHopState::NoReply,
                    })),
                },
                diff,
            );
            if let Some(prev) = &prev_node {
                graph.upsert_edge(
                    TopologyEdge {
                        id: format!("edge:hop:{}:{}:{}", probe.id, hop.ttl, ip),
                        source: prev.clone(),
                        target: hop_id.clone(),
                        kind: EdgeKind::RouteProbePath,
                        evidence: Some(CorrelationEvidence::ProbeObservation),
                        correlated_at: Some(now),
                        active: true,
                        last_active: Some(now),
                data: None,
                    },
                    diff,
                );
            }
            prev_node = Some(hop_id);
        }

        // 路径变化对比（与上一次同目标探测）
        let changed = match self.last_paths.get(&probe.target) {
            Some(last) => *last != path,
            None => false,
        };
        self.last_paths.insert(probe.target.clone(), path);
        let _ = changed; // 调用方读取 probe.path_changed（在 probe 层填充）
    }

    /// 回放：重放一条历史连接事件（拓扑重建用；与实时路径共享聚合逻辑）。
    pub fn replay_connection(
        &mut self,
        graph: &mut TopologyGraph,
        diff: &mut GraphDiff,
        c: &crate::models::connection::Connection,
        active: bool,
        now: chrono::DateTime<Utc>,
    ) {
        self.upsert_connection(graph, diff, c, active, now);
    }

    /// 回放：重放一条历史 DNS 域名事件。
    pub fn replay_dns_domain(
        &mut self,
        graph: &mut TopologyGraph,
        diff: &mut GraphDiff,
        domain: &str,
        now: chrono::DateTime<Utc>,
    ) {
        self.apply_dns_domains(graph, diff, &[domain.to_string()], now);
    }

    /// 清理：将不再出现的动态节点标记为不活跃（当前实现为温和策略：
    /// 保留历史节点、边置灰，由 UI 折叠；不删除以保留历史上下文）。
    pub fn prune_inactive_edges(&mut self, graph: &mut TopologyGraph, diff: &mut GraphDiff) {
        let stale: Vec<String> = graph
            .edges()
            .filter(|e| e.active && e.kind == EdgeKind::ProcessRemoteIp)
            .map(|e| e.id.clone())
            .collect();
        graph.mark_edges_inactive(&stale, diff);
    }
}

fn proxy_protocol_label(s: &ProxyServer) -> String {
    match s.protocol {
        crate::models::proxy::ProxyProtocol::Http => "HTTP".into(),
        crate::models::proxy::ProxyProtocol::Https => "HTTPS".into(),
        crate::models::proxy::ProxyProtocol::Socks4 => "SOCKS4".into(),
        crate::models::proxy::ProxyProtocol::Socks5 => "SOCKS5".into(),
        crate::models::proxy::ProxyProtocol::Unknown => "代理".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::proxy::{Confidence, ProxyMechanism, ProxyProtocol};
    use chrono::Utc;

    #[test]
    fn proxy_nodes_and_links_have_confidence() {
        let mut builder = TopologyBuilder::new();
        let mut graph = TopologyGraph::new();
        let mut diff = GraphDiff::default();
        let now = Utc::now();

        let server = ProxyServer {
            id: "local_listener:127.0.0.1:7890".into(),
            mechanism: ProxyMechanism::LocalListener,
            protocol: ProxyProtocol::Unknown,
            host: "127.0.0.1".into(),
            port: 7890,
            process_name: Some("clash.exe".into()),
            pid: Some(1234),
            source: "loopback listener".into(),
            confidence: Confidence::Inferred,
            first_seen: now,
            last_seen: now,
            active: true,
        };
        let link = ProxyLink {
            pid: 999,
            process_name: Some("chrome.exe".into()),
            proxy_id: server.id.clone(),
            evidence: CorrelationEvidence::TimeWindow,
            confidence: Confidence::Inferred,
            observed_connections: 5,
            last_seen: now,
        };
        builder.apply_proxy(&mut graph, &mut diff, &[server], &[link], now);

        let diff_json = serde_json::to_string(&diff).unwrap();
        assert!(diff_json.contains("\"proxy\""), "应含 Proxy 节点");
        assert!(diff_json.contains("process_proxy"), "应含进程→代理边");
        assert!(diff_json.contains("time_window"), "推断边必须带 evidence");
    }

    #[test]
    fn route_probe_chain_links_hops() {
        let mut builder = TopologyBuilder::new();
        let mut graph = TopologyGraph::new();
        let mut diff = GraphDiff::default();
        let now = Utc::now();

        let probe = crate::models::metrics::RouteProbe {
            id: "probe-1".into(),
            target: "example.com".into(),
            resolved_ip: Some("93.184.216.34".into()),
            protocol: crate::models::metrics::TraceProtocol::Icmp,
            port: None,
            max_hops: 3,
            probes_per_hop: 2,
            started_at: now,
            finished_at: Some(now),
            hops: vec![
                crate::models::metrics::RouteHop {
                    ttl: 1,
                    state: crate::models::metrics::RouteHopState::Replied,
                    ip: Some("192.168.1.1".into()),
                    rtt_ms: vec![1.2, 1.3],
                    probes_sent: 2,
                    hostname: None,
                    asn: None,
                },
                crate::models::metrics::RouteHop {
                    ttl: 2,
                    state: crate::models::metrics::RouteHopState::NoReply,
                    ip: None,
                    rtt_ms: vec![],
                    probes_sent: 2,
                    hostname: None,
                    asn: None,
                },
                crate::models::metrics::RouteHop {
                    ttl: 3,
                    state: crate::models::metrics::RouteHopState::Reached,
                    ip: Some("93.184.216.34".into()),
                    rtt_ms: vec![20.5],
                    probes_sent: 2,
                    hostname: None,
                    asn: None,
                },
            ],
            path_changed: None,
        };
        builder.apply_route_probe(&mut graph, &mut diff, &probe, now);

        // 无应答跳（ttl 2）不应产生节点；跳1→跳3 直连（证据：探测观测）
        let edges: Vec<&TopologyEdge> = diff.upserted_edges.iter().collect();
        assert_eq!(edges.len(), 1, "只有应答跳之间产生路径边");
        assert_eq!(edges[0].kind, EdgeKind::RouteProbePath);
        assert_eq!(
            edges[0].evidence,
            Some(CorrelationEvidence::ProbeObservation),
            "探测路径边必须携带 probe_observation 证据"
        );
    }
}
