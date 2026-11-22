//! 拓扑图数据模型（Rust 侧权威定义，前端 React Flow 直接消费）。
//!
//! 数据准确性约定（产品规范模块 B）：
//! - DNS 解析结果 ≠ 实际建立连接；域名→IP 边必须携带关联依据与时间戳；
//! - 一个 IP 可对应多个域名，一个域名可对应多个 IP，均通过边表达；
//! - 同一进程的多个连接是独立节点/边，不同时间的连接不得合并；
//! - 推断出的路径（低置信度）必须显式标注，不得呈现为真实物理路径。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 节点类型（MVP 7 类 + 二轮新增 4 类）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    LocalComputer,
    NetworkAdapter,
    Gateway,
    DnsServer,
    Process,
    Domain,
    RemoteIp,
    /// 本地代理服务（二轮）。
    Proxy,
    /// VPN / 虚拟网卡接口（二轮）。
    Vpn,
    /// 路由探测跳点（二轮）。
    RouteHop,
}

/// 边类型：不同边类型在 UI 使用不同颜色 / 线型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeKind {
    /// 本机 → 网卡。
    HostAdapter,
    /// 网卡 → 网关。
    AdapterGateway,
    /// 网卡 → DNS 服务器。
    AdapterDns,
    /// 进程 → 域名（该进程发起过对该域名的连接）。
    ProcessDomain,
    /// 进程 → 远端 IP（真实连接）。
    ProcessRemoteIp,
    /// 域名 → IP（DNS 解析结果，须带时间与依据）。
    DomainIp,
    /// 进程 → 本地代理（推断或确认的代理使用，二轮）。
    ProcessProxy,
    /// 本地代理 → 远端代理服务器/出口（代理进程自身的真实连接，二轮）。
    ProxyEgress,
    /// 路由探测路径（跳点 → 跳点，主动探测产物，二轮）。
    RouteProbePath,
}

/// 域名→IP 边的关联依据（置信度标注的核心字段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationEvidence {
    /// DNS 响应与连接建立时间高度吻合（高置信度）。
    DnsThenConnect,
    /// 仅有 DNS 记录，未见对应连接（仅展示，不得视为真实路径）。
    DnsOnly,
    /// 反向解析（PTR）推断（低置信度，须标注）。
    PtrLookup,
    /// 时间窗口推断（低置信度，须标注）。
    TimeWindow,
    /// 主动探测直接观测（traceroute 每跳应答，属于探测事实而非推断）。
    ProbeObservation,
}

/// 拓扑节点。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopologyNode {
    pub id: String,
    pub kind: NodeKind,
    pub label: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    /// 当前是否活跃（非活跃节点显示为历史状态）。
    pub active: bool,
    /// 附加数据（按节点类型的 JSON，UI 渲染详情用；如 VPN 类别、代理机制等）。
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

/// 拓扑边。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopologyEdge {
    pub id: String,
    pub source: String,
    pub target: String,
    pub kind: EdgeKind,
    /// 仅 DomainIp 边使用；其余为 None。
    pub evidence: Option<CorrelationEvidence>,
    /// 关联成立的时间（DomainIp 边）。
    pub correlated_at: Option<DateTime<Utc>>,
    pub active: bool,
    /// 最近一次活跃时间（用于展示历史连接）。
    pub last_active: Option<DateTime<Utc>>,
    /// 附加数据（如协议类型；UI 过滤用）。
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn topology_edge_roundtrip() {
        let now = Utc::now();
        let edge = TopologyEdge {
            id: "domain-ip:example.com:93.184.216.34".into(),
            source: "domain:example.com".into(),
            target: "ip:93.184.216.34".into(),
            kind: EdgeKind::DomainIp,
            evidence: Some(CorrelationEvidence::DnsThenConnect),
            correlated_at: Some(now),
            active: true,
            last_active: Some(now),
            data: None,
        };
        let json = serde_json::to_string(&edge).unwrap();
        assert!(json.contains("\"kind\":\"domain_ip\""));
        assert!(json.contains("\"evidence\":\"dns_then_connect\""));
        let back: TopologyEdge = serde_json::from_str(&json).unwrap();
        assert_eq!(back.evidence, Some(CorrelationEvidence::DnsThenConnect));
    }

    #[test]
    fn node_kinds_serialize_snake_case() {
        assert_eq!(
            serde_json::to_string(&NodeKind::LocalComputer).unwrap(),
            "\"local_computer\""
        );
        assert_eq!(
            serde_json::to_string(&NodeKind::RemoteIp).unwrap(),
            "\"remote_ip\""
        );
    }
}
