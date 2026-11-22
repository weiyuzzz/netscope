//! 代理与 VPN 数据模型（Proxy Intelligence，二轮新增）。
//!
//! 数据准确性约定：
//! - 系统代理（WinInet）、WinHTTP 代理、本地监听推断、TUN/VPN 是**不同机制**，
//!   严格分字段标注，不混为一谈；
//! - 所有推断关系必须携带 `confidence`；无法确认的链路显示为推断，不伪造关联。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::models::topology::CorrelationEvidence;

/// 代理检测机制（不同机制分别检测，禁止混同）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyMechanism {
    /// WinInet 系统代理（注册表 Internet Settings，影响多数桌面应用）。
    WinInet,
    /// WinHTTP 默认代理（服务与部分系统组件使用）。
    WinHttp,
    /// 环回监听推断的本地代理服务（证据：端口特征 + 被多进程连接）。
    LocalListener,
}

/// 代理协议类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyProtocol {
    Http,
    Https,
    Socks4,
    Socks5,
    /// 端口特征推断但协议未确认。
    Unknown,
}

/// 关联/识别置信度。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    /// 有直接证据（注册表值 / API 返回 / 明文协议特征）。
    Confirmed,
    /// 有间接证据（端口特征 + 多进程连接行为）。
    Inferred,
    /// 弱证据，仅提示可能相关。
    Speculative,
}

/// 一个代理服务（不同机制下各有一条，绝不合并为同一"代理"概念）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyServer {
    /// 稳定 ID：`{mechanism}:{host}:{port}`。
    pub id: String,
    pub mechanism: ProxyMechanism,
    pub protocol: ProxyProtocol,
    pub host: String,
    pub port: u16,
    /// 本地代理服务进程（仅 LocalListener / 本机服务时有）。
    pub process_name: Option<String>,
    pub pid: Option<u32>,
    /// 证据来源描述（注册表键 / API / 监听推断依据）。
    pub source: String,
    pub confidence: Confidence,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub active: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyEventKind {
    Detected,
    Changed,
    Removed,
}

/// 代理配置/服务变化事件。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyEvent {
    pub timestamp: DateTime<Utc>,
    pub kind: ProxyEventKind,
    pub mechanism: ProxyMechanism,
    /// 变化摘要（如 "proxy 127.0.0.1:7890 enabled" / "disabled"）。
    pub summary: String,
    pub detail: serde_json::Value,
}

/// 虚拟/VPN 网卡类别（按 description / friendly name 证据分类）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VirtualAdapterKind {
    /// 非虚拟物理网卡。
    Physical,
    /// 通用 TUN/TAP 隧道接口（如 WireGuard、OpenVPN TUN 模式）。
    Tun,
    /// Tailscale 虚拟组网。
    Tailscale,
    /// WireGuard。
    WireGuard,
    /// OpenVPN TAP 适配器。
    OpenVpnTap,
    /// Hyper-V / WSL / 容器虚拟交换机。
    HyperVSwitch,
    /// Windows 内置回环。
    Loopback,
    /// 其他虚拟适配器（提供描述，由 UI 展示证据）。
    OtherVirtual,
}

/// VPN / 虚拟网卡接口信息快照。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnInterface {
    pub if_index: u32,
    pub kind: VirtualAdapterKind,
    pub friendly_name: String,
    pub description: String,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    /// 系统默认路由当前是否经由该接口（真实路由表判定）。
    pub is_default_route_owner: bool,
    /// 若为默认路由出口，其网关地址。
    pub gateway_of_default: Option<String>,
    /// 协商速率（虚拟网卡常为 0 或 10Gbps 合成值，如实记录）。
    pub speed_bps: u64,
    pub operational_status: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub active: bool,
}

/// 用户主动触发的公网出口探测结果。
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EgressInfo {
    pub timestamp: Option<DateTime<Utc>>,
    /// 公网出口 IP。
    pub ip: Option<String>,
    /// ASN（如 "AS4134"）。
    pub asn: Option<String>,
    /// ASN 组织名。
    pub org: Option<String>,
    pub country: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    /// 结果来源服务（如 "ipify" / "ipinfo"）。
    pub source: Option<String>,
    /// 探测失败的原始错误（如实展示，不静默）。
    pub error: Option<String>,
    /// 本次探测所经过的代理机制提示（可观察时）。
    pub via_proxy: Option<String>,
}

/// 代理链路推断（拓扑中 Process → Proxy 边的依据）。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProxyLink {
    /// 发起连接的进程 PID。
    pub pid: u32,
    pub process_name: Option<String>,
    /// 目标代理服务 ID（ProxyServer.id）。
    pub proxy_id: String,
    pub evidence: CorrelationEvidence,
    pub confidence: Confidence,
    /// 观测到的连接次数（时间窗内）。
    pub observed_connections: u32,
    pub last_seen: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_mechanisms_are_distinct() {
        // 三种机制序列化名互不相同，UI/存储严格区分
        let a = serde_json::to_string(&ProxyMechanism::WinInet).unwrap();
        let b = serde_json::to_string(&ProxyMechanism::WinHttp).unwrap();
        let c = serde_json::to_string(&ProxyMechanism::LocalListener).unwrap();
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_eq!(a, "\"win_inet\"");
        assert_eq!(b, "\"win_http\"");
    }

    #[test]
    fn proxy_server_roundtrip() {
        let now = Utc::now();
        let server = ProxyServer {
            id: "local_listener:127.0.0.1:7890".into(),
            mechanism: ProxyMechanism::LocalListener,
            protocol: ProxyProtocol::Unknown,
            host: "127.0.0.1".into(),
            port: 7890,
            process_name: Some("clash.exe".into()),
            pid: Some(1234),
            source: "loopback listener, contacted by 3 processes".into(),
            confidence: Confidence::Inferred,
            first_seen: now,
            last_seen: now,
            active: true,
        };
        let json = serde_json::to_string(&server).unwrap();
        assert!(json.contains("\"mechanism\":\"local_listener\""));
        assert!(json.contains("\"confidence\":\"inferred\""));
        let back: ProxyServer = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, server.id);
    }

    #[test]
    fn virtual_adapter_kind_roundtrip() {
        assert_eq!(
            serde_json::to_string(&VirtualAdapterKind::Tailscale).unwrap(),
            "\"tailscale\""
        );
        assert_eq!(
            serde_json::to_string(&VirtualAdapterKind::HyperVSwitch).unwrap(),
            "\"hyper_v_switch\""
        );
    }
}
