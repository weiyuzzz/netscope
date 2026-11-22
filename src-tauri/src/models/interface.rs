//! 网络接口（网卡）模型，对应 GetAdaptersAddresses 输出。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 接口运行状态（`IfOperStatusOperational` 映射）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalStatus {
    Up,
    Down,
    Testing,
    Unknown,
    Dormant,
    NotPresent,
    LowerLayerDown,
}

/// 接口类型（MIB IfType 子集，按产品需求保留常用项）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceType {
    Ethernet,
    Wifi,
    Loopback,
    Tunnel,
    Ppp,
    Other,
}

/// 一块网卡的完整信息快照。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkInterface {
    /// 接口索引（IfIndex）。
    pub index: u32,
    /// 适配器名称（如 GUID 形式）。
    pub name: String,
    /// 用户友好名称（如 "以太网"、"WLAN"）。
    pub friendly_name: String,
    pub description: String,
    pub if_type: InterfaceType,
    pub operational_status: OperationalStatus,
    /// 协商速率 bps（0 表示不可用）。
    pub speed_bps: u64,
    pub mtu: u32,
    pub mac_address: Option<String>,
    pub ipv4_addresses: Vec<String>,
    pub ipv6_addresses: Vec<String>,
    /// 该接口配置的 DNS 服务器。
    pub dns_servers: Vec<String>,
    /// 接口网关（可能多个，IPv4/IPv6 混合）。
    pub gateways: Vec<String>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_roundtrip() {
        let now = Utc::now();
        let iface = NetworkInterface {
            index: 12,
            name: "{A1B2C3D4-0000-0000-0000-000000000000}".into(),
            friendly_name: "以太网".into(),
            description: "Realtek PCIe GbE Family Controller".into(),
            if_type: InterfaceType::Ethernet,
            operational_status: OperationalStatus::Up,
            speed_bps: 1_000_000_000,
            mtu: 1500,
            mac_address: Some("AA:BB:CC:DD:EE:FF".into()),
            ipv4_addresses: vec!["192.168.1.10".into()],
            ipv6_addresses: vec!["fe80::1".into()],
            dns_servers: vec!["192.168.1.1".into()],
            gateways: vec!["192.168.1.1".into()],
            first_seen: now,
            last_seen: now,
        };
        let json = serde_json::to_string(&iface).unwrap();
        assert!(json.contains("\"friendlyName\""));
        assert!(json.contains("\"operationalStatus\":\"up\""));
        assert!(json.contains("\"ifType\":\"ethernet\""));
        let back: NetworkInterface = serde_json::from_str(&json).unwrap();
        assert_eq!(back.index, 12);
        assert_eq!(back.ipv4_addresses.len(), 1);
    }
}
