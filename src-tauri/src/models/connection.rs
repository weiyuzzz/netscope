//! 网络连接模型（TCP 连接与 UDP 端点统一表示）。
//!
//! 注意：UDP 是无连接协议，UDP 记录仅代表系统登记的端点（`state = Endpoint`），
//! 不得与 TCP 的 `Established` 混淆。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 连接唯一标识：由协议、四元组与 PID 派生的稳定字符串 ID。
pub type ConnectionId = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// TCP 连接状态（与 Windows TCP_TABLE 状态对应）；UDP 仅使用 `Endpoint`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    DeleteTcb,
    /// UDP 端点（非连接状态）。
    Endpoint,
}

/// 通信端点（IP + 端口）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    pub ip: String,
    pub port: u16,
}

/// 一次采样的连接记录。同一连接在多次采样间通过 `id` 保持身份一致，
/// `first_seen` / `last_seen` 由关联层负责维护（Phase 2）。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Connection {
    pub id: ConnectionId,
    pub pid: u32,
    /// 进程名（可能因权限不足无法获取）。
    pub process_name: Option<String>,
    pub protocol: Protocol,
    pub local: Endpoint,
    /// UDP 端点可能没有明确远端。
    pub remote: Option<Endpoint>,
    pub state: ConnectionState,
    /// 所属网卡接口索引（经 GetBestInterface 关联，可为空）。
    pub interface_index: Option<u32>,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

/// 由连接五元组派生稳定 ID：同一条连接在多次采样间保持一致，
/// 不同时间 / 不同端点的连接不会合并。
pub fn derive_connection_id(
    protocol: Protocol,
    pid: u32,
    local: &Endpoint,
    remote: Option<&Endpoint>,
) -> ConnectionId {
    let proto = match protocol {
        Protocol::Tcp => "tcp",
        Protocol::Udp => "udp",
    };
    match remote {
        Some(r) => format!(
            "{proto}:{}:{}:{}:{}:{}",
            local.ip, local.port, r.ip, r.port, pid
        ),
        None => format!("{proto}:{}:{}:-:-:{}", local.ip, local.port, pid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ep(ip: &str, port: u16) -> Endpoint {
        Endpoint {
            ip: ip.to_string(),
            port,
        }
    }

    #[test]
    fn connection_id_is_stable_and_distinct() {
        let local = ep("192.168.1.10", 52341);
        let remote_a = ep("142.250.66.238", 443);
        let remote_b = ep("142.250.66.239", 443);

        let id1 = derive_connection_id(Protocol::Tcp, 4242, &local, Some(&remote_a));
        let id2 = derive_connection_id(Protocol::Tcp, 4242, &local, Some(&remote_a));
        let id3 = derive_connection_id(Protocol::Tcp, 4242, &local, Some(&remote_b));
        let id4 = derive_connection_id(Protocol::Tcp, 500, &local, Some(&remote_a));

        assert_eq!(id1, id2, "同一条连接的 ID 必须稳定");
        assert_ne!(id1, id3, "不同远端不得合并");
        assert_ne!(id1, id4, "不同 PID 不得合并");

        let udp = derive_connection_id(Protocol::Udp, 4242, &local, None);
        assert!(udp.contains("udp:192.168.1.10:52341:-:-:4242"));
    }

    #[test]
    fn connection_serializes_camel_case() {
        let now = Utc::now();
        let conn = Connection {
            id: derive_connection_id(Protocol::Tcp, 1, &ep("127.0.0.1", 1000), Some(&ep("127.0.0.1", 80))),
            pid: 1,
            process_name: Some("test.exe".into()),
            protocol: Protocol::Tcp,
            local: ep("127.0.0.1", 1000),
            remote: Some(ep("127.0.0.1", 80)),
            state: ConnectionState::Established,
            interface_index: Some(12),
            first_seen: now,
            last_seen: now,
            bytes_sent: 1024,
            bytes_received: 2048,
        };
        let json = serde_json::to_string(&conn).unwrap();
        assert!(json.contains("\"processName\""));
        assert!(json.contains("\"interfaceIndex\""));
        assert!(json.contains("\"bytesSent\""));
        let back: Connection = serde_json::from_str(&json).unwrap();
        assert_eq!(back.state, ConnectionState::Established);
        assert_eq!(back.protocol, Protocol::Tcp);
    }

    #[test]
    fn udp_state_serializes_as_endpoint() {
        let json = serde_json::to_string(&ConnectionState::Endpoint).unwrap();
        assert_eq!(json, "\"endpoint\"");
    }
}
