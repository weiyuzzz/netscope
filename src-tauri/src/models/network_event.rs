//! 统一网络事件模型。
//!
//! 所有采集器输出统一转换为 `NetworkEvent`，携带统一 UTC 时间戳与来源标注；
//! 来源标注是后续 DNS↔连接关联置信度判断的基础。Phase 2 将 payload 精化为强类型。

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 事件来源（数据可信度标注的基础）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventSource {
    /// IP Helper API 连接表轮询。
    ConnectionTable,
    /// GetAdaptersAddresses。
    Adapters,
    /// ETW 实时事件（可选能力）。
    Etw,
    /// DNS 事件（ETW DNS Client 或主动探测）。
    Dns,
    /// 主动探测（ping / traceroute）。
    Probe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkEventKind {
    ConnectionOpened,
    ConnectionUpdated,
    ConnectionClosed,
    InterfaceChanged,
    DnsQuery,
    DnsResponse,
}

/// 统一事件：所有模块间传递的网络事件形态。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkEvent {
    /// 事件发生时间（统一 UTC）。
    pub timestamp: DateTime<Utc>,
    pub source: EventSource,
    pub kind: NetworkEventKind,
    /// 事件载荷（Phase 2 改为强类型枚举）。
    pub payload: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn event_roundtrip() {
        let event = NetworkEvent {
            timestamp: Utc::now(),
            source: EventSource::ConnectionTable,
            kind: NetworkEventKind::ConnectionClosed,
            payload: json!({ "connectionId": "tcp:1.2.3.4:80-5.6.7.8:443-1000" }),
        };
        let json = serde_json::to_string(&event).unwrap();
        assert!(json.contains("\"source\":\"connection_table\""));
        assert!(json.contains("\"kind\":\"connection_closed\""));
        let back: NetworkEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back.kind, NetworkEventKind::ConnectionClosed);
        assert_eq!(back.source, EventSource::ConnectionTable);
    }
}
